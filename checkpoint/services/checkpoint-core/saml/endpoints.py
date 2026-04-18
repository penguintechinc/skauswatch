"""
checkpoint-core — SAML 2.0 IdP endpoints.

Blueprint: saml_bp, prefix /saml

Endpoints:
  GET  /saml/metadata              — IdP metadata XML (public, no auth)
  GET  /saml/sso                   — IdP-initiated SSO redirect
  POST /saml/acs/<sp_entity_b64>   — Assertion Consumer Service (SP posts response here)
  POST /saml/slo                   — Single Logout (stub, returns 200)
  GET  /saml/upstream/<idp_id>     — Generate AuthnRequest for upstream IdP federation
"""
from __future__ import annotations

import base64
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from quart import Blueprint, Response, current_app, jsonify, request

from audit.logger import AuditLogger
from saml.utils import (
    SAMLIdpConfig,
    SAMLSpConfig,
    build_saml_response,
    generate_saml_request,
    validate_saml_response,
)

logger = logging.getLogger(__name__)

saml_bp = Blueprint("saml", __name__, url_prefix="/saml")


# ── App extension helpers ──────────────────────────────────────────────────────


def _get_db() -> Any:
    return current_app.extensions["checkpoint_db"]


def _get_config() -> Any:
    return current_app.extensions["checkpoint_config"]


def _get_core() -> Any:
    return current_app.extensions["checkpoint_core_client"]


def _get_audit() -> AuditLogger:
    return current_app.extensions["checkpoint_audit"]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


# ── Helpers ────────────────────────────────────────────────────────────────────


def _get_sp_config(sp_entity_id: str) -> SAMLSpConfig | None:
    """Look up SP configuration from checkpoint_saml_providers by entity_id."""
    db = _get_db()
    row = db(db.checkpoint_saml_providers.entity_id == sp_entity_id).select().first()
    if row is None:
        return None
    return SAMLSpConfig(
        entity_id=row.entity_id,
        acs_url=row.acs_url,
        signing_cert=row.signing_cert or "",
        name_id_format=row.name_id_format or "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        attribute_mapping=row.attribute_mapping or {},
    )


def _get_active_signing_key(db: Any) -> dict[str, Any] | None:
    """Return active signing key row or None."""
    row = db(
        (db.checkpoint_signing_keys.is_active == True)  # noqa: E712
    ).select(orderby=~db.checkpoint_signing_keys.id).first()
    return row


# ── Endpoints ──────────────────────────────────────────────────────────────────


@saml_bp.route("/metadata", methods=["GET"])
async def idp_metadata() -> Response:
    """
    Return IdP SAML metadata XML.

    No authentication required — this is a public discovery document.
    """
    cfg = _get_config()
    db = _get_db()

    signing_key = _get_active_signing_key(db)
    signing_cert = ""
    if signing_key:
        signing_cert = signing_key.get("public_key", "") or ""

    issuer_url = cfg.issuer_url.rstrip("/")
    sso_url = f"{issuer_url}/saml/sso"
    slo_url = f"{issuer_url}/saml/slo"

    metadata_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="{issuer_url}">
  <md:IDPSSODescriptor
      WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{_strip_pem(signing_cert)}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{slo_url}"/>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{sso_url}"/>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{sso_url}"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    return Response(metadata_xml, content_type="application/xml")


@saml_bp.route("/sso", methods=["GET", "POST"])
async def sso() -> Any:
    """
    IdP Single Sign-On endpoint.

    Expects a SAMLRequest parameter (base64-encoded AuthnRequest) and a
    RelayState. After user identity is established via the Bearer JWT in the
    Authorization header, builds and returns a signed SAML Response.

    This endpoint is intended for SP-initiated SSO where the calling code
    has already obtained a valid JWT (e.g., from the OIDC flow) and needs
    to exchange it for a SAML assertion.
    """
    from oidc.jwt_utils import verify_token

    db = _get_db()
    cfg = _get_config()
    audit = _get_audit()

    # Authenticate the requesting user via JWT
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401

    raw_jwt = auth[7:]
    try:
        claims = verify_token(db, cfg.issuer_url, raw_jwt)
    except Exception:
        return jsonify({"error": "unauthorized"}), 401

    user_uuid: str = claims.get("sub", "")

    # Determine target SP from SAMLRequest
    saml_request_b64: str = ""
    relay_state: str = ""
    sp_entity_id: str = ""

    if request.method == "GET":
        saml_request_b64 = request.args.get("SAMLRequest", "")
        relay_state = request.args.get("RelayState", "")
        sp_entity_id = request.args.get("sp", "")  # Direct SP entity ID param
    else:
        form_data = await request.form
        saml_request_b64 = form_data.get("SAMLRequest", "")
        relay_state = form_data.get("RelayState", "")
        sp_entity_id = form_data.get("sp", "")

    # Parse sp_entity_id from the SAMLRequest Issuer if not provided directly
    if not sp_entity_id and saml_request_b64:
        try:
            sp_entity_id = _extract_issuer_from_authn_request(saml_request_b64)
        except Exception as exc:
            logger.warning("saml.sso.authn_request_parse_error error=%r", exc)

    if not sp_entity_id:
        return jsonify({"error": "sp entity_id required (SAMLRequest Issuer or ?sp= param)"}), 400

    sp_config = _get_sp_config(sp_entity_id)
    if sp_config is None:
        return jsonify({"error": "unknown service provider"}), 404

    # Fetch user from core
    core = _get_core()
    try:
        user = await core.get_user(user_uuid)
    except Exception as exc:
        logger.error("saml.sso.get_user_error user_uuid=%s error=%r", user_uuid, exc)
        return jsonify({"error": "failed to retrieve user identity"}), 500

    if user is None:
        return jsonify({"error": "user not found"}), 404

    # Get active signing key
    signing_key_row = _get_active_signing_key(db)
    if signing_key_row is None:
        return jsonify({"error": "no active signing key — operator action required"}), 503

    idp_config: dict[str, Any] = {
        "issuer": cfg.issuer_url,
        "private_key_encrypted": signing_key_row["private_key_encrypted"],
        "signing_cert": signing_key_row["public_key"] or "",
    }

    try:
        saml_response_b64 = build_saml_response(user, sp_config, idp_config)
    except Exception as exc:
        logger.error("saml.sso.build_response_error error=%r", exc)
        return jsonify({"error": "failed to build SAML response"}), 500

    await audit.log(
        "saml.sso_issued",
        actor_uuid=user_uuid,
        actor_ip=_client_ip(),
        details={"sp_entity_id": sp_entity_id},
    )

    # Return the response for HTTP-POST binding
    acs_url = sp_config.acs_url
    html = f"""<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="{acs_url}">
    <input type="hidden" name="SAMLResponse" value="{saml_response_b64}">
    <input type="hidden" name="RelayState" value="{relay_state}">
    <noscript><button type="submit">Continue</button></noscript>
  </form>
</body>
</html>"""

    return Response(html, content_type="text/html")


@saml_bp.route("/acs/<sp_entity_b64>", methods=["POST"])
async def acs(sp_entity_b64: str) -> Any:
    """
    Assertion Consumer Service — receive and validate a SAML Response
    from an upstream IdP (used in federation/proxy mode).

    sp_entity_b64: URL-safe base64-encoded SP entity ID (our checkpoint identity).
    """
    db = _get_db()
    cfg = _get_config()
    audit = _get_audit()

    try:
        sp_entity_id = base64.urlsafe_b64decode(sp_entity_b64 + "==").decode()
    except Exception:
        return jsonify({"error": "invalid sp_entity_b64"}), 400

    form_data = await request.form
    saml_response_b64: str = form_data.get("SAMLResponse", "")
    relay_state: str = form_data.get("RelayState", "")

    if not saml_response_b64:
        return jsonify({"error": "SAMLResponse is required"}), 400

    # Find the upstream IDP that sent this response
    # Look up by relay_state prefix (format: "idp:<idp_id>:<original_relay_state>")
    upstream_idp_id: str | None = None
    original_relay_state: str = relay_state
    if relay_state.startswith("idp:"):
        parts = relay_state.split(":", 2)
        if len(parts) >= 2:
            upstream_idp_id = parts[1]
            original_relay_state = parts[2] if len(parts) > 2 else ""

    if not upstream_idp_id:
        return jsonify({"error": "relay_state must carry upstream IDP id"}), 400

    # Load the upstream IDP config
    idp_row = db(db.checkpoint_upstream_idps.id == int(upstream_idp_id)).select().first()
    if idp_row is None:
        return jsonify({"error": "upstream IDP not found"}), 404

    from crypto.envelope import decrypt_config_json

    try:
        idp_cfg_decrypted = decrypt_config_json(idp_row.config_json_encrypted)
    except Exception as exc:
        logger.error("saml.acs.config_decrypt_error idp_id=%s error=%r", upstream_idp_id, exc)
        return jsonify({"error": "IDP configuration error"}), 500

    idp_cert = idp_cfg_decrypted.get("signing_cert", "")
    issuer = idp_cfg_decrypted.get("entity_id", "")

    sp_config = SAMLSpConfig(
        entity_id=sp_entity_id,
        acs_url=f"{cfg.issuer_url.rstrip('/')}/saml/acs/{sp_entity_b64}",
        signing_cert="",
        name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    )

    try:
        claims = validate_saml_response(
            saml_response_b64,
            sp_config,
            db,
            issuer=issuer,
            idp_cert_pem=idp_cert,
        )
    except ValueError as exc:
        logger.warning("saml.acs.validation_error error=%r", exc)
        await audit.log(
            "saml.acs_validation_failed",
            actor_uuid=None,
            actor_ip=_client_ip(),
            details={"error": str(exc), "idp_id": upstream_idp_id},
        )
        return jsonify({"error": str(exc)}), 400

    await audit.log(
        "saml.acs_validated",
        actor_uuid=claims.get("sub"),
        actor_ip=_client_ip(),
        details={"idp_id": upstream_idp_id, "relay_state": original_relay_state},
    )

    return jsonify({
        "sub": claims["sub"],
        "email": claims["email"],
        "attributes": claims["attributes"],
        "relay_state": original_relay_state,
    })


@saml_bp.route("/slo", methods=["GET", "POST"])
async def slo() -> Any:
    """
    Single Logout endpoint (stub).

    Accepts SLO requests and responds with success. Full SLO session
    termination is handled by the OIDC token revocation flow.
    """
    logger.info("saml.slo.received client_ip=%s", _client_ip())
    return jsonify({"status": "logout_acknowledged"})


@saml_bp.route("/upstream/<int:idp_id>", methods=["GET"])
async def upstream_sso_redirect(idp_id: int) -> Any:
    """
    Generate a SAML AuthnRequest for an upstream IdP and return the redirect URL.

    Query params:
      relay_state — optional relay state to carry through
      sp          — SP entity ID to use as the Issuer in the AuthnRequest

    Returns:
      JSON with redirect_url (caller must redirect the user's browser there)
    """
    db = _get_db()
    cfg = _get_config()

    relay_state_in: str = request.args.get("relay_state", "")
    sp_entity_id: str = request.args.get("sp", cfg.issuer_url)

    idp_row = db(db.checkpoint_upstream_idps.id == idp_id).select().first()
    if idp_row is None:
        return jsonify({"error": "upstream IDP not found"}), 404

    from crypto.envelope import decrypt_config_json

    try:
        idp_cfg = decrypt_config_json(idp_row.config_json_encrypted)
    except Exception as exc:
        logger.error("saml.upstream.config_decrypt_error idp_id=%d error=%r", idp_id, exc)
        return jsonify({"error": "IDP configuration error"}), 500

    idp_config = SAMLIdpConfig(
        entity_id=idp_cfg.get("entity_id", ""),
        sso_url=idp_cfg.get("sso_url", ""),
        signing_cert=idp_cfg.get("signing_cert", ""),
    )

    # Embed idp_id in relay_state so the ACS handler can route back
    composed_relay_state = f"idp:{idp_id}:{relay_state_in}"

    # ACS URL for this IDP interaction
    sp_entity_b64 = base64.urlsafe_b64encode(sp_entity_id.encode()).decode().rstrip("=")
    acs_url = f"{cfg.issuer_url.rstrip('/')}/saml/acs/{sp_entity_b64}"

    try:
        saml_request_b64, relay_state_out = generate_saml_request(
            idp_config=idp_config,
            relay_state=composed_relay_state,
            acs_url=acs_url,
            sp_entity_id=sp_entity_id,
        )
    except Exception as exc:
        logger.error("saml.upstream.generate_request_error idp_id=%d error=%r", idp_id, exc)
        return jsonify({"error": "failed to generate AuthnRequest"}), 500

    redirect_url = (
        f"{idp_config.sso_url}?"
        f"SAMLRequest={urllib.parse.quote(saml_request_b64)}&"
        f"RelayState={urllib.parse.quote(relay_state_out)}"
    )

    return jsonify({
        "redirect_url": redirect_url,
        "idp_id": idp_id,
        "relay_state": relay_state_out,
    })


# ── Private helpers ────────────────────────────────────────────────────────────


def _strip_pem(pem: str) -> str:
    """Strip PEM headers and whitespace from a certificate, returning just the base64 body."""
    lines = [
        line.strip()
        for line in pem.splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    return "".join(lines)


def _extract_issuer_from_authn_request(saml_request_b64: str) -> str:
    """
    Extract the Issuer element from a base64-encoded SAML AuthnRequest.

    Uses defusedxml for safe parsing.
    """
    import defusedxml.ElementTree as det

    xml_bytes = base64.b64decode(saml_request_b64)
    root = det.fromstring(xml_bytes)
    issuer_el = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    if issuer_el is not None and issuer_el.text:
        return issuer_el.text.strip()
    return ""
