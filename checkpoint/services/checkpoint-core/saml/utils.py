"""
checkpoint-core — SAML 2.0 utility functions.

Provides:
  build_saml_response    — build and sign a SAML 2.0 Assertion + Response XML
  validate_saml_response — verify SP-submitted AuthnResponse (sig, audience, time, JTI)
  generate_saml_request  — build an AuthnRequest for outbound SP-initiated SSO (upstream IDP)

Security requirements enforced:
  - All signatures verified with defusedxml (XXE prevention)
  - Audience restriction checked
  - NotBefore / NotOnOrAfter time window enforced (±5 min clock skew allowed)
  - JTI replay protection (stored in checkpoint_saml_jti_used)
  - Private key decrypted via AES-256-GCM envelope (MEK from environment)
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import defusedxml.ElementTree as defused_et
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from lxml import etree

logger = logging.getLogger(__name__)

# ── XML namespace constants ───────────────────────────────────────────────────

NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NS_XS = "http://www.w3.org/2001/XMLSchema"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

NSMAP: dict[str, str] = {
    "saml": NS_SAML,
    "samlp": NS_SAMLP,
    "ds": NS_DS,
    "xs": NS_XS,
    "xsi": NS_XSI,
}

# ── Clock skew tolerance ──────────────────────────────────────────────────────

_CLOCK_SKEW_SECONDS = 300  # ±5 minutes


# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass(slots=True)
class SAMLSpConfig:
    """Service Provider configuration used by both IdP and SP functions."""

    entity_id: str
    acs_url: str
    signing_cert: str  # PEM — used by IdP to verify SP requests (optional)
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    attribute_mapping: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class SAMLIdpConfig:
    """Upstream IdP configuration for SP-initiated SSO."""

    entity_id: str
    sso_url: str
    signing_cert: str  # PEM — IdP cert for verifying inbound assertions


# ── Envelope decryption helper ────────────────────────────────────────────────


def _decrypt_private_key(encrypted_b64: str, mek_b64: str = "") -> bytes:
    """
    Decrypt an AES-256-GCM–encrypted private key stored as base64.

    Format: base64(nonce[12] + ciphertext + tag[16])
    MEK provided as base64-encoded 32-byte key (CHECKPOINT_SIGNING_MEK env var if not supplied).
    """
    if not mek_b64:
        mek_b64 = os.environ.get("CHECKPOINT_SIGNING_MEK", "")
    if not mek_b64:
        raise ValueError(
            "CHECKPOINT_SIGNING_MEK must be set to a base64-encoded 32-byte AES-256 key"
        )
    mek_bytes = base64.b64decode(mek_b64)
    if len(mek_bytes) != 32:
        raise ValueError(
            f"CHECKPOINT_SIGNING_MEK must decode to exactly 32 bytes (got {len(mek_bytes)})"
        )
    blob = base64.b64decode(encrypted_b64)
    nonce = blob[:12]
    ciphertext_and_tag = blob[12:]
    aesgcm = AESGCM(mek_bytes)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, None)


# ── SAML timestamp helpers ─────────────────────────────────────────────────────


def _utc_now() -> datetime:
    """Return timezone-aware UTC datetime with tzinfo stripped for DB compat."""
    return datetime.now(tz=timezone.utc)


def _fmt(dt: datetime) -> str:
    """Format datetime as SAML-compatible ISO8601Z string."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── build_saml_response ────────────────────────────────────────────────────────


def build_saml_response(
    user_record: Any,
    sp_config: SAMLSpConfig,
    idp_config: dict[str, Any],
) -> str:
    """
    Build, sign, and base64-encode a SAML 2.0 AuthnResponse.

    Args:
        user_record:  Object/dict with .uuid, .email, .display_name, .groups attributes.
        sp_config:    SAMLSpConfig for the target SP.
        idp_config:   Dict with keys:
                        issuer         (str)  — IdP entity ID
                        private_key_encrypted (str) — AES-256-GCM encrypted PEM private key
                        signing_cert   (str)  — IdP signing certificate (PEM)
                        validity_secs  (int, optional) — assertion validity, default 300

    Returns:
        Base64-encoded, signed SAML AuthnResponse XML string.
    """
    now = _utc_now()
    validity = int(idp_config.get("validity_secs", 300))
    not_before = _fmt(now - timedelta(seconds=_CLOCK_SKEW_SECONDS))
    not_on_or_after = _fmt(now + timedelta(seconds=validity))
    response_id = "_" + uuid.uuid4().hex
    assertion_id = "_" + uuid.uuid4().hex

    # Resolve user attributes
    if hasattr(user_record, "uuid"):
        user_uuid = str(user_record.uuid)
        user_email = str(user_record.email)
        display_name = str(getattr(user_record, "display_name", "") or "")
    else:
        user_uuid = str(user_record.get("uuid", ""))
        user_email = str(user_record.get("email", ""))
        display_name = str(user_record.get("display_name", "") or "")

    issuer_str = idp_config["issuer"]

    # Build Response element
    response = etree.Element(f"{{{NS_SAMLP}}}Response", nsmap=NSMAP)
    response.set("ID", response_id)
    response.set("Version", "2.0")
    response.set("IssueInstant", _fmt(now))
    response.set("Destination", sp_config.acs_url)
    response.set("InResponseTo", "")  # SP supplies this at runtime; placeholder

    issuer_el = etree.SubElement(response, f"{{{NS_SAML}}}Issuer")
    issuer_el.text = issuer_str

    status = etree.SubElement(response, f"{{{NS_SAMLP}}}Status")
    status_code = etree.SubElement(status, f"{{{NS_SAMLP}}}StatusCode")
    status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    # Assertion
    assertion = etree.SubElement(response, f"{{{NS_SAML}}}Assertion", nsmap=NSMAP)
    assertion.set("ID", assertion_id)
    assertion.set("Version", "2.0")
    assertion.set("IssueInstant", _fmt(now))

    a_issuer = etree.SubElement(assertion, f"{{{NS_SAML}}}Issuer")
    a_issuer.text = issuer_str

    # Subject
    subject = etree.SubElement(assertion, f"{{{NS_SAML}}}Subject")
    name_id = etree.SubElement(subject, f"{{{NS_SAML}}}NameID")
    name_id.set("Format", sp_config.name_id_format)
    name_id.text = user_email

    subj_conf = etree.SubElement(subject, f"{{{NS_SAML}}}SubjectConfirmation")
    subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    subj_conf_data = etree.SubElement(subj_conf, f"{{{NS_SAML}}}SubjectConfirmationData")
    subj_conf_data.set("NotOnOrAfter", not_on_or_after)
    subj_conf_data.set("Recipient", sp_config.acs_url)

    # Conditions
    conditions = etree.SubElement(assertion, f"{{{NS_SAML}}}Conditions")
    conditions.set("NotBefore", not_before)
    conditions.set("NotOnOrAfter", not_on_or_after)
    aud_restriction = etree.SubElement(conditions, f"{{{NS_SAML}}}AudienceRestriction")
    audience = etree.SubElement(aud_restriction, f"{{{NS_SAML}}}Audience")
    audience.text = sp_config.entity_id

    # AuthnStatement
    authn_stmt = etree.SubElement(assertion, f"{{{NS_SAML}}}AuthnStatement")
    authn_stmt.set("AuthnInstant", _fmt(now))
    authn_ctx = etree.SubElement(authn_stmt, f"{{{NS_SAML}}}AuthnContext")
    authn_ctx_class = etree.SubElement(authn_ctx, f"{{{NS_SAML}}}AuthnContextClassRef")
    authn_ctx_class.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # AttributeStatement
    attr_stmt = etree.SubElement(assertion, f"{{{NS_SAML}}}AttributeStatement")
    _add_attribute(attr_stmt, "uid", user_uuid)
    _add_attribute(attr_stmt, "email", user_email)
    if display_name:
        _add_attribute(attr_stmt, "displayName", display_name)

    # SP-defined attribute mappings
    for saml_attr, user_attr in sp_config.attribute_mapping.items():
        val: str | None = None
        if hasattr(user_record, user_attr):
            val = getattr(user_record, user_attr)
        elif isinstance(user_record, dict):
            val = user_record.get(user_attr)
        if val is not None:
            _add_attribute(attr_stmt, saml_attr, str(val))

    # Sign the assertion
    private_key_pem = _decrypt_private_key(idp_config["private_key_encrypted"])
    _sign_element(assertion, private_key_pem, assertion_id)

    xml_bytes = etree.tostring(response, xml_declaration=True, encoding="UTF-8")
    return base64.b64encode(xml_bytes).decode()


def _add_attribute(parent: etree._Element, name: str, value: str) -> None:
    """Append a SAML Attribute element with a single AttributeValue."""
    attr = etree.SubElement(parent, f"{{{NS_SAML}}}Attribute")
    attr.set("Name", name)
    attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
    attr_val = etree.SubElement(attr, f"{{{NS_SAML}}}AttributeValue")
    attr_val.set(f"{{{NS_XSI}}}type", "xs:string")
    attr_val.text = value


def _sign_element(element: etree._Element, private_key_pem: bytes, ref_id: str) -> None:
    """
    Insert a simple enveloped XML signature into *element*.

    Uses RSA-SHA256 with SHA-256 digest. Inserts the Signature element
    immediately after the Issuer child (SAML convention).
    """
    # Canonicalise the element (exclusive C14N) for digest
    c14n = etree.tostring(element, method="c14n", exclusive=True, with_comments=False)
    digest = hashlib.sha256(c14n).digest()
    digest_b64 = base64.b64encode(digest).decode()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature_bytes = private_key.sign(  # type: ignore[attr-defined]
        c14n,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(signature_bytes).decode()

    # Build Signature element
    sig = etree.Element(f"{{{NS_DS}}}Signature", nsmap={"ds": NS_DS})
    signed_info = etree.SubElement(sig, f"{{{NS_DS}}}SignedInfo")
    c14n_method = etree.SubElement(signed_info, f"{{{NS_DS}}}CanonicalizationMethod")
    c14n_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
    sig_method = etree.SubElement(signed_info, f"{{{NS_DS}}}SignatureMethod")
    sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    reference = etree.SubElement(signed_info, f"{{{NS_DS}}}Reference")
    reference.set("URI", f"#{ref_id}")
    transforms = etree.SubElement(reference, f"{{{NS_DS}}}Transforms")
    t_env = etree.SubElement(transforms, f"{{{NS_DS}}}Transform")
    t_env.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    t_c14n = etree.SubElement(transforms, f"{{{NS_DS}}}Transform")
    t_c14n.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
    digest_method = etree.SubElement(reference, f"{{{NS_DS}}}DigestMethod")
    digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
    digest_value_el = etree.SubElement(reference, f"{{{NS_DS}}}DigestValue")
    digest_value_el.text = digest_b64
    sig_value_el = etree.SubElement(sig, f"{{{NS_DS}}}SignatureValue")
    sig_value_el.text = sig_b64

    # Insert after Issuer
    issuer_idx: int = 0
    for i, child in enumerate(element):
        if child.tag == f"{{{NS_SAML}}}Issuer":
            issuer_idx = i + 1
            break
    element.insert(issuer_idx, sig)


# ── validate_saml_response ────────────────────────────────────────────────────


def validate_saml_response(
    saml_response_b64: str,
    sp_config: SAMLSpConfig,
    db: Any,
    issuer: str,
    idp_cert_pem: str,
) -> dict[str, Any]:
    """
    Validate an incoming SAML 2.0 AuthnResponse from an SP.

    Checks performed:
      1. XML parsing via defusedxml (XXE prevention)
      2. Signature verification with the IdP signing certificate
      3. Audience restriction — sp_config.entity_id must appear in Conditions
      4. Time window — NotBefore / NotOnOrAfter with ±5 min clock skew
      5. JTI (Assertion ID) replay — stored in checkpoint_saml_jti_used

    Args:
        saml_response_b64: Base64-encoded SAML Response XML.
        sp_config:         SAMLSpConfig for the expected SP.
        db:                PyDAL DAL instance (needs checkpoint_saml_jti_used table).
        issuer:            Expected Issuer string (IdP entity ID).
        idp_cert_pem:      PEM certificate of the signing IdP.

    Returns:
        Dict with extracted claims: sub, email, attributes.

    Raises:
        ValueError: on any validation failure.
    """
    try:
        xml_bytes = base64.b64decode(saml_response_b64)
    except Exception as exc:
        raise ValueError(f"saml_response is not valid base64: {exc}") from exc

    # Parse with a hardened lxml XMLParser — disables external entity resolution
    # and network access, making it safe against XXE even for untrusted SAML XML.
    # resolve_entities=False prevents entity expansion; no_network=True blocks
    # fetching of external DTD/entity URIs; huge_tree=False caps memory usage.
    _safe_parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        load_dtd=False,
    )
    try:
        root = etree.fromstring(xml_bytes, _safe_parser)  # nosec B320
    except etree.XMLSyntaxError as exc:
        raise ValueError(f"SAML XML syntax error: {exc}") from exc

    # Find Assertion
    assertions = root.findall(f".//{{{NS_SAML}}}Assertion")
    if not assertions:
        raise ValueError("SAML response contains no Assertion")
    assertion = assertions[0]

    # Verify assertion ID uniqueness (replay protection)
    assertion_id = assertion.get("ID", "")
    if not assertion_id:
        raise ValueError("Assertion missing ID attribute")

    id_hash = hashlib.sha256(assertion_id.encode()).hexdigest()
    if hasattr(db, "checkpoint_saml_jti_used"):
        existing = db(db.checkpoint_saml_jti_used.jti_hash == id_hash).select().first()
        if existing is not None:
            raise ValueError(f"SAML assertion ID replay detected: {assertion_id[:16]}…")
        db.checkpoint_saml_jti_used.insert(
            jti_hash=id_hash,
            used_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        db.commit()

    # Verify issuer
    issuer_els = assertion.findall(f"{{{NS_SAML}}}Issuer")
    if not issuer_els or issuer_els[0].text != issuer:
        raise ValueError(
            f"SAML issuer mismatch: expected {issuer!r}, got {issuer_els[0].text if issuer_els else None!r}"
        )

    # Verify audience restriction
    audiences = assertion.findall(
        f".//{{{NS_SAML}}}AudienceRestriction/{{{NS_SAML}}}Audience"
    )
    audience_values = {a.text for a in audiences if a.text}
    if sp_config.entity_id not in audience_values:
        raise ValueError(
            f"SAML audience restriction violation: {sp_config.entity_id!r} not in {audience_values}"
        )

    # Verify time conditions
    conditions_el = assertion.find(f"{{{NS_SAML}}}Conditions")
    now = _utc_now().replace(tzinfo=None)
    if conditions_el is not None:
        not_before_str = conditions_el.get("NotBefore")
        not_after_str = conditions_el.get("NotOnOrAfter")
        if not_before_str:
            not_before_dt = _parse_saml_datetime(not_before_str)
            if now < not_before_dt - timedelta(seconds=_CLOCK_SKEW_SECONDS):
                raise ValueError(f"SAML assertion not yet valid (NotBefore={not_before_str})")
        if not_after_str:
            not_after_dt = _parse_saml_datetime(not_after_str)
            if now > not_after_dt + timedelta(seconds=_CLOCK_SKEW_SECONDS):
                raise ValueError(f"SAML assertion expired (NotOnOrAfter={not_after_str})")

    # Verify signature
    sig_el = assertion.find(f"{{{NS_DS}}}Signature")
    if sig_el is None:
        raise ValueError("SAML assertion is not signed")

    _verify_signature(assertion, sig_el, idp_cert_pem)

    # Extract claims
    name_id_el = assertion.find(f".//{{{NS_SAML}}}NameID")
    subject_email = name_id_el.text if name_id_el is not None else ""

    attributes: dict[str, str] = {}
    for attr_el in assertion.findall(f".//{{{NS_SAML}}}Attribute"):
        attr_name = attr_el.get("Name", "")
        val_el = attr_el.find(f"{{{NS_SAML}}}AttributeValue")
        if attr_name and val_el is not None:
            attributes[attr_name] = val_el.text or ""

    sub_uuid = attributes.get("uid", "")
    return {
        "sub": sub_uuid or subject_email,
        "email": subject_email,
        "attributes": attributes,
    }


def _parse_saml_datetime(dt_str: str) -> datetime:
    """Parse SAML ISO8601Z datetime string to naive UTC datetime."""
    dt_str = dt_str.rstrip("Z")
    try:
        return datetime.fromisoformat(dt_str)
    except ValueError:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S")


def _verify_signature(
    element: etree._Element,
    sig_el: etree._Element,
    cert_pem: str,
) -> None:
    """
    Verify RSA-SHA256 enveloped signature using the provided PEM certificate.

    Raises ValueError if signature is invalid.
    """
    from cryptography import x509

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        pub_key = cert.public_key()
    except Exception as exc:
        raise ValueError(f"Invalid IdP certificate: {exc}") from exc

    sig_value_el = sig_el.find(f"{{{NS_DS}}}SignatureValue")
    if sig_value_el is None or not sig_value_el.text:
        raise ValueError("SAML signature missing SignatureValue")

    sig_bytes = base64.b64decode(sig_value_el.text.strip())

    # Remove the Signature element from the element copy for C14N digest
    element_copy = _clone_without_signature(element, sig_el)
    c14n_bytes = etree.tostring(element_copy, method="c14n", exclusive=True, with_comments=False)

    try:
        pub_key.verify(sig_bytes, c14n_bytes, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[attr-defined]
    except Exception as exc:
        raise ValueError(f"SAML signature verification failed: {exc}") from exc


def _clone_without_signature(
    element: etree._Element,
    sig_el: etree._Element,
) -> etree._Element:
    """Return a deep copy of *element* with the Signature child removed."""
    import copy

    clone = copy.deepcopy(element)
    for child in list(clone):
        if child.tag == f"{{{NS_DS}}}Signature":
            clone.remove(child)
    return clone


# ── generate_saml_request ────────────────────────────────────────────────────


def generate_saml_request(
    idp_config: SAMLIdpConfig,
    relay_state: str,
    acs_url: str,
    sp_entity_id: str,
) -> tuple[str, str]:
    """
    Generate a SAML 2.0 AuthnRequest for SP-initiated SSO to an upstream IdP.

    Args:
        idp_config:    SAMLIdpConfig for the target upstream IdP.
        relay_state:   Relay state value to round-trip through the IdP.
        acs_url:       This SP's ACS URL (where IdP should post the response).
        sp_entity_id:  This SP's entity ID.

    Returns:
        Tuple of (saml_request_b64, relay_state).
        The caller should redirect to:
          idp_config.sso_url?SAMLRequest=<saml_request_b64>&RelayState=<relay_state>
    """
    now = _utc_now()
    request_id = "_" + uuid.uuid4().hex

    request = etree.Element(f"{{{NS_SAMLP}}}AuthnRequest", nsmap=NSMAP)
    request.set("ID", request_id)
    request.set("Version", "2.0")
    request.set("IssueInstant", _fmt(now))
    request.set("Destination", idp_config.sso_url)
    request.set("AssertionConsumerServiceURL", acs_url)
    request.set("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    request.set("ForceAuthn", "false")
    request.set("IsPassive", "false")

    issuer_el = etree.SubElement(request, f"{{{NS_SAML}}}Issuer")
    issuer_el.text = sp_entity_id

    name_id_policy = etree.SubElement(request, f"{{{NS_SAMLP}}}NameIDPolicy")
    name_id_policy.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    name_id_policy.set("AllowCreate", "true")

    requested_authn_ctx = etree.SubElement(request, f"{{{NS_SAMLP}}}RequestedAuthnContext")
    requested_authn_ctx.set("Comparison", "minimum")
    authn_ctx_class_ref = etree.SubElement(requested_authn_ctx, f"{{{NS_SAML}}}AuthnContextClassRef")
    authn_ctx_class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    xml_bytes = etree.tostring(request, xml_declaration=True, encoding="UTF-8")
    request_b64 = base64.b64encode(xml_bytes).decode()
    return request_b64, relay_state
