"""
checkpoint-core — SCIM 2.0 attribute mappers.

Converts between gRPC UserRecord/GroupRecord DTOs and RFC 7644 SCIM JSON
representations.

References:
  RFC 7643 — SCIM Core Schema
  RFC 7644 — SCIM Protocol
"""
from __future__ import annotations

from typing import Any

# SCIM schema URNs
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def user_to_scim(user: Any, base_url: str = "") -> dict[str, Any]:
    """
    Convert a CoreIdentityClient UserRecord to a SCIM User resource.

    Parameters
    ----------
    user:     UserRecord from CoreIdentityClient (or proto user object).
    base_url: Base URL of the SCIM endpoint (e.g. https://checkpoint.example.com/scim/v2).
              Used to build the meta.location URL.

    Returns a dict conforming to RFC 7643 User schema.
    """
    # Split display_name into name parts (best-effort)
    display = getattr(user, "display_name", "") or ""
    parts = display.split(" ", 1)
    given = parts[0] if parts else ""
    family = parts[1] if len(parts) > 1 else ""

    # Map groups list to SCIM groups
    groups: list[dict[str, str]] = [
        {"value": g, "display": g}
        for g in (getattr(user, "groups", []) or [])
    ]

    scim_user: dict[str, Any] = {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.uuid,
        "externalId": user.uuid,
        "userName": user.username,
        "name": {
            "formatted": display,
            "givenName": given,
            "familyName": family,
        },
        "displayName": display,
        "emails": [
            {"value": user.email, "primary": True, "type": "work"}
        ],
        "active": bool(user.is_active),
        "groups": groups,
        "meta": {
            "resourceType": "User",
            "location": f"{base_url.rstrip('/')}/Users/{user.uuid}",
        },
    }

    # Attach custom attributes as SCIM extension if present
    attrs: dict[str, str] = getattr(user, "attributes", {}) or {}
    if attrs:
        scim_user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] = {
            k: v for k, v in attrs.items()
        }

    return scim_user


def group_to_scim(group: Any, members: list[Any] | None = None, base_url: str = "") -> dict[str, Any]:
    """
    Convert a GroupRecord (or proto group) to a SCIM Group resource.

    Parameters
    ----------
    group:    GroupRecord from CoreIdentityClient.
    members:  Optional list of UserRecords to include as SCIM members.
    base_url: Base URL for meta.location.
    """
    scim_members: list[dict[str, str]] = []
    if members:
        for m in members:
            scim_members.append({
                "value": m.uuid,
                "display": getattr(m, "display_name", "") or m.username,
                "$ref": f"{base_url.rstrip('/')}/Users/{m.uuid}",
            })

    return {
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": group.uuid,
        "externalId": group.uuid,
        "displayName": group.name,
        "members": scim_members,
        "meta": {
            "resourceType": "Group",
            "location": f"{base_url.rstrip('/')}/Groups/{group.uuid}",
        },
    }


def scim_to_user_fields(scim_body: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a SCIM User resource body to the field dict accepted by
    CoreIdentityClient.create_user / .update_user.

    Handles both POST (full resource) and PATCH operation payloads.
    Only maps known fields — ignores unknown SCIM extensions.
    """
    fields: dict[str, Any] = {}

    if "userName" in scim_body:
        fields["username"] = scim_body["userName"]

    if "displayName" in scim_body:
        fields["display_name"] = scim_body["displayName"]
    elif "name" in scim_body:
        name = scim_body["name"]
        if isinstance(name, dict):
            if name.get("formatted"):
                fields["display_name"] = name["formatted"]
            elif name.get("givenName") or name.get("familyName"):
                fields["display_name"] = (
                    f"{name.get('givenName', '')} {name.get('familyName', '')}".strip()
                )

    if "emails" in scim_body:
        emails = scim_body["emails"]
        if isinstance(emails, list) and emails:
            # Prefer primary email, fall back to first
            primary = next((e for e in emails if e.get("primary")), emails[0])
            fields["email"] = primary.get("value", "")

    if "active" in scim_body:
        fields["is_active"] = bool(scim_body["active"])

    if "password" in scim_body:
        fields["password"] = scim_body["password"]

    return fields


def scim_error(status: int, detail: str, scim_type: str = "") -> dict[str, Any]:
    """Build a RFC 7644 SCIM error response dict."""
    err: dict[str, Any] = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        err["scimType"] = scim_type
    return err


def scim_list_response(
    resources: list[dict[str, Any]],
    total_results: int,
    start_index: int = 1,
) -> dict[str, Any]:
    """Build a RFC 7644 SCIM ListResponse."""
    return {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": total_results,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }
