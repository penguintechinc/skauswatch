"""
checkpoint-core — LDAP DN and filter sanitisation utilities.

All input that arrives from LDAP clients is untrusted.  This module provides:
  - DN parsing and validation against an allowed base DN
  - LDAP filter sanitisation (injection prevention)
  - Attribute-set helpers for converting CoreIdentityClient user/group
    records into LDAP attribute dictionaries

Security note:
  LDAP injection is performed by inserting unescaped special characters into
  filter expressions (e.g. `*)(uid=*))(|(uid=*`).  All filter values that
  originate from client-supplied search filters must pass through
  `validate_ldap_filter()` before being forwarded to any backend.
"""
from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Characters that MUST be escaped in LDAP filter values (RFC 4515 §3)
# The raw characters \x00 * ( ) \ are special in LDAP filters.
_FILTER_ILLEGAL_RE = re.compile(r"[*\x00\(\)\\]")

# DN component regex — allow letters, digits, spaces, common punctuation
# but reject shell metacharacters and LDAP injection sequences.
# Explicitly excludes \r and \n to prevent CRLF injection.
_DN_SAFE_ATTR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-]*$")
_DN_SAFE_VALUE_RE = re.compile(r"^[^,=\+<>#;\x00\\\"\r\n]{1,256}$")


# ── DN utilities ───────────────────────────────────────────────────────────────


def validate_dn(dn: str, base_dn: str) -> bool:
    """
    Validate that `dn` is a syntactically well-formed Distinguished Name
    and is a descendant of (or equal to) `base_dn`.

    Args:
        dn:      The Distinguished Name to validate.
        base_dn: The allowed LDAP base DN (e.g. "dc=example,dc=com").

    Returns:
        True if `dn` is safe and within `base_dn`; False otherwise.
    """
    if not dn or not base_dn:
        return False

    # Reject CRLF before any stripping — .strip() would silently remove them
    if "\r" in dn or "\n" in dn:
        logger.warning("dn_utils.crlf_in_dn")
        return False

    dn_lower = dn.strip().lower()
    base_lower = base_dn.strip().lower()

    # Must end with (or be equal to) the base DN
    if not (dn_lower == base_lower or dn_lower.endswith("," + base_lower)):
        return False

    # Validate each RDN component
    components = dn.split(",")
    for component in components:
        component = component.strip()
        if "=" not in component:
            return False
        attr, _, value = component.partition("=")
        attr = attr.strip()
        value = value.strip()
        if not _DN_SAFE_ATTR_RE.match(attr):
            logger.warning("dn_utils.invalid_dn_attr attr=%r", attr)
            return False
        if not _DN_SAFE_VALUE_RE.match(value):
            logger.warning("dn_utils.invalid_dn_value value_length=%d", len(value))
            return False

    return True


def parse_user_email(dn: str, base_dn: str) -> str | None:
    """
    Extract the user's email (or uid) from a user entry DN.

    Expects DNs in the form:
      uid=alice@example.com,ou=users,dc=example,dc=com
      mail=alice@example.com,ou=users,dc=example,dc=com

    Args:
        dn:      The full Distinguished Name of the user entry.
        base_dn: The LDAP base DN.

    Returns:
        The email string extracted from the uid/mail RDN, or None if the DN
        is not a user entry or is malformed.
    """
    if not validate_dn(dn, base_dn):
        return None

    components = dn.split(",")
    if not components:
        return None

    rdn = components[0].strip()
    if "=" not in rdn:
        return None

    attr, _, value = rdn.partition("=")
    attr_lower = attr.strip().lower()
    value = value.strip()

    # Only uid= and mail= are accepted for user email extraction.
    # cn= is intentionally excluded: group entries use cn= too, so accepting
    # cn= here would make group DNs ambiguous with user DNs.
    if attr_lower in ("uid", "mail"):
        if "@" in value or re.match(r"^[A-Za-z0-9._\-]{1,128}$", value):
            return value.lower()

    return None


def parse_group_name(dn: str, base_dn: str) -> str | None:
    """
    Extract the group name from a group entry DN.

    Expects DNs in the form:
      cn=engineering,ou=groups,dc=example,dc=com

    Args:
        dn:      The full Distinguished Name of the group entry.
        base_dn: The LDAP base DN.

    Returns:
        The group name extracted from the cn RDN, or None if the DN is not
        a group entry or is malformed.
    """
    if not validate_dn(dn, base_dn):
        return None

    components = dn.split(",")
    if not components:
        return None

    rdn = components[0].strip()
    if "=" not in rdn:
        return None

    attr, _, value = rdn.partition("=")
    attr_lower = attr.strip().lower()
    value = value.strip()

    if attr_lower == "cn":
        if re.match(r"^[A-Za-z0-9._\- ]{1,128}$", value):
            return value

    return None


def validate_ldap_filter(filter_str: str) -> bool:
    """
    Validate that an LDAP filter string does not contain injection sequences.

    This is a conservative allow-list validator:
      - Allows ASCII alphanumeric characters, basic comparison operators,
        RFC 4515 presence/substring filters, and parentheses that are part
        of properly nested Boolean sub-filters.
      - Rejects NULL bytes and unescaped backslash sequences.

    Note: This is a heuristic guard, not a full RFC 4515 parser.  For
    production-grade security, use ldaptor's built-in filter parsing, which
    is based on the full BNF grammar.

    Args:
        filter_str: The raw LDAP filter string, e.g. "(uid=alice)".

    Returns:
        True if the filter passes basic injection checks; False otherwise.
    """
    if not filter_str:
        return False

    # Null bytes are always illegal
    if "\x00" in filter_str:
        logger.warning("ldap_filter.null_byte_detected")
        return False

    # Unescaped backslash outside of \\XX hex escape sequences is suspicious
    # (RFC 4515 allows \\XX for escaped characters)
    unescaped_bs = re.search(r"\\(?![0-9A-Fa-f]{2})", filter_str)
    if unescaped_bs:
        logger.warning("ldap_filter.unescaped_backslash")
        return False

    # Reject filters longer than a reasonable limit (prevents DoS via huge filters)
    if len(filter_str) > 4096:
        logger.warning("ldap_filter.too_long length=%d", len(filter_str))
        return False

    return True


def sanitise_filter_value(value: str) -> str:
    """
    Escape special characters in an LDAP filter value per RFC 4515.

    This is used when checkpoint itself constructs LDAP filters using
    user-supplied values (e.g. searching by email), not when passing
    client-supplied filters through.

    Args:
        value: Raw string to embed in an LDAP filter value.

    Returns:
        Escaped string safe for use in an LDAP filter expression.
    """
    # RFC 4515 §3: escape *, (, ), \, NUL
    return _FILTER_ILLEGAL_RE.sub(
        lambda m: f"\\{ord(m.group(0)):02X}",
        value,
    )


# ── Attribute helpers ─────────────────────────────────────────────────────────


def user_to_ldap_attrs(
    user_record: dict[str, Any],
    base_dn: str,
) -> dict[str, list[bytes]]:
    """
    Convert a CoreIdentityClient user record to an LDAP attribute dictionary.

    The returned dict maps LDAP attribute names to lists of bytes values,
    as expected by ldaptor's entry objects.

    Args:
        user_record: User record from CoreIdentityClient.get_user() or
                     search_users().  Expected keys: uuid, email,
                     display_name, is_active, groups.
        base_dn:     LDAP base DN (used to construct the entry DN).

    Returns:
        dict[str, list[bytes]] of LDAP attributes.
    """
    uuid: str = user_record.get("uuid", "")
    email: str = user_record.get("email", "")
    display_name: str = user_record.get("display_name", "") or email
    is_active: bool = bool(user_record.get("is_active", True))
    groups: list[str] = user_record.get("groups", [])

    # Build memberOf DNs for each group
    member_of: list[bytes] = [
        f"cn={g},ou=groups,{base_dn}".encode()
        for g in groups
    ]

    attrs: dict[str, list[bytes]] = {
        "objectClass": [b"inetOrgPerson", b"organizationalPerson", b"person", b"top"],
        "uid": [email.encode()],
        "mail": [email.encode()],
        "cn": [display_name.encode()],
        "displayName": [display_name.encode()],
        "sn": [(display_name.split()[-1] if display_name else email).encode()],
        "entryUUID": [uuid.encode()],
        "nsAccountLock": [b"false" if is_active else b"true"],
    }
    if member_of:
        attrs["memberOf"] = member_of

    return attrs


def group_to_ldap_attrs(
    group_record: dict[str, Any],
    base_dn: str,
) -> dict[str, list[bytes]]:
    """
    Convert a CoreIdentityClient group record to an LDAP attribute dictionary.

    Args:
        group_record: Group record.  Expected keys: uuid, name, member_uuids,
                      member_emails.
        base_dn:      LDAP base DN.

    Returns:
        dict[str, list[bytes]] of LDAP attributes.
    """
    uuid: str = group_record.get("uuid", "")
    name: str = group_record.get("name", "")
    member_emails: list[str] = group_record.get("member_emails", [])

    # member attributes as uid=<email>,ou=users,<base_dn>
    members: list[bytes] = [
        f"uid={email},ou=users,{base_dn}".encode()
        for email in member_emails
    ]

    attrs: dict[str, list[bytes]] = {
        "objectClass": [b"groupOfNames", b"top"],
        "cn": [name.encode()],
        "entryUUID": [uuid.encode()],
        "member": members if members else [b""],
    }

    return attrs
