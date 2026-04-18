"""
checkpoint-core — LDAP server (RFC 4511).

LDAPServer: asyncio TCP server using ldaptor for protocol handling.

All directory operations (search, bind, compare) are proxied through
CoreIdentityClient (gRPC).  checkpoint NEVER queries identity tables directly.

Supported LDAP operations:
  - Bind (simple auth via CoreIdentityClient.verify_password or JWT)
  - Search (users under ou=users, groups under ou=groups)
  - Compare
  - Unbind

Unsupported operations return an appropriate LDAP error code:
  - Add / Modify / Delete / Rename → unwillingToPerform (53)

Security:
  - All DN values are validated via ldap.dn_utils.validate_dn()
  - Search filters are validated via ldap.dn_utils.validate_ldap_filter()
  - Anonymous binds are rejected unless ldap_allow_anon=True
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapserver import BaseLDAPServer

from ldap.dn_utils import (
    group_to_ldap_attrs,
    parse_group_name,
    parse_user_email,
    user_to_ldap_attrs,
    validate_dn,
    validate_ldap_filter,
)

logger = logging.getLogger(__name__)


# ── LDAP result codes (RFC 4511 §4.1.9) ──────────────────────────────────────

_SUCCESS = 0
_OPERATIONS_ERROR = 1
_INVALID_CREDENTIALS = 49
_INSUFFICIENT_ACCESS = 50
_UNWILLING_TO_PERFORM = 53
_INVALID_DN_SYNTAX = 34
_NO_SUCH_OBJECT = 32
_OTHER = 80


# ── Protocol handler ──────────────────────────────────────────────────────────


class _CheckpointLDAPHandler(BaseLDAPServer):
    """
    ldaptor protocol handler that proxies operations to CoreIdentityClient.

    One instance is created per connection by asyncio's protocol factory.
    """

    def __init__(
        self,
        core_client: Any,
        base_dn: str,
        allow_anon: bool = False,
    ) -> None:
        super().__init__()
        self._core = core_client
        self._base_dn = base_dn
        self._allow_anon = allow_anon
        self._bound_dn: str | None = None  # None = not authenticated
        self._bound_user_uuid: str | None = None

    # ── Bind ──────────────────────────────────────────────────────────────────

    def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Any,
        reply: Any,
    ) -> None:
        """Handle simple bind: authenticate the DN against CoreIdentityClient."""
        dn: str = request.dn.decode(errors="replace") if isinstance(request.dn, bytes) else request.dn
        password_bytes: bytes = request.auth if isinstance(request.auth, bytes) else b""
        password: str = password_bytes.decode(errors="replace")

        # Anonymous bind
        if not dn and not password:
            if self._allow_anon:
                self._bound_dn = ""
                self._bound_user_uuid = None
                reply(pureldap.LDAPBindResponse(resultCode=_SUCCESS))
                return
            else:
                reply(pureldap.LDAPBindResponse(
                    resultCode=_INSUFFICIENT_ACCESS,
                    errorMessage=b"Anonymous binds are not permitted",
                ))
                return

        # Validate DN syntax
        if not validate_dn(dn, self._base_dn):
            reply(pureldap.LDAPBindResponse(
                resultCode=_INVALID_DN_SYNTAX,
                errorMessage=b"Invalid DN syntax",
            ))
            return

        # Extract email from uid= RDN
        email = parse_user_email(dn, self._base_dn)
        if not email:
            # Not a user entry DN — reject
            reply(pureldap.LDAPBindResponse(
                resultCode=_INVALID_CREDENTIALS,
                errorMessage=b"Invalid credentials",
            ))
            return

        # Schedule coroutine to verify credentials
        asyncio.ensure_future(
            self._async_bind(dn=dn, email=email, password=password, reply=reply)
        )

    async def _async_bind(
        self,
        dn: str,
        email: str,
        password: str,
        reply: Any,
    ) -> None:
        """Async credential verification via CoreIdentityClient."""
        try:
            result = await self._core.verify_password(email=email, password=password)
            if result and result.get("authenticated"):
                self._bound_dn = dn
                self._bound_user_uuid = result.get("uuid", "")
                logger.info(
                    "ldap.bind.success dn_prefix=%s",
                    dn.split(",")[0] if dn else "[anon]",
                )
                reply(pureldap.LDAPBindResponse(resultCode=_SUCCESS))
            else:
                logger.info(
                    "ldap.bind.invalid_credentials dn_prefix=%s",
                    dn.split(",")[0] if dn else "[unknown]",
                )
                reply(pureldap.LDAPBindResponse(
                    resultCode=_INVALID_CREDENTIALS,
                    errorMessage=b"Invalid credentials",
                ))
        except Exception as exc:
            logger.error("ldap.bind.error error=%r", exc)
            reply(pureldap.LDAPBindResponse(
                resultCode=_OPERATIONS_ERROR,
                errorMessage=b"Internal error",
            ))

    # ── Search ────────────────────────────────────────────────────────────────

    def handle_LDAPSearchRequest(
        self,
        request: pureldap.LDAPSearchRequest,
        controls: Any,
        reply: Any,
    ) -> None:
        """Handle LDAP search: translate to CoreIdentityClient calls."""
        if self._bound_dn is None and not self._allow_anon:
            reply(pureldap.LDAPSearchResultDone(
                resultCode=_INSUFFICIENT_ACCESS,
                errorMessage=b"Not authenticated",
            ))
            return

        base_dn_bytes: bytes = request.baseObject
        base_dn_str: str = base_dn_bytes.decode(errors="replace") if isinstance(base_dn_bytes, bytes) else base_dn_bytes

        # Validate search base
        if base_dn_str and not validate_dn(base_dn_str, self._base_dn):
            reply(pureldap.LDAPSearchResultDone(
                resultCode=_INVALID_DN_SYNTAX,
                errorMessage=b"Invalid search base DN",
            ))
            return

        # Extract filter string for validation
        filter_str = str(request.filter)
        if not validate_ldap_filter(filter_str):
            reply(pureldap.LDAPSearchResultDone(
                resultCode=_UNWILLING_TO_PERFORM,
                errorMessage=b"Invalid search filter",
            ))
            return

        scope: int = request.scope  # 0=base, 1=one, 2=sub

        asyncio.ensure_future(
            self._async_search(
                base_dn=base_dn_str,
                scope=scope,
                ldap_filter=request.filter,
                attributes=request.attributes,
                size_limit=request.sizeLimit or 500,
                reply=reply,
            )
        )

    async def _async_search(
        self,
        base_dn: str,
        scope: int,
        ldap_filter: Any,
        attributes: Any,
        size_limit: int,
        reply: Any,
    ) -> None:
        """Async search: query CoreIdentityClient and emit search results."""
        try:
            base_lower = base_dn.lower().strip()
            root_lower = self._base_dn.lower().strip()

            # Determine what to search
            is_users_ou = f"ou=users,{root_lower}" in base_lower or base_lower == root_lower
            is_groups_ou = f"ou=groups,{root_lower}" in base_lower

            # Extract a simple search term from the filter (best-effort)
            query_term = _extract_filter_query(ldap_filter)

            count = 0

            if is_users_ou or (not is_groups_ou and scope >= 1):
                # Search users
                users = await self._core.search_users(query=query_term or "", limit=size_limit)
                for user in users:
                    if count >= size_limit:
                        break
                    entry_dn = f"uid={user.get('email', '')},ou=users,{self._base_dn}"
                    attrs = user_to_ldap_attrs(user, self._base_dn)
                    entry = _build_search_entry(entry_dn, attrs, attributes)
                    reply(entry)
                    count += 1

            if is_groups_ou or (base_lower == root_lower and scope >= 1):
                # Search groups
                groups = await self._core.search_groups(query=query_term or "", limit=size_limit - count)
                for group in groups:
                    if count >= size_limit:
                        break
                    entry_dn = f"cn={group.get('name', '')},ou=groups,{self._base_dn}"
                    attrs = group_to_ldap_attrs(group, self._base_dn)
                    entry = _build_search_entry(entry_dn, attrs, attributes)
                    reply(entry)
                    count += 1

            reply(pureldap.LDAPSearchResultDone(resultCode=_SUCCESS))

        except Exception as exc:
            logger.error("ldap.search.error error=%r", exc)
            reply(pureldap.LDAPSearchResultDone(
                resultCode=_OPERATIONS_ERROR,
                errorMessage=b"Internal error",
            ))

    # ── Compare ───────────────────────────────────────────────────────────────

    def handle_LDAPCompareRequest(
        self,
        request: pureldap.LDAPCompareRequest,
        controls: Any,
        reply: Any,
    ) -> None:
        """Handle LDAP compare (used by some auth systems for group membership)."""
        if self._bound_dn is None and not self._allow_anon:
            reply(pureldap.LDAPCompareResponse(
                resultCode=_INSUFFICIENT_ACCESS,
                errorMessage=b"Not authenticated",
            ))
            return

        entry_dn: str = (
            request.entry.decode(errors="replace")
            if isinstance(request.entry, bytes)
            else request.entry
        )
        attr_type: str = request.ava.attributeType.decode() if isinstance(request.ava.attributeType, bytes) else request.ava.attributeType
        attr_value: bytes = request.ava.assertionValue if isinstance(request.ava.assertionValue, bytes) else request.ava.assertionValue.encode()

        asyncio.ensure_future(
            self._async_compare(
                entry_dn=entry_dn,
                attr_type=attr_type,
                attr_value=attr_value,
                reply=reply,
            )
        )

    async def _async_compare(
        self,
        entry_dn: str,
        attr_type: str,
        attr_value: bytes,
        reply: Any,
    ) -> None:
        """Async compare: fetch entry and compare attribute value."""
        try:
            if not validate_dn(entry_dn, self._base_dn):
                reply(pureldap.LDAPCompareResponse(
                    resultCode=_INVALID_DN_SYNTAX,
                    errorMessage=b"Invalid DN",
                ))
                return

            email = parse_user_email(entry_dn, self._base_dn)
            if email:
                results = await self._core.search_users(query=email, limit=1)
                if not results:
                    reply(pureldap.LDAPCompareResponse(resultCode=_NO_SUCH_OBJECT))
                    return
                user = results[0]
                attrs = user_to_ldap_attrs(user, self._base_dn)
                attr_list = attrs.get(attr_type, [])
                if attr_value in attr_list:
                    reply(pureldap.LDAPCompareResponse(resultCode=6))  # compareTrue
                else:
                    reply(pureldap.LDAPCompareResponse(resultCode=5))  # compareFalse
                return

            group_name = parse_group_name(entry_dn, self._base_dn)
            if group_name:
                groups = await self._core.search_groups(query=group_name, limit=1)
                if not groups:
                    reply(pureldap.LDAPCompareResponse(resultCode=_NO_SUCH_OBJECT))
                    return
                group = groups[0]
                attrs = group_to_ldap_attrs(group, self._base_dn)
                attr_list = attrs.get(attr_type, [])
                if attr_value in attr_list:
                    reply(pureldap.LDAPCompareResponse(resultCode=6))  # compareTrue
                else:
                    reply(pureldap.LDAPCompareResponse(resultCode=5))  # compareFalse
                return

            reply(pureldap.LDAPCompareResponse(resultCode=_NO_SUCH_OBJECT))

        except Exception as exc:
            logger.error("ldap.compare.error error=%r", exc)
            reply(pureldap.LDAPCompareResponse(
                resultCode=_OPERATIONS_ERROR,
                errorMessage=b"Internal error",
            ))

    # ── Unsupported write operations ───────────────────────────────────────────

    def handle_LDAPAddRequest(self, request: Any, controls: Any, reply: Any) -> None:
        """Reject: checkpoint is a read-only LDAP proxy."""
        reply(pureldap.LDAPAddResponse(
            resultCode=_UNWILLING_TO_PERFORM,
            errorMessage=b"checkpoint LDAP is read-only",
        ))

    def handle_LDAPModifyRequest(self, request: Any, controls: Any, reply: Any) -> None:
        """Reject: checkpoint is a read-only LDAP proxy."""
        reply(pureldap.LDAPModifyResponse(
            resultCode=_UNWILLING_TO_PERFORM,
            errorMessage=b"checkpoint LDAP is read-only",
        ))

    def handle_LDAPDelRequest(self, request: Any, controls: Any, reply: Any) -> None:
        """Reject: checkpoint is a read-only LDAP proxy."""
        reply(pureldap.LDAPDeleteResponse(
            resultCode=_UNWILLING_TO_PERFORM,
            errorMessage=b"checkpoint LDAP is read-only",
        ))

    def handle_LDAPModifyDNRequest(self, request: Any, controls: Any, reply: Any) -> None:
        """Reject: checkpoint is a read-only LDAP proxy."""
        reply(pureldap.LDAPModifyDNResponse(
            resultCode=_UNWILLING_TO_PERFORM,
            errorMessage=b"checkpoint LDAP is read-only",
        ))


# ── LDAPServer ────────────────────────────────────────────────────────────────


class LDAPServer:
    """
    Asyncio TCP server that exposes an LDAP interface for checkpoint-core.

    Instantiate once in `create_app()` and call `start()` as an asyncio task.

    Usage:
        server = LDAPServer(
            core_client=core_client,
            base_dn=cfg.ldap_base_dn,
            port=cfg.ldap_port,
            ldaps_port=cfg.ldaps_port,   # 0 to disable
            allow_anon=False,
        )
        asyncio.create_task(server.start())
        # Stops when server.stop() is called or task is cancelled.
    """

    def __init__(
        self,
        core_client: Any,
        base_dn: str,
        port: int = 389,
        ldaps_port: int = 636,
        allow_anon: bool = False,
    ) -> None:
        """
        Initialise the LDAP server.

        Args:
            core_client: CoreIdentityClient (gRPC) for identity lookups.
            base_dn:     LDAP base DN (e.g. "dc=example,dc=com").
            port:        TCP port for plain LDAP (0 to disable).
            ldaps_port:  TCP port for LDAPS (0 to disable — TLS not yet impl).
            allow_anon:  Allow anonymous binds (False by default).
        """
        self._core = core_client
        self._base_dn = base_dn
        self._port = port
        self._ldaps_port = ldaps_port
        self._allow_anon = allow_anon
        self._server: asyncio.AbstractServer | None = None
        self._ldaps_server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """
        Start the LDAP TCP listener(s) and serve until cancelled.

        The coroutine runs indefinitely — cancel the task or call stop() to
        shut down gracefully.
        """
        loop = asyncio.get_event_loop()

        def _factory() -> _CheckpointLDAPHandler:
            return _CheckpointLDAPHandler(
                core_client=self._core,
                base_dn=self._base_dn,
                allow_anon=self._allow_anon,
            )

        if self._port:
            try:
                self._server = await loop.create_server(
                    _factory,
                    host="0.0.0.0",  # nosec B104 — intentional: LDAP must bind to all interfaces
                    port=self._port,
                )
                logger.info("ldap_server.listening port=%d base_dn=%s", self._port, self._base_dn)
            except OSError as exc:
                logger.error("ldap_server.bind_error port=%d error=%r", self._port, exc)
                raise

        if self._ldaps_port:
            # LDAPS (TLS) is a future enhancement — log and skip for now.
            # Full TLS support requires an SSL context with a server certificate.
            logger.info(
                "ldap_server.ldaps_not_yet_enabled port=%d — configure TLS certificates to enable",
                self._ldaps_port,
            )

        if self._server is None:
            logger.warning("ldap_server.no_listener_started — LDAP disabled")
            return

        # Keep running until cancelled
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("ldap_server.shutdown port=%d", self._port)
            raise

    async def stop(self) -> None:
        """Gracefully stop the LDAP server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("ldap_server.stopped port=%d", self._port)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _extract_filter_query(ldap_filter: Any) -> str:
    """
    Best-effort extraction of a search term from an ldaptor filter object.

    This is used to narrow the CoreIdentityClient query.  It handles simple
    equality and substring filters on uid/mail/cn attributes.

    Args:
        ldap_filter: ldaptor filter object (e.g. LDAPFilter_equalityMatch).

    Returns:
        A search string for CoreIdentityClient, or "" if no useful term found.
    """
    try:
        # Equality filter: (uid=alice@example.com)
        if hasattr(ldap_filter, "attributeType") and hasattr(ldap_filter, "assertionValue"):
            attr = ldap_filter.attributeType
            value = ldap_filter.assertionValue
            attr_str = attr.decode() if isinstance(attr, bytes) else str(attr)
            value_str = value.decode() if isinstance(value, bytes) else str(value)
            if attr_str.lower() in ("uid", "mail", "cn", "email", "displayname", "display_name"):
                return value_str.replace("*", "").strip()

        # Substring filter: (uid=alice*)
        if hasattr(ldap_filter, "type") and hasattr(ldap_filter, "substrings"):
            attr = ldap_filter.type
            attr_str = attr.decode() if isinstance(attr, bytes) else str(attr)
            if attr_str.lower() in ("uid", "mail", "cn", "email"):
                for sub in ldap_filter.substrings:
                    if hasattr(sub, "value") and sub.value:
                        v = sub.value
                        return (v.decode() if isinstance(v, bytes) else str(v)).strip()

        # AND / OR filter: recurse into first sub-filter
        if hasattr(ldap_filter, "filters"):
            for sub in ldap_filter.filters:
                term = _extract_filter_query(sub)
                if term:
                    return term

    except Exception:
        pass  # Silently fall back to empty query

    return ""


def _build_search_entry(
    dn: str,
    attrs: dict[str, list[bytes]],
    requested_attrs: Any,
) -> pureldap.LDAPSearchResultEntry:
    """
    Build an LDAPSearchResultEntry from a DN and attribute dict.

    Filters the attributes to only those requested by the client (or all if
    the client sent an empty/None attributes list).

    Args:
        dn:               Entry Distinguished Name.
        attrs:            Full attribute dict.
        requested_attrs:  Sequence of requested attribute names from the client.

    Returns:
        LDAPSearchResultEntry suitable for passing to the reply callback.
    """
    # Determine which attributes to include
    if requested_attrs:
        requested = {
            (a.decode().lower() if isinstance(a, bytes) else a.lower())
            for a in requested_attrs
        }
        # "1.1" means return no attributes; "*" means all
        if "1.1" in requested:
            filtered = {}
        elif "*" in requested:
            filtered = dict(attrs)
        else:
            filtered = {k: v for k, v in attrs.items() if k.lower() in requested}
    else:
        filtered = dict(attrs)

    # Build ldaptor attribute list: list of (name_bytes, set_of_value_bytes)
    ldap_attrs = [
        (name.encode() if isinstance(name, str) else name, set(values))
        for name, values in filtered.items()
    ]

    return pureldap.LDAPSearchResultEntry(
        objectName=dn.encode() if isinstance(dn, str) else dn,
        attributes=ldap_attrs,
    )
