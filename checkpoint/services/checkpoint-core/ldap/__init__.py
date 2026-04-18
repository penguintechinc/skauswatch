"""
checkpoint-core — LDAP server implementation.

Provides an RFC 4511–compliant LDAP server that proxies all directory
operations through CoreIdentityClient (gRPC).  checkpoint never queries
identity data directly.

Sub-modules:
  ldap.dn_utils  — DN and LDAP filter sanitisation utilities
  ldap.server    — LDAPServer: asyncio TCP server using ldaptor
"""
