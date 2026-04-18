"""
Tests for ldap/dn_utils.py — LDAP DN validation and sanitization (pure functions).

Covers:
  - validate_dn() — syntactic validation and base DN containment
  - validate_ldap_filter() — injection prevention in filters
  - parse_user_email() — extract email from user DN
  - parse_group_name() — extract name from group DN
  - sanitise_filter_value() — escape RFC 4515 special chars
  - user_to_ldap_attrs() / group_to_ldap_attrs() — object attribute builders
"""
from __future__ import annotations

import pytest

from ldap import dn_utils


class TestValidateDn:
    """Test validate_dn() DN validation."""

    @pytest.mark.parametrize("dn,base_dn,expected", [
        # Valid cases
        ("uid=alice@example.com,ou=users,dc=example,dc=com", "dc=example,dc=com", True),
        ("uid=bob,ou=users,dc=example,dc=com", "dc=example,dc=com", True),
        ("cn=admins,ou=groups,dc=example,dc=com", "dc=example,dc=com", True),
        ("uid=test,ou=users,dc=example,dc=com", "dc=example,dc=com", True),
        # Case-insensitive base DN matching
        ("uid=alice@example.com,OU=users,DC=example,DC=com", "dc=example,dc=com", True),
        # Equal to base DN
        ("dc=example,dc=com", "dc=example,dc=com", True),
    ])
    def test_valid_dns(self, dn: str, base_dn: str, expected: bool) -> None:
        """validate_dn() accepts valid DNs."""
        assert dn_utils.validate_dn(dn, base_dn) == expected

    @pytest.mark.parametrize("dn,base_dn,expected", [
        # Invalid cases
        ("", "dc=example,dc=com", False),
        ("uid=alice@example.com", "dc=example,dc=com", False),  # Missing base DN
        ("uid=alice,ou=anytree,dc=example,dc=com", "dc=wrong,dc=com", False),  # Outside base DN
        ("uid=test\x00injection,ou=users,dc=example,dc=com", "dc=example,dc=com", False),  # Null byte
        ("uid=test\r\n,ou=users,dc=example,dc=com", "dc=example,dc=com", False),  # CRLF
        ("uid=test;DROP TABLE users,ou=users,dc=example,dc=com", "dc=example,dc=com", False),  # Semicolon
        ("x" * 600 + ",ou=users,dc=example,dc=com", "dc=example,dc=com", False),  # > 512 chars
    ])
    def test_invalid_dns(self, dn: str, base_dn: str, expected: bool) -> None:
        """validate_dn() rejects invalid DNs."""
        assert dn_utils.validate_dn(dn, base_dn) == expected

    def test_rejects_empty_base_dn(self) -> None:
        """validate_dn() rejects empty base DN."""
        assert dn_utils.validate_dn("uid=alice,ou=users,dc=example,dc=com", "") is False

    def test_rejects_malformed_component(self) -> None:
        """validate_dn() rejects component without '='."""
        assert dn_utils.validate_dn("uid=alice,malformed,dc=example,dc=com", "dc=example,dc=com") is False

    def test_rejects_invalid_attr_name(self) -> None:
        """validate_dn() rejects attr names with invalid characters."""
        assert dn_utils.validate_dn("9invalid=alice,ou=users,dc=example,dc=com", "dc=example,dc=com") is False

    def test_rejects_value_with_special_chars(self) -> None:
        """validate_dn() rejects values with special chars."""
        assert dn_utils.validate_dn('uid=alice"quote,ou=users,dc=example,dc=com', "dc=example,dc=com") is False


class TestValidateLdapFilter:
    """Test validate_ldap_filter() filter validation."""

    @pytest.mark.parametrize("filter_str,expected", [
        # Valid filters
        ("(objectClass=*)", True),
        ("(mail=user@example.com)", True),
        ("(&(uid=foo)(cn=bar))", True),
        ("(|(uid=alice)(uid=bob))", True),
        ("(sn=Smith)", True),
        ("(givenName=John)", True),
    ])
    def test_valid_filters(self, filter_str: str, expected: bool) -> None:
        """validate_ldap_filter() accepts valid filters."""
        assert dn_utils.validate_ldap_filter(filter_str) == expected

    @pytest.mark.parametrize("filter_str,expected", [
        # Invalid filters
        ("", False),  # Empty
        ("(uid=test\x00)", False),  # Null byte
        ("(uid=test\\1Q)", False),  # Unescaped backslash (not hex)
        ("(uid=test\x00rm)", False),  # Null byte embedded in filter value
        ("x" * 5000, False),  # Too long (> 4096)
    ])
    def test_invalid_filters(self, filter_str: str, expected: bool) -> None:
        """validate_ldap_filter() rejects invalid filters."""
        assert dn_utils.validate_ldap_filter(filter_str) == expected

    def test_accepts_escaped_hex_chars(self) -> None:
        """validate_ldap_filter() accepts \\HH hex escapes."""
        # \\2A is escaped asterisk
        assert dn_utils.validate_ldap_filter("(uid=test\\2A)") is True

    def test_rejects_unescaped_backslash(self) -> None:
        """validate_ldap_filter() rejects backslash not followed by two hex digits.
        \\ba would be valid (0xBA), but \\zz starts with a non-hex char."""
        assert dn_utils.validate_ldap_filter("(uid=test\\zzz)") is False


class TestParseUserEmail:
    """Test parse_user_email() email extraction from DN."""

    @pytest.mark.parametrize("dn,base_dn,expected_email", [
        ("uid=alice@example.com,ou=users,dc=example,dc=com", "dc=example,dc=com", "alice@example.com"),
        ("mail=bob@example.com,ou=users,dc=example,dc=com", "dc=example,dc=com", "bob@example.com"),
        ("uid=charlie,ou=users,dc=example,dc=com", "dc=example,dc=com", "charlie"),
        # cn= is intentionally NOT supported — ambiguous with group DNs
    ])
    def test_extracts_email(self, dn: str, base_dn: str, expected_email: str) -> None:
        """parse_user_email() extracts email from user DN."""
        result = dn_utils.parse_user_email(dn, base_dn)
        assert result == expected_email

    @pytest.mark.parametrize("dn,base_dn", [
        ("cn=admins,ou=groups,dc=example,dc=com", "dc=example,dc=com"),  # Group DN
        ("ou=users,dc=example,dc=com", "dc=example,dc=com"),  # No uid/mail
        ("uid=invalid\x00,ou=users,dc=example,dc=com", "dc=example,dc=com"),  # Invalid DN
    ])
    def test_returns_none_for_invalid(self, dn: str, base_dn: str) -> None:
        """parse_user_email() returns None for non-user or invalid DNs."""
        assert dn_utils.parse_user_email(dn, base_dn) is None


class TestParseGroupName:
    """Test parse_group_name() group name extraction from DN."""

    @pytest.mark.parametrize("dn,base_dn,expected_name", [
        ("cn=engineering,ou=groups,dc=example,dc=com", "dc=example,dc=com", "engineering"),
        ("cn=sales-team,ou=groups,dc=example,dc=com", "dc=example,dc=com", "sales-team"),
        ("cn=admin.super,ou=groups,dc=example,dc=com", "dc=example,dc=com", "admin.super"),
    ])
    def test_extracts_group_name(self, dn: str, base_dn: str, expected_name: str) -> None:
        """parse_group_name() extracts group name from group DN."""
        result = dn_utils.parse_group_name(dn, base_dn)
        assert result == expected_name

    @pytest.mark.parametrize("dn,base_dn", [
        ("uid=alice@example.com,ou=users,dc=example,dc=com", "dc=example,dc=com"),  # User DN
        ("ou=groups,dc=example,dc=com", "dc=example,dc=com"),  # No cn
        ("cn=bad\x00group,ou=groups,dc=example,dc=com", "dc=example,dc=com"),  # Invalid
    ])
    def test_returns_none_for_non_group(self, dn: str, base_dn: str) -> None:
        """parse_group_name() returns None for non-group or invalid DNs."""
        assert dn_utils.parse_group_name(dn, base_dn) is None


class TestSanitiseFilterValue:
    """Test sanitise_filter_value() RFC 4515 escaping."""

    @pytest.mark.parametrize("value,expected", [
        ("alice", "alice"),  # No special chars
        ("alice*bob", "alice\\2Abob"),  # Asterisk
        ("(test)", "\\28test\\29"),  # Parentheses
        ("a\\b", "a\\5Cb"),  # Backslash
        ("a\x00b", "a\\00b"),  # Null byte
        ("test", "test"),  # Plain
    ])
    def test_escapes_special_chars(self, value: str, expected: str) -> None:
        """sanitise_filter_value() escapes RFC 4515 special characters."""
        result = dn_utils.sanitise_filter_value(value)
        assert result == expected


class TestUserToLdapAttrs:
    """Test user_to_ldap_attrs() user record to LDAP attribute conversion."""

    def test_converts_user_record(self) -> None:
        """user_to_ldap_attrs() converts user record to LDAP attrs."""
        user = {
            "uuid": "user-123",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "is_active": True,
            "groups": ["engineering", "backend"],
        }

        result = dn_utils.user_to_ldap_attrs(user, "dc=example,dc=com")

        assert result["uid"] == [b"alice@example.com"]
        assert result["mail"] == [b"alice@example.com"]
        assert result["cn"] == [b"Alice Smith"]
        assert result["entryUUID"] == [b"user-123"]
        assert result["nsAccountLock"] == [b"false"]
        assert b"cn=engineering,ou=groups,dc=example,dc=com" in result["memberOf"]
        assert b"cn=backend,ou=groups,dc=example,dc=com" in result["memberOf"]

    def test_handles_inactive_user(self) -> None:
        """user_to_ldap_attrs() sets nsAccountLock for inactive users."""
        user = {
            "uuid": "user-456",
            "email": "bob@example.com",
            "is_active": False,
        }

        result = dn_utils.user_to_ldap_attrs(user, "dc=example,dc=com")

        assert result["nsAccountLock"] == [b"true"]

    def test_handles_missing_display_name(self) -> None:
        """user_to_ldap_attrs() uses email as fallback for display_name."""
        user = {
            "uuid": "user-789",
            "email": "charlie@example.com",
            "display_name": None,
        }

        result = dn_utils.user_to_ldap_attrs(user, "dc=example,dc=com")

        assert result["cn"] == [b"charlie@example.com"]


class TestGroupToLdapAttrs:
    """Test group_to_ldap_attrs() group record to LDAP attribute conversion."""

    def test_converts_group_record(self) -> None:
        """group_to_ldap_attrs() converts group record to LDAP attrs."""
        group = {
            "uuid": "group-123",
            "name": "engineering",
            "member_emails": ["alice@example.com", "bob@example.com"],
        }

        result = dn_utils.group_to_ldap_attrs(group, "dc=example,dc=com")

        assert result["cn"] == [b"engineering"]
        assert result["entryUUID"] == [b"group-123"]
        assert b"uid=alice@example.com,ou=users,dc=example,dc=com" in result["member"]
        assert b"uid=bob@example.com,ou=users,dc=example,dc=com" in result["member"]

    def test_handles_empty_members(self) -> None:
        """group_to_ldap_attrs() handles groups with no members."""
        group = {
            "uuid": "group-456",
            "name": "empty-group",
            "member_emails": [],
        }

        result = dn_utils.group_to_ldap_attrs(group, "dc=example,dc=com")

        assert result["member"] == [b""]  # Empty member list


class TestRoundTrip:
    """Test round-trip conversions."""

    def test_email_to_dn_to_email_roundtrip(self) -> None:
        """Email extracted from built DN matches original."""
        email = "alice@example.com"
        base_dn = "dc=example,dc=com"

        # Build DN from email
        user = {"uuid": "u1", "email": email}
        attrs = dn_utils.user_to_ldap_attrs(user, base_dn)
        uid_bytes = attrs["uid"][0]
        dn = f"uid={uid_bytes.decode()},ou=users,{base_dn}"

        # Extract back
        extracted = dn_utils.parse_user_email(dn, base_dn)

        assert extracted == email

    def test_group_name_to_dn_to_name_roundtrip(self) -> None:
        """Group name extracted from built DN matches original."""
        group_name = "engineering"
        base_dn = "dc=example,dc=com"

        # Build DN
        dn = f"cn={group_name},ou=groups,{base_dn}"

        # Extract back
        extracted = dn_utils.parse_group_name(dn, base_dn)

        assert extracted == group_name
