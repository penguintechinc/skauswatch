"""Coverage tests for jwt_utils.py, ldap_dn_utils.py missing lines."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


class TestJwtUtilsCoverage:
    """Test oidc/jwt_utils.py missing line coverage."""

    def test_pem_to_jwk_unsupported_algorithm(self):
        """Test _pem_to_jwk returns None for unsupported algorithm."""
        from oidc.jwt_utils import _pem_to_jwk

        # RSA public key
        rsa_pub = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5IHuA5ZLvxxXxxA
-----END PUBLIC KEY-----"""

        result = _pem_to_jwk(rsa_pub, "test-kid", "UNSUPPORTED")
        assert result is None

    def test_pem_to_jwk_invalid_pem(self):
        """Test _pem_to_jwk returns None for invalid PEM."""
        from oidc.jwt_utils import _pem_to_jwk

        result = _pem_to_jwk("not-valid-pem", "test-kid", "RS256")
        assert result is None

    def test_get_active_signing_key_missing(self):
        """Test get_active_signing_key logs and returns None when no active key."""
        from oidc.jwt_utils import get_active_signing_key

        mock_db = MagicMock()
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("oidc.jwt_utils.logger") as mock_logger:
            result = get_active_signing_key(mock_db)
            assert result is None
            mock_logger.error.assert_called_once()

    def test_get_active_signing_key_returns_dict_structure(self):
        """Test get_active_signing_key returns correct dict with all fields."""
        from oidc.jwt_utils import get_active_signing_key

        mock_db = MagicMock()
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.kid = "test-kid"
        mock_row.algorithm = "RS256"
        mock_row.public_key = "test-pub"
        mock_row.private_key_encrypted = "test-enc"

        mock_db.return_value.select.return_value.first.return_value = mock_row

        result = get_active_signing_key(mock_db)
        assert result is not None
        assert result["id"] == 1
        assert result["kid"] == "test-kid"
        assert result["algorithm"] == "RS256"


class TestLdapDnUtilsCoverage:
    """Test ldap/dn_utils.py missing line coverage."""

    def test_parse_user_email_invalid_dn(self):
        """Test parse_user_email returns None for invalid DN."""
        from ldap.dn_utils import parse_user_email

        result = parse_user_email("invalid-dn", "dc=example,dc=com")
        assert result is None

    def test_parse_user_email_no_equals_in_rdn(self):
        """Test parse_user_email returns None when RDN has no equals sign."""
        from ldap.dn_utils import parse_user_email

        # validate_dn will reject this
        result = parse_user_email("uid_no_equals,ou=users,dc=example,dc=com", "dc=example,dc=com")
        assert result is None

    def test_parse_group_name_invalid_dn(self):
        """Test parse_group_name returns None for invalid DN."""
        from ldap.dn_utils import parse_group_name

        result = parse_group_name("invalid-dn", "dc=example,dc=com")
        assert result is None

    def test_parse_group_name_no_equals_in_rdn(self):
        """Test parse_group_name returns None when RDN has no equals sign."""
        from ldap.dn_utils import parse_group_name

        # validate_dn will reject this
        result = parse_group_name("cn_no_equals,ou=groups,dc=example,dc=com", "dc=example,dc=com")
        assert result is None

    def test_validate_ldap_filter_null_byte(self):
        """Test validate_ldap_filter rejects null bytes."""
        from ldap.dn_utils import validate_ldap_filter

        result = validate_ldap_filter("(uid=test\x00)")
        assert result is False

    def test_validate_ldap_filter_unescaped_backslash(self):
        """Test validate_ldap_filter rejects unescaped backslash."""
        from ldap.dn_utils import validate_ldap_filter

        result = validate_ldap_filter("(uid=test\\invalid)")
        assert result is False

    def test_validate_ldap_filter_too_long(self):
        """Test validate_ldap_filter rejects filters longer than 4096 chars."""
        from ldap.dn_utils import validate_ldap_filter

        long_filter = "(uid=" + "a" * 5000 + ")"
        result = validate_ldap_filter(long_filter)
        assert result is False

    def test_validate_dn_crlf_in_dn(self):
        """Test validate_dn rejects CRLF in DN."""
        from ldap.dn_utils import validate_dn

        result = validate_dn("uid=test\r\ninjection,dc=example,dc=com", "dc=example,dc=com")
        assert result is False

    def test_validate_dn_with_logger_warning(self):
        """Test validate_dn logs warning on CRLF detection."""
        from ldap.dn_utils import validate_dn

        with patch("ldap.dn_utils.logger") as mock_logger:
            result = validate_dn("uid=test\rinjection,dc=example,dc=com", "dc=example,dc=com")
            assert result is False
            mock_logger.warning.assert_called()
