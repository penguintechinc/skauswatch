"""Unit tests for validator functions in utils.validators module."""

import pytest
from utils.validators import (
    validate_target_value,
    validate_severity,
    validate_scanner_type,
    validate_scan_type,
    validate_finding_status,
    validate_cron_expression,
    validate_job_status,
    validate_priority,
    sanitize_string,
    validate_pagination,
)


class TestValidateTargetValue:
    """Tests for validate_target_value function."""

    # Domain validation tests
    def test_valid_domain_simple(self):
        """Test valid simple domain."""
        is_valid, error = validate_target_value("domain", "example.com")
        assert is_valid is True
        assert error == ""

    def test_valid_domain_subdomain(self):
        """Test valid domain with subdomain."""
        is_valid, error = validate_target_value("domain", "sub.example.com")
        assert is_valid is True
        assert error == ""

    def test_valid_domain_multiple_subdomains(self):
        """Test valid domain with multiple subdomains."""
        is_valid, error = validate_target_value("domain", "api.v2.example.com")
        assert is_valid is True
        assert error == ""

    def test_domain_with_protocol_prefix(self):
        """Test domain validation rejects protocol prefix."""
        is_valid, error = validate_target_value("domain", "http://example.com")
        assert is_valid is False
        assert "protocol prefix" in error.lower()

    def test_domain_with_https_prefix(self):
        """Test domain validation rejects https protocol."""
        is_valid, error = validate_target_value("domain", "https://example.com")
        assert is_valid is False
        assert "protocol prefix" in error.lower()

    def test_invalid_domain_format(self):
        """Test invalid domain format."""
        is_valid, error = validate_target_value("domain", "invalid domain")
        assert is_valid is False
        assert "invalid" in error.lower()

    def test_domain_exceeds_max_length(self):
        """Test domain exceeding 255 character limit."""
        # Create a domain that exceeds 255 chars by having invalid format (too long)
        long_domain = "a" * 200 + ".b" * 30  # will fail on format or length
        is_valid, error = validate_target_value("domain", long_domain)
        assert is_valid is False

    def test_domain_at_reasonable_length(self):
        """Test domain at reasonable length that validates."""
        domain = "sub." + "a" * 50 + ".example.com"
        is_valid, error = validate_target_value("domain", domain)
        assert is_valid is True
        assert error == ""

    def test_domain_empty_string(self):
        """Test empty string for domain."""
        is_valid, error = validate_target_value("domain", "")
        assert is_valid is False
        assert "non-empty string" in error.lower()

    def test_domain_with_trailing_dot(self):
        """Test domain ending with dot."""
        is_valid, error = validate_target_value("domain", "example.com.")
        assert is_valid is False

    # IPv4 validation tests
    def test_valid_ipv4_address(self):
        """Test valid IPv4 address."""
        is_valid, error = validate_target_value("ip", "192.168.1.1")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv4_localhost(self):
        """Test IPv4 localhost address."""
        is_valid, error = validate_target_value("ip", "127.0.0.1")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv4_all_zeros(self):
        """Test IPv4 0.0.0.0."""
        is_valid, error = validate_target_value("ip", "0.0.0.0")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv4_all_ones(self):
        """Test IPv4 255.255.255.255."""
        is_valid, error = validate_target_value("ip", "255.255.255.255")
        assert is_valid is True
        assert error == ""

    def test_invalid_ipv4_out_of_range(self):
        """Test invalid IPv4 with octet out of range."""
        is_valid, error = validate_target_value("ip", "999.999.999.999")
        assert is_valid is False
        assert "invalid" in error.lower()

    def test_invalid_ipv4_partial(self):
        """Test invalid IPv4 with missing octet."""
        is_valid, error = validate_target_value("ip", "192.168.1")
        assert is_valid is False
        assert "invalid" in error.lower()

    # IPv6 validation tests
    def test_valid_ipv6_loopback(self):
        """Test valid IPv6 loopback address."""
        is_valid, error = validate_target_value("ip", "::1")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv6_full(self):
        """Test valid full IPv6 address."""
        is_valid, error = validate_target_value("ip", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv6_compressed(self):
        """Test valid compressed IPv6 address."""
        is_valid, error = validate_target_value("ip", "2001:db8:85a3::8a2e:370:7334")
        assert is_valid is True
        assert error == ""

    def test_valid_ipv6_all_zeros(self):
        """Test IPv6 all zeros."""
        is_valid, error = validate_target_value("ip", "::")
        assert is_valid is True
        assert error == ""

    def test_invalid_ipv6_format(self):
        """Test invalid IPv6 format."""
        is_valid, error = validate_target_value("ip", "gggg::1")
        assert is_valid is False
        assert "invalid" in error.lower()

    # URL validation tests
    def test_valid_url_http(self):
        """Test valid HTTP URL."""
        is_valid, error = validate_target_value("url", "http://example.com")
        assert is_valid is True
        assert error == ""

    def test_valid_url_https(self):
        """Test valid HTTPS URL."""
        is_valid, error = validate_target_value("url", "https://example.com")
        assert is_valid is True
        assert error == ""

    def test_valid_url_with_path(self):
        """Test valid URL with path."""
        is_valid, error = validate_target_value("url", "https://example.com/path/to/resource")
        assert is_valid is True
        assert error == ""

    def test_valid_url_with_query(self):
        """Test valid URL with query parameters."""
        is_valid, error = validate_target_value("url", "https://example.com?key=value")
        assert is_valid is True
        assert error == ""

    def test_valid_url_with_port(self):
        """Test valid URL with port."""
        is_valid, error = validate_target_value("url", "https://example.com:8443/path")
        assert is_valid is True
        assert error == ""

    def test_invalid_url_no_scheme(self):
        """Test URL without scheme."""
        is_valid, error = validate_target_value("url", "example.com")
        assert is_valid is False
        assert "scheme" in error.lower()

    def test_invalid_url_ftp_scheme(self):
        """Test URL with unsupported FTP scheme."""
        is_valid, error = validate_target_value("url", "ftp://example.com")
        assert is_valid is False
        assert "http or https" in error.lower()

    def test_invalid_url_no_netloc(self):
        """Test URL without netloc."""
        is_valid, error = validate_target_value("url", "https://")
        assert is_valid is False
        assert "network location" in error.lower()

    # CIDR validation tests
    def test_valid_cidr_network(self):
        """Test valid CIDR notation."""
        is_valid, error = validate_target_value("cidr", "192.168.0.0/24")
        assert is_valid is True
        assert error == ""

    def test_valid_cidr_class_b(self):
        """Test valid Class B CIDR."""
        is_valid, error = validate_target_value("cidr", "172.16.0.0/12")
        assert is_valid is True
        assert error == ""

    def test_valid_cidr_class_c(self):
        """Test valid Class C CIDR."""
        is_valid, error = validate_target_value("cidr", "10.0.0.0/8")
        assert is_valid is True
        assert error == ""

    def test_valid_cidr_slash_32(self):
        """Test CIDR with /32 (single host)."""
        is_valid, error = validate_target_value("cidr", "192.168.1.1/32")
        assert is_valid is True
        assert error == ""

    def test_valid_cidr_ipv6(self):
        """Test valid IPv6 CIDR notation."""
        is_valid, error = validate_target_value("cidr", "2001:db8::/32")
        assert is_valid is True
        assert error == ""

    def test_valid_cidr_single_host_ipv6(self):
        """Test valid IPv6 CIDR with /128."""
        is_valid, error = validate_target_value("cidr", "2001:db8::1/128")
        assert is_valid is True
        assert error == ""

    # Unknown target type
    def test_unknown_target_type(self):
        """Test with unknown target type."""
        is_valid, error = validate_target_value("unknown", "test")
        assert is_valid is False
        assert "unknown target type" in error.lower()

    # Empty and invalid inputs
    def test_none_value(self):
        """Test with None value."""
        is_valid, error = validate_target_value("domain", None)
        assert is_valid is False
        assert "non-empty string" in error.lower()

    def test_integer_value(self):
        """Test with integer value."""
        is_valid, error = validate_target_value("domain", 12345)
        assert is_valid is False
        assert "non-empty string" in error.lower()

    # Case insensitivity for target type
    def test_target_type_case_insensitive(self):
        """Test that target type is case-insensitive."""
        is_valid, error = validate_target_value("DOMAIN", "example.com")
        assert is_valid is True
        assert error == ""

    def test_target_type_mixed_case(self):
        """Test mixed case target type."""
        is_valid, error = validate_target_value("DoMaIn", "example.com")
        assert is_valid is True
        assert error == ""


class TestValidateSeverity:
    """Tests for validate_severity function."""

    @pytest.mark.parametrize("severity,expected", [
        ("critical", True),
        ("high", True),
        ("medium", True),
        ("low", True),
        ("info", True),
    ])
    def test_valid_severities(self, severity, expected):
        """Test all valid severity levels."""
        assert validate_severity(severity) is expected

    @pytest.mark.parametrize("severity,expected", [
        ("CRITICAL", True),
        ("HIGH", True),
        ("MEDIUM", True),
        ("LOW", True),
        ("INFO", True),
        ("Critical", True),
        ("High", True),
    ])
    def test_severity_case_insensitive(self, severity, expected):
        """Test severity is case-insensitive."""
        assert validate_severity(severity) is expected

    @pytest.mark.parametrize("severity,expected", [
        ("unknown", False),
        ("", False),
        ("severe", False),
        ("blocker", False),
    ])
    def test_invalid_severities(self, severity, expected):
        """Test invalid severity levels."""
        assert validate_severity(severity) is expected

    def test_severity_with_whitespace(self):
        """Test severity with surrounding whitespace."""
        assert validate_severity("  critical  ") is True
        assert validate_severity("  invalid  ") is False


class TestValidateScannerType:
    """Tests for validate_scanner_type function."""

    @pytest.mark.parametrize("scanner_type,expected", [
        ("nuclei", True),
        ("zap", True),
        ("openvas", True),
    ])
    def test_valid_scanner_types(self, scanner_type, expected):
        """Test all valid scanner types."""
        assert validate_scanner_type(scanner_type) is expected

    @pytest.mark.parametrize("scanner_type,expected", [
        ("NUCLEI", True),
        ("ZAP", True),
        ("OPENVAS", True),
        ("Nuclei", True),
        ("Zap", True),
    ])
    def test_scanner_type_case_insensitive(self, scanner_type, expected):
        """Test scanner type is case-insensitive."""
        assert validate_scanner_type(scanner_type) is expected

    @pytest.mark.parametrize("scanner_type,expected", [
        ("nessus", False),
        ("burp", False),
        ("", False),
        ("unknown", False),
    ])
    def test_invalid_scanner_types(self, scanner_type, expected):
        """Test invalid scanner types."""
        assert validate_scanner_type(scanner_type) is expected

    def test_scanner_type_with_whitespace(self):
        """Test scanner type with surrounding whitespace."""
        assert validate_scanner_type("  nuclei  ") is True
        assert validate_scanner_type("  nessus  ") is False


class TestValidateScanType:
    """Tests for validate_scan_type function."""

    @pytest.mark.parametrize("scan_type,expected", [
        ("baseline", True),
        ("full", True),
        ("api", True),
        ("custom", True),
        ("discovery", True),
        ("full_and_fast", True),
        ("full_and_deep", True),
    ])
    def test_valid_scan_types(self, scan_type, expected):
        """Test all valid scan types."""
        assert validate_scan_type(scan_type) is expected

    @pytest.mark.parametrize("scan_type,expected", [
        ("BASELINE", True),
        ("FULL", True),
        ("API", True),
        ("CUSTOM", True),
        ("DISCOVERY", True),
        ("FULL_AND_FAST", True),
        ("FULL_AND_DEEP", True),
        ("Baseline", True),
        ("Full", True),
    ])
    def test_scan_type_case_insensitive(self, scan_type, expected):
        """Test scan type is case-insensitive."""
        assert validate_scan_type(scan_type) is expected

    @pytest.mark.parametrize("scan_type,expected", [
        ("unknown", False),
        ("partial", False),
        ("", False),
        ("quick", False),
    ])
    def test_invalid_scan_types(self, scan_type, expected):
        """Test invalid scan types."""
        assert validate_scan_type(scan_type) is expected

    def test_scan_type_with_whitespace(self):
        """Test scan type with surrounding whitespace."""
        assert validate_scan_type("  baseline  ") is True
        assert validate_scan_type("  unknown  ") is False


class TestValidateFindingStatus:
    """Tests for validate_finding_status function."""

    @pytest.mark.parametrize("status,expected", [
        ("open", True),
        ("acknowledged", True),
        ("false_positive", True),
        ("fixed", True),
    ])
    def test_valid_finding_statuses(self, status, expected):
        """Test all valid finding statuses."""
        assert validate_finding_status(status) is expected

    @pytest.mark.parametrize("status,expected", [
        ("OPEN", True),
        ("ACKNOWLEDGED", True),
        ("FALSE_POSITIVE", True),
        ("FIXED", True),
        ("Open", True),
        ("Acknowledged", True),
    ])
    def test_finding_status_case_insensitive(self, status, expected):
        """Test finding status is case-insensitive."""
        assert validate_finding_status(status) is expected

    @pytest.mark.parametrize("status,expected", [
        ("closed", False),
        ("resolved", False),
        ("", False),
        ("unknown", False),
    ])
    def test_invalid_finding_statuses(self, status, expected):
        """Test invalid finding statuses."""
        assert validate_finding_status(status) is expected

    def test_finding_status_with_whitespace(self):
        """Test finding status with surrounding whitespace."""
        assert validate_finding_status("  open  ") is True
        assert validate_finding_status("  closed  ") is False


class TestValidateCronExpression:
    """Tests for validate_cron_expression function."""

    def test_valid_cron_every_5_minutes(self):
        """Test valid cron expression for every 5 minutes."""
        is_valid, error = validate_cron_expression("*/5 * * * *")
        assert is_valid is True
        assert error == ""

    def test_valid_cron_daily_at_2am(self):
        """Test valid cron expression for daily at 2 AM."""
        is_valid, error = validate_cron_expression("0 2 * * *")
        assert is_valid is True
        assert error == ""

    def test_valid_cron_monday_at_9am(self):
        """Test valid cron expression for Monday at 9 AM."""
        is_valid, error = validate_cron_expression("0 9 * * MON")
        assert is_valid is True
        assert error == ""

    def test_valid_cron_every_hour(self):
        """Test valid cron expression for every hour."""
        is_valid, error = validate_cron_expression("0 * * * *")
        assert is_valid is True
        assert error == ""

    def test_valid_cron_midnight_every_day(self):
        """Test valid cron expression for midnight every day."""
        is_valid, error = validate_cron_expression("0 0 * * *")
        assert is_valid is True
        assert error == ""

    def test_valid_cron_first_day_of_month(self):
        """Test valid cron expression for first day of month."""
        is_valid, error = validate_cron_expression("0 0 1 * *")
        assert is_valid is True
        assert error == ""

    def test_valid_cron_6_field_format(self):
        """Test valid 6-field cron format with seconds."""
        is_valid, error = validate_cron_expression("0 */5 * * * *")
        assert is_valid is True
        assert error == ""

    def test_invalid_cron_too_few_fields(self):
        """Test invalid cron with too few fields."""
        is_valid, error = validate_cron_expression("* * *")
        assert is_valid is False
        assert "invalid" in error.lower()

    def test_invalid_cron_invalid_text(self):
        """Test invalid cron expression."""
        is_valid, error = validate_cron_expression("invalid")
        assert is_valid is False
        assert "invalid" in error.lower()

    def test_invalid_cron_out_of_range(self):
        """Test invalid cron with out of range values."""
        is_valid, error = validate_cron_expression("0 25 * * *")
        assert is_valid is False
        assert "invalid" in error.lower()

    def test_cron_empty_string(self):
        """Test empty string for cron expression."""
        is_valid, error = validate_cron_expression("")
        assert is_valid is False
        assert "non-empty string" in error.lower()

    def test_cron_none_value(self):
        """Test None for cron expression."""
        is_valid, error = validate_cron_expression(None)
        assert is_valid is False
        assert "non-empty string" in error.lower()

    def test_cron_with_leading_trailing_whitespace(self):
        """Test cron expression with whitespace."""
        is_valid, error = validate_cron_expression("  */5 * * * *  ")
        assert is_valid is True
        assert error == ""


class TestValidateJobStatus:
    """Tests for validate_job_status function."""

    @pytest.mark.parametrize("status,expected", [
        ("pending", True),
        ("running", True),
        ("completed", True),
        ("failed", True),
        ("cancelled", True),
    ])
    def test_valid_job_statuses(self, status, expected):
        """Test all valid job statuses."""
        assert validate_job_status(status) is expected

    @pytest.mark.parametrize("status,expected", [
        ("PENDING", True),
        ("RUNNING", True),
        ("COMPLETED", True),
        ("FAILED", True),
        ("CANCELLED", True),
        ("Pending", True),
        ("Running", True),
    ])
    def test_job_status_case_insensitive(self, status, expected):
        """Test job status is case-insensitive."""
        assert validate_job_status(status) is expected

    @pytest.mark.parametrize("status,expected", [
        ("unknown", False),
        ("paused", False),
        ("", False),
        ("finished", False),
    ])
    def test_invalid_job_statuses(self, status, expected):
        """Test invalid job statuses."""
        assert validate_job_status(status) is expected

    def test_job_status_with_whitespace(self):
        """Test job status with surrounding whitespace."""
        assert validate_job_status("  pending  ") is True
        assert validate_job_status("  unknown  ") is False


class TestValidatePriority:
    """Tests for validate_priority function."""

    @pytest.mark.parametrize("priority,expected", [
        (1, True),
        (5, True),
        (10, True),
        (2, True),
        (9, True),
    ])
    def test_valid_priorities(self, priority, expected):
        """Test valid priority values."""
        assert validate_priority(priority) is expected

    @pytest.mark.parametrize("priority,expected", [
        (0, False),
        (-1, False),
        (11, False),
        (100, False),
        (-10, False),
    ])
    def test_invalid_priorities(self, priority, expected):
        """Test invalid priority values."""
        assert validate_priority(priority) is expected

    def test_priority_boundary_lower(self):
        """Test priority at lower boundary (1)."""
        assert validate_priority(1) is True

    def test_priority_boundary_upper(self):
        """Test priority at upper boundary (10)."""
        assert validate_priority(10) is True

    def test_priority_just_below_range(self):
        """Test priority just below valid range."""
        assert validate_priority(0) is False

    def test_priority_just_above_range(self):
        """Test priority just above valid range."""
        assert validate_priority(11) is False

    def test_priority_non_integer(self):
        """Test non-integer priority."""
        assert validate_priority("5") is False
        assert validate_priority(5.5) is False
        assert validate_priority(None) is False

    def test_priority_float_in_range(self):
        """Test float value in range."""
        assert validate_priority(5.0) is False


class TestSanitizeString:
    """Tests for sanitize_string function."""

    def test_sanitize_normal_string(self):
        """Test sanitizing normal string."""
        result = sanitize_string("hello")
        assert result == "hello"

    def test_sanitize_with_leading_whitespace(self):
        """Test string with leading whitespace."""
        result = sanitize_string("  hello")
        assert result == "hello"

    def test_sanitize_with_trailing_whitespace(self):
        """Test string with trailing whitespace."""
        result = sanitize_string("hello  ")
        assert result == "hello"

    def test_sanitize_with_both_whitespaces(self):
        """Test string with leading and trailing whitespace."""
        result = sanitize_string("  hello world  ")
        assert result == "hello world"

    def test_sanitize_internal_whitespace_preserved(self):
        """Test internal whitespace is preserved."""
        result = sanitize_string("hello   world")
        assert result == "hello   world"

    def test_sanitize_null_bytes(self):
        """Test null bytes are removed."""
        result = sanitize_string("hello\x00world")
        assert result == "helloworld"
        assert "\x00" not in result

    def test_sanitize_control_characters(self):
        """Test control characters are removed."""
        result = sanitize_string("hello\x01\x02\x03world")
        assert result == "helloworld"

    def test_sanitize_tab_character(self):
        """Test tab character (control character) is removed."""
        result = sanitize_string("hello\tworld")
        assert result == "helloworld"

    def test_sanitize_newline_character(self):
        """Test newline character (control character) is removed."""
        result = sanitize_string("hello\nworld")
        assert result == "helloworld"

    def test_sanitize_carriage_return(self):
        """Test carriage return character is removed."""
        result = sanitize_string("hello\rworld")
        assert result == "helloworld"

    def test_sanitize_truncate_to_max_length(self):
        """Test string truncation to max length."""
        long_string = "a" * 300
        result = sanitize_string(long_string, max_length=255)
        assert len(result) == 255
        assert result == "a" * 255

    def test_sanitize_truncate_custom_max_length(self):
        """Test truncation with custom max length."""
        string = "a" * 100
        result = sanitize_string(string, max_length=50)
        assert len(result) == 50

    def test_sanitize_exact_max_length(self):
        """Test string exactly at max length."""
        string = "a" * 255
        result = sanitize_string(string, max_length=255)
        assert len(result) == 255
        assert result == string

    def test_sanitize_complex_string(self):
        """Test complex string with multiple issues."""
        string = "  hello\x00world\nfoo\x01bar  "
        result = sanitize_string(string, max_length=255)
        assert result == "helloworldfoobar"

    def test_sanitize_all_control_characters(self):
        """Test removal of all control characters."""
        # Include various control characters (0x00-0x1F)
        test_string = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
        result = sanitize_string(test_string)
        assert result == ""

    def test_sanitize_non_string_returns_empty(self):
        """Test non-string input returns empty string."""
        assert sanitize_string(None) == ""
        assert sanitize_string(123) == ""
        assert sanitize_string([]) == ""

    def test_sanitize_unicode_preserved(self):
        """Test Unicode characters are preserved."""
        result = sanitize_string("café")
        assert result == "café"

    def test_sanitize_unicode_with_whitespace(self):
        """Test Unicode with whitespace."""
        result = sanitize_string("  café  ")
        assert result == "café"

    def test_sanitize_empty_string(self):
        """Test sanitizing empty string."""
        result = sanitize_string("")
        assert result == ""

    def test_sanitize_whitespace_only_string(self):
        """Test sanitizing whitespace-only string."""
        result = sanitize_string("   \t\n  ")
        assert result == ""

    def test_sanitize_high_control_characters(self):
        """Test removal of high control characters (0x7F-0x9F)."""
        # Include DEL (0x7F) and other high control characters
        test_string = "hello\x7f\x80\x9fworld"
        result = sanitize_string(test_string)
        assert result == "helloworld"

    def test_sanitize_zero_max_length(self):
        """Test with zero max length."""
        result = sanitize_string("hello", max_length=0)
        assert result == ""


class TestValidatePagination:
    """Tests for validate_pagination function."""

    def test_pagination_default_values(self):
        """Test default values for pagination."""
        page, per_page = validate_pagination(0, 0)
        assert page == 1
        assert per_page == 20

    def test_pagination_valid_values(self):
        """Test valid pagination values."""
        page, per_page = validate_pagination(2, 50)
        assert page == 2
        assert per_page == 50

    def test_pagination_page_one(self):
        """Test page 1."""
        page, per_page = validate_pagination(1, 20)
        assert page == 1
        assert per_page == 20

    def test_pagination_per_page_one(self):
        """Test per_page of 1."""
        page, per_page = validate_pagination(1, 1)
        assert page == 1
        assert per_page == 1

    def test_pagination_per_page_max(self):
        """Test per_page at maximum (100)."""
        page, per_page = validate_pagination(1, 100)
        assert page == 1
        assert per_page == 100

    def test_pagination_negative_page(self):
        """Test negative page number."""
        page, per_page = validate_pagination(-1, 20)
        assert page == 1
        assert per_page == 20

    def test_pagination_negative_per_page(self):
        """Test negative per_page."""
        page, per_page = validate_pagination(1, -1)
        assert page == 1
        assert per_page == 20

    def test_pagination_per_page_exceeds_limit(self):
        """Test per_page exceeding 100."""
        page, per_page = validate_pagination(1, 200)
        assert page == 1
        assert per_page == 20

    def test_pagination_per_page_101(self):
        """Test per_page of 101."""
        page, per_page = validate_pagination(1, 101)
        assert page == 1
        assert per_page == 20

    def test_pagination_per_page_just_under_limit(self):
        """Test per_page of 99."""
        page, per_page = validate_pagination(1, 99)
        assert page == 1
        assert per_page == 99

    def test_pagination_large_page_number(self):
        """Test large page number."""
        page, per_page = validate_pagination(1000, 50)
        assert page == 1000
        assert per_page == 50

    def test_pagination_non_integer_page(self):
        """Test non-integer page."""
        page, per_page = validate_pagination("5", 20)
        assert page == 1
        assert per_page == 20

    def test_pagination_non_integer_per_page(self):
        """Test non-integer per_page."""
        page, per_page = validate_pagination(1, "50")
        assert page == 1
        assert per_page == 20

    def test_pagination_float_page(self):
        """Test float page."""
        page, per_page = validate_pagination(2.5, 20)
        assert page == 1
        assert per_page == 20

    def test_pagination_float_per_page(self):
        """Test float per_page."""
        page, per_page = validate_pagination(1, 50.5)
        assert page == 1
        assert per_page == 20

    def test_pagination_none_page(self):
        """Test None page."""
        page, per_page = validate_pagination(None, 20)
        assert page == 1
        assert per_page == 20

    def test_pagination_none_per_page(self):
        """Test None per_page."""
        page, per_page = validate_pagination(1, None)
        assert page == 1
        assert per_page == 20

    def test_pagination_both_invalid(self):
        """Test both parameters invalid."""
        page, per_page = validate_pagination(-5, 250)
        assert page == 1
        assert per_page == 20

    def test_pagination_page_zero_per_page_valid(self):
        """Test page 0 with valid per_page."""
        page, per_page = validate_pagination(0, 50)
        assert page == 1
        assert per_page == 50

    def test_pagination_large_values(self):
        """Test very large valid values."""
        page, per_page = validate_pagination(999999, 100)
        assert page == 999999
        assert per_page == 100
