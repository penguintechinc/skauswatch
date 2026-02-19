"""Parser for OpenVAS XML report format.

This module provides functions to parse OpenVAS vulnerability scanner output
into normalized finding objects. OpenVAS (now part of Greenbone Vulnerability
Management) uses XML format for scan results.
"""

import xml.etree.ElementTree as ET
from datetime import datetime

from scanners.base import NormalizedFinding


def parse_openvas_report(xml_data: str) -> list[NormalizedFinding]:
    """Parse OpenVAS XML report into normalized findings.

    OpenVAS XML report structure:
    - <report> root element
    - <results> containing multiple <result> elements
    - Each result contains: nvt, host, port, severity, description, etc.

    Args:
        xml_data: XML string containing OpenVAS report data.

    Returns:
        List of NormalizedFinding objects.
    """
    findings = []

    try:
        root = ET.fromstring(xml_data)

        # Find all result elements in the report
        results = root.findall(".//result")

        for result in results:
            try:
                finding = _parse_result(result)
                if finding:
                    findings.append(finding)
            except Exception as e:
                # Log warning but continue processing other results
                print(f"Warning: Failed to parse OpenVAS result: {e}")
                continue

    except ET.ParseError as e:
        print(f"Error: Failed to parse OpenVAS XML: {e}")
        return []

    return findings


def _parse_result(result: ET.Element) -> NormalizedFinding | None:
    """Parse a single OpenVAS result element into a NormalizedFinding.

    Args:
        result: XML Element representing a single vulnerability result.

    Returns:
        NormalizedFinding object or None if result should be skipped.
    """
    # Extract NVT (Network Vulnerability Test) details
    nvt = result.find("nvt")
    if nvt is None:
        return None

    # Extract basic information
    oid = nvt.get("oid", "unknown")
    name = _get_text(nvt, "name", "Unknown Vulnerability")
    family = _get_text(nvt, "family", "")

    # Extract severity
    severity_text = _get_text(result, "severity", "0.0")
    try:
        severity_score = float(severity_text)
    except ValueError:
        severity_score = 0.0

    # Map CVSS score to severity level
    severity = _cvss_to_severity(severity_score)

    # Extract threat level (OpenVAS uses: High, Medium, Low, Log, Debug)
    threat = _get_text(result, "threat", "Log")

    # Override severity if threat is "Log" or "Debug" (informational)
    if threat.lower() in ("log", "debug"):
        severity = "info"

    # Extract description
    description = _get_text(nvt, "description", "")

    # Extract solution/remediation
    solution = _get_text(nvt, "solution", "")
    solution_type = _get_text(nvt, "solution_type", "")
    remediation = f"{solution}\nSolution Type: {solution_type}" if solution else ""

    # Extract affected host and port
    host = _get_text(result, "host", "")
    port = _get_text(result, "port", "")
    affected_url = f"{host}:{port}" if host and port else host

    # Extract CVE references
    cve_ids = []
    refs = nvt.find("refs")
    if refs is not None:
        for ref in refs.findall("ref"):
            ref_type = ref.get("type", "")
            ref_id = ref.get("id", "")
            if ref_type.lower() == "cve":
                cve_ids.append(ref_id)

    # Extract CWE references (if available)
    cwe_ids = []
    # OpenVAS doesn't always provide CWE directly, check in tags
    tags = _get_text(nvt, "tags", "")
    if "cwe-" in tags.lower():
        # Parse CWE from tags string
        cwe_ids = _extract_cwe_from_tags(tags)

    # Build evidence from result details
    evidence_parts = []

    # Add host and port info
    if host:
        evidence_parts.append(f"Host: {host}")
    if port:
        evidence_parts.append(f"Port: {port}")

    # Add threat level
    evidence_parts.append(f"Threat Level: {threat}")

    # Add QoD (Quality of Detection)
    qod = _get_text(result, "qod", "")
    qod_type = _get_text(result, "qod_type", "")
    if qod:
        evidence_parts.append(f"Quality of Detection: {qod}% ({qod_type})")

    # Add detected version/result
    detected_result = _get_text(result, "description", "")
    if detected_result:
        evidence_parts.append(f"Detection Result:\n{detected_result[:500]}")

    # Add CVE references to evidence
    if cve_ids:
        evidence_parts.append(f"CVE References: {', '.join(cve_ids)}")

    # Add family information
    if family:
        evidence_parts.append(f"Vulnerability Family: {family}")

    evidence = "\n".join(evidence_parts)

    # Generate unique finding ID
    timestamp = datetime.utcnow().timestamp()
    finding_id = f"openvas_{oid}_{host}_{port}_{int(timestamp)}"

    # Build raw finding dictionary
    raw_finding = {
        "oid": oid,
        "name": name,
        "family": family,
        "severity": severity_text,
        "threat": threat,
        "host": host,
        "port": port,
        "description": description,
        "solution": solution,
        "cve_ids": cve_ids,
    }

    return NormalizedFinding(
        finding_id=finding_id,
        severity=severity,
        title=name,
        description=description,
        remediation=remediation,
        affected_url=affected_url,
        cvss_score=severity_score,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        evidence=evidence,
        raw_finding=raw_finding,
        discovered_at=datetime.utcnow(),
    )


def _get_text(element: ET.Element, path: str, default: str = "") -> str:
    """Safely extract text content from XML element.

    Args:
        element: Parent XML element.
        path: XPath or tag name to find.
        default: Default value if element not found.

    Returns:
        Text content or default value.
    """
    child = element.find(path)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _cvss_to_severity(cvss_score: float) -> str:
    """Convert CVSS score to severity level.

    CVSS v3.0 severity ratings:
    - 0.0: None (info)
    - 0.1-3.9: Low
    - 4.0-6.9: Medium
    - 7.0-8.9: High
    - 9.0-10.0: Critical

    Args:
        cvss_score: CVSS score (0.0-10.0).

    Returns:
        Normalized severity string.
    """
    if cvss_score == 0.0:
        return "info"
    elif cvss_score < 4.0:
        return "low"
    elif cvss_score < 7.0:
        return "medium"
    elif cvss_score < 9.0:
        return "high"
    else:
        return "critical"


def _extract_cwe_from_tags(tags: str) -> list[str]:
    """Extract CWE identifiers from OpenVAS tags string.

    Args:
        tags: Tags string from OpenVAS NVT.

    Returns:
        List of CWE identifiers (e.g., ["CWE-79", "CWE-89"]).
    """
    cwe_ids = []
    tags_lower = tags.lower()

    # Simple pattern matching for CWE-XXX
    import re

    pattern = r"cwe-(\d+)"
    matches = re.findall(pattern, tags_lower)

    for match in matches:
        cwe_ids.append(f"CWE-{match}")

    return cwe_ids
