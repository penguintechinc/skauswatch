"""Parser for Nuclei JSON output format.

This module provides functions to parse Nuclei vulnerability scanner output
into normalized finding objects. Nuclei is a fast and customizable vulnerability
scanner that uses templates to detect security issues.
"""

from datetime import datetime

from scanners.base import NormalizedFinding


def parse_nuclei_finding(nuclei_json: dict) -> NormalizedFinding:
    """Parse a single Nuclei JSON finding into a NormalizedFinding.

    Nuclei JSON format typically contains:
    - template-id: Template identifier
    - info: Metadata (name, severity, description, reference, classification, etc.)
    - type: Protocol type (http, dns, etc.)
    - host: Target host
    - matched-at: URL where match occurred
    - extracted-results: Extracted data
    - curl-command: Reproduction curl command
    - matcher-name: Name of the matcher that triggered

    Args:
        nuclei_json: Dictionary containing a single Nuclei JSON finding.

    Returns:
        NormalizedFinding object with standardized fields.
    """
    # Extract basic info
    template_id = nuclei_json.get("template-id", "unknown")
    info = nuclei_json.get("info", {})

    # Extract severity (default to info)
    severity = info.get("severity", "info").lower()

    # Normalize severity values
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    severity = severity_map.get(severity, "info")

    # Extract title and description
    title = info.get("name", template_id)
    description = info.get("description", "")

    # Extract remediation
    remediation = info.get("remediation", "")

    # Extract affected URL
    affected_url = nuclei_json.get("matched-at", nuclei_json.get("host", ""))

    # Extract CVSS score
    classification = info.get("classification", {})
    cvss_metrics = classification.get("cvss-metrics", "")
    cvss_score = classification.get("cvss-score", 0.0)

    # Convert cvss_score to float
    try:
        cvss_score = float(cvss_score)
    except (ValueError, TypeError):
        cvss_score = 0.0

    # Extract CVE IDs
    cve_ids = []
    cve_id = classification.get("cve-id")
    if cve_id:
        if isinstance(cve_id, list):
            cve_ids = [str(cve).strip() for cve in cve_id if cve]
        else:
            cve_ids = [str(cve_id).strip()]

    # Extract CWE IDs
    cwe_ids = []
    cwe_id = classification.get("cwe-id")
    if cwe_id:
        if isinstance(cwe_id, list):
            cwe_ids = [str(cwe).strip() for cwe in cwe_id if cwe]
        else:
            cwe_ids = [str(cwe_id).strip()]

    # Build evidence string
    evidence_parts = []

    # Add matcher name if present
    matcher_name = nuclei_json.get("matcher-name")
    if matcher_name:
        evidence_parts.append(f"Matcher: {matcher_name}")

    # Add extracted results if present
    extracted = nuclei_json.get("extracted-results")
    if extracted:
        if isinstance(extracted, list):
            evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted)}")
        else:
            evidence_parts.append(f"Extracted: {extracted}")

    # Add curl command if present
    curl_cmd = nuclei_json.get("curl-command")
    if curl_cmd:
        evidence_parts.append(f"Curl: {curl_cmd}")

    # Add request/response if present
    request = nuclei_json.get("request")
    if request:
        evidence_parts.append(f"Request: {request[:500]}")

    response = nuclei_json.get("response")
    if response:
        evidence_parts.append(f"Response: {response[:500]}")

    evidence = "\n".join(evidence_parts)

    # Generate finding ID
    finding_id = f"{template_id}_{affected_url}_{datetime.utcnow().timestamp()}"

    return NormalizedFinding(
        finding_id=finding_id,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        affected_url=affected_url,
        cvss_score=cvss_score,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        evidence=evidence,
        raw_finding=nuclei_json,
        discovered_at=datetime.utcnow(),
    )
