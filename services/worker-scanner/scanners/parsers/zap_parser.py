"""Parser for OWASP ZAP JSON alert format.

This module provides functions to parse OWASP ZAP vulnerability scanner output
into normalized finding objects. ZAP is a popular open-source web application
security scanner maintained by OWASP.
"""

from datetime import datetime

from scanners.base import NormalizedFinding


def parse_zap_alert(alert: dict) -> NormalizedFinding:
    """Parse a single ZAP alert into a NormalizedFinding.

    ZAP alert format typically contains:
    - alertRef: Alert reference ID
    - pluginId: Plugin/rule ID
    - name: Alert name/title
    - riskcode: Risk level (0=Info, 1=Low, 2=Medium, 3=High)
    - confidence: Confidence level (0=FP, 1=Low, 2=Medium, 3=High)
    - description: Detailed description
    - solution: Remediation advice
    - reference: External references
    - cweid: CWE identifier
    - wascid: WASC identifier
    - url: Affected URL
    - method: HTTP method
    - evidence: Evidence from the response
    - attack: Attack payload used
    - param: Vulnerable parameter

    Args:
        alert: Dictionary containing a single ZAP alert.

    Returns:
        NormalizedFinding object with standardized fields.
    """
    # Extract basic info
    alert_ref = alert.get("alertRef", "")
    plugin_id = alert.get("pluginId", "unknown")
    title = alert.get("name", f"ZAP Alert {plugin_id}")

    # Extract severity from riskcode
    risk_code = alert.get("riskcode", "0")
    severity_map = {
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "info",
    }
    severity = severity_map.get(str(risk_code), "info")

    # Extract description and remediation
    description = alert.get("description", "")
    remediation = alert.get("solution", "")

    # Extract affected URL
    affected_url = alert.get("url", "")

    # Extract CWE IDs
    cwe_ids = []
    cwe_id = alert.get("cweid")
    if cwe_id and str(cwe_id) != "-1":
        cwe_ids = [f"CWE-{cwe_id}"]

    # Build evidence string
    evidence_parts = []

    # Add HTTP method
    method = alert.get("method")
    if method:
        evidence_parts.append(f"Method: {method}")

    # Add parameter
    param = alert.get("param")
    if param:
        evidence_parts.append(f"Parameter: {param}")

    # Add attack payload
    attack = alert.get("attack")
    if attack:
        evidence_parts.append(f"Attack: {attack}")

    # Add evidence from response
    evidence_data = alert.get("evidence")
    if evidence_data:
        evidence_parts.append(f"Evidence: {evidence_data[:500]}")

    # Add reference URLs
    reference = alert.get("reference")
    if reference:
        evidence_parts.append(f"Reference: {reference}")

    # Add confidence level
    confidence = alert.get("confidence")
    if confidence:
        confidence_map = {
            "0": "False Positive",
            "1": "Low",
            "2": "Medium",
            "3": "High",
        }
        confidence_str = confidence_map.get(str(confidence), str(confidence))
        evidence_parts.append(f"Confidence: {confidence_str}")

    evidence = "\n".join(evidence_parts)

    # Generate finding ID
    finding_id = f"zap_{plugin_id}_{affected_url}_{datetime.utcnow().timestamp()}"

    # CVSS score not directly provided by ZAP, can be estimated from risk
    cvss_map = {
        "3": 7.5,  # High
        "2": 5.0,  # Medium
        "1": 2.5,  # Low
        "0": 0.0,  # Info
    }
    cvss_score = cvss_map.get(str(risk_code), 0.0)

    return NormalizedFinding(
        finding_id=finding_id,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        affected_url=affected_url,
        cvss_score=cvss_score,
        cve_ids=[],  # ZAP doesn't typically provide CVE IDs directly
        cwe_ids=cwe_ids,
        evidence=evidence,
        raw_finding=alert,
        discovered_at=datetime.utcnow(),
    )
