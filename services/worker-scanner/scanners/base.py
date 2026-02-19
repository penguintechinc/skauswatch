"""Abstract base scanner class defining the interface for all scanner implementations.

This module provides the base classes and data structures that all scanner
implementations must follow. It defines standardized formats for scan results,
findings, and scanner status to ensure consistency across different scanning tools.
"""

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from utils.logger import get_logger


@dataclass(slots=True)
class ScannerStatus:
    """Status information for a scanner tool.

    Attributes:
        name: Human-readable name of the scanner.
        available: Whether the scanner is available and functional.
        version: Version string of the scanner (empty if unknown).
        message: Additional status information or error details.
        last_checked: Timestamp of last status check (None if never checked).
    """

    name: str
    available: bool
    version: str = ""
    message: str = ""
    last_checked: datetime | None = None


@dataclass(slots=True)
class NormalizedFinding:
    """Standardized representation of a security finding.

    This class normalizes findings from different scanners into a consistent
    format for storage and reporting.

    Attributes:
        finding_id: Unique identifier for this finding.
        severity: Standardized severity level (critical/high/medium/low/info).
        title: Brief title describing the finding.
        description: Detailed description of the security issue.
        remediation: Suggested remediation steps (empty if not provided).
        affected_url: URL or resource affected by this finding.
        cvss_score: CVSS score if available (0.0 if not provided).
        cve_ids: List of related CVE identifiers.
        cwe_ids: List of related CWE identifiers.
        evidence: Supporting evidence or proof of concept.
        raw_finding: Original finding data from the scanner.
        discovered_at: Timestamp when the finding was discovered.
    """

    finding_id: str
    severity: str
    title: str
    description: str
    remediation: str = ""
    affected_url: str = ""
    cvss_score: float = 0.0
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    evidence: str = ""
    raw_finding: dict = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding to a JSON-serializable dictionary.

        Returns:
            Dictionary representation with datetime converted to ISO format.
        """
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "affected_url": self.affected_url,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "evidence": self.evidence,
            "raw_finding": self.raw_finding,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass(slots=True)
class ScanResult:
    """Result of a security scan operation.

    Attributes:
        success: Whether the scan completed successfully.
        scanner_type: Type of scanner that produced this result.
        scan_type: Type of scan performed (e.g., quick, full, authenticated).
        findings: List of normalized security findings.
        error_message: Error message if scan failed (empty if successful).
        duration_seconds: Duration of the scan in seconds.
        raw_output: Raw output from the scanner tool.
        summary: Summary statistics about the scan results.
    """

    success: bool
    scanner_type: str
    scan_type: str
    findings: list[NormalizedFinding] = field(default_factory=list)
    error_message: str = ""
    duration_seconds: int = 0
    raw_output: str = ""
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the scan result to a JSON-serializable dictionary.

        Returns:
            Dictionary representation with all nested objects converted.
        """
        return {
            "success": self.success,
            "scanner_type": self.scanner_type,
            "scan_type": self.scan_type,
            "findings": [finding.to_dict() for finding in self.findings],
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "raw_output": self.raw_output,
            "summary": self.summary,
        }


class BaseScanner(abc.ABC):
    """Abstract base class for all security scanner implementations.

    This class defines the interface that all scanner implementations must
    follow. It provides common functionality and enforces a consistent API
    across different scanning tools.

    Subclasses must define a SCANNER_TYPE class attribute and implement
    all abstract methods.
    """

    SCANNER_TYPE: str = ""  # Must be overridden by subclasses

    def __init__(self, config: dict) -> None:
        """Initialize the scanner with configuration.

        Args:
            config: Scanner-specific configuration dictionary.
        """
        self.config = config
        self.logger = get_logger(f"scanner.{self.scanner_type}")

    @property
    def scanner_type(self) -> str:
        """Get the scanner type identifier.

        Returns:
            Scanner type string defined by the SCANNER_TYPE class attribute.

        Raises:
            NotImplementedError: If SCANNER_TYPE is not defined by the subclass.
        """
        if not self.SCANNER_TYPE:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define SCANNER_TYPE class attribute"
            )
        return self.SCANNER_TYPE

    @abc.abstractmethod
    def scan(
        self, target: str, scan_type: str, config: dict | None = None
    ) -> ScanResult:
        """Execute a security scan against the target.

        Args:
            target: Target URL, IP address, or hostname to scan.
            scan_type: Type of scan to perform (e.g., quick, full, authenticated).
            config: Optional scan-specific configuration to override defaults.

        Returns:
            ScanResult containing the findings and scan metadata.
        """
        pass

    @abc.abstractmethod
    def parse_results(self, raw_output: str) -> list[NormalizedFinding]:
        """Parse raw scanner output into normalized findings.

        Args:
            raw_output: Raw output string from the scanner tool.

        Returns:
            List of normalized security findings.
        """
        pass

    @abc.abstractmethod
    def get_status(self) -> ScannerStatus:
        """Check if the scanner is available and return its status.

        Returns:
            ScannerStatus indicating availability and version information.
        """
        pass

    @abc.abstractmethod
    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate scanner-specific configuration.

        Args:
            config: Configuration dictionary to validate.

        Returns:
            Tuple of (is_valid, error_message). If valid, error_message is empty.
        """
        pass

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity values from different scanners to standard levels.

        Maps various severity representations to one of: critical, high, medium,
        low, or info. Handles different formats including:
        - String values (Critical, HIGH, Medium, etc.)
        - Numeric values (ZAP risk levels: 3=High, 2=Medium, 1=Low, 0=Info)
        - Scanner-specific values (OpenVAS: Alarm, Log, etc.)

        Args:
            severity: Raw severity value from scanner output.

        Returns:
            Normalized severity string (critical/high/medium/low/info).
            Returns "info" if severity cannot be determined.
        """
        if not severity:
            return "info"

        # Convert to lowercase for case-insensitive matching
        severity_lower = str(severity).lower().strip()

        # Direct matches
        if severity_lower in ("critical", "high", "medium", "low", "info"):
            return severity_lower

        # Critical severity mappings
        if severity_lower in ("crit", "5", "critical"):
            return "critical"

        # High severity mappings
        if severity_lower in ("3", "hi", "alarm"):
            return "high"

        # Medium severity mappings
        if severity_lower in ("2", "med", "moderate", "warning"):
            return "medium"

        # Low severity mappings
        if severity_lower in ("1", "lo", "minor", "note"):
            return "low"

        # Info/Informational mappings
        if severity_lower in ("0", "informational", "log", "debug"):
            return "info"

        # Default to info if unknown
        self.logger.warning(
            f"Unknown severity value '{severity}', defaulting to 'info'"
        )
        return "info"
