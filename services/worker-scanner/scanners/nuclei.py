"""Nuclei vulnerability scanner implementation.

This module provides a wrapper for the Nuclei CLI tool, a fast and customizable
vulnerability scanner that uses YAML templates to detect security issues across
web applications, network services, and infrastructure.

Nuclei supports various scan types:
- baseline: Critical, high, and medium severity vulnerabilities
- full: All severity levels with comprehensive template coverage
- custom: User-defined templates and severity filters
"""

import json
import os
import shlex
import subprocess
import time
from datetime import datetime

from scanners.base import BaseScanner, NormalizedFinding, ScanResult, ScannerStatus
from scanners.parsers.nuclei_parser import parse_nuclei_finding


class NucleiScanner(BaseScanner):
    """Nuclei vulnerability scanner wrapper.

    This scanner executes the Nuclei CLI tool and parses its JSON output into
    normalized findings. It supports different scan types with configurable
    rate limiting and concurrency.

    Attributes:
        SCANNER_TYPE: Identifier for this scanner type.
        binary_path: Path to the nuclei binary.
        templates_path: Path to the nuclei templates directory.
        rate_limit: Maximum requests per second.
        concurrency: Number of concurrent scan threads.
    """

    SCANNER_TYPE = "nuclei"

    def __init__(self, config: dict) -> None:
        """Initialize the Nuclei scanner with configuration.

        Args:
            config: Configuration dictionary containing scanner settings.
                Expected keys:
                - binary_path: Path to nuclei binary (default: from env or /usr/local/bin/nuclei)
                - templates_path: Path to templates (default: from env or /root/nuclei-templates)
                - rate_limit: Max requests/sec (default: 150)
                - concurrency: Concurrent threads (default: 25)
        """
        super().__init__(config)

        # Set binary path from config, env var, or default
        self.binary_path = config.get(
            "binary_path",
            os.environ.get("NUCLEI_BINARY_PATH", "/usr/local/bin/nuclei")
        )

        # Set templates path from config, env var, or default
        self.templates_path = config.get(
            "templates_path",
            os.environ.get("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")
        )

        # Set rate limit and concurrency
        self.rate_limit = config.get("rate_limit", 150)
        self.concurrency = config.get("concurrency", 25)

        self.logger.info(
            f"Initialized Nuclei scanner: binary={self.binary_path}, "
            f"templates={self.templates_path}, rate_limit={self.rate_limit}, "
            f"concurrency={self.concurrency}"
        )

    def scan(
        self,
        target: str,
        scan_type: str,
        config: dict | None = None
    ) -> ScanResult:
        """Execute a Nuclei scan against the target.

        Args:
            target: Target URL, IP address, or hostname to scan.
            scan_type: Type of scan to perform (baseline/full/custom).
            config: Optional scan-specific configuration to override defaults.
                For custom scans, expected keys:
                - templates: List of template paths
                - severity_filter: Comma-separated severity levels
                - exclude_templates: Comma-separated template patterns to exclude
                - timeout: Scan timeout in seconds

        Returns:
            ScanResult containing findings and scan metadata.
        """
        start_time = time.time()
        merge_config = {**self.config, **(config or {})}

        self.logger.info(
            f"Starting Nuclei {scan_type} scan against {target}"
        )

        # Build command line arguments
        cmd_parts = [self.binary_path]

        # Target
        cmd_parts.extend(["-target", target])

        # JSON output
        cmd_parts.append("-json")

        # Rate limit and concurrency
        cmd_parts.extend(["-rate-limit", str(self.rate_limit)])
        cmd_parts.extend(["-concurrency", str(self.concurrency)])

        # Silent mode (no banner)
        cmd_parts.append("-silent")

        # Scan type specific configuration
        if scan_type == "baseline":
            # Baseline: critical, high, medium only
            cmd_parts.extend(["-severity", "critical,high,medium"])
            self.logger.debug("Baseline scan: filtering critical,high,medium severity")

        elif scan_type == "full":
            # Full scan: all severities, no filter
            self.logger.debug("Full scan: no severity filter")

        elif scan_type == "custom":
            # Custom scan: use config for templates and filters
            if not merge_config.get("templates"):
                error_msg = "Custom scan requires 'templates' list in config"
                self.logger.error(error_msg)
                return ScanResult(
                    success=False,
                    scanner_type=self.SCANNER_TYPE,
                    scan_type=scan_type,
                    error_message=error_msg,
                    duration_seconds=int(time.time() - start_time),
                )

            # Add custom templates
            for template in merge_config["templates"]:
                cmd_parts.extend(["-t", template])
                self.logger.debug(f"Added custom template: {template}")

            # Add severity filter if specified
            if "severity_filter" in merge_config:
                cmd_parts.extend(["-severity", merge_config["severity_filter"]])
                self.logger.debug(
                    f"Custom severity filter: {merge_config['severity_filter']}"
                )

            # Add exclude templates if specified
            if "exclude_templates" in merge_config:
                cmd_parts.extend(
                    ["-exclude-templates", merge_config["exclude_templates"]]
                )
                self.logger.debug(
                    f"Excluding templates: {merge_config['exclude_templates']}"
                )

        else:
            error_msg = f"Invalid scan_type: {scan_type}"
            self.logger.error(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=int(time.time() - start_time),
            )

        # Add timeout if specified
        scan_timeout = merge_config.get("timeout", 3600)
        if "timeout" in merge_config:
            cmd_parts.extend(["-timeout", str(merge_config["timeout"])])

        # Log the command being executed
        self.logger.debug(f"Executing command: {' '.join(shlex.quote(p) for p in cmd_parts)}")

        # Execute the scan
        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=scan_timeout,
                check=False,  # Don't raise on non-zero exit
            )

            duration = int(time.time() - start_time)

            # Log execution results
            self.logger.debug(
                f"Nuclei scan completed: exit_code={result.returncode}, "
                f"duration={duration}s"
            )

            # Parse the results
            raw_output = result.stdout
            findings = self.parse_results(raw_output)

            # Build summary
            severity_counts = {}
            for finding in findings:
                severity_counts[finding.severity] = (
                    severity_counts.get(finding.severity, 0) + 1
                )

            summary = {
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "scan_duration": duration,
                "exit_code": result.returncode,
            }

            # Log summary
            self.logger.info(
                f"Nuclei scan completed: {len(findings)} findings in {duration}s "
                f"(exit_code={result.returncode})"
            )
            for severity, count in severity_counts.items():
                self.logger.info(f"  {severity}: {count}")

            # Check for stderr warnings/errors
            if result.stderr:
                self.logger.warning(f"Nuclei stderr output: {result.stderr[:1000]}")

            return ScanResult(
                success=True,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                findings=findings,
                duration_seconds=duration,
                raw_output=raw_output,
                summary=summary,
            )

        except subprocess.TimeoutExpired:
            duration = int(time.time() - start_time)
            error_msg = f"Nuclei scan timed out after {duration}s"
            self.logger.error(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=duration,
            )

        except FileNotFoundError:
            duration = int(time.time() - start_time)
            error_msg = f"Nuclei binary not found at {self.binary_path}"
            self.logger.error(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=duration,
            )

        except Exception as e:
            duration = int(time.time() - start_time)
            error_msg = f"Nuclei scan failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=duration,
            )

    def parse_results(self, raw_output: str) -> list[NormalizedFinding]:
        """Parse Nuclei JSON output into normalized findings.

        Nuclei outputs one JSON object per line for each finding. This method
        parses each line and converts it to a NormalizedFinding.

        Args:
            raw_output: Raw JSON output from Nuclei (newline-delimited JSON objects).

        Returns:
            List of NormalizedFinding objects.
        """
        findings = []

        if not raw_output or not raw_output.strip():
            self.logger.debug("No output from Nuclei scan")
            return findings

        # Split by newlines and parse each JSON object
        for line_num, line in enumerate(raw_output.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            try:
                nuclei_json = json.loads(line)
                finding = parse_nuclei_finding(nuclei_json)
                findings.append(finding)

            except json.JSONDecodeError as e:
                self.logger.warning(
                    f"Failed to parse JSON on line {line_num}: {e}\n"
                    f"Line content: {line[:200]}"
                )
                continue

            except Exception as e:
                self.logger.error(
                    f"Failed to parse Nuclei finding on line {line_num}: {e}",
                    exc_info=True,
                )
                continue

        self.logger.debug(f"Parsed {len(findings)} findings from Nuclei output")
        return findings

    def get_status(self) -> ScannerStatus:
        """Check if Nuclei is available and return its status.

        Returns:
            ScannerStatus with availability and version information.
        """
        try:
            # Run nuclei -version to check availability
            result = subprocess.run(
                [self.binary_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                # Parse version from output
                # Expected format: "Nuclei vX.Y.Z"
                version = "unknown"
                output = result.stdout.strip()

                # Try to extract version number
                if output:
                    parts = output.split()
                    for part in parts:
                        if part.startswith("v") or part[0].isdigit():
                            version = part.lstrip("v")
                            break

                self.logger.info(f"Nuclei is available: version {version}")
                return ScannerStatus(
                    name="Nuclei",
                    available=True,
                    version=version,
                    message="Nuclei scanner is operational",
                    last_checked=datetime.utcnow(),
                )

            else:
                error_msg = f"Nuclei returned non-zero exit code: {result.returncode}"
                self.logger.warning(error_msg)
                return ScannerStatus(
                    name="Nuclei",
                    available=False,
                    version="",
                    message=error_msg,
                    last_checked=datetime.utcnow(),
                )

        except FileNotFoundError:
            error_msg = f"Nuclei binary not found at {self.binary_path}"
            self.logger.error(error_msg)
            return ScannerStatus(
                name="Nuclei",
                available=False,
                version="",
                message=error_msg,
                last_checked=datetime.utcnow(),
            )

        except subprocess.TimeoutExpired:
            error_msg = "Nuclei version check timed out"
            self.logger.error(error_msg)
            return ScannerStatus(
                name="Nuclei",
                available=False,
                version="",
                message=error_msg,
                last_checked=datetime.utcnow(),
            )

        except Exception as e:
            error_msg = f"Failed to check Nuclei status: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return ScannerStatus(
                name="Nuclei",
                available=False,
                version="",
                message=error_msg,
                last_checked=datetime.utcnow(),
            )

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate Nuclei scanner configuration.

        Args:
            config: Configuration dictionary to validate.
                Expected keys:
                - scan_type: Must be baseline, full, or custom
                - templates: Required for custom scans (list of paths)
                - rate_limit: Optional positive integer
                - concurrency: Optional positive integer
                - severity_filter: Optional comma-separated severity levels
                - exclude_templates: Optional comma-separated template patterns
                - timeout: Optional positive integer

        Returns:
            Tuple of (is_valid, error_message). If valid, error_message is empty.
        """
        # Validate scan_type if present
        scan_type = config.get("scan_type")
        if scan_type:
            valid_types = ["baseline", "full", "custom"]
            if scan_type not in valid_types:
                return (
                    False,
                    f"Invalid scan_type '{scan_type}'. Must be one of: {', '.join(valid_types)}",
                )

            # Custom scans require templates
            if scan_type == "custom" and not config.get("templates"):
                return (
                    False,
                    "Custom scan_type requires 'templates' list in config",
                )

            # Validate templates is a list if present
            if "templates" in config:
                templates = config["templates"]
                if not isinstance(templates, list):
                    return (
                        False,
                        f"'templates' must be a list, got {type(templates).__name__}",
                    )
                if not templates:
                    return (False, "'templates' list cannot be empty")

        # Validate rate_limit if present
        rate_limit = config.get("rate_limit")
        if rate_limit is not None:
            try:
                rate_limit_int = int(rate_limit)
                if rate_limit_int <= 0:
                    return (
                        False,
                        f"'rate_limit' must be a positive integer, got {rate_limit}",
                    )
            except (ValueError, TypeError):
                return (
                    False,
                    f"'rate_limit' must be a positive integer, got {rate_limit}",
                )

        # Validate concurrency if present
        concurrency = config.get("concurrency")
        if concurrency is not None:
            try:
                concurrency_int = int(concurrency)
                if concurrency_int <= 0:
                    return (
                        False,
                        f"'concurrency' must be a positive integer, got {concurrency}",
                    )
            except (ValueError, TypeError):
                return (
                    False,
                    f"'concurrency' must be a positive integer, got {concurrency}",
                )

        # Validate timeout if present
        timeout = config.get("timeout")
        if timeout is not None:
            try:
                timeout_int = int(timeout)
                if timeout_int <= 0:
                    return (
                        False,
                        f"'timeout' must be a positive integer, got {timeout}",
                    )
            except (ValueError, TypeError):
                return (
                    False,
                    f"'timeout' must be a positive integer, got {timeout}",
                )

        # Validate severity_filter if present
        if "severity_filter" in config:
            severity_filter = config["severity_filter"]
            if not isinstance(severity_filter, str):
                return (
                    False,
                    f"'severity_filter' must be a string, got {type(severity_filter).__name__}",
                )

            # Check that severity levels are valid
            valid_severities = {"critical", "high", "medium", "low", "info", "informational"}
            provided_severities = {s.strip().lower() for s in severity_filter.split(",")}
            invalid_severities = provided_severities - valid_severities

            if invalid_severities:
                return (
                    False,
                    f"Invalid severity levels in 'severity_filter': {', '.join(invalid_severities)}. "
                    f"Valid levels: {', '.join(sorted(valid_severities))}",
                )

        # Validate exclude_templates if present
        if "exclude_templates" in config:
            exclude_templates = config["exclude_templates"]
            if not isinstance(exclude_templates, str):
                return (
                    False,
                    f"'exclude_templates' must be a string, got {type(exclude_templates).__name__}",
                )

        # All validations passed
        return (True, "")
