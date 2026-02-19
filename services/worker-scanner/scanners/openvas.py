"""OpenVAS GMP protocol client scanner implementation.

This module provides integration with OpenVAS (Greenbone Vulnerability Management)
using the Greenbone Management Protocol (GMP). It supports various scan
configurations including discovery, baseline, and full vulnerability scans.
"""

import os
import time
import xml.etree.ElementTree as ET
from datetime import datetime

from gvm.connections import TLSConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp

from scanners.base import BaseScanner, NormalizedFinding, ScanResult, ScannerStatus
from scanners.parsers.openvas_parser import parse_openvas_report


class OpenvasScanner(BaseScanner):
    """OpenVAS scanner implementation using GMP protocol.

    This scanner integrates with an OpenVAS instance via the Greenbone
    Management Protocol (GMP) to perform network and vulnerability scans.
    It supports multiple scan types:
    - discovery: Quick network discovery scan
    - full_and_fast: Balanced vulnerability scan (default)
    - full_and_deep: Comprehensive deep vulnerability scan
    - baseline: Alias for full_and_fast
    - full: Alias for full_and_deep

    The scanner creates targets and tasks in OpenVAS, monitors scan progress,
    and retrieves results in XML format.
    """

    SCANNER_TYPE = "openvas"

    # OpenVAS scan configuration IDs (standard configs)
    SCAN_CONFIGS = {
        "discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
        "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
        "full_and_deep": "708f25c4-7489-11df-8094-002264764cea",
    }

    # Default OpenVAS scanner ID (built-in scanner)
    DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

    # XML report format ID (standard XML format)
    XML_REPORT_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5"

    def __init__(self, config: dict) -> None:
        """Initialize the OpenVAS scanner with configuration.

        Args:
            config: Scanner configuration dictionary. May contain:
                - host: OpenVAS GMP host
                - port: OpenVAS GMP port (default 9390)
                - username: GMP username
                - password: GMP password
                - timeout: Scan timeout in seconds (default 7200)
        """
        super().__init__(config)

        # Get OpenVAS configuration from config or environment
        self.host = config.get("host", os.getenv("SCANNER_OPENVAS_HOST", "openvas"))
        self.port = int(config.get("port", os.getenv("SCANNER_OPENVAS_PORT", "9390")))
        self.username = config.get(
            "username", os.getenv("SCANNER_OPENVAS_USER", "admin")
        )
        self.password = config.get(
            "password", os.getenv("SCANNER_OPENVAS_PASSWORD", "admin")
        )

        # Scan timeout (OpenVAS scans can be very slow)
        self.scan_timeout = config.get("timeout", 7200)  # 2 hours default

        self.logger.info(
            f"Initialized OpenVAS scanner with host={self.host}:{self.port}"
        )

    def _connect(self) -> tuple:
        """Establish connection to OpenVAS GMP service.

        Returns:
            Tuple of (Gmp instance, connection object).

        Raises:
            GvmError: If connection or authentication fails.
        """
        try:
            # Create TLS connection to OpenVAS GMP
            connection = TLSConnection(hostname=self.host, port=self.port, timeout=30)

            # Create GMP protocol instance
            gmp = Gmp(connection=connection)

            # Connect and authenticate
            connection.connect()
            gmp.authenticate(self.username, self.password)

            self.logger.debug(
                f"Successfully connected to OpenVAS at {self.host}:{self.port}"
            )
            return gmp, connection

        except GvmError as e:
            self.logger.error(f"Failed to connect to OpenVAS: {e}")
            raise

        except Exception as e:
            self.logger.error(f"Unexpected error connecting to OpenVAS: {e}")
            raise

    def scan(
        self, target: str, scan_type: str, config: dict | None = None
    ) -> ScanResult:
        """Execute a security scan against the target.

        Args:
            target: Target IP address, hostname, or CIDR range to scan.
            scan_type: Type of scan to perform (discovery, full_and_fast, etc.).
            config: Optional scan-specific configuration.

        Returns:
            ScanResult containing the findings and scan metadata.
        """
        start_time = time.time()
        scan_config = config or {}

        self.logger.info(f"Starting OpenVAS {scan_type} scan of target: {target}")

        gmp = None
        connection = None
        task_id = None
        target_id = None

        try:
            # Validate configuration
            valid, error = self.validate_config({"scan_type": scan_type, **scan_config})
            if not valid:
                return ScanResult(
                    success=False,
                    scanner_type=self.scanner_type,
                    scan_type=scan_type,
                    error_message=error,
                    duration_seconds=int(time.time() - start_time),
                )

            # Map scan type to OpenVAS config ID
            config_id = self._get_scan_config_id(scan_type)

            # Connect to OpenVAS
            gmp, connection = self._connect()

            # Create unique target
            timestamp = int(time.time())
            target_name = f"skauswatch-{target.replace('/', '_')}-{timestamp}"

            self.logger.debug(f"Creating target: {target_name}")
            target_response = gmp.create_target(name=target_name, hosts=[target])
            target_id = self._extract_id_from_response(target_response)
            self.logger.info(f"Created target {target_name} with ID: {target_id}")

            # Create scan task
            task_name = f"skauswatch-scan-{timestamp}"
            self.logger.debug(f"Creating task: {task_name}")
            task_response = gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=self.DEFAULT_SCANNER_ID,
            )
            task_id = self._extract_id_from_response(task_response)
            self.logger.info(f"Created task {task_name} with ID: {task_id}")

            # Start the scan task
            self.logger.debug(f"Starting task {task_id}")
            gmp.start_task(task_id)
            self.logger.info(f"Task {task_id} started")

            # Poll task status until completion
            self.logger.debug(f"Polling task {task_id} for completion")
            if not self._poll_task_status(gmp, task_id):
                error_msg = f"Task {task_id} timed out after {self.scan_timeout}s"
                self.logger.error(error_msg)
                return ScanResult(
                    success=False,
                    scanner_type=self.scanner_type,
                    scan_type=scan_type,
                    error_message=error_msg,
                    duration_seconds=int(time.time() - start_time),
                )

            # Get task details to extract report ID
            self.logger.debug(f"Retrieving task details for {task_id}")
            task_response = gmp.get_task(task_id)
            report_id = self._extract_report_id(task_response)
            self.logger.info(f"Retrieved report ID: {report_id}")

            # Get report in XML format
            self.logger.debug(f"Downloading report {report_id}")
            report_response = gmp.get_report(
                report_id=report_id, report_format_id=self.XML_REPORT_FORMAT_ID
            )

            # Extract XML content from response
            raw_output = ET.tostring(report_response, encoding="unicode")

            # Parse results
            self.logger.debug("Parsing OpenVAS report")
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
                "scan_type": scan_type,
                "target": target,
                "task_id": task_id,
                "report_id": report_id,
            }

            duration = int(time.time() - start_time)
            self.logger.info(
                f"OpenVAS {scan_type} scan completed in {duration}s with "
                f"{len(findings)} findings"
            )

            # Clean up: delete task and target
            self._cleanup_resources(gmp, task_id, target_id)

            return ScanResult(
                success=True,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                findings=findings,
                duration_seconds=duration,
                raw_output=raw_output,
                summary=summary,
            )

        except GvmError as e:
            error_msg = f"OpenVAS GMP error: {e}"
            self.logger.error(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=int(time.time() - start_time),
            )

        except Exception as e:
            error_msg = f"Unexpected error during OpenVAS scan: {e}"
            self.logger.exception(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=int(time.time() - start_time),
            )

        finally:
            # Always disconnect
            if connection:
                try:
                    connection.disconnect()
                    self.logger.debug("Disconnected from OpenVAS")
                except Exception as e:
                    self.logger.warning(f"Error disconnecting from OpenVAS: {e}")

    def _get_scan_config_id(self, scan_type: str) -> str:
        """Map scan type to OpenVAS scan config ID.

        Args:
            scan_type: User-specified scan type.

        Returns:
            OpenVAS scan configuration UUID.
        """
        # Handle aliases
        if scan_type == "baseline":
            scan_type = "full_and_fast"
        elif scan_type == "full":
            scan_type = "full_and_deep"

        # Get config ID from mapping
        config_id = self.SCAN_CONFIGS.get(scan_type)

        if not config_id:
            # Default to full_and_fast if unknown
            self.logger.warning(
                f"Unknown scan type '{scan_type}', using 'full_and_fast'"
            )
            config_id = self.SCAN_CONFIGS["full_and_fast"]

        return config_id

    def _poll_task_status(self, gmp: Gmp, task_id: str, interval: int = 30) -> bool:
        """Poll task status until completion or timeout.

        Args:
            gmp: Authenticated GMP instance.
            task_id: Task UUID to monitor.
            interval: Polling interval in seconds.

        Returns:
            True if task completed successfully, False if timed out.
        """
        start_time = time.time()

        while True:
            elapsed = time.time() - start_time
            if elapsed > self.scan_timeout:
                self.logger.warning(f"Task {task_id} timed out after {elapsed}s")
                return False

            # Get task status
            task_response = gmp.get_task(task_id)
            status = self._extract_task_status(task_response)

            self.logger.debug(f"Task {task_id} status: {status}")

            # Check for completion
            if status in ("Done", "Stopped"):
                self.logger.info(f"Task {task_id} completed with status: {status}")
                return True

            # Check for error states
            if status in ("Interrupted", "Stopped by user"):
                self.logger.error(f"Task {task_id} failed with status: {status}")
                return False

            # Continue polling
            self.logger.debug(
                f"Task {task_id} still running ({status}), " f"elapsed: {int(elapsed)}s"
            )
            time.sleep(interval)

    def _extract_id_from_response(self, response) -> str:
        """Extract resource ID from GMP response.

        Args:
            response: GMP response (XML element or string).

        Returns:
            Resource ID string.

        Raises:
            ValueError: If ID cannot be extracted.
        """
        try:
            # Response is an XML Element
            if hasattr(response, "attrib"):
                resource_id = response.attrib.get("id")
                if resource_id:
                    return resource_id

            # Try to parse as string
            if isinstance(response, str):
                root = ET.fromstring(response)
                resource_id = root.attrib.get("id")
                if resource_id:
                    return resource_id

            # Try to find first element with id attribute
            if hasattr(response, "find"):
                for elem in response.iter():
                    resource_id = elem.attrib.get("id")
                    if resource_id:
                        return resource_id

            raise ValueError("No 'id' attribute found in response")

        except Exception as e:
            self.logger.error(f"Failed to extract ID from response: {e}")
            raise ValueError(f"Failed to extract ID from response: {e}")

    def _extract_task_status(self, task_response) -> str:
        """Extract task status from task response.

        Args:
            task_response: GMP task response XML.

        Returns:
            Task status string (e.g., "Running", "Done", "Stopped").
        """
        try:
            # Find status element in the task
            status_elem = task_response.find(".//status")
            if status_elem is not None and status_elem.text:
                return status_elem.text.strip()

            return "Unknown"

        except Exception as e:
            self.logger.warning(f"Failed to extract task status: {e}")
            return "Unknown"

    def _extract_report_id(self, task_response) -> str:
        """Extract report ID from task response.

        Args:
            task_response: GMP task response XML.

        Returns:
            Report ID string.

        Raises:
            ValueError: If report ID cannot be extracted.
        """
        try:
            # Find the last report element (most recent report)
            report_elem = task_response.find(".//last_report/report")
            if report_elem is not None:
                report_id = report_elem.attrib.get("id")
                if report_id:
                    return report_id

            # Alternative: find any report element
            report_elem = task_response.find(".//report")
            if report_elem is not None:
                report_id = report_elem.attrib.get("id")
                if report_id:
                    return report_id

            raise ValueError("No report ID found in task response")

        except Exception as e:
            self.logger.error(f"Failed to extract report ID: {e}")
            raise ValueError(f"Failed to extract report ID: {e}")

    def _cleanup_resources(
        self, gmp: Gmp, task_id: str | None, target_id: str | None
    ) -> None:
        """Clean up OpenVAS resources (task and target).

        Args:
            gmp: Authenticated GMP instance.
            task_id: Task UUID to delete (optional).
            target_id: Target UUID to delete (optional).
        """
        try:
            # Delete task if provided
            if task_id:
                self.logger.debug(f"Deleting task {task_id}")
                gmp.delete_task(task_id, ultimate=True)
                self.logger.info(f"Deleted task {task_id}")

            # Delete target if provided
            if target_id:
                self.logger.debug(f"Deleting target {target_id}")
                gmp.delete_target(target_id, ultimate=True)
                self.logger.info(f"Deleted target {target_id}")

        except Exception as e:
            self.logger.warning(f"Error during cleanup: {e}")

    def parse_results(self, raw_output: str) -> list[NormalizedFinding]:
        """Parse raw OpenVAS XML report into normalized findings.

        Args:
            raw_output: Raw XML string containing OpenVAS report.

        Returns:
            List of normalized security findings.
        """
        try:
            findings = parse_openvas_report(raw_output)
            self.logger.info(f"Parsed {len(findings)} findings from OpenVAS report")
            return findings

        except Exception as e:
            self.logger.error(f"Failed to parse OpenVAS report: {e}")
            return []

    def get_status(self) -> ScannerStatus:
        """Check if OpenVAS is available and return its status.

        Returns:
            ScannerStatus indicating availability and version information.
        """
        try:
            # Connect and get version
            gmp, connection = self._connect()

            try:
                # Get GMP version
                version_response = gmp.get_version()
                version = (
                    version_response.text
                    if hasattr(version_response, "text")
                    else "unknown"
                )

                return ScannerStatus(
                    name="OpenVAS",
                    available=True,
                    version=version,
                    message="OpenVAS is available and responding",
                    last_checked=datetime.utcnow(),
                )

            finally:
                connection.disconnect()

        except GvmError as e:
            return ScannerStatus(
                name="OpenVAS",
                available=False,
                version="",
                message=f"GMP error: {e}",
                last_checked=datetime.utcnow(),
            )

        except Exception as e:
            return ScannerStatus(
                name="OpenVAS",
                available=False,
                version="",
                message=f"Failed to connect to OpenVAS at {self.host}:{self.port}: {e}",
                last_checked=datetime.utcnow(),
            )

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate OpenVAS scanner configuration.

        Args:
            config: Configuration dictionary to validate.

        Returns:
            Tuple of (is_valid, error_message). If valid, error_message is empty.
        """
        # Validate scan_type
        scan_type = config.get("scan_type")
        if not scan_type:
            return False, "scan_type is required"

        valid_scan_types = [
            "discovery",
            "full_and_fast",
            "full_and_deep",
            "baseline",
            "full",
        ]
        if scan_type not in valid_scan_types:
            return False, f"scan_type must be one of {valid_scan_types}"

        # Validate port_range format if provided
        port_range = config.get("port_range")
        if port_range:
            # Basic validation: should be like "1-65535" or "22,80,443"
            import re

            if not re.match(r"^[\d,\-\s]+$", str(port_range)):
                return (
                    False,
                    "port_range must contain only numbers, commas, and hyphens",
                )

        return True, ""
