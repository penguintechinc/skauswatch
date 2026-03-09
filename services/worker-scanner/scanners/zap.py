"""OWASP ZAP REST API client scanner implementation.

This module provides integration with OWASP ZAP (Zed Attack Proxy) for web
application security scanning. It supports baseline, full, and API scanning
modes through ZAP's REST API.
"""

import json
import os
import time
from datetime import datetime

import httpx
from scanners.base import BaseScanner, NormalizedFinding, ScannerStatus, ScanResult
from scanners.parsers.zap_parser import parse_zap_alert


class ZapScanner(BaseScanner):
    """OWASP ZAP scanner implementation using REST API.

    This scanner integrates with a ZAP instance running in daemon mode to
    perform web application security scans. It supports three scan types:
    - baseline: Spider + passive scan
    - full: Spider + passive + active scan
    - api: OpenAPI import + spider + active scan

    The scanner communicates with ZAP via its REST API and polls for scan
    completion before retrieving results.
    """

    SCANNER_TYPE = "zap"

    def __init__(self, config: dict) -> None:
        """Initialize the ZAP scanner with configuration.

        Args:
            config: Scanner configuration dictionary. May contain:
                - base_url: ZAP API base URL
                - api_key: ZAP API key for authentication
                - timeout: Request timeout in seconds
        """
        super().__init__(config)

        # Get ZAP configuration from config or environment
        self.base_url = config.get(
            "base_url", os.getenv("SCANNER_ZAP_URL", "http://zap:8080")
        )
        self.api_key = config.get("api_key", os.getenv("SCANNER_ZAP_API_KEY", ""))

        # Create HTTP client with timeout
        timeout = config.get("timeout", 30)
        headers = {}
        if self.api_key:
            headers["X-ZAP-API-Key"] = self.api_key

        self.client = httpx.Client(
            base_url=self.base_url, timeout=timeout, headers=headers
        )

        self.logger.info(f"Initialized ZAP scanner with base_url={self.base_url}")

    def scan(
        self, target: str, scan_type: str, config: dict | None = None
    ) -> ScanResult:
        """Execute a security scan against the target.

        Args:
            target: Target URL to scan (e.g., https://example.com).
            scan_type: Type of scan to perform (baseline, full, or api).
            config: Optional scan-specific configuration.

        Returns:
            ScanResult containing the findings and scan metadata.
        """
        start_time = time.time()
        scan_config = config or {}

        self.logger.info(f"Starting ZAP {scan_type} scan of target: {target}")

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

            # Execute scan based on type
            if scan_type == "baseline":
                alerts = self._run_baseline_scan(target, scan_config)
            elif scan_type == "full":
                alerts = self._run_full_scan(target, scan_config)
            elif scan_type == "api":
                alerts = self._run_api_scan(target, scan_config)
            else:
                return ScanResult(
                    success=False,
                    scanner_type=self.scanner_type,
                    scan_type=scan_type,
                    error_message=f"Unknown scan type: {scan_type}",
                    duration_seconds=int(time.time() - start_time),
                )

            # Parse results
            raw_output = json.dumps({"alerts": alerts}, indent=2)
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
            }

            duration = int(time.time() - start_time)
            self.logger.info(
                f"ZAP {scan_type} scan completed in {duration}s with "
                f"{len(findings)} findings"
            )

            return ScanResult(
                success=True,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                findings=findings,
                duration_seconds=duration,
                raw_output=raw_output,
                summary=summary,
            )

        except httpx.ConnectError as e:
            error_msg = f"Failed to connect to ZAP at {self.base_url}: {e}"
            self.logger.error(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=int(time.time() - start_time),
            )

        except httpx.TimeoutException as e:
            error_msg = f"ZAP request timed out: {e}"
            self.logger.error(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=int(time.time() - start_time),
            )

        except httpx.HTTPError as e:
            error_msg = f"HTTP error during ZAP scan: {e}"
            self.logger.error(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=int(time.time() - start_time),
            )

        except Exception as e:
            error_msg = f"Unexpected error during ZAP scan: {e}"
            self.logger.exception(error_msg)
            return ScanResult(
                success=False,
                scanner_type=self.scanner_type,
                scan_type=scan_type,
                error_message=error_msg,
                duration_seconds=int(time.time() - start_time),
            )

    def _run_baseline_scan(self, target: str, config: dict) -> list[dict]:
        """Run a baseline scan (spider + passive scan).

        Args:
            target: Target URL to scan.
            config: Scan configuration.

        Returns:
            List of ZAP alert dictionaries.
        """
        self.logger.info(f"Running baseline scan on {target}")

        # Step 1: Access the URL
        self.logger.debug("Accessing target URL")
        self.client.post("/JSON/core/action/accessUrl/", params={"url": target})

        # Step 2: Start spider scan
        self.logger.debug("Starting spider scan")
        max_children = config.get("max_children", 10)
        spider_response = self.client.post(
            "/JSON/spider/action/scan/",
            params={"url": target, "maxChildren": max_children},
        )
        spider_data = spider_response.json()
        spider_id = spider_data.get("scan")

        # Step 3: Poll spider status
        self.logger.debug(f"Polling spider status (ID: {spider_id})")
        if not self._poll_spider(spider_id):
            self.logger.warning("Spider scan timed out")

        # Step 4: Wait for passive scan to complete
        self.logger.debug("Waiting for passive scan completion")
        self._wait_for_passive_scan()

        # Step 5: Retrieve alerts
        self.logger.debug("Retrieving alerts")
        alerts_response = self.client.get(
            "/JSON/core/view/alerts/", params={"baseurl": target}
        )
        alerts_data = alerts_response.json()
        alerts = alerts_data.get("alerts", [])

        self.logger.info(f"Baseline scan completed with {len(alerts)} alerts")
        return alerts

    def _run_full_scan(self, target: str, config: dict) -> list[dict]:
        """Run a full scan (spider + passive + active scan).

        Args:
            target: Target URL to scan.
            config: Scan configuration.

        Returns:
            List of ZAP alert dictionaries.
        """
        self.logger.info(f"Running full scan on {target}")

        # Step 1: Access the URL
        self.logger.debug("Accessing target URL")
        self.client.post("/JSON/core/action/accessUrl/", params={"url": target})

        # Step 2: Start spider scan
        self.logger.debug("Starting spider scan")
        max_children = config.get("max_children", 10)
        spider_response = self.client.post(
            "/JSON/spider/action/scan/",
            params={"url": target, "maxChildren": max_children},
        )
        spider_data = spider_response.json()
        spider_id = spider_data.get("scan")

        # Step 3: Poll spider status
        self.logger.debug(f"Polling spider status (ID: {spider_id})")
        if not self._poll_spider(spider_id):
            self.logger.warning("Spider scan timed out")

        # Step 4: Wait for passive scan to complete
        self.logger.debug("Waiting for passive scan completion")
        self._wait_for_passive_scan()

        # Step 5: Start active scan
        self.logger.debug("Starting active scan")
        ascan_response = self.client.post(
            "/JSON/ascan/action/scan/", params={"url": target}
        )
        ascan_data = ascan_response.json()
        scan_id = ascan_data.get("scan")

        # Step 6: Poll active scan status
        self.logger.debug(f"Polling active scan status (ID: {scan_id})")
        if not self._poll_active_scan(scan_id):
            self.logger.warning("Active scan timed out")

        # Step 7: Retrieve alerts
        self.logger.debug("Retrieving alerts")
        alerts_response = self.client.get(
            "/JSON/core/view/alerts/", params={"baseurl": target}
        )
        alerts_data = alerts_response.json()
        alerts = alerts_data.get("alerts", [])

        self.logger.info(f"Full scan completed with {len(alerts)} alerts")
        return alerts

    def _run_api_scan(self, target: str, config: dict) -> list[dict]:
        """Run an API scan (OpenAPI import + spider + active scan).

        Args:
            target: Target URL to scan.
            config: Scan configuration (must contain openapi_url).

        Returns:
            List of ZAP alert dictionaries.
        """
        self.logger.info(f"Running API scan on {target}")

        # Step 1: Import OpenAPI spec
        openapi_url = config.get("openapi_url")
        if openapi_url:
            self.logger.debug(f"Importing OpenAPI spec from {openapi_url}")
            self.client.post(
                "/JSON/openapi/action/importUrl/", params={"url": openapi_url}
            )

        # Step 2: Start spider scan
        self.logger.debug("Starting spider scan")
        max_children = config.get("max_children", 10)
        spider_response = self.client.post(
            "/JSON/spider/action/scan/",
            params={"url": target, "maxChildren": max_children},
        )
        spider_data = spider_response.json()
        spider_id = spider_data.get("scan")

        # Step 3: Poll spider status
        self.logger.debug(f"Polling spider status (ID: {spider_id})")
        if not self._poll_spider(spider_id):
            self.logger.warning("Spider scan timed out")

        # Step 4: Start active scan
        self.logger.debug("Starting active scan")
        ascan_response = self.client.post(
            "/JSON/ascan/action/scan/", params={"url": target}
        )
        ascan_data = ascan_response.json()
        scan_id = ascan_data.get("scan")

        # Step 5: Poll active scan status
        self.logger.debug(f"Polling active scan status (ID: {scan_id})")
        if not self._poll_active_scan(scan_id):
            self.logger.warning("Active scan timed out")

        # Step 6: Retrieve alerts
        self.logger.debug("Retrieving alerts")
        alerts_response = self.client.get(
            "/JSON/core/view/alerts/", params={"baseurl": target}
        )
        alerts_data = alerts_response.json()
        alerts = alerts_data.get("alerts", [])

        self.logger.info(f"API scan completed with {len(alerts)} alerts")
        return alerts

    def _poll_spider(
        self, spider_id: str, interval: int = 5, timeout: int = 3600
    ) -> bool:
        """Poll spider scan status until completion.

        Args:
            spider_id: Spider scan ID.
            interval: Polling interval in seconds.
            timeout: Maximum time to wait in seconds.

        Returns:
            True if spider completed, False if timed out.
        """
        start_time = time.time()
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                self.logger.warning(f"Spider {spider_id} timed out after {elapsed}s")
                return False

            response = self.client.get(
                "/JSON/spider/view/status/", params={"scanId": spider_id}
            )
            data = response.json()
            status = data.get("status", "0")

            if status == "100":
                self.logger.debug(f"Spider {spider_id} completed")
                return True

            self.logger.debug(f"Spider {spider_id} progress: {status}%")
            time.sleep(interval)

    def _poll_active_scan(
        self, scan_id: str, interval: int = 5, timeout: int = 3600
    ) -> bool:
        """Poll active scan status until completion.

        Args:
            scan_id: Active scan ID.
            interval: Polling interval in seconds.
            timeout: Maximum time to wait in seconds.

        Returns:
            True if scan completed, False if timed out.
        """
        start_time = time.time()
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                self.logger.warning(f"Active scan {scan_id} timed out after {elapsed}s")
                return False

            response = self.client.get(
                "/JSON/ascan/view/status/", params={"scanId": scan_id}
            )
            data = response.json()
            status = data.get("status", "0")

            if status == "100":
                self.logger.debug(f"Active scan {scan_id} completed")
                return True

            self.logger.debug(f"Active scan {scan_id} progress: {status}%")
            time.sleep(interval)

    def _wait_for_passive_scan(self, interval: int = 2, timeout: int = 300) -> bool:
        """Wait for passive scan to complete processing.

        Args:
            interval: Polling interval in seconds.
            timeout: Maximum time to wait in seconds.

        Returns:
            True if passive scan completed, False if timed out.
        """
        start_time = time.time()
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                self.logger.warning(f"Passive scan timed out after {elapsed}s")
                return False

            response = self.client.get("/JSON/pscan/view/recordsToScan/")
            data = response.json()
            records = data.get("recordsToScan", "1")

            if records == "0":
                self.logger.debug("Passive scan completed")
                return True

            self.logger.debug(f"Passive scan records remaining: {records}")
            time.sleep(interval)

    def parse_results(self, raw_output: str) -> list[NormalizedFinding]:
        """Parse raw ZAP alerts JSON into normalized findings.

        Args:
            raw_output: Raw JSON string containing ZAP alerts.

        Returns:
            List of normalized security findings.
        """
        try:
            data = json.loads(raw_output)
            alerts = data.get("alerts", [])

            findings = []
            for alert in alerts:
                try:
                    finding = parse_zap_alert(alert)
                    findings.append(finding)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to parse ZAP alert: {e}", extra={"alert": alert}
                    )
                    continue

            return findings

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse ZAP output as JSON: {e}")
            return []

    def get_status(self) -> ScannerStatus:
        """Check if ZAP is available and return its status.

        Returns:
            ScannerStatus indicating availability and version information.
        """
        try:
            response = self.client.get("/JSON/core/view/version/")
            data = response.json()
            version = data.get("version", "unknown")

            return ScannerStatus(
                name="OWASP ZAP",
                available=True,
                version=version,
                message="ZAP is available and responding",
                last_checked=datetime.utcnow(),
            )

        except httpx.ConnectError:
            return ScannerStatus(
                name="OWASP ZAP",
                available=False,
                version="",
                message=f"Failed to connect to ZAP at {self.base_url}",
                last_checked=datetime.utcnow(),
            )

        except Exception as e:
            return ScannerStatus(
                name="OWASP ZAP",
                available=False,
                version="",
                message=f"Error checking ZAP status: {e}",
                last_checked=datetime.utcnow(),
            )

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate ZAP scanner configuration.

        Args:
            config: Configuration dictionary to validate.

        Returns:
            Tuple of (is_valid, error_message). If valid, error_message is empty.
        """
        # Validate scan_type
        scan_type = config.get("scan_type")
        if not scan_type:
            return False, "scan_type is required"

        valid_scan_types = ["baseline", "full", "api"]
        if scan_type not in valid_scan_types:
            return False, f"scan_type must be one of {valid_scan_types}"

        # Validate API scan config
        if scan_type == "api":
            openapi_url = config.get("openapi_url")
            if not openapi_url:
                return False, "openapi_url is required for API scans"

        return True, ""
