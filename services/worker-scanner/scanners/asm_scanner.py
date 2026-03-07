"""ASM (Attack Surface Management) orchestrator scanner.

Orchestrates MasscanScanner, BannerGrabber, ScreenshotScanner, and CertInspector
to build a complete attack surface picture for a target.

Celery task: execute_asm_scan(scan_id) added to workers/scan_worker.py separately.
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Optional

from database.models import get_configured_db
from scanners.banner_grabber import grab_banners_batch
from scanners.base import BaseScanner, NormalizedFinding, ScannerStatus, ScanResult
from scanners.cert_inspector import inspect_cert
from scanners.masscan import MasscanScanner
from scanners.screenshot import ScreenshotScanner
from utils.logger import get_logger

logger = get_logger(__name__)

# TLS ports to inspect certificates
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
# HTTP ports for gowitness
HTTP_PORTS = {80, 8080, 8081, 8088, 3000, 3001, 4000, 5000, 8888, 9090}
# HTTPS ports for gowitness
HTTPS_PORTS = {443, 8443, 9443}
# RDP ports for xfreerdp
RDP_PORTS = {3389}
# VNC ports for vncsnapshot
VNC_PORTS = {5900, 5901}


class ASMScanner(BaseScanner):
    """Attack Surface Management scanner orchestrator.

    Runs masscan -> banner grabbing -> screenshots -> cert inspection
    and persists all results to the ASM database tables.
    """

    SCANNER_TYPE = "asm"

    def scan(
        self, target: str, scan_type: str = "asm", config: dict | None = None
    ) -> ScanResult:
        """Run the full ASM scan pipeline synchronously (wraps async).

        Args:
            target: IP, CIDR, or hostname to scan.
            scan_type: 'internal', 'external', or 'both'.
            config: Optional config overrides.

        Returns:
            ScanResult with aggregated findings.
        """
        if config is None:
            config = {}
        return asyncio.run(self._run_asm_scan(target, scan_type, config))

    async def _run_asm_scan(
        self, target: str, scan_type: str, config: dict
    ) -> ScanResult:
        """Run the full ASM pipeline asynchronously."""
        start = datetime.utcnow()
        all_findings: list[NormalizedFinding] = []

        # Step 1: Port discovery via masscan
        logger.info(f"ASM scan starting: target={target}, mode={scan_type}")
        masscan = MasscanScanner(config=self.config)
        masscan_result = masscan.scan(target=target, scan_type="asm", config=config)

        if not masscan_result.success:
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message=f"Port discovery failed: {masscan_result.error_message}",
            )

        all_findings.extend(masscan_result.findings)
        open_ports = (
            json.loads(masscan_result.raw_output) if masscan_result.raw_output else []
        )
        logger.info(f"Discovered {len(open_ports)} open ports")

        if not open_ports:
            duration = (datetime.utcnow() - start).total_seconds()
            return ScanResult(
                success=True,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                findings=all_findings,
                duration_seconds=int(duration),
                summary={"open_ports": 0, "target": target},
            )

        # Step 2: Banner grabbing (async batch)
        banner_timeout = self.config.get("banner_timeout", 5.0)
        max_bytes = self.config.get("banner_max_bytes", 2048)
        banners = await grab_banners_batch(
            open_ports,
            timeout=banner_timeout,
            max_bytes=max_bytes,
        )
        logger.info(f"Banner grabbing complete for {len(banners)} ports")

        # Step 3: Screenshots
        screenshot_results: list[dict[str, Any]] = []
        screenshotter = ScreenshotScanner(config=self.config)

        screenshot_tasks = []
        scan_id = config.get("scan_id", 0)

        for entry in open_ports:
            ip = entry["ip"]
            port = entry["port"]

            if port in HTTP_PORTS:
                screenshot_tasks.append(
                    screenshotter.screenshot_http(scan_id, ip, port, use_https=False)
                )
            if port in HTTPS_PORTS:
                screenshot_tasks.append(
                    screenshotter.screenshot_http(scan_id, ip, port, use_https=True)
                )
            if port in RDP_PORTS:
                screenshot_tasks.append(screenshotter.screenshot_rdp(scan_id, ip, port))
            if port in VNC_PORTS:
                screenshot_tasks.append(screenshotter.screenshot_vnc(scan_id, ip, port))

        if screenshot_tasks:
            results = await asyncio.gather(*screenshot_tasks, return_exceptions=True)
            for r in results:
                if r and not isinstance(r, Exception):
                    screenshot_results.append(r)

        logger.info(f"Screenshot capture complete: {len(screenshot_results)} captures")

        # Step 4: TLS cert inspection
        cert_results: list[dict[str, Any]] = []
        tls_services = [e for e in open_ports if e["port"] in TLS_PORTS]

        for entry in tls_services:
            cert_data = inspect_cert(
                entry["ip"],
                entry["port"],
                timeout=self.config.get("cert_timeout", 5.0),
            )
            if cert_data and "error" not in cert_data:
                cert_data["ip"] = entry["ip"]
                cert_data["port"] = entry["port"]
                cert_results.append(cert_data)

                # Add cert findings for expired/expiring certs
                if cert_data.get("is_expired"):
                    all_findings.append(
                        NormalizedFinding(
                            finding_id=f"asm-cert-expired-{entry['ip']}-{entry['port']}",
                            severity="high",
                            title=f"Expired TLS certificate on {entry['ip']}:{entry['port']}",
                            description=(
                                f"The TLS certificate expired {abs(cert_data.get('days_until_expiry', 0))} days ago. "
                                f"Subject: {cert_data.get('subject', 'unknown')}"
                            ),
                            affected_url=f"https://{entry['ip']}:{entry['port']}",
                            raw_finding=cert_data,
                        )
                    )
                elif cert_data.get("days_until_expiry", 999) < 30:
                    all_findings.append(
                        NormalizedFinding(
                            finding_id=f"asm-cert-expiring-{entry['ip']}-{entry['port']}",
                            severity="medium",
                            title=f"TLS certificate expiring soon on {entry['ip']}:{entry['port']}",
                            description=(
                                f"The TLS certificate expires in {cert_data.get('days_until_expiry')} days. "
                                f"Subject: {cert_data.get('subject', 'unknown')}"
                            ),
                            affected_url=f"https://{entry['ip']}:{entry['port']}",
                            raw_finding=cert_data,
                        )
                    )

        logger.info(f"Cert inspection complete: {len(cert_results)} certs")

        duration = (datetime.utcnow() - start).total_seconds()

        return ScanResult(
            success=True,
            scanner_type=self.SCANNER_TYPE,
            scan_type=scan_type,
            findings=all_findings,
            duration_seconds=int(duration),
            summary={
                "target": target,
                "open_ports": len(open_ports),
                "banners_grabbed": len(banners),
                "screenshots": len(screenshot_results),
                "certs_inspected": len(cert_results),
                "open_ports_data": open_ports,
                "banners_data": banners,
                "screenshot_data": screenshot_results,
                "cert_data": cert_results,
            },
        )

    def parse_results(self, raw_output: str) -> list[NormalizedFinding]:
        """Not used directly - scan() returns findings directly."""
        return []

    def get_status(self) -> ScannerStatus:
        """Return status indicating ASM scanner components availability."""
        masscan = MasscanScanner(config={})
        masscan_status = masscan.get_status()
        return ScannerStatus(
            name="asm",
            available=masscan_status.available,
            version="1.0.0",
            message=f"masscan: {masscan_status.message}",
            last_checked=datetime.utcnow(),
        )

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate ASM config."""
        mode = config.get("mode", "external")
        if mode not in ("internal", "external", "both"):
            return (
                False,
                f"mode must be 'internal', 'external', or 'both', got '{mode}'",
            )
        masscan = MasscanScanner(config={})
        return masscan.validate_config(config)
