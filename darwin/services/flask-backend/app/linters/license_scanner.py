"""CycloneDX License Scanner for detecting package licenses."""

import json
import asyncio
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from .base import BaseLinter, LintResult, LintIssue


@dataclass(slots=True)
class LicenseDetection:
    """License detection result."""
    package_name: str
    package_version: str
    license_name: str
    license_source: str  # "manifest", "file", "inferred"
    file_path: str
    confidence: float  # 0.0 to 1.0


@dataclass(slots=True)
class LicenseScanResult:
    """License scan result with detections."""
    success: bool
    detections: list[LicenseDetection] = field(default_factory=list)
    error: Optional[str] = None
    execution_time_ms: int = 0


class CycloneDXScanner(BaseLinter):
    """
    CycloneDX License Scanner.

    Uses CycloneDX CLI and ScanCode to detect licenses in dependencies.
    """
    name = "cyclonedx"
    languages = ["python", "javascript", "typescript", "go", "java", "ruby", "php"]

    async def is_available(self) -> bool:
        """Check if CycloneDX is installed."""
        try:
            returncode, _, _ = await self._run_command(
                ["cyclonedx", "--version"],
                cwd=Path("/tmp"),
                timeout=5
            )
            return returncode == 0
        except Exception:
            return False

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """
        Run license scan on path.

        This method is required by BaseLinter but license scanning
        returns LicenseScanResult, not LintResult.
        """
        result = await self.scan_licenses(path)

        # Convert to LintResult for compatibility
        issues = []
        for detection in result.detections:
            # Check if license is in violation (will be checked against policies)
            issues.append(LintIssue(
                file=detection.file_path,
                line=0,
                column=0,
                severity="info",
                rule_id=f"license-{detection.license_name}",
                message=f"License detected: {detection.license_name} in {detection.package_name}",
                suggestion=None,
            ))

        return LintResult(
            linter=self.name,
            success=result.success,
            issues=issues,
            error=result.error,
            execution_time_ms=result.execution_time_ms,
        )

    async def scan_licenses(self, path: Path) -> LicenseScanResult:
        """
        Scan directory for package licenses.

        Args:
            path: Path to scan

        Returns:
            LicenseScanResult with all detected licenses
        """
        import time
        start = time.time()

        detections = []

        # Scan Python packages (requirements.txt, setup.py, pyproject.toml)
        python_detections = await self._scan_python(path)
        detections.extend(python_detections)

        # Scan JavaScript packages (package.json, package-lock.json)
        js_detections = await self._scan_javascript(path)
        detections.extend(js_detections)

        # Scan Go packages (go.mod, go.sum)
        go_detections = await self._scan_go(path)
        detections.extend(go_detections)

        # Scan generic license files with ScanCode
        scancode_detections = await self._scan_with_scancode(path)
        detections.extend(scancode_detections)

        execution_time = int((time.time() - start) * 1000)

        return LicenseScanResult(
            success=True,
            detections=detections,
            execution_time_ms=execution_time,
        )

    async def _scan_python(self, path: Path) -> list[LicenseDetection]:
        """Scan Python dependencies for licenses."""
        detections = []

        # Check for requirements.txt
        requirements_file = path / "requirements.txt"
        if requirements_file.exists():
            # Use pip-licenses if available
            returncode, stdout, stderr = await self._run_command(
                ["pip-licenses", "--format=json", "--with-system"],
                cwd=path,
                timeout=30
            )

            if returncode == 0 and stdout:
                try:
                    licenses = json.loads(stdout)
                    for pkg in licenses:
                        detections.append(LicenseDetection(
                            package_name=pkg.get("Name", "unknown"),
                            package_version=pkg.get("Version", "unknown"),
                            license_name=pkg.get("License", "UNKNOWN"),
                            license_source="manifest",
                            file_path=str(requirements_file),
                            confidence=0.9,
                        ))
                except json.JSONDecodeError:
                    pass

        return detections

    async def _scan_javascript(self, path: Path) -> list[LicenseDetection]:
        """Scan JavaScript/Node.js dependencies for licenses."""
        detections = []

        package_json = path / "package.json"
        if package_json.exists():
            # Use license-checker if available
            returncode, stdout, stderr = await self._run_command(
                ["npx", "license-checker", "--json"],
                cwd=path,
                timeout=60
            )

            if returncode == 0 and stdout:
                try:
                    licenses = json.loads(stdout)
                    for pkg_name, pkg_info in licenses.items():
                        # Parse package@version
                        parts = pkg_name.rsplit("@", 1)
                        name = parts[0]
                        version = parts[1] if len(parts) > 1 else "unknown"

                        detections.append(LicenseDetection(
                            package_name=name,
                            package_version=version,
                            license_name=pkg_info.get("licenses", "UNKNOWN"),
                            license_source="manifest",
                            file_path=str(package_json),
                            confidence=0.9,
                        ))
                except json.JSONDecodeError:
                    pass

        return detections

    async def _scan_go(self, path: Path) -> list[LicenseDetection]:
        """Scan Go module dependencies for licenses."""
        detections = []

        go_mod = path / "go.mod"
        if go_mod.exists():
            # Use go-licenses if available
            returncode, stdout, stderr = await self._run_command(
                ["go", "list", "-m", "-json", "all"],
                cwd=path,
                timeout=60
            )

            if returncode == 0 and stdout:
                # Parse go list output (NDJSON)
                for line in stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        mod = json.loads(line)
                        if "Path" in mod:
                            detections.append(LicenseDetection(
                                package_name=mod["Path"],
                                package_version=mod.get("Version", "unknown"),
                                license_name="UNKNOWN",  # Go doesn't embed license info
                                license_source="inferred",
                                file_path=str(go_mod),
                                confidence=0.5,
                            ))
                    except json.JSONDecodeError:
                        continue

        return detections

    async def _scan_with_scancode(self, path: Path) -> list[LicenseDetection]:
        """Scan for license files using ScanCode toolkit."""
        detections = []

        # Run scancode on LICENSE* files
        returncode, stdout, stderr = await self._run_command(
            [
                "scancode",
                "--license",
                "--json-pp", "-",
                "--max-depth", "2",
                str(path)
            ],
            cwd=path,
            timeout=120
        )

        if returncode == 0 and stdout:
            try:
                result = json.loads(stdout)
                for file_result in result.get("files", []):
                    licenses = file_result.get("licenses", [])
                    if licenses:
                        file_path = file_result.get("path", "unknown")
                        for lic in licenses:
                            detections.append(LicenseDetection(
                                package_name="<root>",
                                package_version="1.0.0",
                                license_name=lic.get("key", "UNKNOWN"),
                                license_source="file",
                                file_path=file_path,
                                confidence=lic.get("score", 0.0) / 100.0,
                            ))
            except json.JSONDecodeError:
                pass

        return detections
