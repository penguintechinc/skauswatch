"""
ClamAV scanner client for malware detection.

This module provides synchronous ClamAV scanning capabilities.
Designed to be called via executor for async/threading integration.
"""

from dataclasses import dataclass
import logging
from typing import Optional

try:
    import clamd
except ImportError:
    clamd = None


logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a ClamAV scan."""

    is_malware: bool
    is_pup: bool
    threat_names: list[str]


class ClamAVScanner:
    """
    Synchronous ClamAV scanner client.

    Connects to ClamAV daemon via Unix socket and performs file scans.
    """

    def __init__(
        self, socket_path: str = "/var/run/clamav/clamd.ctl", timeout: int = 60
    ) -> None:
        """
        Initialize ClamAV scanner.

        Args:
            socket_path: Path to ClamAV daemon socket
            timeout: Socket timeout in seconds

        Raises:
            ImportError: If clamd library is not installed
        """
        if clamd is None:
            raise ImportError(
                "clamd library is required for ClamAV scanning. "
                "Install it with: pip install pyclamd"
            )

        self.socket_path = socket_path
        self.timeout = timeout
        self._client: Optional[clamd.ClamdUnixSocket] = None

    def _get_client(self) -> clamd.ClamdUnixSocket:
        """
        Get or create ClamAV client instance.

        Returns:
            ClamdUnixSocket instance

        Raises:
            ConnectionError: If unable to connect to ClamAV daemon
        """
        if self._client is None:
            try:
                self._client = clamd.ClamdUnixSocket(self.socket_path)
                self._client.socket.settimeout(self.timeout)
            except (clamd.ClamdNetworkException, OSError) as e:
                logger.error(
                    f"Failed to connect to ClamAV daemon at {self.socket_path}: {e}"
                )
                raise ConnectionError(f"Cannot connect to ClamAV daemon: {e}") from e

        return self._client

    def ping(self) -> bool:
        """
        Check if ClamAV daemon is responsive.

        Returns:
            True if daemon is responsive, False otherwise
        """
        try:
            client = self._get_client()
            result = client.ping()
            logger.debug(f"ClamAV ping result: {result}")
            return result == "PONG"
        except (ConnectionError, clamd.ClamdNetworkException, OSError) as e:
            logger.warning(f"ClamAV ping failed: {e}")
            self._client = None
            return False

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file for malware using ClamAV.

        Args:
            file_path: Path to file to scan

        Returns:
            ScanResult with detection status and threat names

        Raises:
            FileNotFoundError: If file does not exist
            ConnectionError: If unable to connect to ClamAV daemon
        """
        import os

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            client = self._get_client()
            result = client.scan_file(file_path)

            if result is None:
                # File is clean
                return ScanResult(is_malware=False, is_pup=False, threat_names=[])

            # result is a dict like:
            # {'/path/to/file': ('FOUND', 'Virus.Name')}
            threat_names = []
            is_pup = False

            for file_scanned, (status, threat_name) in result.items():
                if status == "FOUND":
                    threat_names.append(threat_name)
                    # Check if it's a PUP (Potentially Unwanted Program)
                    if "PUP" in threat_name or "PUA" in threat_name:
                        is_pup = True

            is_malware = len(threat_names) > 0

            logger.info(
                f"ClamAV scan of {file_path}: "
                f"malware={is_malware}, pup={is_pup}, "
                f"threats={threat_names}"
            )

            return ScanResult(
                is_malware=is_malware, is_pup=is_pup, threat_names=threat_names
            )

        except (clamd.ClamdNetworkException, OSError) as e:
            logger.error(f"ClamAV scan failed for {file_path}: {e}")
            self._client = None
            raise ConnectionError(f"ClamAV scan failed: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error scanning {file_path} with ClamAV: {e}")
            raise
