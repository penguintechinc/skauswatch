"""Screenshot capture for ASM - HTTP/HTTPS via gowitness, RDP/VNC via xfreerdp/vncsnapshot.

All captures are uploaded to MinIO/S3 bucket skauswatch-asm-artifacts.
"""

import asyncio
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class ScreenshotScanner:
    """Captures screenshots of web, RDP, and VNC services.

    Uses:
        - gowitness for HTTP/HTTPS screenshots
        - xfreerdp3 + xvfb-run for RDP login screen capture
        - vncsnapshot for VNC unauthenticated screenshot attempt

    Screenshots are uploaded to S3 and metadata returned.
    """

    def __init__(self, config: dict) -> None:
        """Initialize with S3 and timeout config.

        Args:
            config: Dict with optional keys:
                - s3_endpoint_url: MinIO/S3 endpoint
                - s3_access_key: Access key
                - s3_secret_key: Secret key
                - s3_bucket: Bucket name (default: skauswatch-asm-artifacts)
                - s3_region: AWS region (default: us-east-1)
                - screenshot_timeout: Seconds per capture (default: 10)
        """
        self.s3_endpoint = config.get(
            "s3_endpoint_url",
            os.environ.get("ASM_S3_ENDPOINT_URL", "http://minio:9000"),
        )
        self.s3_access_key = config.get(
            "s3_access_key",
            os.environ.get("ASM_S3_ACCESS_KEY", "minioadmin"),
        )
        self.s3_secret_key = config.get(
            "s3_secret_key",
            os.environ.get("ASM_S3_SECRET_KEY", "minioadmin"),
        )
        self.s3_bucket = config.get(
            "s3_bucket",
            os.environ.get("ASM_S3_BUCKET", "skauswatch-asm-artifacts"),
        )
        self.s3_region = config.get(
            "s3_region",
            os.environ.get("ASM_S3_REGION", "us-east-1"),
        )
        self.timeout = int(config.get(
            "screenshot_timeout",
            os.environ.get("ASM_SCREENSHOT_TIMEOUT", "10"),
        ))

    def _get_s3_client(self):
        """Create an aiobotocore S3 client."""
        import aiobotocore.session
        session = aiobotocore.session.get_session()
        return session.create_client(
            "s3",
            endpoint_url=self.s3_endpoint,
            aws_access_key_id=self.s3_access_key,
            aws_secret_access_key=self.s3_secret_key,
            region_name=self.s3_region,
        )

    async def _ensure_bucket(self, client) -> None:
        """Create bucket if it doesn't exist."""
        try:
            await client.head_bucket(Bucket=self.s3_bucket)
        except Exception:
            try:
                await client.create_bucket(Bucket=self.s3_bucket)
                logger.info(f"Created S3 bucket: {self.s3_bucket}")
            except Exception as e:
                logger.warning(f"Could not create bucket {self.s3_bucket}: {e}")

    async def _upload_file(self, client, local_path: str, s3_key: str) -> bool:
        """Upload a file to S3.

        Args:
            client: aiobotocore S3 client.
            local_path: Local file path to upload.
            s3_key: S3 object key.

        Returns:
            True if upload succeeded, False otherwise.
        """
        try:
            with open(local_path, "rb") as f:
                await client.put_object(
                    Bucket=self.s3_bucket,
                    Key=s3_key,
                    Body=f.read(),
                )
            return True
        except Exception as e:
            logger.error(f"Failed to upload {local_path} to s3://{self.s3_bucket}/{s3_key}: {e}")
            return False

    async def screenshot_http(
        self,
        scan_id: int,
        host: str,
        port: int,
        use_https: bool = False,
    ) -> Optional[dict[str, Any]]:
        """Capture HTTP/HTTPS screenshot using gowitness.

        Args:
            scan_id: ASM scan ID for S3 key prefix.
            host: Target hostname or IP.
            port: Target port.
            use_https: Use HTTPS scheme if True.

        Returns:
            Dict with s3_key, url, tool, captured_at, or None on failure.
        """
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host}:{port}"
        proto_label = "https" if use_https else "http"
        s3_key = f"screenshots/{scan_id}/{host}/{port}-{proto_label}.png"

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, f"{port}-{proto_label}.png")

            cmd = [
                "gowitness",
                "single",
                "--url", url,
                "--screenshot-path", tmpdir,
                "--timeout", str(self.timeout),
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 10,
                )

                # gowitness names files based on URL hash - find the PNG
                png_files = list(Path(tmpdir).glob("*.png"))
                if not png_files:
                    logger.warning(f"No screenshot produced for {url}")
                    return None

                actual_file = str(png_files[0])
                captured_at = datetime.utcnow()

                async with self._get_s3_client() as client:
                    await self._ensure_bucket(client)
                    if await self._upload_file(client, actual_file, s3_key):
                        file_size = os.path.getsize(actual_file)
                        logger.info(f"Screenshot captured for {url}: {s3_key}")
                        return {
                            "s3_key": s3_key,
                            "url": url,
                            "tool": "gowitness",
                            "captured_at": captured_at.isoformat(),
                            "file_size_bytes": file_size,
                        }

            except subprocess.TimeoutExpired:
                logger.warning(f"gowitness timed out for {url}")
            except FileNotFoundError:
                logger.error("gowitness binary not found in PATH")
            except Exception as e:
                logger.error(f"Screenshot error for {url}: {e}")

        return None

    async def screenshot_rdp(
        self,
        scan_id: int,
        host: str,
        port: int = 3389,
    ) -> Optional[dict[str, Any]]:
        """Capture RDP login screen using xfreerdp3 + xvfb-run.

        Does NOT authenticate - captures the login screen only.

        Args:
            scan_id: ASM scan ID for S3 key prefix.
            host: Target hostname or IP.
            port: RDP port (default 3389).

        Returns:
            Dict with s3_key, url, tool, captured_at, or None on failure.
        """
        s3_key = f"screenshots/{scan_id}/{host}/{port}-rdp.bmp"

        with tempfile.TemporaryDirectory() as tmpdir:
            bmp_file = os.path.join(tmpdir, "rdp_capture.bmp")

            cmd = [
                "xvfb-run", "-a",
                "xfreerdp3",
                f"/v:{host}:{port}",
                "/auth-only",
                "/size:1280x720",
                f"/bmp-file:{bmp_file}",
                "/timeout:5000",
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 15,
                )

                if os.path.exists(bmp_file) and os.path.getsize(bmp_file) > 0:
                    captured_at = datetime.utcnow()
                    async with self._get_s3_client() as client:
                        await self._ensure_bucket(client)
                        if await self._upload_file(client, bmp_file, s3_key):
                            logger.info(f"RDP screenshot captured for {host}:{port}")
                            return {
                                "s3_key": s3_key,
                                "url": f"rdp://{host}:{port}",
                                "tool": "xfreerdp3",
                                "captured_at": captured_at.isoformat(),
                                "file_size_bytes": os.path.getsize(bmp_file),
                            }

            except subprocess.TimeoutExpired:
                logger.warning(f"xfreerdp timed out for {host}:{port}")
            except FileNotFoundError:
                logger.error("xfreerdp3 or xvfb-run binary not found")
            except Exception as e:
                logger.error(f"RDP screenshot error for {host}:{port}: {e}")

        return None

    async def screenshot_vnc(
        self,
        scan_id: int,
        host: str,
        port: int = 5900,
    ) -> Optional[dict[str, Any]]:
        """Capture VNC screenshot using vncsnapshot (unauthenticated attempt).

        Args:
            scan_id: ASM scan ID for S3 key prefix.
            host: Target hostname or IP.
            port: VNC port (default 5900).

        Returns:
            Dict with s3_key, url, tool, captured_at, or None on failure.
        """
        # VNC display number = port - 5900
        display = port - 5900
        s3_key = f"screenshots/{scan_id}/{host}/{port}-vnc.png"

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "vnc_capture.png")

            cmd = [
                "vncsnapshot",
                "-passwd", "/dev/null",
                "-timeout", str(self.timeout),
                f"{host}:{display}",
                out_file,
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 10,
                )

                if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                    captured_at = datetime.utcnow()
                    async with self._get_s3_client() as client:
                        await self._ensure_bucket(client)
                        if await self._upload_file(client, out_file, s3_key):
                            logger.info(f"VNC screenshot captured for {host}:{port}")
                            return {
                                "s3_key": s3_key,
                                "url": f"vnc://{host}:{port}",
                                "tool": "vncsnapshot",
                                "captured_at": captured_at.isoformat(),
                                "file_size_bytes": os.path.getsize(out_file),
                            }

            except subprocess.TimeoutExpired:
                logger.warning(f"vncsnapshot timed out for {host}:{port}")
            except FileNotFoundError:
                logger.error("vncsnapshot binary not found")
            except Exception as e:
                logger.error(f"VNC screenshot error for {host}:{port}: {e}")

        return None

    async def generate_presigned_url(self, s3_key: str, expires_in: int = 3600) -> Optional[str]:
        """Generate a presigned URL for an S3 object.

        Args:
            s3_key: S3 object key.
            expires_in: URL expiry in seconds (default 1 hour).

        Returns:
            Presigned URL string, or None on failure.
        """
        try:
            async with self._get_s3_client() as client:
                url = await client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": self.s3_bucket, "Key": s3_key},
                    ExpiresIn=expires_in,
                )
                return url
        except Exception as e:
            logger.error(f"Failed to generate presigned URL for {s3_key}: {e}")
            return None
