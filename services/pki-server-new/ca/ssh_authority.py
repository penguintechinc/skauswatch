"""SSH Certificate Authority implementation."""

import base64
import hashlib
import os
import secrets
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

import structlog

from ..config import SSHCAConfig

logger = structlog.get_logger()


class SSHCertificateAuthority:
    """SSH Certificate Authority for issuing and managing SSH certificates."""

    CERTIFICATE_TYPES = {
        "user": "-n",
        "host": "-h",
    }

    DEFAULT_USER_EXTENSIONS = {
        "permit-agent-forwarding": "",
        "permit-port-forwarding": "",
        "permit-pty": "",
        "permit-user-rc": "",
    }

    def __init__(self, config: SSHCAConfig):
        """Initialize SSH CA."""
        self.config = config
        self._serial_counter = 1
        self._krl_version = 0
        self._ca_public_key = None
        self._ca_fingerprint = None

    async def initialize(self) -> None:
        """Load or generate SSH CA key."""
        ca_key_path = Path(self.config.ca_key_path)
        ca_pub_path = Path(self.config.ca_public_key_path)

        if ca_key_path.exists():
            await self._load_ca()
        else:
            logger.warning("SSH CA key not found, generating new CA")
            await self._generate_ca()

        logger.info("SSH CA initialized", fingerprint=self._ca_fingerprint)

    async def _load_ca(self) -> None:
        """Load existing SSH CA key."""
        pub_path = Path(self.config.ca_public_key_path)

        if pub_path.exists():
            with open(pub_path, "r") as f:
                self._ca_public_key = f.read().strip()
        else:
            # Extract public key from private key
            result = subprocess.run(
                ["ssh-keygen", "-y", "-f", self.config.ca_key_path],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                self._ca_public_key = result.stdout.strip()
                with open(pub_path, "w") as f:
                    f.write(self._ca_public_key)

        # Get fingerprint
        result = subprocess.run(
            ["ssh-keygen", "-lf", self.config.ca_key_path],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            parts = result.stdout.split()
            if len(parts) >= 2:
                self._ca_fingerprint = parts[1]

    async def _generate_ca(self) -> None:
        """Generate new SSH CA key."""
        ca_key_path = Path(self.config.ca_key_path)
        ca_pub_path = Path(self.config.ca_public_key_path)

        # Ensure directory exists
        ca_key_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate ED25519 key (recommended for SSH CA)
        key_type = self.config.default_key_type
        cmd = [
            "ssh-keygen",
            "-t",
            key_type,
            "-f",
            str(ca_key_path),
            "-N",
            self.config.ca_key_password or "",
            "-C",
            "SkausWatch SSH CA",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to generate SSH CA key: {result.stderr}")

        # Set permissions
        os.chmod(ca_key_path, 0o600)
        os.chmod(ca_pub_path, 0o644)

        await self._load_ca()

    def _get_next_serial(self) -> int:
        """Get next serial number."""
        serial = self._serial_counter
        self._serial_counter += 1
        return serial

    async def issue_certificate(
        self,
        public_key: str,
        certificate_type: str = "user",
        key_id: str = None,
        principals: List[str] = None,
        validity_seconds: int = 86400,
        extensions: Dict[str, str] = None,
        critical_options: Dict[str, str] = None,
        source_addresses: List[str] = None,
        force_command: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Issue a new SSH certificate.

        Returns:
            Tuple of (certificate, serial_number, metadata)
        """
        if not principals:
            raise ValueError("At least one principal is required")

        if certificate_type not in self.CERTIFICATE_TYPES:
            raise ValueError(f"Invalid certificate type: {certificate_type}")

        # Validate validity
        if validity_seconds > self.config.max_validity_seconds:
            validity_seconds = self.config.max_validity_seconds

        # Generate serial and key_id
        serial = self._get_next_serial()
        if not key_id:
            key_id = f"skauswatch-{certificate_type}-{serial}"

        # Calculate timestamps
        valid_after = datetime.utcnow()
        valid_before = valid_after + timedelta(seconds=validity_seconds)

        # Create temporary files for signing
        with tempfile.TemporaryDirectory() as tmpdir:
            pub_key_file = Path(tmpdir) / "key.pub"
            cert_file = Path(tmpdir) / "key-cert.pub"

            # Write public key
            with open(pub_key_file, "w") as f:
                f.write(public_key)

            # Build ssh-keygen command
            cmd = [
                "ssh-keygen",
                "-s",
                self.config.ca_key_path,
                "-I",
                key_id,
                "-z",
                str(serial),
                "-V",
                f"+{validity_seconds}s",
            ]

            # Add certificate type flag
            if certificate_type == "host":
                cmd.append("-h")

            # Add principals
            cmd.extend(["-n", ",".join(principals)])

            # Add options for user certificates
            if certificate_type == "user":
                options = []

                # Add extensions
                ext = extensions if extensions else self.DEFAULT_USER_EXTENSIONS
                for name, value in ext.items():
                    if value:
                        options.append(f"{name}={value}")
                    else:
                        options.append(name)

                # Add critical options
                if critical_options:
                    for name, value in critical_options.items():
                        cmd.extend(["-O", f"critical:{name}={value}"])

                # Add source address restriction
                if source_addresses:
                    cmd.extend(["-O", f"source-address={','.join(source_addresses)}"])

                # Add force command
                if force_command:
                    cmd.extend(["-O", f"force-command={force_command}"])

                # Add extensions
                for opt in options:
                    if "=" in opt:
                        cmd.extend(["-O", opt])
                    else:
                        cmd.extend(["-O", f"extension:{opt}"])

            # Add the public key file
            cmd.append(str(pub_key_file))

            # Execute signing
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to sign certificate: {result.stderr}")

            # Read the certificate
            with open(cert_file, "r") as f:
                certificate = f.read().strip()

        # Determine key type from public key
        key_type = "unknown"
        if public_key.startswith("ssh-rsa"):
            key_type = "rsa"
        elif public_key.startswith("ssh-ed25519"):
            key_type = "ed25519"
        elif public_key.startswith("ecdsa-sha2"):
            key_type = "ecdsa"

        metadata = {
            "serial_number": str(serial),
            "key_id": key_id,
            "certificate_type": certificate_type,
            "principals": principals,
            "valid_after": valid_after.isoformat(),
            "valid_before": valid_before.isoformat(),
            "key_type": key_type,
            "hostname": hostname,
            "extensions": extensions or self.DEFAULT_USER_EXTENSIONS,
            "critical_options": critical_options or {},
            "source_addresses": source_addresses,
            "force_command": force_command,
        }

        logger.info(
            "SSH certificate issued",
            serial=serial,
            key_id=key_id,
            type=certificate_type,
            principals=principals,
            validity_seconds=validity_seconds,
        )

        return certificate, str(serial), metadata

    async def generate_krl(
        self, revoked_entries: List[Dict[str, Any]]
    ) -> Tuple[bytes, int]:
        """
        Generate a Key Revocation List.

        Args:
            revoked_entries: List of dicts with serial_number or public_key

        Returns:
            Tuple of (krl_binary, krl_version)
        """
        self._krl_version += 1

        with tempfile.TemporaryDirectory() as tmpdir:
            krl_file = Path(tmpdir) / "revoked.krl"
            spec_file = Path(tmpdir) / "revoke_spec"

            # Build revocation specification
            spec_lines = []
            for entry in revoked_entries:
                if "serial_number" in entry:
                    spec_lines.append(f"serial: {entry['serial_number']}")
                elif "public_key" in entry:
                    spec_lines.append(f"key: {entry['public_key']}")

            with open(spec_file, "w") as f:
                f.write("\n".join(spec_lines))

            # Generate KRL
            cmd = [
                "ssh-keygen",
                "-k",
                "-f",
                str(krl_file),
                "-s",
                self.config.ca_key_path,
                str(spec_file),
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to generate KRL: {result.stderr}")

            # Read KRL
            with open(krl_file, "rb") as f:
                krl_binary = f.read()

        # Optionally save to configured path
        krl_path = Path(self.config.krl_path)
        krl_path.parent.mkdir(parents=True, exist_ok=True)
        with open(krl_path, "wb") as f:
            f.write(krl_binary)

        logger.info(
            "KRL generated",
            version=self._krl_version,
            revoked_count=len(revoked_entries),
        )

        return krl_binary, self._krl_version

    async def check_certificate(self, certificate: str) -> Dict[str, Any]:
        """Parse and validate an SSH certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = Path(tmpdir) / "cert.pub"

            with open(cert_file, "w") as f:
                f.write(certificate)

            # Parse certificate
            cmd = ["ssh-keygen", "-L", "-f", str(cert_file)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise ValueError(f"Invalid certificate: {result.stderr}")

            # Parse output
            info = self._parse_certificate_info(result.stdout)

            # Verify against CA
            cmd = [
                "ssh-keygen",
                "-c",
                "-f",
                str(cert_file),
                "-I",
                self.config.ca_public_key_path,
            ]
            verify_result = subprocess.run(cmd, capture_output=True, text=True)
            info["verified"] = verify_result.returncode == 0

            return info

    def _parse_certificate_info(self, output: str) -> Dict[str, Any]:
        """Parse ssh-keygen -L output."""
        info = {
            "type": None,
            "serial": None,
            "key_id": None,
            "principals": [],
            "valid_after": None,
            "valid_before": None,
            "extensions": {},
            "critical_options": {},
        }

        for line in output.split("\n"):
            line = line.strip()

            if line.startswith("Type:"):
                info["type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Serial:"):
                info["serial"] = line.split(":", 1)[1].strip()
            elif line.startswith("Key ID:"):
                info["key_id"] = line.split(":", 1)[1].strip().strip('"')
            elif line.startswith("Principals:"):
                # Principals are on following lines
                continue
            elif line.startswith("Valid:"):
                valid_str = line.split(":", 1)[1].strip()
                if " to " in valid_str:
                    parts = valid_str.split(" to ")
                    info["valid_after"] = parts[0].strip()
                    info["valid_before"] = parts[1].strip()
            elif "Extensions:" in line or "Critical Options:" in line:
                continue
            elif line and not line.startswith("Public key:"):
                # Could be a principal or extension
                if line and not ":" in line:
                    info["principals"].append(line)

        return info

    def get_ca_public_key(self) -> str:
        """Get CA public key."""
        return self._ca_public_key

    def get_ca_info(self) -> Dict[str, Any]:
        """Get SSH CA information."""
        # Determine key type from public key
        key_type = "unknown"
        if self._ca_public_key:
            if self._ca_public_key.startswith("ssh-rsa"):
                key_type = "rsa"
            elif self._ca_public_key.startswith("ssh-ed25519"):
                key_type = "ed25519"
            elif self._ca_public_key.startswith("ecdsa-sha2"):
                key_type = "ecdsa"

        return {
            "ca_public_key": self._ca_public_key,
            "key_type": key_type,
            "fingerprint": self._ca_fingerprint,
            "serial_counter": self._serial_counter,
            "krl_version": self._krl_version,
        }

    def generate_known_hosts_entry(
        self, hostnames: List[str], cert_authority: bool = True
    ) -> str:
        """Generate known_hosts entry for host certificate verification."""
        hosts = ",".join(hostnames)
        prefix = "@cert-authority " if cert_authority else ""
        return f"{prefix}{hosts} {self._ca_public_key}"

    def generate_authorized_keys_entry(
        self, principals: List[str], options: Dict[str, str] = None
    ) -> str:
        """Generate authorized_keys entry for user certificate verification."""
        options = options or {}
        option_str = ""

        if options:
            opts = []
            for key, value in options.items():
                if value:
                    opts.append(f'{key}="{value}"')
                else:
                    opts.append(key)
            option_str = ",".join(opts) + " "

        principals_str = ",".join(principals)
        return (
            f'{option_str}cert-authority,principals="{principals_str}" '
            f"{self._ca_public_key}"
        )

    def generate_ssh_config(
        self,
        hostname: str,
        port: int = 22,
        user: Optional[str] = None,
        identity_file: Optional[str] = None,
    ) -> str:
        """Generate SSH config snippet for a host."""
        config_lines = [
            f"Host {hostname}",
            f"    HostName {hostname}",
            f"    Port {port}",
        ]

        if user:
            config_lines.append(f"    User {user}")

        if identity_file:
            config_lines.append(f"    IdentityFile {identity_file}")
            config_lines.append(f"    CertificateFile {identity_file}-cert.pub")

        return "\n".join(config_lines)
