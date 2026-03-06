"""Masscan port scanner wrapper for ASM discovery.

Wraps the masscan binary to perform fast TCP port discovery.
Requires NET_RAW capability (set via docker-compose cap_add).
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime
from typing import Any

import yaml

from scanners.base import BaseScanner, NormalizedFinding, ScanResult, ScannerStatus


class MasscanScanner(BaseScanner):
    """Fast TCP port scanner using masscan binary.

    Requires:
        - masscan binary in PATH with cap_net_raw+ep set
        - NET_RAW docker capability (cap_add in docker-compose)
    """

    SCANNER_TYPE = "masscan"

    # Ports that indicate HTTP/HTTPS services for screenshot targeting
    HTTP_PORTS = {80, 8080, 8081, 8088, 4000, 5000, 3000, 3001, 9090, 8888}
    HTTPS_PORTS = {443, 8443, 9443, 9200, 5601}
    TLS_PORTS = {443, 8443, 9443, 636, 993, 995, 465, 587, 2376}
    RDP_PORTS = {3389}
    VNC_PORTS = {5900, 5901}

    def _load_default_ports(self) -> list[int]:
        """Load default port list from scanner_defaults.yaml."""
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "scanner_defaults.yaml"
        )
        try:
            with open(config_path) as f:
                defaults = yaml.safe_load(f)
            return defaults.get("asm", {}).get("default_ports", [80, 443, 22, 3389])
        except Exception:
            self.logger.warning("Could not load scanner_defaults.yaml, using minimal defaults")
            return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]

    def _build_port_arg(self, config: dict) -> str:
        """Merge default ports with admin-configured extra ports.

        Args:
            config: Scan configuration dict, may contain 'extra_ports' list.

        Returns:
            Comma-separated port string for masscan -p argument.
        """
        defaults = self._load_default_ports()
        extras = config.get("extra_ports", [])
        all_ports = sorted(
            set(defaults) | {int(p) for p in extras if str(p).strip().isdigit()}
        )
        return ",".join(str(p) for p in all_ports)

    def scan(
        self, target: str, scan_type: str = "asm", config: dict | None = None
    ) -> ScanResult:
        """Execute masscan port discovery against target.

        Args:
            target: IP address, CIDR range, or hostname to scan.
            scan_type: Scan type (ignored - always does port discovery).
            config: Optional config dict with 'extra_ports', 'rate'.

        Returns:
            ScanResult with findings for each open port.
        """
        if config is None:
            config = {}

        start = datetime.utcnow()
        port_arg = self._build_port_arg(config)
        rate = config.get("rate", self.config.get("masscan_rate", 1000))

        self.logger.info(
            f"Starting masscan on {target} with {len(port_arg.split(','))} ports at {rate} pps"
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_file:
            out_path = out_file.name

        try:
            cmd = [
                "masscan",
                target,
                f"-p{port_arg}",
                f"--rate={rate}",
                "--output-format", "json",
                f"--output-filename={out_path}",
                "--wait=3",
            ]

            self.logger.debug(f"Masscan command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode not in (0, 1):
                # masscan exits 1 on some systems even on success
                error_msg = result.stderr.strip() or "masscan exited with error"
                if "Operation not permitted" in error_msg or "permission" in error_msg.lower():
                    self.logger.error(
                        "Masscan requires NET_RAW capability. "
                        "Ensure cap_add: [NET_RAW] in docker-compose.yml "
                        "and setcap cap_net_raw+ep /usr/bin/masscan in Dockerfile"
                    )
                    return ScanResult(
                        success=False,
                        scanner_type=self.SCANNER_TYPE,
                        scan_type=scan_type,
                        error_message="NET_RAW capability required for masscan",
                    )

            # Parse output file
            open_ports = self._parse_masscan_output(out_path)

            # Build findings
            findings = []
            for entry in open_ports:
                port = entry["port"]
                proto = entry.get("proto", "tcp")
                ip = entry["ip"]

                # Determine service label
                service = self._guess_service(port)

                finding = NormalizedFinding(
                    finding_id=f"masscan-{ip}-{port}-{proto}",
                    severity="info",
                    title=f"Open port {port}/{proto} on {ip}",
                    description=f"Port {port}/{proto} is open on {ip}. Service: {service}",
                    affected_url=f"{ip}:{port}",
                    raw_finding=entry,
                )
                findings.append(finding)

            duration = (datetime.utcnow() - start).total_seconds()
            self.logger.info(
                f"Masscan completed: found {len(open_ports)} open ports in {duration:.1f}s"
            )

            return ScanResult(
                success=True,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                findings=findings,
                duration_seconds=int(duration),
                raw_output=json.dumps(open_ports),
                summary={
                    "open_ports_count": len(open_ports),
                    "target": target,
                    "ports_scanned": port_arg,
                    "rate": rate,
                },
            )

        except subprocess.TimeoutExpired:
            self.logger.error("Masscan timed out after 600 seconds")
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message="Masscan timed out",
            )
        except FileNotFoundError:
            self.logger.error("masscan binary not found in PATH")
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message="masscan binary not found",
            )
        except Exception as e:
            self.logger.exception(f"Unexpected error during masscan: {e}")
            return ScanResult(
                success=False,
                scanner_type=self.SCANNER_TYPE,
                scan_type=scan_type,
                error_message=str(e),
            )
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

    def _parse_masscan_output(self, out_path: str) -> list[dict[str, Any]]:
        """Parse masscan JSON output file into list of port records.

        Masscan JSON format:
        { "ip": "1.2.3.4", "timestamp": "1234567890",
          "ports": [ {"port": 80, "proto": "tcp", "status": "open", ...} ] }

        Args:
            out_path: Path to masscan JSON output file.

        Returns:
            List of dicts with keys: ip, port, proto, status, timestamp.
        """
        results = []
        try:
            with open(out_path) as f:
                content = f.read().strip()

            if not content:
                return results

            # masscan outputs one JSON object per line (not a JSON array)
            # Sometimes it wraps in an array, sometimes not
            if content.startswith("["):
                # Array format
                data = json.loads(content.rstrip(",\n]") + "]")
                if isinstance(data, list):
                    for entry in data:
                        ip = entry.get("ip", "")
                        ts = entry.get("timestamp", "")
                        for port_info in entry.get("ports", []):
                            results.append({
                                "ip": ip,
                                "port": port_info.get("port", 0),
                                "proto": port_info.get("proto", "tcp"),
                                "status": port_info.get("status", "open"),
                                "timestamp": ts,
                            })
            else:
                # Line-by-line format
                for line in content.split("\n"):
                    line = line.strip().strip(",")
                    if not line or line.startswith("//"):
                        continue
                    try:
                        entry = json.loads(line)
                        ip = entry.get("ip", "")
                        ts = entry.get("timestamp", "")
                        for port_info in entry.get("ports", []):
                            results.append({
                                "ip": ip,
                                "port": port_info.get("port", 0),
                                "proto": port_info.get("proto", "tcp"),
                                "status": port_info.get("status", "open"),
                                "timestamp": ts,
                            })
                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            self.logger.warning(f"Masscan output file not found: {out_path}")
        except Exception as e:
            self.logger.error(f"Error parsing masscan output: {e}")

        return results

    def _guess_service(self, port: int) -> str:
        """Guess service name from well-known port number."""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
            143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
            465: "smtps", 587: "smtp-tls", 636: "ldaps", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper",
            2375: "docker", 2376: "docker-tls", 2379: "etcd", 3000: "http-alt",
            3306: "mysql", 3389: "rdp", 4369: "rabbitmq-epmd", 5000: "http-alt",
            5432: "postgresql", 5601: "kibana", 5672: "rabbitmq-amqp",
            5900: "vnc", 5901: "vnc", 5984: "couchdb", 6379: "redis",
            6443: "k8s-api", 7474: "neo4j", 8080: "http-alt", 8443: "https-alt",
            8500: "consul", 8888: "jupyter", 9000: "minio", 9042: "cassandra",
            9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
            11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
        }
        return service_map.get(port, "unknown")

    def parse_results(self, raw_output: str) -> list[NormalizedFinding]:
        """Parse raw masscan JSON string into findings (not used directly)."""
        findings = []
        try:
            entries = json.loads(raw_output)
            for entry in entries:
                findings.append(NormalizedFinding(
                    finding_id=f"masscan-{entry['ip']}-{entry['port']}",
                    severity="info",
                    title=f"Open port {entry['port']}/{entry.get('proto', 'tcp')}",
                    description=f"Port {entry['port']} is open on {entry['ip']}",
                    affected_url=f"{entry['ip']}:{entry['port']}",
                    raw_finding=entry,
                ))
        except Exception as e:
            self.logger.error(f"Error parsing masscan results: {e}")
        return findings

    def get_status(self) -> ScannerStatus:
        """Check if masscan binary is available."""
        try:
            result = subprocess.run(
                ["masscan", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            version = ""
            for line in result.stdout.split("\n") + result.stderr.split("\n"):
                if "masscan" in line.lower() and any(c.isdigit() for c in line):
                    version = line.strip()
                    break
            return ScannerStatus(
                name="masscan",
                available=result.returncode == 0,
                version=version,
                message="masscan available" if result.returncode == 0 else "masscan error",
                last_checked=datetime.utcnow(),
            )
        except FileNotFoundError:
            return ScannerStatus(
                name="masscan",
                available=False,
                message="masscan binary not found in PATH",
                last_checked=datetime.utcnow(),
            )
        except Exception as e:
            return ScannerStatus(
                name="masscan",
                available=False,
                message=str(e),
                last_checked=datetime.utcnow(),
            )

    def validate_config(self, config: dict) -> tuple[bool, str]:
        """Validate masscan configuration."""
        rate = config.get("rate", 1000)
        if not isinstance(rate, int) or rate < 1 or rate > 1000000:
            return False, "rate must be an integer between 1 and 1000000"

        extra_ports = config.get("extra_ports", [])
        if not isinstance(extra_ports, list):
            return False, "extra_ports must be a list"

        for p in extra_ports:
            try:
                port_int = int(p)
                if port_int < 1 or port_int > 65535:
                    return False, f"Invalid port number: {p}"
            except (ValueError, TypeError):
                return False, f"Invalid port value: {p}"

        return True, ""
