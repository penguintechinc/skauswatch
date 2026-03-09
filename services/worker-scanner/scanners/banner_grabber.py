"""Async TCP banner grabber for ASM service identification.

Grabs service banners from open ports using asyncio TCP connections.
Sends protocol-appropriate probes to elicit service responses.
No external binary dependencies.
"""

import asyncio
import socket
from datetime import datetime
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


# Per-port probe definitions (bytes to send after connect)
PORT_PROBES: dict[int, bytes] = {
    21: b"",  # FTP sends banner on connect
    22: b"",  # SSH sends banner on connect
    23: b"",  # Telnet sends banner on connect
    25: b"EHLO scanner\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110: b"",  # POP3 sends banner on connect
    143: b"",  # IMAP sends banner on connect
    443: b"",  # HTTPS - handled differently (TLS)
    3306: b"",  # MySQL sends banner on connect
    5432: b"",  # PostgreSQL handshake required
    6379: b"*1\r\n$4\r\nPING\r\n",  # Redis PING
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"",  # HTTPS-alt
    27017: b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
}

# Default HTTP probe for HTTP-like ports
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"

# Ports that use TLS (skip plain TCP banner grab)
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}

# HTTP-like ports (send HTTP probe)
HTTP_PORTS = {80, 8080, 8081, 8088, 3000, 3001, 4000, 5000, 8888, 9090}


async def grab_banner(
    ip: str,
    port: int,
    timeout: float = 5.0,
    max_bytes: int = 2048,
) -> dict[str, Any]:
    """Grab service banner from a single IP:port.

    Args:
        ip: Target IP address.
        port: Target TCP port.
        timeout: Connection and read timeout in seconds.
        max_bytes: Maximum bytes to read from the service.

    Returns:
        Dict with keys: ip, port, banner, service_name, error (optional).
    """
    result: dict[str, Any] = {
        "ip": ip,
        "port": port,
        "banner": "",
        "service_name": _guess_service(port),
        "error": None,
    }

    if port in TLS_PORTS:
        result["service_name"] = _guess_service(port)
        result["banner"] = "[TLS port - use cert_inspector for details]"
        return result

    # Select probe
    probe = PORT_PROBES.get(port)
    if probe is None:
        probe = HTTP_PROBE if port in HTTP_PORTS else b""

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)
        return result

    try:
        # Send probe if needed
        if probe:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Read banner
        try:
            data = await asyncio.wait_for(
                reader.read(max_bytes),
                timeout=timeout,
            )
            banner = data.decode("utf-8", errors="replace").strip()
            result["banner"] = banner[:max_bytes]
        except asyncio.TimeoutError:
            result["banner"] = ""

        # Extract version info from banner
        version = _extract_version(result["banner"], port)
        if version:
            result["version"] = version

    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return result


async def grab_banners_batch(
    hosts: list[dict[str, Any]],
    timeout: float = 5.0,
    max_bytes: int = 2048,
    concurrency: int = 50,
) -> list[dict[str, Any]]:
    """Grab banners from multiple hosts concurrently.

    Args:
        hosts: List of dicts with 'ip' and 'port' keys (from masscan output).
        timeout: Per-connection timeout in seconds.
        max_bytes: Maximum bytes to read per banner.
        concurrency: Maximum simultaneous connections.

    Returns:
        List of banner result dicts.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def bounded_grab(host: dict[str, Any]) -> dict[str, Any]:
        async with semaphore:
            return await grab_banner(
                ip=host["ip"],
                port=host["port"],
                timeout=timeout,
                max_bytes=max_bytes,
            )

    tasks = [bounded_grab(h) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    logger.info(f"Banner grabbing complete: {len(results)} ports processed")
    return list(results)


def _guess_service(port: int) -> str:
    """Guess service name from port number."""
    service_map = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpc",
        135: "msrpc",
        139: "netbios",
        143: "imap",
        161: "snmp",
        389: "ldap",
        443: "https",
        445: "smb",
        465: "smtps",
        587: "smtp-tls",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        1883: "mqtt",
        2049: "nfs",
        2181: "zookeeper",
        2375: "docker",
        2376: "docker-tls",
        2379: "etcd",
        3306: "mysql",
        3389: "rdp",
        4369: "rabbitmq-epmd",
        5432: "postgresql",
        5601: "kibana",
        5672: "rabbitmq-amqp",
        5900: "vnc",
        5901: "vnc",
        5984: "couchdb",
        6379: "redis",
        6443: "k8s-api",
        8080: "http-alt",
        8443: "https-alt",
        8888: "jupyter",
        9000: "minio",
        9092: "kafka",
        9200: "elasticsearch",
        11211: "memcached",
        27017: "mongodb",
    }
    return service_map.get(port, "unknown")


def _extract_version(banner: str, port: int) -> str:
    """Extract version string from common banner formats."""
    if not banner:
        return ""

    lines = banner.split("\n")
    first_line = lines[0] if lines else ""

    # SSH: "SSH-2.0-OpenSSH_8.9p1"
    if port == 22 and first_line.startswith("SSH-"):
        return first_line.strip()

    # FTP: "220 ProFTPD 1.3.7 Server"
    if port == 21 and first_line.startswith("220 "):
        return first_line[4:].strip()

    # SMTP: "220 mail.example.com ESMTP Postfix"
    if port == 25 and first_line.startswith("220 "):
        return first_line[4:].strip()

    # HTTP Server header
    for line in lines:
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()

    return ""
