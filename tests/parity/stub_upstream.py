"""Deterministic stub upstream shared by BOTH managers under parity test.

Stands in for scanner (ASM proxy), worker-codescan (CodeScan proxy),
logs (SIEM ingest/health), and the S3 endpoint used by bucket
connection tests. Every response is a fixed JSON echo of method+path+query,
so proxy-forwarding parity (path construction, query forwarding, body
pass-through) is directly observable in the diff.

stdlib only; runs inside python:3.13-slim-bookworm.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StubHandler(BaseHTTPRequestHandler):
    """Echo handler: fixed JSON for all methods; HEAD returns bare 200."""

    protocol_version = "HTTP/1.1"

    def _respond(self) -> None:
        path, _, query = self.path.partition("?")
        body_len = int(self.headers.get("Content-Length") or 0)
        upstream_body = self.rfile.read(body_len) if body_len else b""
        try:
            parsed = json.loads(upstream_body) if upstream_body else None
        except ValueError:
            parsed = upstream_body.decode("utf-8", "replace")
        payload = {
            "stub": True,
            "method": self.command,
            "path": path,
            "query": query,
            "body": parsed,
        }
        data = json.dumps(payload, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self) -> None:  # noqa: N802 - http.server API
        """S3 head_bucket support: bare 200, no body."""
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _respond  # noqa: N815 - http.server API
    do_POST = _respond  # noqa: N815 - http.server API
    do_PUT = _respond  # noqa: N815 - http.server API
    do_DELETE = _respond  # noqa: N815 - http.server API

    def log_message(self, *args) -> None:
        """Silence per-request logging (keeps container output clean)."""


if __name__ == "__main__":
    # Binds all interfaces intentionally: this stub runs inside a throwaway
    # test container and must be reachable from the v1/v2 manager containers
    # under parity test — see module docstring.
    ThreadingHTTPServer(("0.0.0.0", 9999), StubHandler).serve_forever()  # noqa: S104
