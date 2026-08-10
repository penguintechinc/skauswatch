#!/usr/bin/env python3
"""Golden parity runner.

Replays the corpus against v1 (Quart) and v2 (Rust) managers side by side
and diffs status + JSON body structurally.

Normalization rule (see README.md): values are byte-compared, except when a
leaf differs on both sides AND both sides match the SAME nondeterminism
class (Python-isoformat timestamp, JWT, UUID, bcrypt hash) — those are
legitimately nondeterministic. A value that matches the class on one side
only is a FORMAT finding and stays a diff.

stdlib + requests only.
"""

import fnmatch
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus import CASES, SEED_PASSWORD  # noqa: E402

V1_BASE = os.environ.get("PARITY_V1_URL", "http://127.0.0.1:15001")
V2_BASE = os.environ.get("PARITY_V2_URL", "http://127.0.0.1:15002")
ENDPOINT_API_SECRET = os.environ.get("ENDPOINT_API_SECRET", "parity-endpoint-secret")
REPORT_DIR = os.environ.get(
    "PARITY_REPORT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
)
ALLOWLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected_diffs.json")
TIMEOUT = int(os.environ.get("PARITY_HTTP_TIMEOUT", "60"))

# Strict Python datetime.isoformat(): no fraction, or exactly 6 digits.
RE_PY_ISOFORMAT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?$")
RE_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RE_BCRYPT = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")

CLASSES = [("TS", RE_PY_ISOFORMAT), ("JWT", RE_JWT), ("UUID", RE_UUID), ("BCRYPT", RE_BCRYPT)]


def value_class(v):
    """Nondeterminism class of a string leaf, or None."""
    if not isinstance(v, str):
        return None
    for name, rx in CLASSES:
        if rx.match(v):
            return name
    return None


def leaves_equal(a, b):
    """Byte-equal, or both differ within the same nondeterminism class."""
    if a == b:
        return True
    ca, cb = value_class(a), value_class(b)
    return ca is not None and ca == cb


MISSING = object()


def diff_json(a, b, path=""):
    """Structural diff → list of {path, v1, v2}; dict key order ignored."""
    diffs = []
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            pa = a.get(key, MISSING)
            pb = b.get(key, MISSING)
            sub = f"{path}.{key}" if path else key
            if pa is MISSING or pb is MISSING:
                diffs.append(
                    {
                        "path": sub,
                        "v1": "<absent>" if pa is MISSING else pa,
                        "v2": "<absent>" if pb is MISSING else pb,
                    }
                )
            else:
                diffs.extend(diff_json(pa, pb, sub))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            diffs.append({"path": f"{path}#len", "v1": len(a), "v2": len(b)})
        # strict=False: the length mismatch is already recorded above (#len);
        # this loop only diffs the common prefix, so a shorter list must not
        # raise here.
        for i, (ia, ib) in enumerate(zip(a, b, strict=False)):
            diffs.extend(diff_json(ia, ib, f"{path}[{i}]"))
    elif isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        diffs.append({"path": path, "v1": a, "v2": b})
    else:
        if not leaves_equal(a, b):
            diffs.append({"path": path, "v1": a, "v2": b})
    return diffs


def agent_key(agent_id):
    """v1 ENDPOINT HMAC: hex(HMAC-SHA256(ENDPOINT_API_SECRET, agent_id))."""
    return hmac.new(ENDPOINT_API_SECRET.encode(), agent_id.encode(), hashlib.sha256).hexdigest()


class Side:
    """One manager under test: base URL, auth tokens, saved context."""

    def __init__(self, name, base):
        self.name = name
        self.base = base
        self.session = requests.Session()
        self.tokens = {}
        self.ctx = {}

    def setup_logins(self):
        for role, email in (
            ("admin", "admin@skauswatch.dev"),
            ("maintainer", "maint@skauswatch.dev"),
            ("viewer", "viewer@skauswatch.dev"),
        ):
            r = self.session.post(
                f"{self.base}/api/v1/auth/login",
                json={"email": email, "password": SEED_PASSWORD},
                timeout=TIMEOUT,
            )
            if r.status_code != 200:
                raise RuntimeError(
                    f"{self.name}: setup login {role} failed: {r.status_code} {r.text[:300]}"
                )
            body = r.json()
            self.tokens[role] = body["access_token"]
            if role == "viewer":
                self.ctx["VIEWER_REFRESH"] = body["refresh_token"]
        self.ctx["ADMIN_ACCESS"] = self.tokens["admin"]

    def headers_for(self, auth):
        h = {}
        if auth in (None, "none"):
            return h
        if auth in self.tokens:
            h["Authorization"] = f"Bearer {self.tokens[auth]}"
        elif auth == "invalid":
            h["Authorization"] = "Bearer not.a.jwt"
        elif auth == "basic":
            h["Authorization"] = "Basic Zm9vOmJhcg=="
        elif auth == "refresh-as-access":
            h["Authorization"] = f"Bearer {self.ctx['VIEWER_REFRESH']}"
        elif auth.startswith("ctx:"):
            h["Authorization"] = f"Bearer {self.ctx[auth[4:]]}"
        elif auth.startswith("agent:"):
            agent = auth.split(":", 1)[1]
            h["X-Agent-ID"] = agent
            h["X-API-Key"] = agent_key(agent)
        elif auth.startswith("agentbad:"):
            agent = auth.split(":", 1)[1]
            h["X-Agent-ID"] = agent
            h["X-API-Key"] = "0" * 64
        elif auth == "agentmissing":
            pass
        else:
            raise ValueError(f"unknown auth spec: {auth}")
        return h

    def substitute(self, obj):
        if isinstance(obj, str) and obj.startswith("$"):
            return self.ctx.get(obj[1:], obj)
        if isinstance(obj, dict):
            return {k: self.substitute(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.substitute(v) for v in obj]
        return obj

    def run_case(self, case):
        headers = self.headers_for(case.get("auth", "none"))
        url = self.base + case["path"]
        if case.get("query"):
            url += "?" + case["query"]
        kwargs = {"headers": headers, "timeout": TIMEOUT}
        if "json" in case:
            kwargs["json"] = self.substitute(case["json"])
        elif "raw_json" in case:
            kwargs["data"] = case["raw_json"]
            headers["Content-Type"] = "application/json"
        elif "files" in case:
            if case["files"]:
                kwargs["files"] = {
                    field: (fname, content.encode())
                    for field, (fname, content) in case["files"].items()
                }
            else:
                # empty multipart: send the content type with no parts
                kwargs["data"] = b""
                headers["Content-Type"] = "multipart/form-data; boundary=parityempty"
        resp = self.session.request(case["method"], url, **kwargs)
        try:
            body = resp.json()
        except ValueError:
            body = {"$raw": resp.text}
        if "save" in case and isinstance(body, dict):
            for name, dotted in case["save"].items():
                cur = body
                for part in dotted.split("."):
                    cur = cur.get(part) if isinstance(cur, dict) else None
                self.ctx[name] = cur
        return resp.status_code, body


def recover_v1():
    """Restart the v1 container after any 500.

    Documented v1 defect: all requests share one thread-local PyDAL
    connection and nothing ever rolls back — the first SQL error leaves the
    Postgres transaction aborted and every later DB request 500s until the
    process restarts. The harness restarts v1 so each case observes v1's
    per-endpoint behavior instead of the cascade. (v2 needs no equivalent:
    pooled sqlx connections recover per query.)
    """
    cmd = os.environ.get("PARITY_V1_RESTART_CMD", "docker restart parity-v1")
    # Local test-harness config (env var, default literal), argv list (no
    # shell=True) — not attacker-controlled input.
    subprocess.run(cmd.split(), check=True, capture_output=True)  # noqa: S603
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            if requests.get(f"{V1_BASE}/healthz", timeout=3).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError("v1 did not come back after restart")


def load_allowlist():
    with open(ALLOWLIST_PATH) as f:
        return json.load(f)


def entries_for(case_id, allowlist):
    out = []
    for e in allowlist:
        if "case" in e and e["case"] == case_id:
            out.append(e)
        elif "case_glob" in e and fnmatch.fnmatch(case_id, e["case_glob"]):
            out.append(e)
    return out


def classify(case_id, s1, s2, b1, b2, diffs, allowlist):
    """PASS / ALLOWLISTED(entry ids) / FINDING."""
    all_diffs = list(diffs)
    if s1 != s2:
        all_diffs.insert(0, {"path": "$status", "v1": s1, "v2": s2})
    if not all_diffs:
        return "PASS", []
    used = []
    remaining = all_diffs
    for entry in entries_for(case_id, allowlist):
        if "expect_status" in entry and entry["expect_status"] != [s1, s2]:
            continue
        if "require_error" in entry:
            e1 = b1.get("error") if isinstance(b1, dict) else None
            e2 = b2.get("error") if isinstance(b2, dict) else None
            if e1 != entry["require_error"] or e2 != entry["require_error"]:
                continue
        prefixes = entry.get("paths")
        before = len(remaining)
        if prefixes is None:
            remaining = []
        else:
            remaining = [d for d in remaining if not any(d["path"].startswith(p) for p in prefixes)]
        if len(remaining) != before:
            used.append(entry["id"])
        if not remaining:
            break
    if not remaining:
        return "ALLOWLISTED", used
    return "FINDING", remaining


def main():
    allowlist = load_allowlist()
    v1 = Side("v1", V1_BASE)
    v2 = Side("v2", V2_BASE)
    v1.setup_logins()
    v2.setup_logins()

    results = []
    counts = {"PASS": 0, "ALLOWLISTED": 0, "FINDING": 0}
    for case in CASES:
        # JWT iat/exp have second granularity: minting two refresh tokens
        # for one user within the same second yields an identical JWT and a
        # token_hash UNIQUE violation (documented v1 defect — it also
        # poisons v1's shared PyDAL connection). Sleep past the boundary.
        if case.get("sleep_before"):
            time.sleep(case["sleep_before"])
        s1, b1 = v1.run_case(case)
        if s1 == 500:
            # v1's shared connection may now be in an aborted transaction —
            # restart before the next case (see recover_v1 docstring).
            v1_needs_recovery = True
        else:
            v1_needs_recovery = False
        s2, b2 = v2.run_case(case)
        diffs = diff_json(b1, b2)
        verdict, extra = classify(case["id"], s1, s2, b1, b2, diffs, allowlist)
        counts[verdict] += 1
        rec = {
            "id": case["id"],
            "method": case["method"],
            "path": case["path"],
            "v1_status": s1,
            "v2_status": s2,
            "verdict": verdict,
        }
        if verdict == "ALLOWLISTED":
            rec["allowlist_entries"] = extra
        elif verdict == "FINDING":
            rec["diffs"] = extra
            rec["v1_body"] = b1
            rec["v2_body"] = b2
        results.append(rec)
        marker = {"PASS": ".", "ALLOWLISTED": "a", "FINDING": "F"}[verdict]
        print(f"{marker} {case['id']} [{s1}/{s2}]", flush=True)
        if v1_needs_recovery:
            recover_v1()

    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(os.path.join(REPORT_DIR, "report.json"), "w") as f:
        json.dump({"counts": counts, "results": results}, f, indent=2, default=str)

    lines = [
        "# Golden parity diff report",
        "",
        f"- cases: {len(results)}",
        f"- pass: {counts['PASS']}",
        f"- allowlisted (documented contract decisions): {counts['ALLOWLISTED']}",
        f"- findings: {counts['FINDING']}",
        "",
    ]
    for rec in results:
        if rec["verdict"] != "FINDING":
            continue
        lines.append(
            f"## FINDING {rec['id']} — {rec['method']} {rec['path']} "
            f"[v1={rec['v1_status']} v2={rec['v2_status']}]"
        )
        for d in rec["diffs"][:40]:
            lines.append(
                f"- `{d['path']}`: v1=`{json.dumps(d['v1'], default=str)[:300]}` "
                f"v2=`{json.dumps(d['v2'], default=str)[:300]}`"
            )
        lines.append("")
    with open(os.path.join(REPORT_DIR, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")

    print(
        f"\ncases={len(results)} pass={counts['PASS']} "
        f"allowlisted={counts['ALLOWLISTED']} findings={counts['FINDING']}"
    )
    print(f"report: {os.path.join(REPORT_DIR, 'report.md')}")
    return 1 if counts["FINDING"] else 0


if __name__ == "__main__":
    sys.exit(main())
