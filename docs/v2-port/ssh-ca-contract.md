# SSH CA Service — v2 Contract Spec (Rust port)

Rust binary `skauswatch-ssh-ca` at `services/ssh-ca` replaces the v1 Python
`services/ssh-ca` deprecation shim and the IceBox SSH CA engine it proxied to
(`icebox/services/ssh-ca/async_ssh_processor.py`, the `AsyncSSHProcessor`
class). SECURITY-SENSITIVE: this service holds an SSH CA signing key.

## Source-of-truth note (scope)

- v1 `services/ssh-ca/async_ssh_processor.py` was only a **deprecation shim**
  (proxied `/api/v1/*` → `ICEBOX_SSH_CA_URL`). It carried no cert template.
- The real engine is the IceBox `AsyncSSHProcessor`
  (`icebox/services/ssh-ca/async_ssh_processor.py`) — the source of the CA key
  loading and the `_build_ssh_certificate` template ported here.
- The engine's own REST layer (`skauswatch.services.ssh_ca.main:app`, per the
  v1 Dockerfile `ENTRYPOINT`) was **not preserved in the repo** — only the
  processor class survives. The REST paths below are therefore reconstructed
  from the engine's operations and the canonical SSH REST shape in the v1
  pki-server (`icebox/services/pki-server/api/v1/ssh.py`).
- The **pki-server** (`services/pki-server-new`, still Python) is a separate
  service with its own SSH/x509 authority — out of scope for this port.

## Bootstrap facts

- REST port **8002** (env `SERVICE_PORT`, fallback `API_PORT`) — v1 ssh-ca
  Dockerfile `SERVICE_PORT`. Prometheus metrics on **:9090**; `/healthz` +
  `/readyz` via the shared telemetry crate.
- `serve` (default) / `healthcheck` clap subcommands; container-native health
  probe (no curl), graceful shutdown on SIGINT/SIGTERM — house pattern.
- Error envelope (house convention, matches manager): handler errors are bare
  `{"error": msg}`; validation is `{"error":"Validation error","details":[…]}`;
  the unknown-route fallback is `{"error":"Not Found","detail":…}`; 500 is
  `{"error":"Internal Server Error"}` (cause logged, never leaked — v1 ssh.py
  leaked `str(e)`; hardened here).
- **Auth: service-internal, no JWT.** v1's ssh.py/engine had no JWT gate
  (identity via an `X-User-ID` header, audit only). This port keeps it
  unauthenticated at the app layer — it is a cluster-internal service reached
  by the manager/pki plane, not exposed to the internet. If it is ever exposed,
  gate it behind the manager's JWT middleware (`backend.md` auth).

## Endpoints (`/api/v1/ssh`)

| M | Path | Notes |
|---|---|---|
| POST | /api/v1/ssh/certificates | Issue a cert (201). Body/response below. |
| GET | /api/v1/ssh/certificates | List; filters `type`, `status`, `limit`≤1000. `{certificates:[…], total}`. |
| GET | /api/v1/ssh/certificates/{id} | Fetch one (404 `{"error":"Certificate not found"}`). |
| POST | /api/v1/ssh/certificates/{id}/revoke | Body `{reason?}`; `{message,certificate_id}`; 404 if unknown. |
| GET | /api/v1/ssh/krl | Current KRL JSON (v1 `_generate_krl_sync` shape). |
| GET | /api/v1/ssh/ca/public-key | `{ca_public_key, ca_fingerprint}`; `Accept: text/plain` → raw line. |

### POST /api/v1/ssh/certificates

Request (field names track the v1 `SSHCertificateRequest` dataclass):

```json
{
  "certificate_type": "user" | "host",
  "public_key": "ssh-ed25519 AAAA… comment",
  "principals": ["alice", "bob"],
  "validity_duration": 3600,          // seconds; alias "validity_seconds"; default 3600
  "extensions": {"permit-pty": ""},   // optional; see defaults below
  "critical_options": {},             // optional
  "source_address": "10.0.0.0/8",     // optional → source-address critical option
  "force_command": "/usr/bin/foo",    // optional → force-command critical option
  "key_id": "…",                      // optional; default "{type}-{request_id}"
  "request_id": "…",                  // optional; UUIDv4 if absent
  "requester_id": "…",                // optional; audit only
  "metadata": {}                      // optional; echoed back
}
```

Response 201 (mirrors the v1 `_sign_certificate_sync` return dict, with
corrected SHA256 fingerprints and an added `key_id`):

```json
{
  "certificate_id": "<request_id>",
  "certificate_type": "user",
  "signed_certificate": "ssh-ed25519-cert-v01@openssh.com AAAA…",
  "serial_number": 1000001,
  "principals": ["alice", "bob"],
  "key_id": "user-<request_id>",
  "valid_after": "2026-07-25T14:57:00",
  "valid_before": "2026-07-25T15:57:00",
  "public_key_fingerprint": "SHA256:…",
  "ca_fingerprint": "SHA256:…",
  "metadata": {}
}
```

Wire timestamps use `skauswatch_streams::py_isoformat` (second precision —
`valid_*` come from integer epoch seconds, so no fractional part, matching v1's
`datetime.fromtimestamp(int).isoformat()`).

## SSH certificate template (parity-critical)

Produced by the `ssh-key` crate (`=0.6.7`), so output is a standards-compliant
OpenSSH certificate. Preserved v1 template semantics:

| Field | Rule (ported from v1 engine) |
|---|---|
| cert type | `user` → `CertType::User` (1), `host` → `CertType::Host` (2). |
| cert algorithm | Derived from the **subject** key (correct OpenSSH behavior). v1 hardcoded `ssh-rsa-cert-v01@openssh.com` for every subject — a defect. |
| key id | `{type}-{request_id}` (e.g. `user-<uuid>`) unless overridden. |
| serial | Monotonic `AtomicU64` seeded at 1_000_000; first issued serial **1_000_001** (v1 `serial_counter` seed). |
| principals | Verbatim from the request (empty ⇒ valid for all principals). |
| valid_after | `now` (unix seconds). |
| valid_before | `valid_after + validity_duration` — **duration semantics preserved**. |
| critical options | Request map + `source-address`/`force-command` shorthands. v1 accepted `source_address`/`force_command` but its builder silently dropped them — fixed here. |
| extensions | Request map verbatim if present; else the 5 OpenSSH-standard `permit-*` for user certs, none for host. v1 defaulted to none (login-unusable) — documented deviation. |
| nonce | 32 random bytes (OsRng), as OpenSSH. |
| signature | By the CA key; `ssh-ed25519` (Ed25519 CA) or ECDSA. |
| fingerprints | Standard OpenSSH `SHA256:<base64>`. v1 used a non-standard hex-of-sha256 — fixed. |

## CA key loading

- Path: `SSH_CA_KEY_PATH` (alias `CA_PRIVATE_KEY_PATH`, the v1 config key), else
  `${SSH_CA_DIR}/ssh_ca_key` (v1 entrypoint derivation). OpenSSH private-key
  format (`ssh-keygen` default).
- **Key algorithm: Ed25519 (preferred) or ECDSA P-256/P-384. RSA CA keys are
  rejected at startup** — see defect #2. Fail-fast with guidance to run
  `ssh-keygen -t ed25519`.
- Missing key file → generates an **ephemeral Ed25519** CA key with a loud
  warning (preserves v1's generate-on-missing demo behavior; unsafe for
  production — certs won't verify after restart). Mount a persistent key.
- The CA private key is **never logged** — only its algorithm and public SHA256
  fingerprint.

## Env vars

| Var | Default | Meaning |
|---|---|---|
| `SERVICE_PORT` / `API_PORT` | 8002 | REST port. |
| `SSH_CA_KEY_PATH` / `CA_PRIVATE_KEY_PATH` | `${SSH_CA_DIR}/ssh_ca_key` | CA private key path. |
| `SSH_CA_DIR` | `/app/ssh-ca` | CA working directory. |
| `SSH_KEYS_DIR` | `/app/keys` | Per-key working directory (preserved). |
| `RUST_LOG` | `info` | Log filter (telemetry crate). |

## DB / streams

- **No DB writes.** The v1 engine kept certs in an in-memory dict
  (`_load_existing_data` was a stub) and there is **no ssh-cert table in the
  live schema**. This port preserves the in-memory model (`store.rs`). Durable
  storage would need a new migration in a later phase.
- **No stream publishes.** The v1 engine did not publish to Redis Streams.

## SSH cert parity outcome

**v1 emits INVALID certificates — verified empirically.** A faithful standalone
reproduction of v1's `_build_ssh_certificate` + `_sign_certificate_data` (run in
a `python:3.13-slim-bookworm` container with `paramiko==3.3.1`, the same CA key
and inputs) produced output that OpenSSH rejects:

```
v1_user-cert.pub:1: invalid key: unknown or unsupported key type
v1_host-cert.pub:1: invalid key: invalid format
```

Root causes in v1 (`_build_ssh_certificate`): the signed base64 blob omits the
leading cert-type string OpenSSH requires; the subject key is wrapped as one
opaque string instead of laid out as type-specific fields; the cert type is
hardcoded `ssh-rsa-cert-v01` regardless of the subject algorithm; the signature
covers the wrong byte range and is not wrapped as an SSH signature string.

**A field-by-field `ssh-keygen -L` diff against v1 is therefore impossible** —
v1 has no parseable certificate. The authoritative reference is OpenSSH's own
`ssh-keygen -s`. v2 was diffed against a golden `ssh-keygen`-signed cert (same
Ed25519 CA, same inputs, fixed serial + validity window):

- **User cert (ed25519 subject): `ssh-keygen -L` byte-identical to golden.**
- **Host cert (rsa subject): `ssh-keygen -L` byte-identical to golden.**
- Matched: cert type, subject/CA fingerprints, key id, serial, valid
  from/to, principals, critical options, extensions.
- v2 certs also pass `Certificate::verify_signature()` and `validate_at()`
  (unit-tested) — signature cryptographically valid and CA-trusted.

The parity run drives the **real** `SshCa::load_or_generate` + `sign` code path
(gated test `ca::tests::emit_parity_certs_when_requested`).

## v1 defects found (port decisions — do NOT replicate)

1. **Broken cert encoding** — v1's hand-rolled `_build_ssh_certificate` emits
   certs `ssh-keygen -L` cannot parse (see above). DECISION: replaced wholesale
   with the `ssh-key` crate; v2 output is byte-identical to `ssh-keygen`.
2. **RSA CA keys** — v1 used RSA (paramiko RSAKey, 2048). The pinned
   `ssh-key = 0.6.7` has an upstream bug (`src/private/rsa.rs`: RSA private-key
   reconstruction passes prime `p` twice instead of `p`/`q`), so **RSA CA
   signing always errors** ("cryptographic error"). 0.7.0 (likely fixed) is a
   pre-release (forbidden by pinning rules). DECISION: v2 requires an
   Ed25519 (or ECDSA) CA key and rejects RSA CA keys at startup. Since v1's
   RSA certs were invalid anyway, no production RSA CA was issuing valid certs —
   this is a security-forward requirement, not a regression. Revisit RSA when
   ssh-key 0.7 is stable.
3. **Cert type hardcoded** — v1 always wrote `ssh-rsa-cert-v01@openssh.com`
   regardless of subject key type. DECISION: derive from the subject (correct).
4. **Non-standard fingerprints** — v1 `ca_fingerprint` was hex of sha256 of the
   public blob. DECISION: standard OpenSSH `SHA256:<base64>`.
5. **`source_address`/`force_command` dropped** — accepted by the v1 request
   dataclass but ignored by the builder. DECISION: mapped to the OpenSSH
   `source-address`/`force-command` critical options.
6. **Empty user extensions** — v1's engine defaulted to no extensions,
   producing certs that cannot even allocate a pty. DECISION: user certs
   default to the 5 OpenSSH-standard `permit-*` extensions when the request
   omits `extensions` (explicit `{}` still yields none).
7. **No persistence** — `_load_existing_data` was a stub; certs lived only in
   memory. DECISION: preserved (no ssh-cert table exists); durable storage is a
   later-phase migration.
8. **500 leaks `str(e)`** — v1 pki-server ssh.py returned the raw exception on
   500. DECISION: v2 logs the cause, returns `{"error":"Internal Server Error"}`.
