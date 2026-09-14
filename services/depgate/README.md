# DepGate

Self-hosted dependency firewall + cache: scans every OCI image layer, npm
tarball, and PyPI wheel/sdist on ingest (ClamAV + YARA-X via
`skauswatch-scan-core`), caches clean artifacts content-addressed, and
quarantines anything else. Full design: `docs/v2-port/v2.1-depgate.md`.

Every route below requires a SkausWatch-issued bearer JWT carrying a
`tenant` claim (`skauswatch_auth::tenant_middleware`) — configure your
client's credential store accordingly before pointing it at DepGate.

## Client setup

### npm

```
npm config set registry https://<depgate-host>/npm/
npm config set //<depgate-host>/npm/:_authToken <jwt>
```

DepGate proxies `GET /npm/{package}` (or `/npm/@{scope}/{package}`) and
rewrites every version's `dist.tarball` to `/npm/{package}/-/{filename}.tgz`
so the actual tarball fetch also routes through DepGate's scanner —
`dist.shasum`/`dist.integrity` are left untouched, so npm's own integrity
check against the original upstream-published values still applies.

### pip / uv

```
pip config set global.index-url https://<jwt>@<depgate-host>/pypi/simple/
# or: uv pip install --index-url https://<jwt>@<depgate-host>/pypi/simple/ <package>
```

DepGate proxies the PEP 503 simple index (and the legacy
`/pypi/pypi/{project}/json` API) and rewrites every package-file link to
`/pypi/packages/...`, preserving the `#sha256=<hex>` fragment (simple
index) / `digests.sha256` field (JSON API) `pip`/`uv` verify against.

### docker / OCI

Point your OCI client's registry mirror config (e.g. containerd
`hosts.toml`, or a credential helper) at `https://<depgate-host>` with the
bearer JWT as the registry credential — see `src/routes/oci.rs` module docs
for the full pull-through contract and known P1 gaps (no push, no
`docker login` challenge flow).

## Seeding the cache

```
skauswatch-depgate seed --manifest seeds/penguintech.yaml
```

Warm-starts the vetted cache from `seeds/penguintech.yaml` — OCI images,
npm packages, and PyPI packages this repo's own tooling actually depends
on (sourced from `package.json`/`services/webui/package.json` and
`tests/parity/requirements.txt`), pinned against TTL eviction. This is the
air-gap warm-start (§6b): an air-gapped deployment never needs upstream
egress for anything already seeded.

## Upstream configuration (env vars)

| Var | Default | Purpose |
|---|---|---|
| `DEPGATE_PUBLIC_BASE_URL` | `http://localhost:{API_PORT}` | This deployment's own externally-reachable base URL — used only to rewrite npm/PyPI links back at DepGate |
| `DEPGATE_UPSTREAM_BASE_URL` | `https://registry-1.docker.io` | OCI upstream registry |
| `DEPGATE_NPM_REGISTRY_URL` | `https://registry.npmjs.org` | npm upstream registry |
| `DEPGATE_NPM_TOKEN` | *(unset)* | Optional Bearer token for a private npm registry |
| `DEPGATE_PYPI_INDEX_URL` | `https://pypi.org` | PyPI simple/JSON index |
| `DEPGATE_PYPI_FILES_URL` | `https://files.pythonhosted.org` | PyPI package-file host |
| `DEPGATE_PYPI_USERNAME` / `DEPGATE_PYPI_PASSWORD` | *(unset)* | Optional Basic auth for a private index |
