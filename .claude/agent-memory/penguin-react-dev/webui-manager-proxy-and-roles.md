---
name: webui-manager-proxy-and-roles
description: webui proxy routing to the manager backend, and the super_admin role value returned by /auth/me
metadata:
  type: project
---

**Proxy routing** (`services/webui/src/server/index.ts`): `/api/vault/*` and
`/api/codescan/*` proxy to their own backends (prefix stripped); everything
else under `/api/*` proxies to the manager backend
(`MANAGER_URL`/`config.managerUrl`) with `pathRewrite: {'^/api': '/api/v1'}`.
So any new "core" admin endpoint (auth, users, tenants, spire, svid-ttl,
license, etc.) lives on the manager backend and is called client-side via
the shared `api` client (baseURL `/api/v1`) using a path relative to that,
e.g. `api.get('/admin/svid-ttl')` — same convention as `usersApi.list()`
calling `/users`.

**`super_admin` role**: the manager backend (`services/manager/src/auth/
mod.rs`, `routes/tenants.rs`) has a `super_admin` role value distinct from
`admin`/`maintainer`/`viewer` — DB-only provisioned, never settable via the
public `/users` API, returned as-is in `/auth/me`'s `role` field. The
webui's `UserRole` type (`src/client/types/index.ts`) originally only had
`admin | maintainer | viewer`; it now also includes `super_admin` (widened
2026-07-31 for the SVID TTL settings feature). `useAuth()`
(`src/client/hooks/useAuth.ts`) exposes `isSuperAdmin()` alongside the
existing `isAdmin()`/`isMaintainer()`/`isViewer()`.

**Why:** neither fact is discoverable by reading a single file — the proxy
mapping requires reading `server/index.ts`, and the role value only shows up
in the Rust manager backend, not anywhere in the webui's own type
definitions until this change.

**How to apply:** for any future super-admin-only UI control in webui, reuse
`useAuth().isSuperAdmin()` rather than re-deriving it, and route new
manager-backed admin endpoints through the plain `api` client with a
`/admin/...`-style relative path — never a bare fetch, never assume a
separate proxy prefix is needed.
