# Memory Index

- [skauswatch tenancy retrofit pattern](project_skauswatch_tenancy_retrofit.md) — org-wide multi-tenant IDOR fix; per-service steps, design doc location, bootstrap tenant literal
- [cross-service stream tenant-shape break is expected](feedback_cross_service_stream_tenant_break.md) — fixing producer-side tenant IDOR can break an out-of-scope consumer's parsing; don't water down the fix to avoid it
- [docker build env gotchas](feedback_docker_build_env_gotchas.md) — `bash -lc` resets PATH losing cargo; `rustup component add` rejects `-q`
- [clippy expect_used per-module allow](feedback_clippy_expect_used_per_module_allow.md) — test modules need their own `#[allow(clippy::expect_used)]`; not blanket-exempted
