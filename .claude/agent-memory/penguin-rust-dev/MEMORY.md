# Memory Index

- [skauswatch tenancy retrofit pattern](project_skauswatch_tenancy_retrofit.md) — org-wide multi-tenant IDOR fix; per-service steps, design doc location, bootstrap tenant literal
- [cross-service stream tenant-shape break is expected](feedback_cross_service_stream_tenant_break.md) — fixing producer-side tenant IDOR can break an out-of-scope consumer's parsing; don't water down the fix to avoid it
- [docker build env gotchas](feedback_docker_build_env_gotchas.md) — `bash -lc` resets PATH losing cargo; `rustup component add` rejects `-q`
- [clippy expect_used per-module allow](feedback_clippy_expect_used_per_module_allow.md) — test modules need their own `#[allow(clippy::expect_used)]`; not blanket-exempted
- [no sudo for docker chown](feedback_no_sudo_for_docker_chown.md) — never `sudo chown` root-owned scratch/target dirs; use `docker run --user` or `docker exec` chown instead
- [async client ctor blocking risk](feedback_async_client_ctor_blocking_risk.md) — don't `block_on` a real async network client (aws_sdk_s3 etc.) inside a sync handler `::new()`; build it in `main.rs::serve()` and pass it in
- [streams fred nil-decode gap](project_streams_fred_nil_decode_gap.md) — FIXED 2026-08-08: fred default-nil-types feature added; read_new no longer errors on idle XREADGROUP poll
- [functions metric panic-closure ceiling](feedback_functions_metric_panic_closures.md) — `.unwrap_or_else(\|e\| panic!())` test idiom inflates Functions denominator with never-fired closures; workspace has a structural ~87% ceiling, don't chase 90% with more tests in the same style
