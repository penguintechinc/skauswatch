---
name: feedback-async-client-ctor-blocking-risk
description: don't build async network clients (aws_sdk_s3, etc.) inside a stream-worker handler's sync ::new() via futures::executor::block_on — construct them in the already-async main.rs::serve() and pass the built client in
metadata:
  type: feedback
---

`services/scanner/src/handler.rs`'s `ScannerHandler::new()` is sync and
already uses `futures::executor::block_on(YaraScanner::load(...))` to load
YARA rules at construction time. That specific call is lower-risk because
`YaraScanner::load` bottoms out in `tokio::fs::read`, which only needs
`Handle::current()` (available on any worker thread already inside the
runtime) via `spawn_blocking` — not Tokio's I/O reactor.

**Don't copy that pattern for anything that does real async network I/O**
(e.g. `skauswatch_s3::client()`, which calls `aws_config::defaults().load()`
and performs actual HTTP/credential-resolution calls). `block_on` provides
no I/O driver of its own; on a single-worker Tokio runtime (very plausible
in a K8s pod with a `100m/250m` CPU limit, where Tokio's default
worker-thread count derives from available parallelism) this can genuinely
deadlock — no other worker thread is left to drive the shared I/O reactor.

**How to apply:** when a stream-worker handler (`ScannerHandler` and
similar in `s3scan`/`worker-vault-sync`) needs a lazily-built async client
(S3, STS, any `aws-sdk-*`, `reqwest` with connection warmup, etc.), build
it in the caller's `main.rs::serve()` (already an `async fn`, properly
`.await`s) and pass the finished client/`Option<Client>` into `::new()` as
a plain parameter — keep `::new()` itself synchronous and free of
`block_on` for anything beyond cheap, `spawn_blocking`-backed work. This is
the pattern used for the ASM screenshot-stage S3 uploader (P12-B,
2026-08-04): `build_screenshot_uploader(&cfg).await` in `main.rs`,
`ScannerHandler::new(pool, producer, config, screenshot_uploader)` stays
sync. Every test call site that doesn't care about the feature just passes
`None`.
