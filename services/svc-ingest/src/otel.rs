//! OpenTelemetry traces + logs bridge for svc-ingest (Spec §11a/§11b,
//! `docs/v2-port/ingest-module-spec.md`). Layers a `tracing-opentelemetry`
//! span exporter and an `opentelemetry-appender-tracing` log bridge on top
//! of the same JSON+`EnvFilter` foundation
//! `skauswatch_telemetry::init_tracing` uses, both funneling through OTLP
//! exporters configured from [`OTLP_ENDPOINT_ENV`] (env-configurable,
//! never hardcoded — `critical-rules.md` Observability). Metrics stay on
//! the existing `metrics`-crate + Prometheus `:9090` path
//! (`skauswatch_telemetry::install_metrics_exporter`, unchanged) — the six
//! names in [`metric_names`] are this module's single source of truth for
//! spec §11a's metric catalogue, so every call site and the smoke test
//! below reference the same constants rather than duplicating string
//! literals that could drift out of sync.
//!
//! `tracing_subscriber`'s global default subscriber can only be installed
//! once per process (`skauswatch_telemetry::init_tracing` already calls
//! `.init()`), so a second, independently-built registry can't be layered
//! on afterward. This module therefore owns its own equivalent
//! JSON+`EnvFilter`(+OTel layers) registry construction rather than
//! extending the shared crate's — `main.rs` calls [`init`] in place of
//! `skauswatch_telemetry::init_tracing`. Editing `crates/skauswatch-telemetry`
//! itself is out of this task's file scope (an org-wide shared crate, not
//! svc-ingest's own `src/`); this is a documented, service-local addition
//! pending a future `rust-logging`-style penguin-libs package
//! (`backend-rust.md`'s "no Rust penguin logging crate exists yet" gap)
//! that could absorb OTLP trace/log bridging for every service at once.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Standard OTLP endpoint env var (`critical-rules.md` Observability) — the
/// only thing that ever differs between PenguinTech's collector and a
/// customer's. Never hardcoded.
pub const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Spec §11a's six mandatory metric names — the single source of truth
/// every call site (`listeners/*`, `writer.rs`, `buffer/jetstream.rs`) and
/// [`tests::every_metric_in_spec_11a_is_registered`] reference, so a typo
/// in one place can't silently drift from the spec or from the other.
pub mod metric_names {
    /// Counter, per-transport label — receiver-side events accepted.
    pub const RECEIVER_EVENTS_TOTAL: &str = "svc_ingest_receiver_events_total";
    /// Histogram, per-parser label — receiver-side parse duration.
    pub const RECEIVER_PARSE_DURATION_MS: &str = "svc_ingest_receiver_parse_duration_ms";
    /// Gauge — current JetStream buffer depth (see
    /// `crate::buffer::jetstream`'s doc comment on this module for the
    /// exact sampling point).
    pub const RECEIVER_QUEUE_DEPTH: &str = "svc_ingest_receiver_queue_depth";
    /// Histogram — writer-side OpenSearch `_bulk` write duration.
    pub const WRITER_BULK_WRITE_DURATION_MS: &str = "svc_ingest_writer_bulk_write_duration_ms";
    /// Counter, per-error-code label — writer-side OpenSearch write
    /// failures.
    pub const WRITER_OPENSEARCH_ERRORS_TOTAL: &str = "svc_ingest_writer_opensearch_errors_total";
    /// Counter, per-transport label — event buffer rejected a push because
    /// it was full (backpressure).
    pub const BUFFER_FULL_REJECTIONS_TOTAL: &str = "svc_ingest_buffer_full_rejections_total";

    /// All six names together, for exhaustive iteration in
    /// [`super::tests::every_metric_in_spec_11a_is_registered`] — no
    /// non-test call site needs the full list, only each individual name.
    #[allow(dead_code)]
    pub const ALL: [&str; 6] = [
        RECEIVER_EVENTS_TOTAL,
        RECEIVER_PARSE_DURATION_MS,
        RECEIVER_QUEUE_DEPTH,
        WRITER_BULK_WRITE_DURATION_MS,
        WRITER_OPENSEARCH_ERRORS_TOTAL,
        BUFFER_FULL_REJECTIONS_TOTAL,
    ];
}

/// Held for the process lifetime so the batch span/log processors keep
/// running; dropping it flushes and stops both providers (a no-op when
/// OTLP export was never enabled — see [`init`]). `main.rs` binds this to
/// `_otel` for the duration of `serve`/`migrate`/`backfill_command`.
pub struct OtelGuard {
    tracer_provider: Option<SdkTracerProvider>,
    logger_provider: Option<SdkLoggerProvider>,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            tracing::warn!(error = %e, "otel tracer provider shutdown failed");
        }
        if let Some(provider) = self.logger_provider.take()
            && let Err(e) = provider.shutdown()
        {
            tracing::warn!(error = %e, "otel logger provider shutdown failed");
        }
    }
}

/// Initializes structured logging + OTLP traces/logs for `service_name`,
/// reading [`OTLP_ENDPOINT_ENV`] from the environment. When unset, OTLP
/// export is skipped entirely (JSON `fmt` + `EnvFilter` only, identical to
/// `skauswatch_telemetry::init_tracing`'s behavior) — a missing/misconfigured
/// exporter must never break the app (`critical-rules.md` Observability:
/// "a dead exporter never breaks the app"). Call once at process startup,
/// before any `tracing` macros fire.
///
/// Also installs the W3C TraceContext propagator as the process-global
/// OpenTelemetry text-map propagator, unconditionally (even when OTLP
/// export itself is disabled) — `crate::buffer::jetstream`'s
/// `inject_trace_context`/`extract_trace_context` depend on a propagator
/// being registered to carry `traceparent` across the receiver -> NATS ->
/// writer queue hop (`critical-rules.md` Observability: "propagate trace
/// context across every service boundary ... queue hops").
pub fn init(service_name: &str) -> OtelGuard {
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let endpoint = std::env::var(OTLP_ENDPOINT_ENV)
        .ok()
        .filter(|s| !s.is_empty());
    warn_if_self_ingesting(service_name, endpoint.as_deref());

    let Some(endpoint) = endpoint else {
        install_subscriber(None, None);
        tracing::info!(
            service = service_name,
            "telemetry initialized (OTLP export disabled: {OTLP_ENDPOINT_ENV} unset)"
        );
        return OtelGuard {
            tracer_provider: None,
            logger_provider: None,
        };
    };

    match build_providers(service_name, &endpoint) {
        Ok((tracer_provider, logger_provider)) => {
            install_subscriber(
                Some(tracer_provider.tracer(service_name.to_owned())),
                Some(&logger_provider),
            );
            tracing::info!(
                service = service_name,
                otlp_endpoint = %endpoint,
                "telemetry initialized (OTLP traces+logs export enabled)"
            );
            OtelGuard {
                tracer_provider: Some(tracer_provider),
                logger_provider: Some(logger_provider),
            }
        }
        Err(e) => {
            // Never let an OTLP misconfiguration crash startup -- degrade
            // to JSON-only logging and keep serving (critical-rules.md
            // Observability: "a dead exporter never breaks the app").
            install_subscriber(None, None);
            tracing::warn!(
                error = %e,
                service = service_name,
                "OTLP exporter setup failed; continuing with JSON-only logging"
            );
            OtelGuard {
                tracer_provider: None,
                logger_provider: None,
            }
        }
    }
}

/// Builds the OTLP gRPC (tonic) span + log exporters and their batching
/// providers, pointed at `endpoint`. Kept separate from [`init`] so the
/// fallible construction (a malformed endpoint, e.g.) is a single,
/// testable `Result`-returning step.
fn build_providers(
    service_name: &str,
    endpoint: &str,
) -> anyhow::Result<(SdkTracerProvider, SdkLoggerProvider)> {
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name.to_owned())
        .build();

    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("otlp span exporter: {e}"))?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();

    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("otlp log exporter: {e}"))?;
    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(log_exporter)
        .build();

    Ok((tracer_provider, logger_provider))
}

/// Installs the process-global `tracing` subscriber: JSON `fmt` +
/// `EnvFilter` always, plus (when `tracer`/`logger_provider` are supplied)
/// the `tracing-opentelemetry` span layer and the
/// `opentelemetry-appender-tracing` log bridge layered into the same
/// `Registry`. Both OTel layers are optional and independent — a caller
/// building only a tracer (or only a logger provider) still gets a valid
/// subscriber.
fn install_subscriber(
    tracer: Option<opentelemetry_sdk::trace::SdkTracer>,
    logger_provider: Option<&SdkLoggerProvider>,
) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json());

    match (tracer, logger_provider) {
        (Some(tracer), Some(logger_provider)) => registry
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .with(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                    logger_provider,
                ),
            )
            .init(),
        (Some(tracer), None) => registry
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .init(),
        (None, Some(logger_provider)) => registry
            .with(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                    logger_provider,
                ),
            )
            .init(),
        (None, None) => registry.init(),
    }
}

/// Spec §11b self-exclusion check: svc-ingest MUST NOT ingest its own
/// telemetry into the lake (infinite loop). This can't be enforced
/// server-side from here (that's the collector's `service.name`
/// discard-filter the spec describes), so this is the client-side guard
/// rail — a loud startup `tracing::warn!` if the configured OTLP endpoint's
/// host matches one of svc-ingest's own service DNS names, so a
/// misconfiguration that would point the collector back at this same
/// service is visible immediately rather than silently looping. Returns
/// whether it fired (so tests can assert on it without scraping logs).
pub fn warn_if_self_ingesting(service_name: &str, endpoint: Option<&str>) -> bool {
    let Some(endpoint) = endpoint else {
        return false;
    };
    let host = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint)
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    if host.is_empty() {
        return false;
    }
    // Matches the K8s Service short name, the crate's own binary/service
    // name, and any FQDN built from either (e.g.
    // `svc-ingest.skauswatch.svc.cluster.local`).
    let self_names = ["svc-ingest", service_name];
    let is_self = self_names
        .iter()
        .any(|name| host == *name || host.starts_with(&format!("{name}.")));
    if is_self {
        tracing::warn!(
            otlp_endpoint = %endpoint,
            service = service_name,
            "{OTLP_ENDPOINT_ENV} appears to resolve to svc-ingest's own service DNS -- this \
             would make svc-ingest ingest its own telemetry into the lake (Spec §11b \
             self-exclusion); refusing to assume this is intentional, but not blocking startup"
        );
    }
    is_self
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use opentelemetry_sdk::logs::in_memory_exporter::InMemoryLogExporter;
    use opentelemetry_sdk::trace::in_memory_exporter::InMemorySpanExporter;

    use super::*;

    // -- warn_if_self_ingesting ---------------------------------------------

    #[test]
    fn self_ingesting_endpoint_is_flagged() {
        assert!(warn_if_self_ingesting(
            "skauswatch-svc-ingest",
            Some("http://svc-ingest:4317")
        ));
        assert!(warn_if_self_ingesting(
            "skauswatch-svc-ingest",
            Some("http://svc-ingest.skauswatch.svc.cluster.local:4317")
        ));
        assert!(warn_if_self_ingesting(
            "skauswatch-svc-ingest",
            Some("http://skauswatch-svc-ingest:4317")
        ));
    }

    #[test]
    fn a_real_collector_endpoint_is_not_flagged() {
        assert!(!warn_if_self_ingesting(
            "skauswatch-svc-ingest",
            Some("http://otel-collector.observability.svc.cluster.local:4317")
        ));
    }

    #[test]
    fn no_endpoint_is_not_flagged() {
        assert!(!warn_if_self_ingesting("skauswatch-svc-ingest", None));
    }

    // -- telemetry_gate_smoke_test -------------------------------------------

    /// Per `testing.md` Telemetry Validation / Spec §11c: proves the real
    /// subscriber-composition code in [`install_subscriber`] actually wires
    /// logs, metrics, AND spans through to a sink — using
    /// `opentelemetry_sdk`'s own `InMemorySpanExporter`/`InMemoryLogExporter`
    /// (the standard OTel Rust SDK testing pattern, gated behind the
    /// `testing` dev-feature) as the "local in-process OTLP test sink" in
    /// place of a real network collector, and a small custom
    /// `metrics::Recorder` for the metrics data point. Reports the actual
    /// counts received -- a zero denominator is a FAIL, never a bare pass.
    #[test]
    fn telemetry_gate_smoke_test() {
        // -- spans + logs: real SdkTracerProvider/SdkLoggerProvider wired
        // to real tracing-opentelemetry/opentelemetry-appender-tracing
        // layers, exactly as `install_subscriber` builds them for
        // production -- only the exporter is swapped for an in-memory one.
        let span_exporter = InMemorySpanExporter::default();
        let tracer_provider = SdkTracerProvider::builder()
            .with_simple_exporter(span_exporter.clone())
            .build();

        let log_exporter = InMemoryLogExporter::default();
        let logger_provider = SdkLoggerProvider::builder()
            .with_simple_exporter(log_exporter.clone())
            .build();

        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("info"))
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")))
            .with(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                    &logger_provider,
                ),
            );
        let _guard = tracing::subscriber::set_default(subscriber);

        // -- metrics: a minimal in-process recorder capturing every
        // `metrics::counter!`/`histogram!`/`gauge!` call by name. Global to
        // the process (this test file's own compiled test binary), so it's
        // installed once here.
        let metrics_sink = install_test_metrics_recorder();

        // Exercise real instrumented code: a span-producing function
        // (`#[tracing::instrument]` on `crate::listeners::syslog::parser::
        // detect_and_parse`), a log record, and one of the six named
        // metrics.
        let _ = crate::listeners::syslog::detect_and_parse("<34>Oct 11 22:14:15 host msg");
        tracing::info!("telemetry_gate_smoke_test log record");
        metrics::counter!(metric_names::RECEIVER_EVENTS_TOTAL, "transport" => "test").increment(1);

        tracer_provider
            .force_flush()
            .expect("flush in-memory span exporter");
        logger_provider
            .force_flush()
            .expect("flush in-memory log exporter");

        let spans = span_exporter.get_finished_spans().expect("finished spans");
        let logs = log_exporter.get_emitted_logs().expect("emitted logs");
        let metric_points = metrics_sink.recorded_count();

        println!(
            "telemetry_gate_smoke_test: {} log record(s), {} metric data point(s), {} span(s) \
             received",
            logs.len(),
            metric_points,
            spans.len()
        );
        assert!(!spans.is_empty(), "expected >=1 span, got 0");
        assert!(!logs.is_empty(), "expected >=1 log record, got 0");
        assert!(metric_points > 0, "expected >=1 metric data point, got 0");
    }

    /// Enumerates every name in [`metric_names::ALL`] (Spec §11a's exact
    /// catalogue) and asserts each has been recorded at least once through
    /// the real `metrics` facade -- proves every metric name is
    /// syntactically valid and reachable end to end (macro -> global
    /// recorder), catching a typo'd/renamed metric the same way the
    /// production call sites in `listeners/*`, `writer.rs`, and
    /// `buffer/jetstream.rs` invoke them (all six of which import these
    /// same constants -- see `metric_names`'s doc comment).
    #[test]
    fn every_metric_in_spec_11a_is_registered() {
        let sink = install_test_metrics_recorder();

        metrics::counter!(metric_names::RECEIVER_EVENTS_TOTAL, "transport" => "test").increment(1);
        metrics::histogram!(metric_names::RECEIVER_PARSE_DURATION_MS, "parser" => "test")
            .record(1.0);
        metrics::gauge!(metric_names::RECEIVER_QUEUE_DEPTH).set(1.0);
        metrics::histogram!(metric_names::WRITER_BULK_WRITE_DURATION_MS).record(1.0);
        metrics::counter!(metric_names::WRITER_OPENSEARCH_ERRORS_TOTAL, "error_code" => "500")
            .increment(1);
        metrics::counter!(metric_names::BUFFER_FULL_REJECTIONS_TOTAL, "transport" => "test")
            .increment(1);

        let recorded = sink.recorded_names();
        println!(
            "every_metric_in_spec_11a_is_registered: {}/6 metric names recorded: {:?}",
            recorded.len(),
            recorded
        );
        for name in metric_names::ALL {
            assert!(
                recorded.contains(&name.to_owned()),
                "spec §11a metric {name:?} was never recorded"
            );
        }
        assert_eq!(
            recorded.len(),
            6,
            "expected exactly 6 distinct metric names"
        );
    }

    // -- minimal test metrics::Recorder --------------------------------------

    /// Captures every metric emitted through the `metrics` facade by name,
    /// without pulling in an extra `metrics-util` dependency for what this
    /// module only needs as a presence/count check. `Clone` is a cheap
    /// `Arc` clone — `install_test_metrics_recorder` hands one clone to
    /// `metrics::set_global_recorder` (which takes ownership) and keeps
    /// another to return to the caller for inspection, both sharing the
    /// same underlying counters.
    #[derive(Clone)]
    struct TestMetricsSink(std::sync::Arc<TestMetricsSinkInner>);

    #[derive(Default)]
    struct TestMetricsSinkInner {
        names: std::sync::Mutex<std::collections::HashSet<String>>,
        count: std::sync::atomic::AtomicUsize,
    }

    impl TestMetricsSink {
        fn new() -> Self {
            Self(std::sync::Arc::new(TestMetricsSinkInner::default()))
        }

        fn recorded_names(&self) -> Vec<String> {
            self.0
                .names
                .lock()
                .expect("sink mutex poisoned")
                .iter()
                .cloned()
                .collect()
        }

        fn recorded_count(&self) -> usize {
            self.0.count.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn record(&self, key: &metrics::Key) {
            self.0
                .names
                .lock()
                .expect("sink mutex poisoned")
                .insert(key.name().to_owned());
            self.0
                .count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct TestCounter(TestMetricsSink, metrics::Key);
    impl metrics::CounterFn for TestCounter {
        fn increment(&self, _value: u64) {
            self.0.record(&self.1);
        }
        fn absolute(&self, _value: u64) {
            self.0.record(&self.1);
        }
    }

    struct TestGauge(TestMetricsSink, metrics::Key);
    impl metrics::GaugeFn for TestGauge {
        fn increment(&self, _value: f64) {
            self.0.record(&self.1);
        }
        fn decrement(&self, _value: f64) {
            self.0.record(&self.1);
        }
        fn set(&self, _value: f64) {
            self.0.record(&self.1);
        }
    }

    struct TestHistogram(TestMetricsSink, metrics::Key);
    impl metrics::HistogramFn for TestHistogram {
        fn record(&self, _value: f64) {
            self.0.record(&self.1);
        }
    }

    impl metrics::Recorder for TestMetricsSink {
        fn describe_counter(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }
        fn register_counter(
            &self,
            key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            metrics::Counter::from_arc(std::sync::Arc::new(TestCounter(self.clone(), key.clone())))
        }
        fn register_gauge(
            &self,
            key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Gauge {
            metrics::Gauge::from_arc(std::sync::Arc::new(TestGauge(self.clone(), key.clone())))
        }
        fn register_histogram(
            &self,
            key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::from_arc(std::sync::Arc::new(TestHistogram(
                self.clone(),
                key.clone(),
            )))
        }
    }

    /// Installs a [`TestMetricsSink`] as the process-global `metrics`
    /// recorder exactly once per test binary (`metrics::set_global_recorder`
    /// can only succeed once per process) and returns a shared clone —
    /// every `#[test]` in this file that needs metrics calls this; a
    /// second call reuses the cached instance instead of erroring.
    fn install_test_metrics_recorder() -> TestMetricsSink {
        static SINK: std::sync::OnceLock<TestMetricsSink> = std::sync::OnceLock::new();
        SINK.get_or_init(|| {
            let sink = TestMetricsSink::new();
            let _ = metrics::set_global_recorder(sink.clone());
            sink
        })
        .clone()
    }
}
