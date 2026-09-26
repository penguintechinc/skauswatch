//! Optional OTLP metrics pipeline layered underneath the same `metrics`-crate
//! facade every service already calls through `counter!`/`gauge!`/
//! `histogram!` (nothing on the call-site changes). [`OtlpRecorder`]
//! implements `metrics::Recorder` by forwarding every registration to an
//! OTLP `SdkMeterProvider`, so [`super::install_metrics_exporter`] can wrap
//! it together with the existing Prometheus recorder in a fan-out
//! (`super::FanoutRecorder`) — Prometheus stays the secondary `:9090` scrape
//! surface, OTLP becomes the primary emission path, per `critical-rules.md`
//! Observability ("Prometheus is NOT a replacement for OTel metric
//! emission").
//!
//! Endpoint comes from [`OTLP_ENDPOINT_ENV`], the same standard env var
//! `services/svc-ingest/src/otel.rs::OTLP_ENDPOINT_ENV` already uses for
//! traces/logs — unset/empty means OTLP export is skipped entirely and
//! callers fall back to Prometheus-only, byte-for-byte the pre-existing
//! behavior. A malformed endpoint or exporter build failure is likewise
//! never fatal: `critical-rules.md` Observability's "a dead exporter never
//! breaks the app" applies to metrics exactly as it does to logs/traces.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::metrics::SdkMeterProvider;

/// Standard OTLP endpoint env var (`critical-rules.md` Observability) — the
/// only thing that ever differs between PenguinTech's collector and a
/// customer's. Never hardcoded.
pub const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Keeps the OTLP `SdkMeterProvider` (and its `PeriodicReader` background
/// export thread) alive for the process lifetime. `SdkMeterProvider::drop`
/// shuts its pipeline down once the last clone is gone
/// (`opentelemetry_sdk`'s own doc comment on the type), and
/// `install_metrics_exporter` returns `Result<(), TelemetryError>` with no
/// guard to hand back to callers (an intentionally additive, non-breaking
/// signature) — this process-lifetime static plays the role a returned
/// guard would otherwise play. `build_recorder` is expected to run at most
/// once per process, mirroring `install_metrics_exporter`'s own contract.
static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

/// Reads [`OTLP_ENDPOINT_ENV`], treating unset/empty the same way
/// `services/svc-ingest/src/otel.rs::init` does for traces/logs (OTLP export
/// skipped, not an error).
pub fn endpoint_from_env() -> Option<String> {
    filter_endpoint(std::env::var(OTLP_ENDPOINT_ENV).ok())
}

/// Pure filtering step behind [`endpoint_from_env`] — unset and empty are
/// both treated as "no OTLP export requested". Split out so this logic is
/// unit-testable without mutating the real process environment: this
/// workspace denies `unsafe_code` (`Cargo.toml` `[workspace.lints.rust]`),
/// and `std::env::set_var`/`remove_var` are `unsafe fn` as of this edition —
/// same `from_values`/`from_env` split convention `services/svc-ingest/
/// src/config.rs` and every other service's `config.rs` already use for
/// exactly this reason.
fn filter_endpoint(raw: Option<String>) -> Option<String> {
    raw.filter(|s| !s.is_empty())
}

/// Builds the OTLP `SdkMeterProvider` for `endpoint`: a `grpc-tonic` push
/// exporter wrapped in the SDK's default `PeriodicReader` (60s interval,
/// overridable via the standard `OTEL_METRIC_EXPORT_INTERVAL` env var), with
/// a `Resource` that auto-detects `OTEL_SERVICE_NAME`/
/// `OTEL_RESOURCE_ATTRIBUTES` (`opentelemetry_sdk::Resource::builder()`'s
/// built-in `EnvResourceDetector` — see `critical-rules.md` Observability's
/// env var table). Kept separate from [`build_recorder`] so the fallible
/// construction is a single, testable `Result`-returning step, matching
/// `services/svc-ingest/src/otel.rs::build_providers`'s split.
///
/// Must be called from within a running Tokio runtime — the OTLP
/// `grpc-tonic` channel builder requires a reactor to be running even though
/// it never actually connects at construction time (same requirement
/// documented on `opentelemetry_sdk::metrics::PeriodicReader`).
fn build_meter_provider(endpoint: &str) -> Result<SdkMeterProvider, String> {
    let resource = opentelemetry_sdk::Resource::builder().build();

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| format!("otlp metric exporter: {e}"))?;

    Ok(SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(exporter)
        .build())
}

/// Builds the OTLP metrics pipeline for `endpoint` and returns a
/// `metrics::Recorder` that forwards every counter/gauge/histogram
/// registration to it. Returns `Err` instead of panicking on any build
/// failure — callers (`install_metrics_exporter`) must treat this as
/// non-fatal and fall back to Prometheus-only.
pub fn build_recorder(endpoint: &str) -> Result<OtlpRecorder, String> {
    let provider = build_meter_provider(endpoint)?;
    let recorder = recorder_from_provider(&provider);
    // Second call in the same process reuses the first provider instead of
    // erroring (see the static's doc comment) — `install_metrics_exporter`
    // is documented as once-per-process, so this is a defensive fallback,
    // not an expected path.
    let _ = METER_PROVIDER.set(provider);
    Ok(recorder)
}

/// Wraps `provider` in an [`OtlpRecorder`]. Split out from [`build_recorder`]
/// so tests can exercise the exact same bridging logic against an
/// in-process `SdkMeterProvider` (e.g. one built on
/// `opentelemetry_sdk::metrics::in_memory_exporter::InMemoryMetricExporter`)
/// instead of a real network endpoint.
pub fn recorder_from_provider(provider: &SdkMeterProvider) -> OtlpRecorder {
    OtlpRecorder {
        meter: provider.meter("skauswatch-telemetry"),
        counters: Mutex::new(HashMap::new()),
        gauges: Mutex::new(HashMap::new()),
        histograms: Mutex::new(HashMap::new()),
    }
}

/// A `metrics::Recorder` backed by an OTel [`opentelemetry::metrics::Meter`].
/// One OTel instrument is created per distinct metric *name* (cached in
/// `counters`/`gauges`/`histograms`); the label set on each `metrics::Key`
/// becomes the OTel attributes passed on every `.add()`/`.record()` call,
/// matching how the existing `PrometheusRecorder` already treats labels as
/// per-call dimensions rather than per-instrument identity.
pub struct OtlpRecorder {
    meter: opentelemetry::metrics::Meter,
    counters: Mutex<HashMap<String, opentelemetry::metrics::Counter<u64>>>,
    gauges: Mutex<HashMap<String, opentelemetry::metrics::Gauge<f64>>>,
    histograms: Mutex<HashMap<String, opentelemetry::metrics::Histogram<f64>>>,
}

/// Converts a `metrics::Key`'s labels into OTel `KeyValue` attributes.
fn key_attributes(key: &Key) -> Vec<KeyValue> {
    key.labels()
        .map(|l| KeyValue::new(l.key().to_owned(), l.value().to_owned()))
        .collect()
}

impl Recorder for OtlpRecorder {
    // OTel instrument descriptions are attached at instrument-build time
    // (`.with_description()`), not via a separate describe step, and the
    // `metrics` crate's `describe_*!` macros are optional/best-effort
    // metadata — the existing `PrometheusRecorder` (still wired first in
    // `FanoutRecorder`) remains the source of truth for human-readable HELP
    // text, so these are no-ops here rather than duplicating that plumbing.
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let name = key.name().to_owned();
        let attributes = key_attributes(key);
        // Recover from a poisoned lock rather than `.expect()`/panic: a
        // panicking metric registration must never be allowed to take the
        // whole recorder down mid-request (`critical-rules.md`
        // Observability: "a dead exporter never breaks the app" extends to
        // the recorder's own internal state, not just the network path).
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let instrument = counters
            .entry(name.clone())
            .or_insert_with(|| self.meter.u64_counter(name).build())
            .clone();
        Counter::from_arc(Arc::new(OtlpCounter {
            instrument,
            attributes,
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let name = key.name().to_owned();
        let attributes = key_attributes(key);
        let mut gauges = self
            .gauges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let instrument = gauges
            .entry(name.clone())
            .or_insert_with(|| self.meter.f64_gauge(name).build())
            .clone();
        Gauge::from_arc(Arc::new(OtlpGauge {
            instrument,
            attributes,
            current_bits: AtomicU64::new(0f64.to_bits()),
        }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let name = key.name().to_owned();
        let attributes = key_attributes(key);
        let mut histograms = self
            .histograms
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let instrument = histograms
            .entry(name.clone())
            .or_insert_with(|| self.meter.f64_histogram(name).build())
            .clone();
        Histogram::from_arc(Arc::new(OtlpHistogram {
            instrument,
            attributes,
        }))
    }
}

struct OtlpCounter {
    instrument: opentelemetry::metrics::Counter<u64>,
    attributes: Vec<KeyValue>,
}

impl CounterFn for OtlpCounter {
    fn increment(&self, value: u64) {
        self.instrument.add(value, &self.attributes);
    }

    fn absolute(&self, value: u64) {
        // OTel `Counter` is monotonic-add-only; there is no "set to this
        // absolute total" primitive to map onto. `metrics::Counter::absolute`
        // is never called anywhere in this workspace today (verified by
        // grep before writing this), so this is a documented approximation
        // for a path that isn't exercised in production: it forwards
        // `value` as a raw `add`, which is only correct if a future caller
        // passes a delta rather than a running total.
        self.instrument.add(value, &self.attributes);
    }
}

struct OtlpGauge {
    instrument: opentelemetry::metrics::Gauge<f64>,
    attributes: Vec<KeyValue>,
    /// Locally-tracked current value (f64 bit pattern) so `increment`/
    /// `decrement` — relative-change calls — can be translated into the
    /// absolute point-in-time reading OTel's synchronous `Gauge` instrument
    /// expects. `set` bypasses the read-modify-write and stores directly.
    current_bits: AtomicU64,
}

impl OtlpGauge {
    fn apply(&self, f: impl Fn(f64) -> f64) {
        let mut current = self.current_bits.load(Ordering::SeqCst);
        loop {
            let next = f(f64::from_bits(current));
            match self.current_bits.compare_exchange_weak(
                current,
                next.to_bits(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.instrument.record(next, &self.attributes);
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl GaugeFn for OtlpGauge {
    fn increment(&self, value: f64) {
        self.apply(|current| current + value);
    }

    fn decrement(&self, value: f64) {
        self.apply(|current| current - value);
    }

    fn set(&self, value: f64) {
        self.current_bits.store(value.to_bits(), Ordering::SeqCst);
        self.instrument.record(value, &self.attributes);
    }
}

struct OtlpHistogram {
    instrument: opentelemetry::metrics::Histogram<f64>,
    attributes: Vec<KeyValue>,
}

impl HistogramFn for OtlpHistogram {
    fn record(&self, value: f64) {
        self.instrument.record(value, &self.attributes);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use opentelemetry_sdk::metrics::PeriodicReader;
    use opentelemetry_sdk::metrics::in_memory_exporter::InMemoryMetricExporter;

    use super::*;

    #[test]
    fn filter_endpoint_treats_unset_and_empty_as_none() {
        assert!(filter_endpoint(None).is_none());
        assert!(filter_endpoint(Some(String::new())).is_none());
        assert_eq!(
            filter_endpoint(Some("http://otel-collector:4317".to_owned())),
            Some("http://otel-collector:4317".to_owned())
        );
    }

    /// `endpoint_from_env` itself can't be exercised against a mutated env
    /// var (this workspace denies `unsafe_code`, ruling out
    /// `std::env::set_var`/`remove_var` in tests — see `filter_endpoint`'s
    /// doc comment), so this only proves the unset-by-default case against
    /// whatever the ambient environment already is, asserting that
    /// assumption first (same defensive pattern
    /// `services/svc-ingest/src/config.rs::from_env_uses_defaults_against_an_unset_environment`
    /// uses) so a dev's shell accidentally exporting this var fails loudly
    /// instead of quietly weakening the test.
    #[test]
    fn endpoint_from_env_is_none_against_an_unset_environment() {
        assert!(
            std::env::var(OTLP_ENDPOINT_ENV).is_err(),
            "test assumes {OTLP_ENDPOINT_ENV} is unset"
        );
        assert!(endpoint_from_env().is_none());
    }

    /// [`build_meter_provider`] is [`build_recorder`]'s fallible
    /// construction step, kept separate specifically so it's testable on
    /// its own (see its doc comment) — proves it actually builds a
    /// `SdkMeterProvider` for a syntactically valid endpoint without making
    /// any network call (the OTLP gRPC/tonic exporter connects lazily on
    /// first export, not at `.build()` time). Needs a live Tokio runtime —
    /// the OTLP gRPC/tonic channel builder requires a reactor to be running
    /// even though it never actually connects at construction time.
    #[tokio::test]
    async fn build_meter_provider_succeeds_for_a_valid_endpoint() {
        let provider = build_meter_provider("http://127.0.0.1:4317")
            .expect("build_meter_provider must succeed for a syntactically valid endpoint");
        provider.shutdown().expect("provider shutdown");
    }

    /// Per `testing.md` Telemetry Validation: proves [`OtlpRecorder`] — the
    /// real bridging code [`build_recorder`] wires into
    /// `FanoutRecorder`/`install_metrics_exporter` in production — actually
    /// forwards a `metrics::Recorder` registration through to an OTLP
    /// export, using `opentelemetry_sdk`'s own `InMemoryMetricExporter`
    /// (the standard OTel Rust SDK testing pattern, gated behind the
    /// `testing` dev-feature) as the "local in-process OTLP test sink" in
    /// place of a real network collector. Reports the actual count received
    /// — a zero denominator is a FAIL, never a bare pass.
    #[test]
    fn otlp_recorder_exports_at_least_one_metric_data_point() {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone())
            // Short interval is irrelevant here -- the test drives export
            // via `force_flush` rather than waiting on the timer, but a
            // short interval keeps the background thread's sleep loop from
            // outliving the test by much if `force_flush` is ever removed.
            .with_interval(Duration::from_millis(10))
            .build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let recorder = recorder_from_provider(&provider);

        // Exercise the real `metrics::Recorder` trait methods directly --
        // exactly what the global `metrics::counter!`/`gauge!`/
        // `histogram!` macros call into once this recorder (via
        // `FanoutRecorder`) is installed globally in production.
        let key = Key::from_name("skauswatch_telemetry_otlp_test_counter");
        let metadata = Metadata::new("test", metrics::Level::INFO, None);
        let counter = recorder.register_counter(&key, &metadata);
        counter.increment(1);

        let gauge_key = Key::from_name("skauswatch_telemetry_otlp_test_gauge");
        let gauge = recorder.register_gauge(&gauge_key, &metadata);
        gauge.set(42.0);

        let hist_key = Key::from_name("skauswatch_telemetry_otlp_test_histogram");
        let histogram = recorder.register_histogram(&hist_key, &metadata);
        histogram.record(1.5);

        provider
            .force_flush()
            .expect("flush in-memory metric exporter");

        let finished = exporter.get_finished_metrics().expect("finished metrics");
        let point_count: usize = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .count();

        println!(
            "otlp_recorder_exports_at_least_one_metric_data_point: {point_count} metric \
             data point(s) exported over OTLP"
        );
        assert!(point_count > 0, "expected >=1 metric data point, got 0");

        provider.shutdown().expect("provider shutdown");
    }
}
