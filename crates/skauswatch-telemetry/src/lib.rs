//! Telemetry bootstrap shared by all skauswatch services: JSON structured
//! logging (tracing), Prometheus metrics on :9090 (with an additive OTLP
//! metrics export path — see [`install_metrics_exporter`]), and the
//! standard `/healthz` + `/readyz` axum router required by every
//! deployment.

mod otlp_metrics;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use metrics::{Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn};
use metrics_exporter_prometheus::PrometheusRecorder;

/// Standard Prometheus metrics port for all PenguinTech services.
pub const METRICS_PORT: u16 = 9090;

/// Errors raised while bootstrapping telemetry.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The Prometheus exporter could not bind or install.
    #[error("metrics exporter error: {0}")]
    Metrics(String),
}

/// Initializes JSON structured logging with `RUST_LOG`-style env filtering.
/// Call once at service startup, before any tracing macros fire.
pub fn init_tracing(service: &str) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!(service, "telemetry initialized");
}

/// Installs the Prometheus exporter listening on `0.0.0.0:<port>`, where
/// `<port>` is read from the `METRICS_PORT` env var (defaulting to
/// [`METRICS_PORT`]). The env override exists for test harnesses that
/// co-locate multiple services on one host; production deployments run one
/// service per pod and never need to set it.
///
/// When `OTEL_EXPORTER_OTLP_ENDPOINT` (see `critical-rules.md` Observability
/// — the same standard env var already used for traces/logs) is set, the
/// global `metrics` recorder installed here ALSO fans every
/// `counter!`/`gauge!`/`histogram!` call out to an OTLP `SdkMeterProvider`
/// pointed at that endpoint — Prometheus on `:9090` remains the secondary
/// scrape surface, unchanged, exactly as before. This requires **no code
/// change in any caller**: every existing `install_metrics_exporter()` call
/// site across all ~13 services gains OTLP metrics purely from the env var
/// being set at deploy time. When the env var is unset (today's default for
/// every deployment), this function's behavior is byte-for-byte identical
/// to before this capability was added. A missing/misconfigured OTLP
/// endpoint never breaks metrics: the error is logged and this function
/// falls back to Prometheus-only rather than returning `Err`
/// (`critical-rules.md` Observability: "a dead exporter never breaks the
/// app").
///
/// Returns an error instead of panicking so callers can fail startup cleanly
/// — reserved for the Prometheus exporter itself failing to bind, which
/// remains the only failure mode this function can return, same as before.
pub fn install_metrics_exporter() -> Result<(), TelemetryError> {
    let port = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(METRICS_PORT);
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new().with_http_listener(addr);

    let Some(endpoint) = otlp_metrics::endpoint_from_env() else {
        // Unchanged fast path: OTLP disabled, install Prometheus exactly as
        // this function always has.
        return builder
            .install()
            .map_err(|e| TelemetryError::Metrics(e.to_string()));
    };

    let (prometheus_recorder, exporter_future) = builder
        .build()
        .map_err(|e| TelemetryError::Metrics(e.to_string()))?;
    spawn_prometheus_exporter(exporter_future);

    match otlp_metrics::build_recorder(&endpoint) {
        Ok(otlp_recorder) => {
            let recorder = FanoutRecorder {
                prometheus: prometheus_recorder,
                otlp: otlp_recorder,
            };
            metrics::set_global_recorder(recorder)
                .map_err(|e| TelemetryError::Metrics(e.to_string()))
        }
        Err(e) => {
            // Never let an OTLP misconfiguration break metrics -- degrade to
            // Prometheus-only and keep serving (critical-rules.md
            // Observability: "a dead exporter never breaks the app").
            tracing::warn!(
                error = %e,
                otlp_endpoint = %endpoint,
                "OTLP metrics exporter setup failed; continuing with Prometheus-only metrics"
            );
            metrics::set_global_recorder(prometheus_recorder)
                .map_err(|e| TelemetryError::Metrics(e.to_string()))
        }
    }
}

/// Spawns the Prometheus exporter's HTTP-listener future, mirroring
/// `PrometheusBuilder::install()`'s own runtime handling exactly (that
/// method is bypassed on this path since we need the `PrometheusRecorder`
/// back before installing it globally — see [`install_metrics_exporter`]).
fn spawn_prometheus_exporter<F, E>(exporter: F)
where
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Debug + Send + 'static,
{
    let exporter = async move {
        if let Err(e) = exporter.await {
            tracing::warn!(error = ?e, "prometheus exporter task exited with an error");
        }
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(exporter);
    } else {
        // Every current call site invokes `install_metrics_exporter` from
        // inside `#[tokio::main]`, so this branch is not expected to run in
        // practice; kept as a graceful fallback rather than a panic, same
        // as `PrometheusBuilder::install()` itself does.
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            std::thread::spawn(move || runtime.block_on(exporter));
        } else {
            tracing::warn!(
                "failed to create a fallback Tokio runtime for the Prometheus exporter; \
                 metrics scrape endpoint will not be served"
            );
        }
    }
}

/// Fans every `metrics::Recorder` call out to both the existing
/// `PrometheusRecorder` (`:9090`, unchanged) and an
/// [`otlp_metrics::OtlpRecorder`] (OTLP `SdkMeterProvider`) — installed as
/// the single global recorder in [`install_metrics_exporter`] once an OTLP
/// endpoint is configured. Prometheus is registered first so it keeps
/// serving even if something about the OTLP side is unhealthy at runtime.
struct FanoutRecorder {
    prometheus: PrometheusRecorder,
    otlp: otlp_metrics::OtlpRecorder,
}

impl metrics::Recorder for FanoutRecorder {
    fn describe_counter(
        &self,
        key: metrics::KeyName,
        unit: Option<metrics::Unit>,
        description: metrics::SharedString,
    ) {
        self.prometheus
            .describe_counter(key.clone(), unit, description.clone());
        self.otlp.describe_counter(key, unit, description);
    }

    fn describe_gauge(
        &self,
        key: metrics::KeyName,
        unit: Option<metrics::Unit>,
        description: metrics::SharedString,
    ) {
        self.prometheus
            .describe_gauge(key.clone(), unit, description.clone());
        self.otlp.describe_gauge(key, unit, description);
    }

    fn describe_histogram(
        &self,
        key: metrics::KeyName,
        unit: Option<metrics::Unit>,
        description: metrics::SharedString,
    ) {
        self.prometheus
            .describe_histogram(key.clone(), unit, description.clone());
        self.otlp.describe_histogram(key, unit, description);
    }

    fn register_counter(&self, key: &metrics::Key, metadata: &metrics::Metadata<'_>) -> Counter {
        let prometheus = self.prometheus.register_counter(key, metadata);
        let otlp = self.otlp.register_counter(key, metadata);
        Counter::from_arc(Arc::new(FanoutCounter(prometheus, otlp)))
    }

    fn register_gauge(&self, key: &metrics::Key, metadata: &metrics::Metadata<'_>) -> Gauge {
        let prometheus = self.prometheus.register_gauge(key, metadata);
        let otlp = self.otlp.register_gauge(key, metadata);
        Gauge::from_arc(Arc::new(FanoutGauge(prometheus, otlp)))
    }

    fn register_histogram(
        &self,
        key: &metrics::Key,
        metadata: &metrics::Metadata<'_>,
    ) -> Histogram {
        let prometheus = self.prometheus.register_histogram(key, metadata);
        let otlp = self.otlp.register_histogram(key, metadata);
        Histogram::from_arc(Arc::new(FanoutHistogram(prometheus, otlp)))
    }
}

struct FanoutCounter(Counter, Counter);
impl CounterFn for FanoutCounter {
    fn increment(&self, value: u64) {
        self.0.increment(value);
        self.1.increment(value);
    }
    fn absolute(&self, value: u64) {
        self.0.absolute(value);
        self.1.absolute(value);
    }
}

struct FanoutGauge(Gauge, Gauge);
impl GaugeFn for FanoutGauge {
    fn increment(&self, value: f64) {
        self.0.increment(value);
        self.1.increment(value);
    }
    fn decrement(&self, value: f64) {
        self.0.decrement(value);
        self.1.decrement(value);
    }
    fn set(&self, value: f64) {
        self.0.set(value);
        self.1.set(value);
    }
}

struct FanoutHistogram(Histogram, Histogram);
impl HistogramFn for FanoutHistogram {
    fn record(&self, value: f64) {
        self.0.record(value);
        self.1.record(value);
    }
}

/// Shared readiness flag: services flip this once dependencies (DB, cache,
/// license client) are up; `/readyz` reports 503 until then.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// Creates a not-yet-ready flag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the service ready to receive traffic.
    pub fn set_ready(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether the service has been marked ready.
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Builds the standard health router exposing `/healthz` (liveness, always
/// 200 once the process serves HTTP) and `/readyz` (readiness-gated).
pub fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(readiness)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(State(readiness): State<Readiness>) -> (StatusCode, Json<serde_json::Value>) {
    if readiness.is_ready() {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready" })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "not ready" })),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn healthz_is_ok_and_readyz_gates_on_flag() {
        let readiness = Readiness::new();
        let server = axum_test::TestServer::new(health_router(readiness.clone()));

        server.get("/healthz").await.assert_status_ok();
        server
            .get("/readyz")
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);

        readiness.set_ready();
        server.get("/readyz").await.assert_status_ok();
    }

    /// Per `testing.md` Telemetry Validation: proves [`FanoutRecorder`] --
    /// the real recorder `install_metrics_exporter` installs globally once
    /// an OTLP endpoint is configured -- actually reaches BOTH the
    /// `PrometheusRecorder` (`:9090` scrape text) and OTLP (via
    /// `opentelemetry_sdk`'s `InMemoryMetricExporter` standing in for a
    /// real network collector) from a single `metrics::counter!`-style
    /// call. Reports the actual counts observed on both sides -- a zero
    /// denominator on either is a FAIL, never a bare pass.
    #[test]
    fn fanout_recorder_reaches_both_prometheus_and_otlp() {
        use opentelemetry_sdk::metrics::PeriodicReader;
        use opentelemetry_sdk::metrics::in_memory_exporter::InMemoryMetricExporter;

        let prometheus_recorder =
            metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let prometheus_handle = prometheus_recorder.handle();

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone())
            .with_interval(std::time::Duration::from_millis(10))
            .build();
        let otlp_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(reader)
            .build();
        let otlp_recorder = crate::otlp_metrics::recorder_from_provider(&otlp_provider);

        let fanout = FanoutRecorder {
            prometheus: prometheus_recorder,
            otlp: otlp_recorder,
        };

        let key = metrics::Key::from_name("skauswatch_telemetry_fanout_test_counter");
        let metadata = metrics::Metadata::new("test", metrics::Level::INFO, None);
        let counter = metrics::Recorder::register_counter(&fanout, &key, &metadata);
        counter.increment(1);

        otlp_provider
            .force_flush()
            .expect("flush in-memory metric exporter");

        let rendered = prometheus_handle.render();
        assert!(
            rendered.contains("skauswatch_telemetry_fanout_test_counter"),
            "expected counter name in Prometheus scrape text, got: {rendered}"
        );

        let finished = exporter.get_finished_metrics().expect("finished metrics");
        let otlp_point_count: usize = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .count();

        println!(
            "fanout_recorder_reaches_both_prometheus_and_otlp: prometheus scrape text \
             {} byte(s) (contains metric: true), {otlp_point_count} OTLP metric data \
             point(s) exported",
            rendered.len()
        );
        assert!(
            otlp_point_count > 0,
            "expected >=1 OTLP metric data point, got 0"
        );

        otlp_provider.shutdown().expect("provider shutdown");
    }
}
