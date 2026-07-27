//! SkausWatch EDR Agent binary — Rust port of v1's Go `edr-agent`
//! (`cmd/edr-agent/main.go`). CLI flags match v1's cobra command exactly so
//! existing systemd units / install scripts (`ExecStart=... --config ...`)
//! keep working unchanged.

use std::path::PathBuf;

use clap::Parser;
use tracing::error;
use tracing_subscriber::EnvFilter;

use skauswatch_edr_agent::agent;
use skauswatch_edr_agent::config::{self, CliOverrides};

/// SkausWatch EDR Agent — monitors system activity, detects security
/// threats, and reports events to the SkausWatch Manager service.
#[derive(Parser, Debug)]
#[command(name = "edr-agent", version)]
struct Cli {
    /// Config file (default: /etc/skauswatch/edr-agent.yaml, then
    /// ./edr-agent.yaml).
    #[arg(long)]
    config: Option<PathBuf>,

    /// SkausWatch Manager API URL.
    #[arg(long = "manager-url")]
    manager_url: Option<String>,

    /// Shared HMAC secret for authenticating with the manager.
    #[arg(long = "api-key")]
    api_key: Option<String>,

    /// Unique agent identifier (auto-generated if empty).
    #[arg(long = "agent-id")]
    agent_id: Option<String>,

    /// Enable debug logging.
    #[arg(long)]
    debug: bool,

    /// Runs one-shot health/config checks and exits — used by the
    /// container `HEALTHCHECK` (never `curl`, per house rules).
    #[arg(long)]
    healthcheck: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let overrides = CliOverrides {
        manager_url: cli.manager_url.clone(),
        api_key: cli.api_key.clone(),
        agent_id: cli.agent_id.clone(),
        debug: cli.debug.then_some(true),
    };
    let cfg = config::load(cli.config.as_deref(), &overrides)?;

    init_tracing(&cfg);

    if cli.healthcheck {
        // The agent has no local listener to probe; a successful config
        // load + tracing init is the healthcheck (matches v1: the agent
        // never exposed a health endpoint either). Exit 0 on success.
        return Ok(());
    }

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        if let Err(e) = agent::run(cfg).await {
            error!(error = %e, "agent exited with error");
            std::process::exit(1);
        }
    });

    Ok(())
}

/// Configures `tracing` from `logging.{level,format,output}`, with
/// `debug=true` forcing debug-level output regardless of `logging.level` —
/// matches v1's `--debug`-wins zap dev/prod selection. `logging.output`
/// supports `stdout`/`stderr`; any other value (e.g. a file path) logs a
/// startup warning and falls back to stdout rather than silently dropping
/// logs — v1 also never implemented file-output despite the YAML field.
fn init_tracing(cfg: &config::AgentConfig) {
    let level = if cfg.debug {
        "debug"
    } else {
        cfg.logging.level.as_str()
    };
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    let to_stderr = cfg.logging.output == "stderr";
    if !to_stderr && cfg.logging.output != "stdout" && !cfg.logging.output.is_empty() {
        eprintln!(
            "[edr-agent] logging.output={:?} is not a supported destination (stdout/stderr only); using stdout",
            cfg.logging.output
        );
    }

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(move || -> Box<dyn std::io::Write> {
            if to_stderr {
                Box::new(std::io::stderr())
            } else {
                Box::new(std::io::stdout())
            }
        });
    if cfg.logging.format == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
}
