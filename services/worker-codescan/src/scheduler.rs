//! CodeScan Sentinel scheduler loop (`worker-codescan scheduler`
//! subcommand; spec docs/v2-port/v2.1-codescan-sentinel.md §10). On every
//! tick, selects repos whose `codescan_repo_configs.polling_interval_minutes`
//! has elapsed (or that have never been polled), takes a per-repo Valkey
//! lease so concurrent scheduler replicas never double-enqueue the same
//! repo within the same tick, publishes a `task_type = "sentinel_scan"`
//! entry onto the shared `codescan:tasks` stream, and stamps
//! `last_poll_at`. This is the code that finally *wires* those three
//! columns — scaffolded since the v1 port, queried by nothing until now.
//!
//! "Opt out, not opt in" (spec §6): every `enabled AND polling_enabled` repo
//! is scanned by default; there is no separate allowlist to populate.

use std::time::Duration;

use skauswatch_streams::{STREAM_CODESCAN_TASKS, StreamProducer};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::lease::LeaseClient;

/// One repo due for a scan, as selected by [`due_repos`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueRepo {
    pub id: i64,
    pub tenant_id: Uuid,
    pub provider: String,
    pub repo_name: String,
    pub repo_url: String,
}

/// Selects every enabled, polling-enabled repo whose interval has elapsed
/// (or that has never been polled at all). Deliberately has no
/// `sentinel_exempt`-style filter beyond `polling_enabled` itself in P1 —
/// the spec's `sentinel_exempt` flag (§6) ships with the policy engine in
/// P3; until then, `polling_enabled` (already a real, queryable column) is
/// the opt-out.
pub async fn due_repos(pool: &PgPool) -> anyhow::Result<Vec<DueRepo>> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, provider, repo_name, repo_url \
         FROM codescan_repo_configs \
         WHERE enabled = true AND polling_enabled = true \
           AND (last_poll_at IS NULL \
                OR last_poll_at < now() - (polling_interval_minutes || ' minutes')::interval)",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DueRepo {
            id: r.get(0),
            tenant_id: r.get(1),
            provider: r.get(2),
            repo_name: r.get(3),
            repo_url: r.get(4),
        })
        .collect())
}

/// Stamps `last_poll_at = now()` once a repo's scan has been enqueued.
pub async fn stamp_polled(pool: &PgPool, repo_id: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE codescan_repo_configs SET last_poll_at = now() WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// One scheduler tick: enqueues every due repo this replica wins the lease
/// race for. Returns the number successfully enqueued (for logging).
pub async fn tick(
    pool: &PgPool,
    producer: &StreamProducer,
    lease: &LeaseClient,
    lease_prefix: &str,
    lease_ttl_ms: i64,
) -> anyhow::Result<usize> {
    let mut enqueued = 0usize;
    for repo in due_repos(pool).await? {
        let key = format!("{lease_prefix}:sentinel:lease:{}", repo.id);
        let token = Uuid::new_v4().to_string();
        match lease.try_acquire(&key, &token, lease_ttl_ms).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::warn!(repo_id = repo.id, error = %e, "lease acquire failed, skipping this tick");
                continue;
            }
        }

        let fields = vec![
            ("task_type".to_owned(), "sentinel_scan".to_owned()),
            ("repo_config_id".to_owned(), repo.id.to_string()),
            ("tenant_id".to_owned(), repo.tenant_id.to_string()),
            ("provider".to_owned(), repo.provider.clone()),
            ("repo_name".to_owned(), repo.repo_name.clone()),
            ("repo_url".to_owned(), repo.repo_url.clone()),
        ];
        match producer.publish(STREAM_CODESCAN_TASKS, fields).await {
            Ok(_) => {
                if let Err(e) = stamp_polled(pool, repo.id).await {
                    tracing::warn!(repo_id = repo.id, error = %e, "failed to stamp last_poll_at");
                }
                enqueued += 1;
            }
            Err(e) => {
                tracing::warn!(repo_id = repo.id, error = %e, "failed to enqueue sentinel scan task");
            }
        }

        // Release promptly rather than relying solely on TTL expiry: on a
        // transient publish failure this lets the very next tick retry
        // immediately instead of waiting out the full lease TTL, and on
        // success there is nothing left for the lease to protect once
        // `last_poll_at` is stamped.
        if let Err(e) = lease.release(&key, &token).await {
            tracing::warn!(repo_id = repo.id, error = %e, "failed to release sentinel lease");
        }
    }
    Ok(enqueued)
}

/// Runs the scheduler loop until `shutdown` fires, ticking every `interval`.
/// Re-checks `license.flag_enabled` on every tick rather than once at
/// startup — a flag flipped OFF mid-run stops new scans on the very next
/// tick, no restart required (same "re-evaluate continuously" discipline as
/// `--dev` mode's license gate, see `general.md`).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    pool: PgPool,
    producer: StreamProducer,
    lease: LeaseClient,
    lease_prefix: String,
    lease_ttl_ms: i64,
    interval: Duration,
    license: std::sync::Arc<penguin_licensing::LicenseClient>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !license.flag_enabled(crate::sentinel::SENTINEL_FLAG).await {
                    continue;
                }
                match tick(&pool, &producer, &lease, &lease_prefix, lease_ttl_ms).await {
                    Ok(n) if n > 0 => tracing::info!(enqueued = n, "sentinel scheduler tick"),
                    Ok(_) => {}
                    Err(e) => tracing::error!(error = %e, "sentinel scheduler tick failed"),
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use fred::interfaces::{ClientLike, KeysInterface};

    use super::*;

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../codescan-backend/migrations"
        ))
        .await
    }

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_owned())
    }

    async fn test_producer(prefix: &str) -> StreamProducer {
        StreamProducer::connect(&redis_url(), None, prefix)
            .await
            .unwrap_or_else(|e| panic!("connect producer: {e}"))
    }

    async fn test_lease() -> LeaseClient {
        LeaseClient::connect(&redis_url(), None)
            .await
            .unwrap_or_else(|e| panic!("connect lease: {e}"))
    }

    const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

    fn test_tenant() -> Uuid {
        TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("tenant uuid: {e}"))
    }

    async fn seed_repo(
        pool: &PgPool,
        repo_name: &str,
        polling_enabled: bool,
        interval_minutes: i32,
        last_poll_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs \
             (tenant_id, provider, repo_url, repo_name, enabled, polling_enabled, \
              polling_interval_minutes, last_poll_at) \
             VALUES ($1, 'github', $2, $3, true, $4, $5, $6) RETURNING id",
        )
        .bind(test_tenant())
        .bind(format!("https://github.com/acme/{repo_name}"))
        .bind(repo_name)
        .bind(polling_enabled)
        .bind(interval_minutes)
        .bind(last_poll_at)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo: {e}"));
        row.get::<i64, _>(0)
    }

    #[tokio::test]
    async fn due_repos_includes_never_polled_repos() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "never-polled", true, 60, None).await;
        let due = due_repos(&pool)
            .await
            .unwrap_or_else(|e| panic!("due_repos: {e}"));
        assert!(due.iter().any(|r| r.id == id));
    }

    #[tokio::test]
    async fn due_repos_excludes_recently_polled_repos() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "just-polled", true, 60, Some(chrono::Utc::now())).await;
        let due = due_repos(&pool)
            .await
            .unwrap_or_else(|e| panic!("due_repos: {e}"));
        assert!(!due.iter().any(|r| r.id == id));
    }

    #[tokio::test]
    async fn due_repos_includes_repos_past_their_interval() {
        let pool = test_pool().await;
        let stale = chrono::Utc::now() - chrono::Duration::hours(2);
        let id = seed_repo(&pool, "stale-poll", true, 60, Some(stale)).await;
        let due = due_repos(&pool)
            .await
            .unwrap_or_else(|e| panic!("due_repos: {e}"));
        assert!(due.iter().any(|r| r.id == id));
    }

    #[tokio::test]
    async fn due_repos_excludes_polling_disabled_repos() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "polling-off", false, 60, None).await;
        let due = due_repos(&pool)
            .await
            .unwrap_or_else(|e| panic!("due_repos: {e}"));
        assert!(!due.iter().any(|r| r.id == id));
    }

    #[tokio::test]
    async fn stamp_polled_sets_last_poll_at() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "to-stamp", true, 60, None).await;
        stamp_polled(&pool, id)
            .await
            .unwrap_or_else(|e| panic!("stamp: {e}"));
        let row = sqlx::query("SELECT last_poll_at FROM codescan_repo_configs WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(0)
                .is_some()
        );
    }

    #[tokio::test]
    async fn tick_enqueues_a_due_repo_and_stamps_it() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "tick-repo", true, 60, None).await;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let prefix = format!("test-scheduler-{nanos}");
        let producer = test_producer(&prefix).await;
        let lease = test_lease().await;

        let enqueued = tick(&pool, &producer, &lease, &prefix, 30_000)
            .await
            .unwrap_or_else(|e| panic!("tick: {e}"));
        assert!(enqueued >= 1);

        let row = sqlx::query("SELECT last_poll_at FROM codescan_repo_configs WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(0)
                .is_some(),
            "a successfully enqueued repo must have last_poll_at stamped"
        );
    }

    #[tokio::test]
    async fn tick_skips_a_repo_whose_lease_is_already_held() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "leased-repo", true, 60, None).await;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let prefix = format!("test-scheduler-leased-{nanos}");
        let producer = test_producer(&prefix).await;
        let lease = test_lease().await;

        // Simulate another replica already holding this repo's lease this
        // tick.
        let key = format!("{prefix}:sentinel:lease:{id}");
        assert!(
            lease
                .try_acquire(&key, "other-replica", 30_000)
                .await
                .unwrap_or_else(|e| panic!("pre-acquire: {e}"))
        );

        let enqueued = tick(&pool, &producer, &lease, &prefix, 30_000)
            .await
            .unwrap_or_else(|e| panic!("tick: {e}"));
        assert_eq!(
            enqueued, 0,
            "a repo whose lease is already held must not be enqueued again"
        );

        let row = sqlx::query("SELECT last_poll_at FROM codescan_repo_configs WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(0)
                .is_none(),
            "a skipped repo must not have last_poll_at stamped"
        );
    }

    #[tokio::test]
    async fn tick_returns_zero_when_no_repos_are_due() {
        // A freshly migrated, isolated schema (skauswatch_testkit::db::test_pool)
        // has no rows in codescan_repo_configs at all — the true "nothing to
        // do this tick" case, distinct from tick_skips_* above where a repo
        // is due but loses the lease race.
        let pool = test_pool().await;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let prefix = format!("test-scheduler-empty-{nanos}");
        let producer = test_producer(&prefix).await;
        let lease = test_lease().await;

        let enqueued = tick(&pool, &producer, &lease, &prefix, 30_000)
            .await
            .unwrap_or_else(|e| panic!("tick: {e}"));
        assert_eq!(enqueued, 0, "no due repos means nothing to enqueue");
    }

    /// Raw fred client (bypassing `LeaseClient`/`StreamProducer`) used only
    /// to poison a stream key's type ahead of a publish, so
    /// `producer.publish` fails deterministically with a real `WRONGTYPE`
    /// error instead of requiring a broken connection to simulate a
    /// transport failure.
    async fn raw_redis_client() -> fred::clients::Client {
        let config = fred::types::config::Config::from_url(&redis_url())
            .unwrap_or_else(|e| panic!("raw client config: {e}"));
        let client = fred::types::Builder::from_config(config)
            .build()
            .unwrap_or_else(|e| panic!("raw client build: {e}"));
        client
            .init()
            .await
            .unwrap_or_else(|e| panic!("raw client connect: {e}"));
        client
    }

    #[tokio::test]
    async fn tick_does_not_stamp_last_poll_at_when_publish_fails() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "publish-fail-repo", true, 60, None).await;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let prefix = format!("test-scheduler-pubfail-{nanos}");
        let producer = test_producer(&prefix).await;
        let lease = test_lease().await;

        // Poison the destination stream key so the XADD inside
        // `producer.publish` fails with a real WRONGTYPE error, forcing
        // `tick`'s publish-error branch without touching the connection.
        let raw = raw_redis_client().await;
        let stream_key =
            skauswatch_streams::prefixed_key(&prefix, skauswatch_streams::STREAM_CODESCAN_TASKS);
        let _: String = raw
            .set(&stream_key, "not-a-stream", None, None, false)
            .await
            .unwrap_or_else(|e| panic!("poison stream key: {e}"));

        let enqueued = tick(&pool, &producer, &lease, &prefix, 30_000)
            .await
            .unwrap_or_else(|e| panic!("tick: {e}"));
        assert_eq!(enqueued, 0, "a publish failure must not count as enqueued");

        let row = sqlx::query("SELECT last_poll_at FROM codescan_repo_configs WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(0)
                .is_none(),
            "a publish failure must not stamp last_poll_at"
        );
    }

    fn gated_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::gated_license("skauswatch")
    }

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    #[tokio::test]
    async fn run_never_enqueues_while_the_sentinel_flag_is_disabled() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "flag-off-repo", true, 60, None).await;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let prefix = format!("test-scheduler-flagoff-{nanos}");
        let producer = test_producer(&prefix).await;
        let lease = test_lease().await;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let run_task = tokio::spawn(run(
            pool.clone(),
            producer,
            lease,
            prefix,
            30_000,
            Duration::from_millis(20),
            gated_license(),
            shutdown_rx,
        ));

        // Several ticks' worth of real wall-clock time with the flag
        // disabled — every tick must `continue` before ever calling `tick`.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        shutdown_tx
            .send(true)
            .unwrap_or_else(|e| panic!("send shutdown: {e}"));
        tokio::time::timeout(std::time::Duration::from_secs(5), run_task)
            .await
            .unwrap_or_else(|e| panic!("run() did not stop in time: {e}"))
            .unwrap_or_else(|e| panic!("run() task panicked: {e}"));

        let row = sqlx::query("SELECT last_poll_at FROM codescan_repo_configs WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(0)
                .is_none(),
            "a disabled sentinel flag must keep run() a complete no-op"
        );
    }

    #[tokio::test]
    async fn run_enqueues_while_enabled_then_stops_cleanly_on_shutdown() {
        let pool = test_pool().await;
        let id = seed_repo(&pool, "flag-on-repo", true, 60, None).await;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let prefix = format!("test-scheduler-flagon-{nanos}");
        let producer = test_producer(&prefix).await;
        let lease = test_lease().await;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let run_task = tokio::spawn(run(
            pool.clone(),
            producer,
            lease,
            prefix,
            30_000,
            Duration::from_millis(20),
            dev_license(),
            shutdown_rx,
        ));

        // Poll for the stamp rather than a single fixed sleep — proves
        // run()'s tick loop actually drove a real tick() to completion
        // (Ok(n) if n > 0 branch) without a flaky fixed-delay race.
        let stamped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let row =
                    sqlx::query("SELECT last_poll_at FROM codescan_repo_configs WHERE id = $1")
                        .bind(id)
                        .fetch_one(&pool)
                        .await
                        .unwrap_or_else(|e| panic!("select: {e}"));
                if row
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>(0)
                    .is_some()
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            stamped.is_ok(),
            "run() must have enqueued and stamped the due repo while the flag is enabled"
        );

        shutdown_tx
            .send(true)
            .unwrap_or_else(|e| panic!("send shutdown: {e}"));
        tokio::time::timeout(std::time::Duration::from_secs(5), run_task)
            .await
            .unwrap_or_else(|e| panic!("run() did not stop in time: {e}"))
            .unwrap_or_else(|e| panic!("run() task panicked: {e}"));
    }
}
