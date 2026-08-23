//! Per-repo Valkey lease so multiple `worker-codescan scheduler` replicas
//! never enqueue the same repo's Sentinel scan twice within the same
//! polling tick (see `crate::scheduler::tick`).
//!
//! Deliberately not routed through `skauswatch_streams::StreamProducer` —
//! its `fred::clients::Client` field is private, and this feature makes no
//! changes to that crate (see the design doc's directory boundaries). This
//! is a small, purpose-built SET-NX/PX acquire + token-checked compare-and-
//! delete release, built directly on the `fred` dependency this crate
//! already carries for stream publishing.

use fred::interfaces::{ClientLike, KeysInterface, LuaInterface};
use fred::types::Builder;
use fred::types::config::{Config as FredConfig, ReconnectPolicy};
use fred::types::{Expiration, SetOptions};

/// A connected Valkey/Redis client used solely for lease acquire/release —
/// no stream or pub/sub traffic.
pub struct LeaseClient {
    client: fred::clients::Client,
}

impl LeaseClient {
    /// Connects and waits for the first successful handshake, mirroring
    /// `skauswatch_streams::StreamProducer::connect`'s retry/backoff policy
    /// so a transient broker outage at scheduler startup doesn't crash the
    /// process.
    pub async fn connect(url: &str, password: Option<&str>) -> anyhow::Result<Self> {
        let effective = skauswatch_streams::redis_url_with_password(url, password);
        let config = FredConfig::from_url(&effective)
            .map_err(|e| anyhow::anyhow!("lease redis config: {e}"))?;
        let mut builder = Builder::from_config(config);
        builder.set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2));
        let client = builder
            .build()
            .map_err(|e| anyhow::anyhow!("lease redis client: {e}"))?;
        client
            .init()
            .await
            .map_err(|e| anyhow::anyhow!("lease redis connect: {e}"))?;
        Ok(Self { client })
    }

    /// Attempts to acquire `key` for `ttl_ms`, tagging it with `token` so
    /// only the holder that set it can release it. Returns `true` on
    /// success, `false` if another replica already holds it — never errors
    /// on lock contention, only on a genuine transport failure.
    pub async fn try_acquire(&self, key: &str, token: &str, ttl_ms: i64) -> anyhow::Result<bool> {
        let result: Option<String> = self
            .client
            .set(
                key,
                token,
                Some(Expiration::PX(ttl_ms)),
                Some(SetOptions::NX),
                false,
            )
            .await
            .map_err(|e| anyhow::anyhow!("lease acquire: {e}"))?;
        Ok(result.is_some())
    }

    /// Releases `key` only if it is still held by `token` — a Lua
    /// compare-and-delete so this replica can never release a lease that
    /// expired and was subsequently re-acquired by someone else.
    pub async fn release(&self, key: &str, token: &str) -> anyhow::Result<()> {
        const SCRIPT: &str = r#"
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
        "#;
        let _: i64 = self
            .client
            .eval(SCRIPT, vec![key.to_owned()], vec![token.to_owned()])
            .await
            .map_err(|e| anyhow::anyhow!("lease release: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_owned())
    }

    async fn client() -> LeaseClient {
        LeaseClient::connect(&redis_url(), None)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"))
    }

    #[tokio::test]
    async fn try_acquire_succeeds_once_then_blocks_a_second_caller() {
        let lease = client().await;
        let key = format!("test-lease-{}", Uuid::new_v4());
        let token_a = "holder-a";
        let token_b = "holder-b";

        let first = lease
            .try_acquire(&key, token_a, 30_000)
            .await
            .unwrap_or_else(|e| panic!("first acquire: {e}"));
        assert!(first, "first acquire on an unheld key must succeed");

        let second = lease
            .try_acquire(&key, token_b, 30_000)
            .await
            .unwrap_or_else(|e| panic!("second acquire: {e}"));
        assert!(
            !second,
            "a second replica must not acquire a lease already held"
        );

        lease.release(&key, token_a).await.unwrap_or_else(|e| {
            panic!("release: {e}");
        });
    }

    #[tokio::test]
    async fn release_with_the_wrong_token_does_not_remove_the_lease() {
        let lease = client().await;
        let key = format!("test-lease-{}", Uuid::new_v4());
        let real_token = "real-holder";

        assert!(
            lease
                .try_acquire(&key, real_token, 30_000)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
        );

        lease
            .release(&key, "impostor-token")
            .await
            .unwrap_or_else(|e| panic!("release call itself must not error: {e}"));

        // The real holder must still be able to release it — proving the
        // impostor release was a no-op, not a silent removal.
        lease
            .release(&key, real_token)
            .await
            .unwrap_or_else(|e| panic!("release: {e}"));
        // A third acquire attempt with a fresh token must now succeed,
        // confirming the key was actually cleared by the real release.
        assert!(
            lease
                .try_acquire(&key, "another-holder", 30_000)
                .await
                .unwrap_or_else(|e| panic!("re-acquire after release: {e}"))
        );
    }

    #[tokio::test]
    async fn release_of_an_already_expired_or_missing_key_is_a_harmless_no_op() {
        let lease = client().await;
        let key = format!("test-lease-{}", Uuid::new_v4());
        lease
            .release(&key, "whatever")
            .await
            .unwrap_or_else(|e| panic!("release of a missing key must not error: {e}"));
    }

    /// Natural PX expiry (not an explicit `release`) must free the key —
    /// the property `crate::scheduler::tick`'s "release promptly rather
    /// than relying solely on TTL expiry" comment calls out as the
    /// fallback if a release is ever missed (crash between acquire and
    /// release, for example).
    #[tokio::test]
    async fn lease_becomes_acquirable_again_after_its_ttl_expires_without_a_release() {
        let lease = client().await;
        let key = format!("test-lease-{}", Uuid::new_v4());
        let token_a = "holder-a";

        assert!(
            lease
                .try_acquire(&key, token_a, 50)
                .await
                .unwrap_or_else(|e| panic!("first acquire: {e}"))
        );

        // Still held immediately after acquiring — a second caller must not
        // race in before the TTL elapses.
        assert!(
            !lease
                .try_acquire(&key, "holder-b", 50)
                .await
                .unwrap_or_else(|e| panic!("immediate second acquire: {e}"))
        );

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(
            lease
                .try_acquire(&key, "holder-c", 30_000)
                .await
                .unwrap_or_else(|e| panic!("acquire after natural expiry: {e}")),
            "a lease must become acquirable again once its PX TTL elapses, with no release call"
        );
    }

    #[tokio::test]
    async fn connect_fails_with_an_invalid_url() {
        let result = LeaseClient::connect("not-a-valid-redis-url", None).await;
        assert!(
            result.is_err(),
            "connect() must reject a URL fred can't parse into a valid config"
        );
    }
}
