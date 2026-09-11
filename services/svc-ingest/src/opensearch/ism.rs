//! ISM (Index State Management) hot/warm/cold/delete lifecycle policy for
//! the unified `skauswatch-logs-*` lake (Task 2.1,
//! `docs/v2-port/ingest-module-spec.md` §8a1). Extends
//! `services/logs/src/opensearch.rs::build_ism_policy`'s 2-state
//! (hot/warm/delete) shape to the Spec's 4-tier shape:
//!
//! | Tier | Storage | Query |
//! |---|---|---|
//! | HOT | local SSD, full indexing | immediate |
//! | WARM | searchable snapshot (S3-compatible repo) | on-demand, transparent |
//! | COLD | plain (non-mounted) snapshot in the same repo | explicit restore required |
//! | DELETE | — | — |
//!
//! WARM mounts the index as a searchable snapshot (`searchable_snapshot`
//! ISM action) against the configured repository -- OpenSearch fetches
//! segments on demand into a local cache, so WARM data stays transparently
//! queryable (Spec: "HOT + WARM transparent"). COLD lowers `index_priority`
//! to the floor rather than mounting anything further -- the Spec's COLD
//! contract ("Explicit restore-on-demand (slow, ~minutes)") is honored by
//! `crate::admin`'s restore endpoint, which performs a real snapshot
//! `_restore` (not a searchable-snapshot mount) against the same
//! repository; that restore, not an ISM action, is what makes COLD data
//! queryable again.
//!
//! Transition ages are **admin-configurable, never license-tier-driven**
//! (Spec §8a1) -- see `crate::admin`'s `PUT /api/v1/admin/ingest/lifecycle`.
//!
//! # Module wiring note
//!
//! This file is deliberately "disjoint from 1.5's `opensearch/mod.rs`"
//! (Task 2.1 brief) -- `opensearch/mod.rs` and `main.rs` are both out of
//! this task's file scope, so this module cannot be declared as
//! `opensearch::ism` the conventional way (a `pub mod ism;` line in
//! `opensearch/mod.rs`). `crate::admin` (also this task's file scope)
//! instead declares it directly via `#[path = "opensearch/ism.rs"] mod
//! ism;`, which places this file's actual path at
//! `services/svc-ingest/src/opensearch/ism.rs` (satisfying the brief)
//! while making it reachable as `crate::admin::ism` rather than
//! `crate::opensearch::ism`. A future task that touches `opensearch/mod.rs`
//! can promote this to a conventional `pub mod ism;` declaration there
//! (deleting `admin.rs`'s `#[path]` shim) with no change to this file's
//! contents.
//!
//! # Dead-code note
//!
//! `crate::admin::router` (this module's sole caller) is not yet invoked
//! from `main.rs`/`bootstrap.rs` -- same interim, unwired state as every
//! other Wave 1/2 module until the next integration gate (see
//! `admin.rs`'s own doc comment).
#![allow(dead_code)]

use serde_json::{Value, json};

/// Fixed ISM policy id this service manages. Replaces v1/`services/logs`'s
/// 2-state `skauswatch-logs-policy` with the unified 4-tier policy (Spec
/// §8a: "replaces the existing `skauswatch-logs-policy`").
pub const ISM_POLICY_ID: &str = "skauswatch-logs-lifecycle-policy";

/// Default HOT -> WARM transition age in days (Spec §8a1 table).
pub const DEFAULT_HOT_TO_WARM_DAYS: i64 = 30;
/// Default WARM -> COLD transition age in days.
pub const DEFAULT_WARM_TO_COLD_DAYS: i64 = 90;
/// Default COLD -> DELETE transition age in days (~1 year).
pub const DEFAULT_COLD_TO_DELETE_DAYS: i64 = 370;

/// A rejected lifecycle-age configuration -- carries the offending values so
/// the admin caller sees exactly what it submitted, not just "invalid".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "lifecycle transition ages must be strictly increasing and positive: \
     hot_to_warm_days={hot_to_warm_days}, warm_to_cold_days={warm_to_cold_days}, \
     cold_to_delete_days={cold_to_delete_days}"
)]
pub struct IsmConfigError {
    /// The rejected HOT -> WARM age.
    pub hot_to_warm_days: i64,
    /// The rejected WARM -> COLD age.
    pub warm_to_cold_days: i64,
    /// The rejected COLD -> DELETE age.
    pub cold_to_delete_days: i64,
}

/// Enforces Spec §8a1: "All three ages are strictly increasing (validated at
/// policy creation/update; reject non-monotonic configs)." A zero or
/// negative age is rejected the same way -- it is not a meaningful
/// `min_index_age` transition condition either.
///
/// # Errors
/// Returns [`IsmConfigError`] when the three ages are not strictly
/// increasing positive integers (`0 < hot_to_warm < warm_to_cold <
/// cold_to_delete`).
pub fn validate_monotonic_ages(
    hot_to_warm_days: i64,
    warm_to_cold_days: i64,
    cold_to_delete_days: i64,
) -> Result<(), IsmConfigError> {
    let strictly_increasing = hot_to_warm_days > 0
        && warm_to_cold_days > hot_to_warm_days
        && cold_to_delete_days > warm_to_cold_days;
    if strictly_increasing {
        Ok(())
    } else {
        Err(IsmConfigError {
            hot_to_warm_days,
            warm_to_cold_days,
            cold_to_delete_days,
        })
    }
}

/// Builds the 4-state hot/warm/cold/delete ISM policy document, PUT-ready
/// for `_plugins/_ism/policies/{id}`. `min_index_age` conditions are
/// measured from index creation (matching `services/logs/src/
/// opensearch.rs::build_ism_policy`'s existing convention), so the three
/// ages passed in are absolute index-age thresholds, not durations spent in
/// the previous state -- which is exactly why [`validate_monotonic_ages`]
/// requires them strictly increasing.
#[must_use]
pub fn build_ism_policy(
    hot_to_warm_days: i64,
    warm_to_cold_days: i64,
    cold_to_delete_days: i64,
    snapshot_repo: &str,
) -> Value {
    json!({
        "policy": {
            "description": format!(
                "SkausWatch unified log lifecycle: hot {hot_to_warm_days}d, \
                 warm (searchable snapshot, repo \"{snapshot_repo}\") {warm_to_cold_days}d, \
                 cold (offloaded, restore-on-demand) {cold_to_delete_days}d, then delete"
            ),
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [
                        {"rollover": {"min_index_age": "1d", "min_doc_count": 10_000_000}}
                    ],
                    "transitions": [
                        {
                            "state_name": "warm",
                            "conditions": {"min_index_age": format!("{hot_to_warm_days}d")}
                        }
                    ]
                },
                {
                    "name": "warm",
                    "actions": [
                        {"read_only": {}},
                        {"force_merge": {"max_num_segments": 1}},
                        {"searchable_snapshot": {"repository": snapshot_repo}}
                    ],
                    "transitions": [
                        {
                            "state_name": "cold",
                            "conditions": {"min_index_age": format!("{warm_to_cold_days}d")}
                        }
                    ]
                },
                {
                    "name": "cold",
                    "actions": [
                        {"index_priority": {"priority": 0}}
                    ],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {"min_index_age": format!("{cold_to_delete_days}d")}
                        }
                    ]
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": []
                }
            ]
        }
    })
}

/// Applies `policy` at `{base_url}/_plugins/_ism/policies/{ISM_POLICY_ID}`,
/// mirroring `services/logs/src/opensearch.rs::ensure_ism_policy`'s PUT
/// shape. Unlike that function (which swallows errors so unattended startup
/// always continues), this one propagates failures: the admin caller who
/// just requested a lifecycle change needs to know whether it actually took
/// effect, not have it silently dropped.
///
/// # Errors
/// Returns the `reqwest` error on transport failure or a non-2xx response.
pub async fn apply_ism_policy(
    client: &reqwest::Client,
    base_url: &str,
    policy: &Value,
) -> Result<(), reqwest::Error> {
    let url = format!("{base_url}/_plugins/_ism/policies/{ISM_POLICY_ID}");
    client
        .put(url)
        .json(policy)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -- validate_monotonic_ages ------------------------------------------

    /// Named regression test from the Task 2.1 brief / Spec §8a1 Testing:
    /// "reject non-monotonic age transitions (test with invalid config,
    /// assert error)".
    #[test]
    fn ism_policy_validation_rejects_non_monotonic_config() {
        let err = validate_monotonic_ages(90, 30, 400).unwrap_err();
        assert_eq!(
            err,
            IsmConfigError {
                hot_to_warm_days: 90,
                warm_to_cold_days: 30,
                cold_to_delete_days: 400,
            }
        );
    }

    #[test]
    fn validate_monotonic_ages_accepts_the_spec_defaults() {
        assert!(
            validate_monotonic_ages(
                DEFAULT_HOT_TO_WARM_DAYS,
                DEFAULT_WARM_TO_COLD_DAYS,
                DEFAULT_COLD_TO_DELETE_DAYS,
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_monotonic_ages_rejects_equal_values() {
        // Strictly increasing, not merely non-decreasing.
        assert!(validate_monotonic_ages(30, 30, 90).is_err());
        assert!(validate_monotonic_ages(30, 90, 90).is_err());
    }

    #[test]
    fn validate_monotonic_ages_rejects_zero_or_negative_first_age() {
        assert!(validate_monotonic_ages(0, 30, 90).is_err());
        assert!(validate_monotonic_ages(-1, 30, 90).is_err());
    }

    // -- build_ism_policy ---------------------------------------------------

    #[test]
    fn ism_policy_has_four_states_hot_warm_cold_delete() {
        let policy = build_ism_policy(30, 90, 370, "skauswatch-snapshots");
        let states = policy["policy"]["states"].as_array().unwrap();
        let names: Vec<&str> = states.iter().map(|s| s["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["hot", "warm", "cold", "delete"]);
        assert_eq!(policy["policy"]["default_state"], "hot");
    }

    #[test]
    fn hot_state_transitions_to_warm_at_configured_age() {
        let policy = build_ism_policy(30, 90, 370, "repo-a");
        let hot = &policy["policy"]["states"][0];
        assert_eq!(hot["transitions"][0]["state_name"], "warm");
        assert_eq!(hot["transitions"][0]["conditions"]["min_index_age"], "30d");
    }

    /// The WARM state's actions must include a `searchable_snapshot` action
    /// against the configured repository -- this (not a delete/evict
    /// action) is what keeps WARM-tier data transparently queryable (Spec:
    /// "HOT + WARM transparent"), the property
    /// `warm_tier_searchable_snapshot_roundtrip` exercises end-to-end.
    #[test]
    fn warm_state_mounts_searchable_snapshot_against_configured_repo() {
        let policy = build_ism_policy(30, 90, 370, "skauswatch-snapshots");
        let warm = &policy["policy"]["states"][1];
        assert_eq!(warm["name"], "warm");
        let actions = warm["actions"].as_array().unwrap();
        let searchable_snapshot = actions
            .iter()
            .find(|a| a.get("searchable_snapshot").is_some())
            .expect("warm state must have a searchable_snapshot action");
        assert_eq!(
            searchable_snapshot["searchable_snapshot"]["repository"],
            "skauswatch-snapshots"
        );
        assert_eq!(warm["transitions"][0]["state_name"], "cold");
        assert_eq!(warm["transitions"][0]["conditions"]["min_index_age"], "90d");
    }

    #[test]
    fn cold_state_transitions_to_delete_at_configured_age_and_never_deletes_itself() {
        let policy = build_ism_policy(30, 90, 370, "repo-a");
        let cold = &policy["policy"]["states"][2];
        assert_eq!(cold["name"], "cold");
        // COLD never deletes directly -- it deprioritizes and waits for the
        // DELETE transition, so a restore before that age still has an
        // index to restore into.
        let actions = cold["actions"].as_array().unwrap();
        assert!(actions.iter().all(|a| a.get("delete").is_none()));
        assert_eq!(cold["transitions"][0]["state_name"], "delete");
        assert_eq!(
            cold["transitions"][0]["conditions"]["min_index_age"],
            "370d"
        );
    }

    #[test]
    fn delete_state_has_no_transitions() {
        let policy = build_ism_policy(30, 90, 370, "repo-a");
        let delete_state = &policy["policy"]["states"][3];
        assert_eq!(delete_state["name"], "delete");
        assert_eq!(delete_state["actions"][0]["delete"], json!({}));
        assert!(delete_state["transitions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn build_ism_policy_description_mentions_all_three_ages_and_repo() {
        let policy = build_ism_policy(30, 90, 370, "my-repo");
        let description = policy["policy"]["description"].as_str().unwrap();
        assert!(description.contains("30d"));
        assert!(description.contains("90d"));
        assert!(description.contains("370d"));
        assert!(description.contains("my-repo"));
    }

    // -- apply_ism_policy ----------------------------------------------------

    #[tokio::test]
    async fn apply_ism_policy_puts_to_the_policy_endpoint() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(format!("/_plugins/_ism/policies/{ISM_POLICY_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"_id": ISM_POLICY_ID})))
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let policy = build_ism_policy(30, 90, 370, "repo-a");
        apply_ism_policy(&client, &mock.uri(), &policy)
            .await
            .unwrap();

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "exactly one PUT to the ISM policy endpoint"
        );
    }

    #[tokio::test]
    async fn apply_ism_policy_propagates_non_2xx_status() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(format!("/_plugins/_ism/policies/{ISM_POLICY_ID}")))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let policy = build_ism_policy(30, 90, 370, "repo-a");
        let result = apply_ism_policy(&client, &mock.uri(), &policy).await;
        assert!(result.is_err(), "a 500 response must propagate as Err");
    }

    #[tokio::test]
    async fn apply_ism_policy_propagates_transport_failure() {
        let client = reqwest::Client::new();
        let policy = build_ism_policy(30, 90, 370, "repo-a");
        // Nothing listens on this port -- connection refused.
        let result = apply_ism_policy(&client, "http://127.0.0.1:1", &policy).await;
        assert!(result.is_err());
    }
}
