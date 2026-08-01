//! Database operations for CodeScan review worker using sqlx 0.9.
//!
//! Every function here takes the caller-validated `tenant_id` from
//! [`crate::message::CodeScanReviewTask`] and applies it as a hard `WHERE`/
//! bind boundary — SELECT/UPDATE filter on it, INSERT stamps it. A row that
//! exists but belongs to a different tenant is indistinguishable from a
//! missing row (see docs/v2-port/tenancy-model.md §4/§6): callers get a
//! generic "not found" rather than any signal the row exists elsewhere.

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Update review status in the database. Scoped to `tenant_id`; a review
/// owned by a different tenant matches zero rows rather than erroring —
/// the caller (`handler::handle`) always re-validates via [`get_review`]
/// immediately after, which does surface the tenant mismatch as an error.
pub async fn update_review_status(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    status: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_reviews SET status = $1, updated_at = NOW() \
         WHERE id = $2 AND tenant_id = $3",
    )
    .bind(status)
    .bind(review_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark review as completed with summary. Scoped to `tenant_id`.
pub async fn complete_review(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    summary: &str,
    comments_count: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_reviews SET status = 'completed', summary = $1, \
         comments_count = $2, completed_at = NOW(), updated_at = NOW() \
         WHERE id = $3 AND tenant_id = $4",
    )
    .bind(summary)
    .bind(comments_count)
    .bind(review_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark review as failed. Scoped to `tenant_id`.
pub async fn mark_review_failed(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    error: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_reviews SET status = 'failed', error_message = $1, \
         updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(error)
    .bind(review_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Insert a review comment finding, stamped with `tenant_id` (the column is
/// `NOT NULL` since `0002_codescan_tenancy.sql` — never omit it).
pub async fn insert_review_comment(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    file_path: &str,
    line_number: i64,
    comment: &str,
    severity: &str,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        "INSERT INTO codescan_review_comments \
         (review_id, tenant_id, file_path, line_number, comment, severity, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id",
    )
    .bind(review_id)
    .bind(tenant_id)
    .bind(file_path)
    .bind(line_number)
    .bind(comment)
    .bind(severity)
    .fetch_one(pool)
    .await?;

    Ok(result.get::<i64, _>(0))
}

/// Fetch review details from database, scoped to `tenant_id`. A review that
/// exists under a different tenant returns the same generic not-found error
/// as a nonexistent id — never leaks cross-tenant existence.
pub async fn get_review(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
) -> anyhow::Result<ReviewRecord> {
    let row = sqlx::query(
        "SELECT id, repo_config_id, status, ai_provider, ai_model, tenant_id \
         FROM codescan_reviews WHERE id = $1 AND tenant_id = $2",
    )
    .bind(review_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("review {} not found", review_id))?;

    Ok(ReviewRecord {
        _id: row.get(0),
        repo_config_id: row.get(1),
        _status: row.get(2),
        _ai_provider: row.get(3),
        _ai_model: row.get(4),
        _tenant_id: row.get(5),
    })
}

/// Fetch repository configuration, scoped to `tenant_id`.
pub async fn get_repo_config(
    pool: &PgPool,
    repo_config_id: i64,
    tenant_id: Uuid,
) -> anyhow::Result<RepoConfigRecord> {
    let row = sqlx::query(
        "SELECT id, tenant_id, provider, repo_url, repo_name \
         FROM codescan_repo_configs WHERE id = $1 AND tenant_id = $2",
    )
    .bind(repo_config_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("repo config {} not found", repo_config_id))?;

    Ok(RepoConfigRecord {
        _id: row.get(0),
        _tenant_id: row.get(1),
        _provider: row.get(2),
        _repo_url: row.get(3),
        _repo_name: row.get(4),
    })
}

/// Review record from database.
#[derive(Debug, Clone)]
pub struct ReviewRecord {
    pub _id: i64,
    pub repo_config_id: i64,
    pub _status: String,
    pub _ai_provider: Option<String>,
    pub _ai_model: Option<String>,
    pub _tenant_id: Uuid,
}

/// Repo configuration record from database.
#[derive(Debug, Clone)]
pub struct RepoConfigRecord {
    pub _id: i64,
    pub _tenant_id: Uuid,
    pub _provider: String,
    pub _repo_url: String,
    pub _repo_name: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Bootstrap tenant literal — matches manager's
    /// `crate::auth::DEFAULT_TENANT_ID` / codescan-backend's migration seed
    /// (see docs/v2-port/tenancy-model.md §8).
    const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
    /// A second, distinct tenant used only to prove cross-tenant isolation —
    /// mirrors codescan-backend's own `TEST_TENANT_ID` convention of a
    /// `..aa`/`..bb`-style literal reserved for tests.
    const OTHER_TENANT_ID: &str = "00000000-0000-0000-0000-0000000000bb";

    fn test_tenant() -> Uuid {
        TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("test tenant uuid: {e}"))
    }

    fn other_tenant() -> Uuid {
        OTHER_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("other tenant uuid: {e}"))
    }

    /// These three tables (`codescan_repo_configs`, `codescan_reviews`,
    /// `codescan_review_comments`) are OWNED by codescan-backend; this
    /// worker only consumes them (see
    /// services/codescan-backend/migrations/0001_codescan_schema.sql header
    /// comment). worker-codescan ships no migrations of its own, so tests
    /// point the shared harness at codescan-backend's migrations dir.
    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../codescan-backend/migrations"
        ))
        .await
    }

    async fn seed_repo_config(pool: &PgPool) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(test_tenant())
        .bind("github")
        .bind("https://github.com/acme/widgets")
        .bind("acme/widgets")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        row.get::<i64, _>(0)
    }

    async fn seed_review(pool: &PgPool, repo_config_id: i64) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_reviews \
             (repo_config_id, tenant_id, status, ai_provider, ai_model) \
             VALUES ($1, $2, 'queued', $3, $4) RETURNING id",
        )
        .bind(repo_config_id)
        .bind(test_tenant())
        .bind("ollama")
        .bind("test-model")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed review: {e}"));
        row.get::<i64, _>(0)
    }

    #[tokio::test]
    async fn update_review_status_changes_status() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        update_review_status(&pool, review, test_tenant(), "processing")
            .await
            .unwrap_or_else(|e| panic!("update status: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "processing");
    }

    #[tokio::test]
    async fn update_review_status_does_not_touch_a_different_tenants_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        // Same review id, wrong tenant: must match zero rows.
        update_review_status(&pool, review, other_tenant(), "processing")
            .await
            .unwrap_or_else(|e| panic!("update status: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(
            row.get::<String, _>(0),
            "queued",
            "a cross-tenant update must never mutate another tenant's row"
        );
    }

    #[tokio::test]
    async fn complete_review_sets_summary_and_comment_count() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        complete_review(&pool, review, test_tenant(), "all clear", 3)
            .await
            .unwrap_or_else(|e| panic!("complete review: {e}"));

        let row = sqlx::query(
            "SELECT status, summary, comments_count, completed_at FROM codescan_reviews WHERE id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "completed");
        assert_eq!(row.get::<String, _>(1), "all clear");
        assert_eq!(row.get::<i32, _>(2), 3);
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(3)
                .is_some()
        );
    }

    #[tokio::test]
    async fn complete_review_does_not_touch_a_different_tenants_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        complete_review(&pool, review, other_tenant(), "all clear", 3)
            .await
            .unwrap_or_else(|e| panic!("complete review: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "queued");
    }

    #[tokio::test]
    async fn mark_review_failed_sets_error_message() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        mark_review_failed(&pool, review, test_tenant(), "boom")
            .await
            .unwrap_or_else(|e| panic!("mark failed: {e}"));

        let row = sqlx::query("SELECT status, error_message FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "failed");
        assert_eq!(row.get::<String, _>(1), "boom");
    }

    #[tokio::test]
    async fn mark_review_failed_does_not_touch_a_different_tenants_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        mark_review_failed(&pool, review, other_tenant(), "boom")
            .await
            .unwrap_or_else(|e| panic!("mark failed: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "queued");
    }

    #[tokio::test]
    async fn insert_review_comment_persists_a_finding_stamped_with_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let comment_id = insert_review_comment(
            &pool,
            review,
            test_tenant(),
            "src/main.rs",
            42,
            "**Title**\n\nBody text",
            "critical",
        )
        .await
        .unwrap_or_else(|e| panic!("insert comment: {e}"));
        assert!(comment_id > 0);

        let row = sqlx::query(
            "SELECT file_path, line_number, comment, severity, tenant_id \
             FROM codescan_review_comments WHERE id = $1",
        )
        .bind(comment_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "src/main.rs");
        assert_eq!(row.get::<i32, _>(1), 42);
        assert_eq!(row.get::<String, _>(2), "**Title**\n\nBody text");
        assert_eq!(row.get::<String, _>(3), "critical");
        assert_eq!(row.get::<Uuid, _>(4), test_tenant());
    }

    #[tokio::test]
    async fn get_review_returns_the_seeded_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let record = get_review(&pool, review, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("get review: {e}"));
        assert_eq!(record._id, review);
        assert_eq!(record.repo_config_id, repo);
        assert_eq!(record._status, "queued");
        assert_eq!(record._ai_provider.as_deref(), Some("ollama"));
        assert_eq!(record._ai_model.as_deref(), Some("test-model"));
        assert_eq!(record._tenant_id, test_tenant());
    }

    #[tokio::test]
    async fn get_review_errors_when_missing() {
        let pool = test_pool().await;
        let result = get_review(&pool, 999_999_999, test_tenant()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_review_is_not_found_for_a_different_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let result = get_review(&pool, review, other_tenant()).await;
        assert!(
            result.is_err(),
            "a review owned by another tenant must not be visible"
        );
    }

    #[tokio::test]
    async fn get_repo_config_returns_the_seeded_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let record = get_repo_config(&pool, repo, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("get repo config: {e}"));
        assert_eq!(record._id, repo);
        assert_eq!(record._tenant_id, test_tenant());
        assert_eq!(record._provider, "github");
        assert_eq!(record._repo_url, "https://github.com/acme/widgets");
        assert_eq!(record._repo_name, "acme/widgets");
    }

    #[tokio::test]
    async fn get_repo_config_errors_when_missing() {
        let pool = test_pool().await;
        let result = get_repo_config(&pool, 999_999_999, test_tenant()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_repo_config_is_not_found_for_a_different_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let result = get_repo_config(&pool, repo, other_tenant()).await;
        assert!(
            result.is_err(),
            "a repo config owned by another tenant must not be visible"
        );
    }
}
