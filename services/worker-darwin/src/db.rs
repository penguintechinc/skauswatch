//! Database operations for Darwin review worker using sqlx 0.9.

use sqlx::{PgPool, Row};

/// Update review status in the database.
pub async fn update_review_status(
    pool: &PgPool,
    review_id: i64,
    status: &str,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE darwin_reviews SET status = $1, updated_at = NOW() WHERE id = $2")
        .bind(status)
        .bind(review_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Mark review as completed with summary.
pub async fn complete_review(
    pool: &PgPool,
    review_id: i64,
    summary: &str,
    comments_count: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE darwin_reviews SET status = 'completed', summary = $1, \
         comments_count = $2, completed_at = NOW(), updated_at = NOW() WHERE id = $3",
    )
    .bind(summary)
    .bind(comments_count)
    .bind(review_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark review as failed.
pub async fn mark_review_failed(pool: &PgPool, review_id: i64, error: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE darwin_reviews SET status = 'failed', error_message = $1, \
         updated_at = NOW() WHERE id = $2",
    )
    .bind(error)
    .bind(review_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Insert a review comment finding.
pub async fn insert_review_comment(
    pool: &PgPool,
    review_id: i64,
    file_path: &str,
    line_number: i64,
    comment: &str,
    severity: &str,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        "INSERT INTO darwin_review_comments \
         (review_id, file_path, line_number, comment, severity, created_at) \
         VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING id",
    )
    .bind(review_id)
    .bind(file_path)
    .bind(line_number)
    .bind(comment)
    .bind(severity)
    .fetch_one(pool)
    .await?;

    Ok(result.get::<i64, _>(0))
}

/// Fetch review details from database.
pub async fn get_review(pool: &PgPool, review_id: i64) -> anyhow::Result<ReviewRecord> {
    let row = sqlx::query(
        "SELECT id, repo_config_id, status, ai_provider, ai_model, tenant_id \
         FROM darwin_reviews WHERE id = $1",
    )
    .bind(review_id)
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

/// Fetch repository configuration.
pub async fn get_repo_config(
    pool: &PgPool,
    repo_config_id: i64,
) -> anyhow::Result<RepoConfigRecord> {
    let row = sqlx::query(
        "SELECT id, tenant_id, provider, repo_url, repo_name FROM darwin_repo_configs WHERE id = $1",
    )
    .bind(repo_config_id)
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
    pub _tenant_id: i64,
}

/// Repo configuration record from database.
#[derive(Debug, Clone)]
pub struct RepoConfigRecord {
    pub _id: i64,
    pub _tenant_id: i64,
    pub _provider: String,
    pub _repo_url: String,
    pub _repo_name: String,
}
