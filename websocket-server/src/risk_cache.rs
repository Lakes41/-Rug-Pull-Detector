use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub address: String,
    pub risk_score: f64,
    pub risk_level: String,
    pub risk_factors: sqlx::types::Json<Vec<String>>,
    pub last_updated: DateTime<Utc>,
}

pub struct RiskCache {
    pool: PgPool,
    cache_duration_minutes: i64,
}

impl RiskCache {
    pub fn new(pool: PgPool, cache_duration_minutes: i64) -> Self {
        Self {
            pool,
            cache_duration_minutes,
        }
    }

    /// Get cached risk score if it exists and is within the cache window
    pub async fn get_cached_risk_score(&self, address: &str) -> Result<Option<RiskScore>> {
        let cutoff_time = Utc::now() - Duration::minutes(self.cache_duration_minutes);

        let row = sqlx::query_as!(
            RiskScore,
            r#"
            SELECT address, risk_score, risk_level, risk_factors as "risk_factors: sqlx::types::Json<Vec<String>>", last_updated
            FROM risk_scores
            WHERE address = $1 AND last_updated > $2
            "#,
            address.to_lowercase(),
            cutoff_time
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Cache a computed risk score
    pub async fn cache_risk_score(
        &self,
        address: &str,
        risk_score: f64,
        risk_level: &str,
        risk_factors: &[String],
    ) -> Result<()> {
        let now = Utc::now();
        let risk_factors_json = sqlx::types::Json(risk_factors.to_vec());

        sqlx::query!(
            r#"
            INSERT INTO risk_scores (address, risk_score, risk_level, risk_factors, last_updated)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (address) 
            DO UPDATE SET 
                risk_score = EXCLUDED.risk_score,
                risk_level = EXCLUDED.risk_level,
                risk_factors = EXCLUDED.risk_factors,
                last_updated = EXCLUDED.last_updated
            "#,
            address.to_lowercase(),
            risk_score,
            risk_level,
            risk_factors_json as _,
            now
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all risk scores updated within the cache window
    pub async fn get_recent_risk_scores(&self) -> Result<Vec<RiskScore>> {
        let cutoff_time = Utc::now() - Duration::minutes(self.cache_duration_minutes);

        let rows = sqlx::query_as!(
            RiskScore,
            r#"
            SELECT address, risk_score, risk_level, risk_factors as "risk_factors: sqlx::types::Json<Vec<String>>", last_updated
            FROM risk_scores
            WHERE last_updated > $1
            ORDER BY last_updated DESC
            "#,
            cutoff_time
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Delete expired cache entries (older than cache window)
    pub async fn cleanup_expired_entries(&self) -> Result<u64> {
        let cutoff_time = Utc::now() - Duration::minutes(self.cache_duration_minutes);

        let result = sqlx::query!(
            r#"
            DELETE FROM risk_scores
            WHERE last_updated < $1
            "#,
            cutoff_time
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
