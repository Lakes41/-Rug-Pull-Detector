use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .connect(database_url)
        .await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    let migration_sql = include_str!("../migrations/0001_initial.sql");
    for statement in migration_sql.split(';') {
        let trimmed = statement.trim();
        if !trimmed.is_empty() {
            sqlx::query(trimmed)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}
