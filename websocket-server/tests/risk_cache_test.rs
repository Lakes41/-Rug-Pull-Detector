use chrono::{Duration, Utc};
use rug_pull_websocket_server::database::{create_pool, run_migrations};
use rug_pull_websocket_server::risk_cache::RiskCache;
use sqlx::PgPool;

#[tokio::test]
async fn test_cache_and_retrieve_risk_score() {
    // Use a test database
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/rug_pull_detector_test".to_string());

    let pool = create_pool(&database_url).await.expect("Failed to create pool");
    run_migrations(&pool).await.expect("Failed to run migrations");

    let risk_cache = RiskCache::new(pool, 15);

    let address = "0xTestAddress123";
    let risk_score = 0.75;
    let risk_level = "HIGH";
    let risk_factors = vec!["high_top_1_concentration".to_string(), "extreme_inequality".to_string()];

    // Cache the risk score
    risk_cache
        .cache_risk_score(address, risk_score, risk_level, &risk_factors)
        .await
        .expect("Failed to cache risk score");

    // Retrieve the cached risk score
    let cached = risk_cache
        .get_cached_risk_score(address)
        .await
        .expect("Failed to retrieve cached risk score");

    assert!(cached.is_some());
    let cached = cached.unwrap();
    assert_eq!(cached.address, address.to_lowercase());
    assert_eq!(cached.risk_score, risk_score);
    assert_eq!(cached.risk_level, risk_level);
    assert_eq!(cached.risk_factors, risk_factors);
}

#[tokio::test]
async fn test_cache_expiration() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/rug_pull_detector_test".to_string());

    let pool = create_pool(&database_url).await.expect("Failed to create pool");
    run_migrations(&pool).await.expect("Failed to run migrations");

    // Use a very short cache duration for testing
    let risk_cache = RiskCache::new(pool, 0); // 0 minutes = immediate expiration

    let address = "0xTestAddress456";
    let risk_score = 0.5;
    let risk_level = "MEDIUM";
    let risk_factors = vec!["moderate_low_effective_holders".to_string()];

    risk_cache
        .cache_risk_score(address, risk_score, risk_level, &risk_factors)
        .await
        .expect("Failed to cache risk score");

    // Should not retrieve expired cache
    let cached = risk_cache
        .get_cached_risk_score(address)
        .await
        .expect("Failed to retrieve cached risk score");

    assert!(cached.is_none());
}

#[tokio::test]
async fn test_cache_update() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/rug_pull_detector_test".to_string());

    let pool = create_pool(&database_url).await.expect("Failed to create pool");
    run_migrations(&pool).await.expect("Failed to run migrations");

    let risk_cache = RiskCache::new(pool, 15);

    let address = "0xTestAddress789";

    // Cache initial risk score
    risk_cache
        .cache_risk_score(address, 0.3, "LOW", &vec!["no_risk_factors".to_string()])
        .await
        .expect("Failed to cache initial risk score");

    // Update with new risk score
    let updated_risk_score = 0.9;
    let updated_risk_level = "HIGH";
    let updated_risk_factors = vec!["extreme_top_1_concentration".to_string()];

    risk_cache
        .cache_risk_score(address, updated_risk_score, updated_risk_level, &updated_risk_factors)
        .await
        .expect("Failed to update risk score");

    // Retrieve updated cache
    let cached = risk_cache
        .get_cached_risk_score(address)
        .await
        .expect("Failed to retrieve cached risk score");

    assert!(cached.is_some());
    let cached = cached.unwrap();
    assert_eq!(cached.risk_score, updated_risk_score);
    assert_eq!(cached.risk_level, updated_risk_level);
    assert_eq!(cached.risk_factors, updated_risk_factors);
}

#[tokio::test]
async fn test_cleanup_expired_entries() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/rug_pull_detector_test".to_string());

    let pool = create_pool(&database_url).await.expect("Failed to create pool");
    run_migrations(&pool).await.expect("Failed to run migrations");

    let risk_cache = RiskCache::new(pool, 0); // Immediate expiration for testing

    // Cache multiple entries
    for i in 0..5 {
        risk_cache
            .cache_risk_score(&format!("0xTestAddress{}", i), 0.5, "MEDIUM", &vec![])
            .await
            .expect("Failed to cache risk score");
    }

    // Cleanup expired entries
    let deleted = risk_cache
        .cleanup_expired_entries()
        .await
        .expect("Failed to cleanup expired entries");

    assert_eq!(deleted, 5);
}
