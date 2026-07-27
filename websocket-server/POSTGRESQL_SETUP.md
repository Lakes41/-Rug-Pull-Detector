# PostgreSQL Integration for Risk Score Caching

This document describes the PostgreSQL integration with SQLx for persistent risk score caching in the Rug Pull Detector WebSocket server.

## Overview

The WebSocket server now uses PostgreSQL to cache computed risk scores, reducing computational overhead by serving cached data for requests made within a 15-minute window.

## Architecture

### Database Schema

The `risk_scores` table stores cached risk scores with the following structure:

- `address` (TEXT, PRIMARY KEY): Token contract address (lowercase)
- `risk_score` (FLOAT8): Computed risk score (0.0-1.0)
- `risk_level` (TEXT): Risk level - LOW, MEDIUM, or HIGH
- `risk_factors` (JSONB): Array of risk factor strings
- `last_updated` (TIMESTAMPTZ): Timestamp for cache validation

Indexes are created on `last_updated` for efficient cache expiration queries and on `risk_level` for filtering by severity.

### Components

1. **Database Module** (`src/database.rs`): Connection pool setup and migration execution
2. **Risk Cache Module** (`src/risk_cache.rs`): Cache operations with 15-minute window logic
3. **Broadcast Module** (`src/broadcast.rs`): Integration with alert broadcasting system

## Setup

### Prerequisites

- PostgreSQL 12 or higher
- Rust with Cargo

### Environment Configuration

Set the `DATABASE_URL` environment variable in your `.env` file:

```bash
DATABASE_URL=postgresql://username:password@host/database
```

Example:
```bash
DATABASE_URL=postgresql://postgres:postgres@localhost/rug_pull_detector
```

### Database Initialization

The server automatically runs migrations on startup using the migration script in `migrations/0001_initial.sql`.

To manually run migrations:

```bash
psql -h localhost -U postgres -d rug_pull_detector -f migrations/0001_initial.sql
```

## Usage

### Caching a Risk Score

```rust
use rug_pull_websocket_server::risk_cache::RiskCache;

let risk_cache = RiskCache::new(pool, 15); // 15-minute cache window

risk_cache.cache_risk_score(
    "0xTokenAddress",
    0.75,
    "HIGH",
    &vec!["high_top_1_concentration".to_string()]
).await?;
```

### Retrieving a Cached Risk Score

```rust
let cached = risk_cache.get_cached_risk_score("0xTokenAddress").await?;

if let Some(score) = cached {
    println!("Cached risk score: {}", score.risk_score);
    println!("Risk level: {}", score.risk_level);
} else {
    // Compute new risk score
}
```

### Checking Cache via Alert Broadcaster

```rust
let broadcaster = AlertBroadcaster::new(subscription_manager, risk_cache);

// Check if cached score exists
if let Some(cached) = broadcaster.get_cached_risk_score("0xTokenAddress").await {
    // Use cached score
} else {
    // Compute and cache new score
    broadcaster.cache_risk_score(
        "0xTokenAddress",
        0.5,
        "MEDIUM",
        &vec!["moderate_risk".to_string()]
    ).await;
}
```

## Cache Expiration

- **Cache Window**: 15 minutes (configurable)
- **Expiration**: Entries older than 15 minutes are not served
- **Cleanup**: Use `cleanup_expired_entries()` to remove expired entries

```rust
let deleted = risk_cache.cleanup_expired_entries().await?;
println!("Deleted {} expired entries", deleted);
```

## Testing

Run the test suite:

```bash
# Set test database URL
export TEST_DATABASE_URL=postgresql://postgres:postgres@localhost/rug_pull_detector_test

# Run tests
cargo test --package rug-pull-websocket-server
```

Test cases cover:
- Caching and retrieving risk scores
- Cache expiration logic
- Cache updates (upsert behavior)
- Cleanup of expired entries

## Performance Considerations

- Connection pool size: 5 connections (configurable in `database.rs`)
- Query timeout: 30 seconds
- Indexes on `last_updated` and `risk_level` for efficient queries
- JSONB for flexible risk_factors storage

## Migration

If upgrading from an in-memory only system:

1. Set up PostgreSQL database
2. Configure `DATABASE_URL` environment variable
3. Start the server - migrations run automatically
4. Existing in-memory data will be replaced with database-backed caching

## Troubleshooting

### Connection Issues

- Verify PostgreSQL is running: `pg_isready`
- Check connection string format
- Ensure database exists: `createdb rug_pull_detector`

### Migration Failures

- Check database permissions
- Verify migration file exists at `migrations/0001_initial.sql`
- Review PostgreSQL logs for detailed errors

### Cache Not Working

- Verify `DATABASE_URL` is set correctly
- Check server logs for database connection errors
- Ensure migrations ran successfully
