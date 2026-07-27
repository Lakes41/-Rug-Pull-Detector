-- Create risk_scores table for caching computed risk scores
CREATE TABLE IF NOT EXISTS risk_scores (
    address TEXT PRIMARY KEY,
    risk_score FLOAT8 NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    risk_factors JSONB NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index on last_updated for efficient cache expiration queries
CREATE INDEX IF NOT EXISTS idx_risk_scores_last_updated ON risk_scores(last_updated);

-- Create index on risk_level for filtering by severity
CREATE INDEX IF NOT EXISTS idx_risk_scores_risk_level ON risk_scores(risk_level);
