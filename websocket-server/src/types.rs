use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub address: String,
    pub alert_type: AlertType,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertType {
    LiquidityDrop { percentage: f64, previous: f64, current: f64 },
    HolderConcentration { percentage: f64 },
    HoneypotDetected,
    MintableToken,
    LargeTransfer { amount: f64, from: String, to: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action")]
pub enum ClientMessage {
    Subscribe { address: String },
    Unsubscribe { address: String },
}

#[derive(Debug, Serialize)]
#[serde(tag = "message")]
pub enum ServerMessage {
    Alert(Alert),
    Subscribed { address: String },
    Unsubscribed { address: String },
    Error { error: String },
}
