use crate::subscription::SubscriptionManager;
use crate::types::Alert;
use rug_pull_websocket_server::risk_cache::{RiskCache, RiskScore};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

pub struct AlertBroadcaster {
    tx: broadcast::Sender<Alert>,
    subscription_manager: Arc<SubscriptionManager>,
    risk_cache: Arc<RiskCache>,
}

impl AlertBroadcaster {
    pub fn new(subscription_manager: Arc<SubscriptionManager>, risk_cache: Arc<RiskCache>) -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            tx,
            subscription_manager,
            risk_cache,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Alert> {
        self.tx.subscribe()
    }

    pub async fn broadcast(&self, alert: Alert) {
        let subscribers = self
            .subscription_manager
            .get_subscribers(&alert.address)
            .await;

        if !subscribers.is_empty() {
            info!(
                "Broadcasting alert for {} to {} subscribers",
                alert.address,
                subscribers.len()
            );
            let _ = self.tx.send(alert);
        }
    }

    pub async fn run_broadcast_loop(&self) {
        // This can be used for periodic checks or integration with external systems
        // For now, alerts are pushed via the broadcast() method
    }

    /// Check if a cached risk score exists for the given address
    pub async fn get_cached_risk_score(&self, address: &str) -> Option<RiskScore> {
        self.risk_cache.get_cached_risk_score(address).await.ok().flatten()
    }

    /// Cache a computed risk score
    pub async fn cache_risk_score(
        &self,
        address: &str,
        risk_score: f64,
        risk_level: &str,
        risk_factors: &[String],
    ) {
        if let Err(e) = self.risk_cache
            .cache_risk_score(address, risk_score, risk_level, risk_factors)
            .await
        {
            tracing::error!("Failed to cache risk score for {}: {}", address, e);
        }
    }
}
