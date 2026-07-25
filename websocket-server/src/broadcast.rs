use crate::subscription::SubscriptionManager;
use crate::types::Alert;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

pub struct AlertBroadcaster {
    tx: broadcast::Sender<Alert>,
    subscription_manager: Arc<SubscriptionManager>,
}

impl AlertBroadcaster {
    pub fn new(subscription_manager: Arc<SubscriptionManager>) -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            tx,
            subscription_manager,
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
}
