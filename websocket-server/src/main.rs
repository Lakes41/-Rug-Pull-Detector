use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};
use uuid::Uuid;

mod broadcast;
mod subscription;
mod types;

use broadcast::AlertBroadcaster;
use subscription::SubscriptionManager;
use types::{Alert, ClientMessage, ServerMessage};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let subscription_manager = Arc::new(SubscriptionManager::new());
    let alert_broadcaster = Arc::new(AlertBroadcaster::new(subscription_manager.clone()));

    let addr = "127.0.0.1:8080";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("WebSocket server listening on {}", addr);

    // Spawn alert broadcaster task
    tokio::spawn(alert_broadcaster.run_broadcast_loop());

    while let Ok((stream, addr)) = listener.accept().await {
        let subscription_manager = subscription_manager.clone();
        let alert_broadcaster = alert_broadcaster.clone();

        tokio::spawn(async move {
            let client_id = Uuid::new_v4();
            info!("New client connected: {} from {}", client_id, addr);

            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    error!("Error during WebSocket handshake: {}", e);
                    return;
                }
            };

            let (mut write, mut read) = ws_stream.split();
            subscription_manager.add_client(client_id).await;

            // Handle incoming messages
            let read_task = async {
                while let Some(msg) = read.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) {
                                match client_msg {
                                    ClientMessage::Subscribe { address } => {
                                        subscription_manager
                                            .subscribe(client_id, &address)
                                            .await;
                                        info!("Client {} subscribed to {}", client_id, address);
                                    }
                                    ClientMessage::Unsubscribe { address } => {
                                        subscription_manager
                                            .unsubscribe(client_id, &address)
                                            .await;
                                        info!("Client {} unsubscribed from {}", client_id, address);
                                    }
                                }
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("Client {} sent close frame", client_id);
                            break;
                        }
                        Err(e) => {
                            error!("Error receiving message: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            };

            // Handle outgoing messages from alert broadcaster
            let mut rx = alert_broadcaster.subscribe();
            let write_task = async {
                while let Ok(alert) = rx.recv().await {
                    if subscription_manager.is_subscribed(client_id, &alert.address).await {
                        let server_msg = ServerMessage::Alert(alert.clone());
                        if let Ok(json) = serde_json::to_string(&server_msg) {
                            if write.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };

            tokio::select! {
                _ = read_task => {},
                _ = write_task => {},
            }

            subscription_manager.remove_client(client_id).await;
            info!("Client {} disconnected", client_id);
        });
    }

    Ok(())
}
