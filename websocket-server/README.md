# Rug Pull Detector - WebSocket Server

Real-time WebSocket server for alert subscriptions using tokio-tungstenite.

## Features

- **Concurrent Connections**: Handles multiple WebSocket connections asynchronously using tokio
- **Pub/Sub Mechanism**: Clients can subscribe to specific smart contract addresses
- **Real-time Alerts**: Broadcasts JSON anomaly alerts within 500ms of triggered events
- **Alert Types**: Liquidity drops, holder concentration, honeypot detection, mintable tokens, large transfers

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo

### Build

```bash
cd websocket-server
cargo build --release
```

## Running the Server

```bash
cargo run
```

The server will start on `ws://127.0.0.1:8080`

## API

### Client Messages

Clients send JSON messages to subscribe/unsubscribe from addresses:

**Subscribe to an address:**
```json
{
  "action": "subscribe",
  "address": "0xdeadbeef1234567890"
}
```

**Unsubscribe from an address:**
```json
{
  "action": "unsubscribe",
  "address": "0xdeadbeef1234567890"
}
```

### Server Messages

The server sends JSON messages for alerts and confirmations:

**Alert message:**
```json
{
  "message": "alert",
  "address": "0xdeadbeef1234567890",
  "alert_type": {
    "type": "LiquidityDrop",
    "percentage": 35.5,
    "previous": 100000.0,
    "current": 64500.0
  },
  "severity": "high",
  "timestamp": "2024-01-15T10:30:00Z",
  "details": {}
}
```

**Subscription confirmation:**
```json
{
  "message": "subscribed",
  "address": "0xdeadbeef1234567890"
}
```

## Alert Types

- `LiquidityDrop`: Sudden decrease in token liquidity
- `HolderConcentration`: High concentration of tokens in few wallets
- `HoneypotDetected`: Token identified as a honeypot
- `MintableToken`: Token with unlimited minting capability
- `LargeTransfer`: Significant token transfer between addresses

## Severity Levels

- `Low`: Minor anomalies
- `Medium`: Moderate risk indicators
- `High`: Significant risk factors
- `Critical`: Immediate threat detected

## Integration

### Python Backend

Use the `websocket_client.py` in the `backend/` directory to send alerts:

```python
from websocket_client import WebSocketAlertClient, AlertTrigger

client = WebSocketAlertClient()
await client.connect()

trigger = AlertTrigger(client)
await trigger.trigger_liquidity_drop_alert(
    address="0xdeadbeef1234567890",
    percentage=35.5,
    previous_liquidity=100000.0,
    current_liquidity=64500.0
)
```

### Frontend

Use the `websocket-client.js` in the `app/lib/` directory:

```javascript
import { alertWebSocket } from './lib/websocket-client';

alertWebSocket.connect();

alertWebSocket.on('alert', (alert) => {
  console.log('Received alert:', alert);
});

alertWebSocket.subscribe('0xdeadbeef1234567890');
```

## Performance

- **Latency**: Alerts broadcast within 500ms of event trigger
- **Concurrency**: Handles thousands of concurrent connections
- **Throughput**: Broadcast channel with 1000 message buffer

## Testing

### Manual Testing with wscat

```bash
npm install -g wscat
wscat -c ws://127.0.0.1:8080
```

Then send subscription messages:
```json
{"action":"subscribe","address":"0xdeadbeef1234567890"}
```

### Python Test Client

Run the example in `backend/websocket_client.py`:
```bash
cd backend
python websocket_client.py
```

## Architecture

- `main.rs`: WebSocket server entry point and connection handling
- `subscription.rs`: Pub/sub mechanism for client subscriptions
- `broadcast.rs`: Alert broadcasting to subscribed clients
- `types.rs`: Data structures for alerts and messages
