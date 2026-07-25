# Rug Pull Detector - Frontend & Microservices

React frontend and predictive modeling backend for the DeFi Rug Pull Detection System.

## Prerequisites

- Node.js 16+ and npm/yarn
- Docker Engine 20.10+ and Docker Compose v2+
- Python 3.10+ (for local non-containerized backend testing)

## Environment Configuration

Before running containers locally, copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Ensure `UID` and `GID` match your local host user to prevent permission conflicts on bind mounts:

```bash
echo "UID=$(id -u)" >> .env
echo "GID=$(id -g)" >> .env
```

## Docker Local Development & Native Linux Setup

### Native Linux & Fedora Workstation Configuration

To ensure seamless execution without root workarounds (`sudo`), follow these setup steps for native Linux distributions (specifically Fedora Workstation):

1. **Enable and Start Docker Daemon**:
   ```bash
   sudo systemctl enable --now docker
   ```

2. **Configure Non-Root Docker Socket Access**:
   Add your host user account to the `docker` group so daemon operations do not require `sudo`:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

3. **Verify Daemon Socket Permissions**:
   Ensure `/var/run/docker.sock` has appropriate read/write permissions for the `docker` group:
   ```bash
   ls -la /var/run/docker.sock
   ```
   If required on certain runner environments, set socket permissions explicitly:
   ```bash
   sudo chmod 666 /var/run/docker.sock
   ```

4. **SELinux Bind Mount Permissions (Fedora Workstation)**:
   Fedora Workstation runs SELinux in enforcing mode by default. Volumes mounted in `docker-compose.yml` include the `:z` flag (e.g., `./backend:/app/backend:z`) to automatically configure shared SELinux labels (`svirt_sandbox_file_t`), allowing containers read/write access without requiring `setenforce 0` or elevated privileges.

### Running with Docker Compose

Start all services in detached or interactive mode:

```bash
docker compose up
```

To run test suites via Docker Compose:

```bash
docker compose run --rm backend
docker compose run --rm frontend
```

## Installation (Host Development)

```bash
cd frontend
npm install
```

## Development

```bash
npm start
```

The app will open at http://localhost:3000

## Build for Production

```bash
npm run build
```

## Features

- **Token Analyzer**: Input token metrics and get instant risk analysis
- **Risk Dashboard**: View analysis history with visual risk indicators
- **Real-time Updates**: Connects to backend API
- **Modern UI**: Built with TailwindCSS and Lucide icons

## API Endpoints

- `POST /api/analyze` - Analyze a single token
- `POST /api/batch-analyze` - Analyze multiple tokens
- `GET /health` - Health check

## Real-Time WebSocket Alerts

The system includes a WebSocket server for real-time anomaly alerts.

### Starting the WebSocket Server

**Locally (requires Rust):**
```bash
cd websocket-server
cargo run
```

**With Docker:**
```bash
docker compose up websocket-server
```

The WebSocket server runs on `ws://127.0.0.1:8080`

### WebSocket Features

- **Pub/Sub Mechanism**: Subscribe to specific smart contract addresses
- **Real-time Alerts**: Receive alerts within 500ms of anomaly detection
- **Alert Types**: Liquidity drops, holder concentration, honeypot detection, mintable tokens, large transfers
- **Auto-reconnection**: Frontend client automatically reconnects on disconnect

### Frontend Integration

The React frontend includes a real-time alert panel:
- Click the bell icon in the top-right corner to open the alert panel
- Subscribe to token addresses to monitor them for anomalies
- View connection status and received alerts in real-time

### Backend Integration

Python backend automatically triggers WebSocket alerts for high-risk tokens:
```python
from websocket_client import AlertTrigger, WebSocketAlertClient

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

## Tech Stack

- React 18
- TailwindCSS
- Lucide React (icons)
- Axios (HTTP client)
- Recharts (charts)
- Rust (tokio-tungstenite) - WebSocket server
- Python (websockets) - Backend alert client

