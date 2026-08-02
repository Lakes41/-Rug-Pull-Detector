import ws from 'k6/ws';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';

// Custom metrics to track latency and connection status
const messageLatency = new Trend('message_processing_latency');
const connectionErrors = new Counter('connection_errors');
const messageErrors = new Counter('message_errors');

export const options = {
    stages: [
        { duration: '15s', target: 200 },  // Ramp up to 200 users
        { duration: '30s', target: 1000 }, // Ramp up to 1000 users/connections
        { duration: '1m', target: 1000 },  // Stay at 1000 users (SLA/load phase)
        { duration: '15s', target: 0 },    // Cool down
    ],
    thresholds: {
        // Enforce the SLA: p95 latency must be under 50ms
        'message_processing_latency': ['p(95) < 50'],
        // Fail the test if connection error rate exceeds 1%
        'connection_errors': ['count < 10'],
    },
};

export default function () {
    const url = 'ws://127.0.0.1:8080';
    const params = { tags: { test_type: 'performance' } };

    const res = ws.connect(url, params, function (socket) {
        socket.on('open', () => {
            // Subscribe to a contract address
            socket.send(JSON.stringify({
                action: 'Subscribe',
                address: '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984'
            }));
        });

        socket.on('message', (data) => {
            try {
                const parsed = JSON.parse(data);
                if (parsed.message === 'Alert') {
                    const timestamp = new Date(parsed.Alert.timestamp).getTime();
                    const now = new Date().getTime();
                    const latency = now - timestamp;
                    
                    messageLatency.add(latency);
                    
                    check(parsed, {
                        'is valid alert': (p) => p.Alert.address !== undefined,
                        'latency within 50ms SLA': (_) => latency < 50,
                    });
                }
            } catch (err) {
                messageErrors.add(1);
            }
        });

        socket.on('error', (e) => {
            connectionErrors.add(1);
            console.error(`WebSocket Error: ${e.error()}`);
        });

        // Keep connection open for 10 seconds to simulate client lifecycle
        socket.setTimeout(() => {
            socket.close();
        }, 10000);
    });

    check(res, { 'status is 101': (r) => r && r.status === 101 });
}
