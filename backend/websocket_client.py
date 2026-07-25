"""
WebSocket client for sending alerts to the Rust WebSocket server.
This integrates with the Python backend to trigger real-time alerts.
"""

import asyncio
import json
import websockets
from datetime import datetime
from typing import Optional
import aiohttp


class WebSocketAlertClient:
    """Client for sending anomaly alerts to the WebSocket server"""

    def __init__(self, websocket_url: str = "ws://127.0.0.1:8080"):
        self.websocket_url = websocket_url
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.connected = False

    async def connect(self):
        """Connect to the WebSocket server"""
        try:
            self.websocket = await websockets.connect(self.websocket_url)
            self.connected = True
            print(f"Connected to WebSocket server at {self.websocket_url}")
            return True
        except Exception as e:
            print(f"Failed to connect to WebSocket server: {e}")
            return False

    async def disconnect(self):
        """Disconnect from the WebSocket server"""
        if self.websocket:
            await self.websocket.close()
            self.connected = False
            print("Disconnected from WebSocket server")

    async def send_alert(
        self,
        address: str,
        alert_type: str,
        severity: str,
        details: dict
    ):
        """
        Send an alert to the WebSocket server
        
        Args:
            address: Smart contract address
            alert_type: Type of alert (liquidity_drop, holder_concentration, etc.)
            severity: Severity level (low, medium, high, critical)
            details: Additional alert details
        """
        if not self.connected:
            print("Not connected to WebSocket server")
            return False

        alert = {
            "address": address,
            "alert_type": alert_type,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": details
        }

        try:
            await self.websocket.send(json.dumps(alert))
            print(f"Alert sent for {address}: {alert_type}")
            return True
        except Exception as e:
            print(f"Failed to send alert: {e}")
            self.connected = False
            return False

    async def subscribe_to_address(self, address: str):
        """Subscribe to alerts for a specific address"""
        if not self.connected:
            return False

        message = {
            "action": "subscribe",
            "address": address
        }

        try:
            await self.websocket.send(json.dumps(message))
            print(f"Subscribed to {address}")
            return True
        except Exception as e:
            print(f"Failed to subscribe: {e}")
            return False

    async def unsubscribe_from_address(self, address: str):
        """Unsubscribe from alerts for a specific address"""
        if not self.connected:
            return False

        message = {
            "action": "unsubscribe",
            "address": address
        }

        try:
            await self.websocket.send(json.dumps(message))
            print(f"Unsubscribed from {address}")
            return True
        except Exception as e:
            print(f"Failed to unsubscribe: {e}")
            return False


class AlertTrigger:
    """Trigger alerts based on token analysis results"""

    def __init__(self, websocket_client: WebSocketAlertClient):
        self.client = websocket_client

    async def trigger_liquidity_drop_alert(
        self,
        address: str,
        percentage: float,
        previous_liquidity: float,
        current_liquidity: float
    ):
        """Trigger a liquidity drop alert"""
        severity = "critical" if percentage > 50 else "high" if percentage > 20 else "medium"
        
        await self.client.send_alert(
            address=address,
            alert_type="liquidity_drop",
            severity=severity,
            details={
                "percentage": percentage,
                "previous": previous_liquidity,
                "current": current_liquidity
            }
        )

    async def trigger_holder_concentration_alert(
        self,
        address: str,
        percentage: float
    ):
        """Trigger a holder concentration alert"""
        severity = "critical" if percentage > 90 else "high" if percentage > 70 else "medium"
        
        await self.client.send_alert(
            address=address,
            alert_type="holder_concentration",
            severity=severity,
            details={"percentage": percentage}
        )

    async def trigger_honeypot_alert(self, address: str):
        """Trigger a honeypot detection alert"""
        await self.client.send_alert(
            address=address,
            alert_type="honeypot_detected",
            severity="critical",
            details={}
        )

    async def trigger_mintable_token_alert(self, address: str):
        """Trigger a mintable token alert"""
        await self.client.send_alert(
            address=address,
            alert_type="mintable_token",
            severity="high",
            details={}
        )


# Example usage
async def main():
    client = WebSocketAlertClient()
    await client.connect()
    
    trigger = AlertTrigger(client)
    
    # Example: Trigger a liquidity drop alert
    await trigger.trigger_liquidity_drop_alert(
        address="0xDEADBEEF1234567890",
        percentage=35.5,
        previous_liquidity=100000.0,
        current_liquidity=64500.0
    )
    
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
