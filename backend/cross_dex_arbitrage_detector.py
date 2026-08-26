"""
Cross-DEX Arbitrage and Toxic Order Flow Anomaly Detector

Monitors liquidity reserves across fragmented pools for the same token pair
and detects price divergence thresholds exceeding 10% between pools that
signal asymmetric draining or insider dumping.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LiquidityPool:
    """Represents a liquidity pool on a specific DEX."""
    pool_address: str
    dex_protocol: str  # e.g., "uniswap_v2", "uniswap_v3", "sushiswap", "curve", "stellar_dex"
    token_address: str
    quote_token_address: str
    reserve_a: float = 0.0
    reserve_b: float = 0.0
    last_updated: float = 0.0
    total_liquidity_usd: float = 0.0


@dataclass
class PriceDivergenceAlert:
    """Alert payload for cross-DEX price divergence."""
    token_address: str
    pool_a: str
    pool_b: str
    dex_a: str
    dex_b: str
    price_a: float
    price_b: float
    divergence_pct: float
    timestamp: float
    severity: str = "high"


class CrossDexArbitrageDetector:
    """
    Detects cross-DEX arbitrage and toxic order flow by monitoring
    price divergence across multiple liquidity pools for the same token.
    """

    DIVERGENCE_THRESHOLD_PCT = 10.0
    SCAN_INTERVAL_SECONDS = 5
    PRICE_CACHE_TTL = 30

    def __init__(self, ws_client=None):
        self.pools: Dict[str, LiquidityPool] = {}
        self.token_pools: Dict[str, List[str]] = {}
        self.price_cache: Dict[str, Dict[str, float]] = {}
        self.alerts: List[PriceDivergenceAlert] = []
        self.ws_client = ws_client
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def register_pool(self, pool: LiquidityPool) -> None:
        """Register a liquidity pool for monitoring."""
        key = f"{pool.pool_address}:{pool.dex_protocol}"
        self.pools[key] = pool
        if pool.token_address not in self.token_pools:
            self.token_pools[pool.token_address] = []
        if key not in self.token_pools[pool.token_address]:
            self.token_pools[pool.token_address].append(key)
        logger.info(f"Registered pool {pool.pool_address} on {pool.dex_protocol} for {pool.token_address}")

    def remove_pool(self, pool_address: str, dex_protocol: str) -> None:
        """Remove a pool from monitoring."""
        key = f"{pool_address}:{dex_protocol}"
        if key in self.pools:
            pool = self.pools.pop(key)
            if pool.token_address in self.token_pools:
                self.token_pools[pool.token_address] = [
                    k for k in self.token_pools[pool.token_address] if k != key
                ]
            logger.info(f"Removed pool {pool_address} from {dex_protocol}")

    def calculate_price(self, pool: LiquidityPool) -> float:
        """Calculate token price from pool reserves."""
        if pool.reserve_b <= 0:
            return 0.0
        return pool.reserve_a / pool.reserve_b

    def detect_divergence(self, token_address: str) -> List[PriceDivergenceAlert]:
        """
        Detect price divergence across pools for a given token.
        Returns alerts for any pool pairs exceeding the threshold.
        """
        pool_keys = self.token_pools.get(token_address, [])
        if len(pool_keys) < 2:
            return []

        now = time.time()
        pool_prices: Dict[str, float] = {}

        for key in pool_keys:
            pool = self.pools.get(key)
            if not pool:
                continue
            price = self.calculate_price(pool)
            if price > 0:
                pool_prices[key] = price

        if len(pool_prices) < 2:
            return []

        alerts = []
        keys = list(pool_prices.keys())

        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                key_a, key_b = keys[i], keys[j]
                price_a, price_b = pool_prices[key_a], pool_prices[key_b]

                if price_a == 0:
                    continue

                divergence_pct = abs(price_a - price_b) / price_a * 100

                if divergence_pct >= self.DIVERGENCE_THRESHOLD_PCT:
                    pool_a = self.pools[key_a]
                    pool_b = self.pools[key_b]

                    severity = "critical" if divergence_pct >= 25 else "high"

                    alert = PriceDivergenceAlert(
                        token_address=token_address,
                        pool_a=pool_a.pool_address,
                        pool_b=pool_b.pool_address,
                        dex_a=pool_a.dex_protocol,
                        dex_b=pool_b.dex_protocol,
                        price_a=price_a,
                        price_b=price_b,
                        divergence_pct=divergence_pct,
                        timestamp=now,
                        severity=severity,
                    )
                    alerts.append(alert)
                    logger.warning(
                        f"Cross-DEX divergence detected: {token_address} "
                        f"{pool_a.dex_protocol}({price_a:.6f}) vs "
                        f"{pool_b.dex_protocol}({price_b:.6f}) = {divergence_pct:.2f}%"
                    )

        self.alerts.extend(alerts)
        return alerts

    async def _broadcast_alert(self, alert: PriceDivergenceAlert) -> None:
        """Send alert to connected WebSocket clients."""
        if self.ws_client:
            try:
                details = {
                    "token": alert.token_address,
                    "divergence_pct": alert.divergence_pct,
                    "pool_a": alert.pool_a,
                    "pool_b": alert.pool_b,
                    "dex_a": alert.dex_a,
                    "dex_b": alert.dex_b,
                    "price_a": alert.price_a,
                    "price_b": alert.price_b,
                }
                await self.ws_client.send_alert(
                    address=alert.token_address,
                    alert_type="cross_dex_arbitrage",
                    severity=alert.severity,
                    details=details,
                )
            except Exception as e:
                logger.error(f"Failed to broadcast alert: {e}")

    async def scan_cycle(self) -> List[PriceDivergenceAlert]:
        """Run a single scan cycle across all monitored tokens."""
        all_alerts = []
        for token_address in list(self.token_pools.keys()):
            alerts = self.detect_divergence(token_address)
            for alert in alerts:
                await self._broadcast_alert(alert)
            all_alerts.extend(alerts)
        return all_alerts

    async def start(self) -> None:
        """Start the continuous monitoring loop."""
        self._running = True
        logger.info("Cross-DEX Arbitrage Detector started")
        while self._running:
            try:
                await self.scan_cycle()
            except Exception as e:
                logger.error(f"Scan cycle error: {e}")
            await asyncio.sleep(self.SCAN_INTERVAL_SECONDS)

    def stop(self) -> None:
        """Stop the monitoring loop."""
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info("Cross-DEX Arbitrage Detector stopped")

    def get_summary(self) -> dict:
        """Get detector status summary."""
        return {
            "total_pools": len(self.pools),
            "monitored_tokens": len(self.token_pools),
            "total_alerts": len(self.alerts),
            "recent_alerts": len([a for a in self.alerts if time.time() - a.timestamp < 3600]),
            "divergence_threshold": self.DIVERGENCE_THRESHOLD_PCT,
        }
