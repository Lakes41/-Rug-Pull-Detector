"""
Mempool Front-Running Detection Monitor

Connects to archive nodes via WebSocket to monitor pending mempool
transactions, flags sandwich attacks, and displays real-time warnings.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class PendingTransaction:
    """A pending mempool transaction."""
    tx_hash: str
    from_address: str
    to_address: str
    value: float
    gas_price: float
    gas_limit: int
    function_sig: str = ""
    token_address: str = ""
    timestamp: float = 0.0
    block_number: int = 0


@dataclass
class SandwichAttack:
    """Detected sandwich attack pattern."""
    victim_tx_hash: str
    frontrun_tx_hash: str
    backrun_tx_hash: str
    attacker_address: str
    token_address: str
    estimated_profit: float
    severity: str  # "high", "critical"
    timestamp: float


class MempoolMonitor:
    """
    Monitors mempool for front-running and sandwich attacks.
    Flags high-gas transactions structured around standard user swaps.
    """

    GAS_PRICE_MULTIPLIER_THRESHOLD = 3.0
    SWAP_FUNCTION_SIGS = {
        "0x38ed1739",  # swapExactTokensForTokens
        "0x8803dbee",  # swapTokensForExactTokens
        "0x7ff36ab5",  # swapExactETHForTokens
        "0x18cbafe5",  # swapExactTokensForETH
        "0xfb3bdb41",  # swapETHForExactTokens
        "0x5c11d795",  # swapExactTokensForTokensSupportingFeeOnTransferTokens
    }

    def __init__(self, ws_client=None):
        self.pending_txs: Dict[str, PendingTransaction] = {}
        self.monitored_pools: Set[str] = set()
        self.attacks: List[SandwichAttack] = []
        self.ws_client = ws_client
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._stats = {
            "txs_monitored": 0,
            "attacks_detected": 0,
            "high_gas_flagged": 0,
        }

    def monitor_pool(self, pool_address: str) -> None:
        """Add a pool address to monitor for sandwich attacks."""
        self.monitored_pools.add(pool_address)
        logger.info(f"Now monitoring pool {pool_address}")

    def unmonitor_pool(self, pool_address: str) -> None:
        """Remove a pool from monitoring."""
        self.monitored_pools.discard(pool_address)

    def is_swap_transaction(self, tx: PendingTransaction) -> bool:
        """Check if transaction is a swap."""
        return tx.function_sig in self.SWAP_FUNCTION_SIGS

    def is_high_gas(self, tx: PendingTransaction, avg_gas_price: float) -> bool:
        """Check if transaction has unusually high gas price."""
        if avg_gas_price <= 0:
            return False
        return tx.gas_price > avg_gas_price * self.GAS_PRICE_MULTIPLIER_THRESHOLD

    def detect_sandwich(self, tx: PendingTransaction) -> Optional[SandwichAttack]:
        """
        Detect if a pending transaction is part of a sandwich attack.
        Looks for patterns: high-gas tx -> normal swap -> high-gas tx
        targeting the same pool.
        """
        if not self.is_swap_transaction(tx):
            return None

        txs_by_pool = {}
        for pending in self.pending_txs.values():
            if pending.to_address in self.monitored_pools:
                if pending.to_address not in txs_by_pool:
                    txs_by_pool[pending.to_address] = []
                txs_by_pool[pending.to_address].append(pending)

        for pool_txs in txs_by_pool.values():
            if len(pool_txs) < 3:
                continue

            pool_txs.sort(key=lambda t: t.gas_price, reverse=True)

            for i in range(1, len(pool_txs) - 1):
                victim = pool_txs[i]
                frontrunner = pool_txs[i - 1]
                backrunner = pool_txs[i + 1]

                if (frontrunner.gas_price > victim.gas_price * self.GAS_PRICE_MULTIPLIER_THRESHOLD and
                    backrunner.gas_price > victim.gas_price * self.GAS_PRICE_MULTIPLIER_THRESHOLD and
                    frontrunner.from_address == backrunner.from_address and
                    frontrunner.from_address != victim.from_address):

                    estimated_profit = abs(frontrunner.value - backrunner.value)
                    severity = "critical" if estimated_profit > 1.0 else "high"

                    attack = SandwichAttack(
                        victim_tx_hash=victim.tx_hash,
                        frontrun_tx_hash=frontrunner.tx_hash,
                        backrun_tx_hash=backrunner.tx_hash,
                        attacker_address=frontrunner.from_address,
                        token_address=victim.token_address,
                        estimated_profit=estimated_profit,
                        severity=severity,
                        timestamp=time.time(),
                    )
                    self.attacks.append(attack)
                    self._stats["attacks_detected"] += 1
                    logger.warning(
                        f"Sandwich attack detected on {victim.token_address}! "
                        f"Attacker: {frontrunner.from_address}, "
                        f"Profit: {estimated_profit}"
                    )
                    return attack

        return None

    async def process_transaction(self, tx: PendingTransaction) -> None:
        """Process an incoming pending transaction."""
        self._stats["txs_monitored"] += 1
        self.pending_txs[tx.tx_hash] = tx

        avg_gas = sum(t.gas_price for t in self.pending_txs.values()) / max(len(self.pending_txs), 1)
        if self.is_high_gas(tx, avg_gas):
            self._stats["high_gas_flagged"] += 1
            await self._broadcast_warning(tx, "high_gas")

        attack = self.detect_sandwich(tx)
        if attack:
            await self._broadcast_attack(attack)

    async def _broadcast_warning(self, tx: PendingTransaction, warning_type: str) -> None:
        """Broadcast warning to WebSocket clients."""
        if self.ws_client:
            try:
                await self.ws_client.send_alert({
                    "type": "MempoolWarning",
                    "warning_type": warning_type,
                    "tx_hash": tx.tx_hash,
                    "gas_price": tx.gas_price,
                    "token": tx.token_address,
                    "severity": "high",
                })
            except Exception as e:
                logger.error(f"Failed to broadcast warning: {e}")

    async def _broadcast_attack(self, attack: SandwichAttack) -> None:
        """Broadcast sandwich attack alert to WebSocket clients."""
        if self.ws_client:
            try:
                await self.ws_client.send_alert({
                    "type": "SandwichAttack",
                    "victim_tx": attack.victim_tx_hash,
                    "attacker": attack.attacker_address,
                    "token": attack.token_address,
                    "estimated_profit": attack.estimated_profit,
                    "severity": attack.severity,
                })
            except Exception as e:
                logger.error(f"Failed to broadcast attack: {e}")

    async def start(self) -> None:
        """Start the mempool monitoring loop."""
        self._running = True
        logger.info("Mempool monitor started")

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        logger.info("Mempool monitor stopped")

    def get_summary(self) -> dict:
        """Get monitoring summary."""
        return {
            "monitored_pools": len(self.monitored_pools),
            "pending_transactions": len(self.pending_txs),
            "attacks_detected": self._stats["attacks_detected"],
            "high_gas_flagged": self._stats["high_gas_flagged"],
            "total_monitoring": self._stats["txs_monitored"],
        }
