"""Tests for Mempool Front-Running Detection Monitor."""

import pytest
from mempool_monitor import MempoolMonitor, PendingTransaction, SandwichAttack


@pytest.fixture
def monitor():
    return MempoolMonitor()


def _make_tx(hash, from_addr, to_addr, gas_price, value=0.0, func_sig="0x38ed1739", token=""):
    return PendingTransaction(
        tx_hash=hash,
        from_address=from_addr,
        to_address=to_addr,
        value=value,
        gas_price=gas_price,
        gas_limit=200000,
        function_sig=func_sig,
        token_address=token,
    )


class TestMempoolMonitor:
    def test_monitor_pool(self, monitor):
        monitor.monitor_pool("0x_pool1")
        assert "0x_pool1" in monitor.monitored_pools

    def test_is_swap_transaction(self, monitor):
        swap_tx = _make_tx("0x1", "A", "B", 100, func_sig="0x38ed1739")
        assert monitor.is_swap_transaction(swap_tx)

        normal_tx = _make_tx("0x2", "A", "B", 100, func_sig="0xabcdef01")
        assert not monitor.is_swap_transaction(normal_tx)

    def test_is_high_gas(self, monitor):
        high_gas = _make_tx("0x1", "A", "B", 300)
        assert monitor.is_high_gas(high_gas, 100)

        normal_gas = _make_tx("0x2", "A", "B", 150)
        assert not monitor.is_high_gas(normal_gas, 100)

    def test_no_sandwich_without_pools(self, monitor):
        tx = _make_tx("0x1", "A", "B", 100, token="TOKEN")
        result = monitor.detect_sandwich(tx)
        assert result is None

    def test_no_sandwich_single_tx(self, monitor):
        monitor.monitor_pool("0x_pool")
        tx = _make_tx("0x1", "A", "0x_pool", 100, token="TOKEN")
        result = monitor.detect_sandwich(tx)
        assert result is None

    def test_sandwich_detection(self, monitor):
        pool = "0x_pool"
        monitor.monitor_pool(pool)

        frontrun = _make_tx("0x_fr", "ATTACKER", pool, 300, value=1.5, token="TOKEN")
        victim = _make_tx("0x_victim", "USER", pool, 50, value=1.0, token="TOKEN")
        backrun = _make_tx("0x_br", "ATTACKER", pool, 300, value=2.0, token="TOKEN")

        monitor.pending_txs = {
            "0x_fr": frontrun,
            "0x_victim": victim,
            "0x_br": backrun,
        }

        attack = monitor.detect_sandwich(victim)
        assert attack is not None
        assert attack.attacker_address == "ATTACKER"
        assert attack.victim_tx_hash == "0x_victim"

    def test_get_summary(self, monitor):
        monitor.monitor_pool("0x_pool1")
        summary = monitor.get_summary()
        assert summary["monitored_pools"] == 1
