"""Tests for Cross-DEX Arbitrage and Toxic Order Flow Anomaly Detector."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cross_dex_arbitrage_detector import (
    CrossDexArbitrageDetector,
    LiquidityPool,
    PriceDivergenceAlert,
)


@pytest.fixture
def detector():
    return CrossDexArbitrageDetector()


def _make_pool(address, dex, token, reserve_a, reserve_b):
    return LiquidityPool(
        pool_address=address,
        dex_protocol=dex,
        token_address=token,
        quote_token_address="USDC",
        reserve_a=reserve_a,
        reserve_b=reserve_b,
    )


class TestCrossDexArbitrageDetector:
    def test_register_pool(self, detector):
        pool = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        detector.register_pool(pool)
        assert "0x111:uniswap_v2" in detector.pools
        assert "TOKEN_A" in detector.token_pools

    def test_remove_pool(self, detector):
        pool = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        detector.register_pool(pool)
        detector.remove_pool("0x111", "uniswap_v2")
        assert "0x111:uniswap_v2" not in detector.pools

    def test_no_divergence_with_single_pool(self, detector):
        pool = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        detector.register_pool(pool)
        alerts = detector.detect_divergence("TOKEN_A")
        assert len(alerts) == 0

    def test_no_divergence_below_threshold(self, detector):
        pool_a = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        pool_b = _make_pool("0x222", "sushiswap", "TOKEN_A", 1050, 2100)
        detector.register_pool(pool_a)
        detector.register_pool(pool_b)
        alerts = detector.detect_divergence("TOKEN_A")
        assert len(alerts) == 0

    def test_divergence_above_threshold(self, detector):
        pool_a = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        pool_b = _make_pool("0x222", "sushiswap", "TOKEN_A", 500, 2000)
        detector.register_pool(pool_a)
        detector.register_pool(pool_b)
        alerts = detector.detect_divergence("TOKEN_A")
        assert len(alerts) == 1
        assert alerts[0].divergence_pct == pytest.approx(50.0)
        assert alerts[0].severity == "critical"

    def test_critical_alert_for_high_divergence(self, detector):
        pool_a = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 100, 200)
        pool_b = _make_pool("0x222", "sushiswap", "TOKEN_A", 500, 200)
        detector.register_pool(pool_a)
        detector.register_pool(pool_b)
        alerts = detector.detect_divergence("TOKEN_A")
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"

    def test_unknown_token_returns_empty(self, detector):
        alerts = detector.detect_divergence("UNKNOWN_TOKEN")
        assert len(alerts) == 0

    def test_get_summary(self, detector):
        pool = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        detector.register_pool(pool)
        summary = detector.get_summary()
        assert summary["total_pools"] == 1
        assert summary["monitored_tokens"] == 1

    def test_multiple_token_pairs(self, detector):
        pool_a1 = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        pool_a2 = _make_pool("0x222", "sushiswap", "TOKEN_A", 500, 2000)
        pool_b1 = _make_pool("0x333", "uniswap_v2", "TOKEN_B", 500, 1000)
        pool_b2 = _make_pool("0x444", "curve", "TOKEN_B", 550, 1100)
        for p in [pool_a1, pool_a2, pool_b1, pool_b2]:
            detector.register_pool(p)

        alerts_a = detector.detect_divergence("TOKEN_A")
        alerts_b = detector.detect_divergence("TOKEN_B")
        assert len(alerts_a) == 1  # 50% divergence
        assert len(alerts_b) == 0  # 0% divergence

    def test_high_severity_for_moderate_divergence(self, detector):
        pool_a = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        pool_b = _make_pool("0x222", "sushiswap", "TOKEN_A", 1100, 2000)
        detector.register_pool(pool_a)
        detector.register_pool(pool_b)
        alerts = detector.detect_divergence("TOKEN_A")
        assert len(alerts) == 1
        assert alerts[0].severity == "high"

    def test_zero_reserve_pool_ignored(self, detector):
        pool_a = _make_pool("0x111", "uniswap_v2", "TOKEN_A", 1000, 2000)
        pool_b = _make_pool("0x222", "sushiswap", "TOKEN_A", 0, 0)
        detector.register_pool(pool_a)
        detector.register_pool(pool_b)
        alerts = detector.detect_divergence("TOKEN_A")
        assert len(alerts) == 0
