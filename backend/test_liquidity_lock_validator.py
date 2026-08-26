"""Tests for Liquidity Lock Validator."""

import pytest
import time
from liquidity_lock_validator import (
    LiquidityLockValidator,
    LockInfo,
    StabilityScore,
)


@pytest.fixture
def validator():
    return LiquidityLockValidator()


def _make_lock(protocol, token, amount, total_liq, days_remaining, duration_days=365):
    return LockInfo(
        locker_address=f"0x_{protocol}_{token}",
        protocol=protocol,
        token_address=token,
        locked_amount=amount,
        total_liquidity=total_liq,
        unlock_timestamp=time.time() + days_remaining * 86400,
        beneficiary="0x_beneficiary",
        lock_duration_days=duration_days,
        time_remaining_days=days_remaining,
    )


class TestLiquidityLockValidator:
    def test_register_lock(self, validator):
        lock = _make_lock("unicrypt", "TOKEN_A", 10000, 20000, 365)
        validator.register_lock(lock)
        assert "TOKEN_A" in validator.locks
        assert len(validator.locks["TOKEN_A"]) == 1

    def test_stability_score_no_locks(self, validator):
        score = validator.compute_stability_score("UNKNOWN")
        assert score.score == 0.0
        assert score.risk_level == "critical"

    def test_stability_score_high_lock(self, validator):
        lock = _make_lock("unicrypt", "TOKEN_A", 20000, 20000, 365)
        validator.register_lock(lock)
        score = validator.compute_stability_score("TOKEN_A")
        assert score.score > 50
        assert score.locks_count == 1
        assert score.total_locked_pct == 100.0

    def test_stability_score_low_lock(self, validator):
        lock = _make_lock("pinklock", "TOKEN_B", 1000, 20000, 30)
        validator.register_lock(lock)
        score = validator.compute_stability_score("TOKEN_B")
        assert score.score < 50

    def test_multiple_locks_improve_score(self, validator):
        lock1 = _make_lock("unicrypt", "TOKEN_C", 5000, 20000, 365)
        lock2 = _make_lock("team_finance", "TOKEN_C", 5000, 20000, 180)
        validator.register_lock(lock1)
        validator.register_lock(lock2)
        score = validator.compute_stability_score("TOKEN_C")
        assert score.locks_count == 2
        assert score.score > 0

    def test_get_summary(self, validator):
        lock = _make_lock("unicrypt", "TOKEN_A", 10000, 20000, 365)
        validator.register_lock(lock)
        summary = validator.get_summary()
        assert summary["total_tokens"] == 1
        assert summary["total_locks"] == 1
        assert "unicrypt" in summary["protocols_supported"]

    def test_risk_levels(self, validator):
        lock_high = _make_lock("unicrypt", "TOKEN_HIGH", 20000, 20000, 365, 365)
        validator.register_lock(lock_high)
        score_high = validator.compute_stability_score("TOKEN_HIGH")
        assert score_high.risk_level in ["low", "medium"]

        lock_low = _make_lock("pinklock", "TOKEN_LOW", 100, 20000, 7, 30)
        validator.register_lock(lock_low)
        score_low = validator.compute_stability_score("TOKEN_LOW")
        assert score_low.risk_level in ["high", "critical"]
