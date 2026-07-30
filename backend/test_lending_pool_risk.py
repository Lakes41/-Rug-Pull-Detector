"""
Test cases for Lending Pool Risk Detection
Tests TVL tracking, oracle/mint monitoring, and lending pool risk scoring.
"""

import pytest
from datetime import datetime, timedelta
from tvl_tracker import (
    TVLTracker,
    TVLSnapshot,
    TVLAnomaly,
    AnomalyType,
    AnomalyDetector,
    TVLDatabase
)
from oracle_mint_monitor import (
    OracleMintMonitor,
    MintBurnEvent,
    OracleUpdate,
    MintBurnAnomaly,
    MintBurnEventType,
    OracleUpdateType,
    InfiniteMintDetector
)
from lending_pool_risk import (
    LendingPoolRiskModifier,
    LendingPoolRiskResult,
    LendingPoolRiskFactors,
    PoolType
)


class TestTVLTracker:
    """Test TVL tracking and anomaly detection"""
    
    def test_store_and_retrieve_snapshot(self):
        """Test storing and retrieving TVL snapshots"""
        tracker = TVLTracker(":memory:")
        
        snapshot = TVLSnapshot(
            pool_address="0x1234567890",
            timestamp=datetime.now(),
            total_value_locked=1000000.0,
            collateral_amount=800000.0,
            borrowed_amount=300000.0,
            liquidity_tokens=500000.0,
            token_prices={"USDC": 1.0, "ETH": 2000.0}
        )
        
        tracker.record_snapshot(snapshot)
        
        retrieved = tracker.get_pool_history("0x1234567890", days=1)
        assert len(retrieved) == 1
        assert retrieved[0].total_value_locked == 1000000.0
        
        tracker.close()
    
    def test_detect_sudden_drop(self):
        """Test sudden TVL drop detection"""
        detector = AnomalyDetector(threshold_percent=20.0)
        
        historical_tvl = [1000000.0, 950000.0, 900000.0, 850000.0]
        current_tvl = 600000.0  # 30% drop
        
        anomaly = detector.detect_sudden_drop(current_tvl, historical_tvl)
        
        assert anomaly is not None
        assert anomaly.anomaly_type == AnomalyType.SUDDEN_DROP
        assert anomaly.severity == "high"
        
        tracker.close()
    
    def test_detect_spike_withdrawal(self):
        """Test collateral withdrawal spike detection"""
        detector = AnomalyDetector(threshold_percent=20.0)
        
        historical_collateral = [800000.0, 750000.0, 700000.0]
        collateral_amount = 500000.0  # Significant drop
        borrowed_amount = 300000.0  # Stable
        
        anomaly = detector.detect_spike_withdrawal(
            collateral_amount, borrowed_amount, historical_collateral
        )
        
        assert anomaly is not None
        assert anomaly.anomaly_type == AnomalyType.SPIKE_WITHDRAWAL
    
    def test_detect_collateral_drain(self):
        """Test rapid collateral drain detection"""
        detector = AnomalyDetector()
        
        previous_tvl = 1000000.0
        current_tvl = 400000.0  # 60% drop
        time_delta_minutes = 30  # Quick drain
        
        anomaly = detector.detect_collateral_drain(
            current_tvl, previous_tvl, time_delta_minutes
        )
        
        assert anomaly is not None
        assert anomaly.anomaly_type == AnomalyType.COLLATERAL_DRAIN
        assert anomaly.severity == "critical"
    
    def test_detect_gradual_decline(self):
        """Test gradual TVL decline detection"""
        detector = AnomalyDetector()
        
        historical_tvl = [1000000.0, 950000.0, 900000.0, 850000.0, 800000.0,
                         750000.0, 700000.0, 650000.0, 600000.0, 550000.0]
        
        anomaly = detector.detect_gradual_decline(historical_tvl)
        
        assert anomaly is not None
        assert anomaly.anomaly_type == AnomalyType.GRADUAL_DECLINE
    
    def test_no_anomaly_safe_pool(self):
        """Test that stable pools don't trigger anomalies"""
        detector = AnomalyDetector(threshold_percent=20.0)
        
        stable_tvl = [1000000.0, 990000.0, 1005000.0, 995000.0, 1000000.0]
        current_tvl = 1000000.0
        
        anomaly = detector.detect_sudden_drop(current_tvl, stable_tvl)
        
        assert anomaly is None


class TestOracleMintMonitor:
    """Test oracle vs mint/burn monitoring"""
    
    def test_store_mint_burn_event(self):
        """Test storing mint/burn events"""
        monitor = OracleMintMonitor(":memory:")
        
        event = MintBurnEvent(
            token_address="0x1234567890",
            event_type=MintBurnEventType.MINT,
            amount=1000000.0,
            timestamp=datetime.now(),
            transaction_hash="0xabcdef123456",
            total_supply_after=11000000.0
        )
        
        monitor.record_mint_burn_event(event)
        
        events, _ = monitor.get_token_history("0x1234567890", days=1)
        assert len(events) == 1
        assert events[0].amount == 1000000.0
        
        monitor.close()
    
    def test_store_oracle_update(self):
        """Test storing oracle updates"""
        monitor = OracleMintMonitor(":memory:")
        
        update = OracleUpdate(
            asset_id="0x1234567890",
            update_type=OracleUpdateType.PRICE_UPDATE,
            old_value=100.0,
            new_value=110.0,
            timestamp=datetime.now(),
            oracle_address="0xoracle123"
        )
        
        monitor.record_oracle_update(update)
        
        _, updates = monitor.get_token_history("0x1234567890", days=1)
        assert len(updates) == 1
        assert updates[0].new_value == 110.0
        
        monitor.close()
    
    def test_detect_rapid_minting(self):
        """Test rapid minting detection"""
        detector = InfiniteMintDetector(supply_change_threshold=50.0)
        
        events = [
            MintBurnEvent(
                token_address="0x1234567890",
                event_type=MintBurnEventType.MINT,
                amount=1000000.0,
                timestamp=datetime.now() - timedelta(minutes=30),
                transaction_hash="0x1",
                total_supply_after=11000000.0
            ),
            MintBurnEvent(
                token_address="0x1234567890",
                event_type=MintBurnEventType.MINT,
                amount=2000000.0,
                timestamp=datetime.now() - timedelta(minutes=20),
                transaction_hash="0x2",
                total_supply_after=13000000.0
            ),
            MintBurnEvent(
                token_address="0x1234567890",
                event_type=MintBurnEventType.MINT,
                amount=3000000.0,
                timestamp=datetime.now() - timedelta(minutes=10),
                transaction_hash="0x3",
                total_supply_after=16000000.0
            )
        ]
        
        anomaly = detector.detect_rapid_minting(events)
        
        assert anomaly is not None
        assert anomaly.anomaly_type == "rapid_minting"
        assert anomaly.severity == "critical"
    
    def test_detect_oracle_price_manipulation(self):
        """Test oracle price manipulation detection"""
        detector = InfiniteMintDetector()
        
        oracle_updates = [
            OracleUpdate(
                asset_id="0x1234567890",
                update_type=OracleUpdateType.PRICE_UPDATE,
                old_value=100.0,
                new_value=150.0,  # 50% increase
                timestamp=datetime.now() - timedelta(minutes=15),
                oracle_address="0xoracle123"
            )
        ]
        
        mint_events = [
            MintBurnEvent(
                token_address="0x1234567890",
                event_type=MintBurnEventType.MINT,
                amount=5000000.0,
                timestamp=datetime.now() - timedelta(minutes=10),
                transaction_hash="0x1"
            )
        ]
        
        anomaly = detector.detect_oracle_price_manipulation(oracle_updates, mint_events)
        
        assert anomaly is not None
        assert anomaly.anomaly_type == "oracle_price_manipulation"
    
    def test_detect_unbacked_minting(self):
        """Test unbacked minting detection"""
        detector = InfiniteMintDetector()
        
        mint_events = [
            MintBurnEvent(
                token_address="0x1234567890",
                event_type=MintBurnEventType.MINT,
                amount=1000000.0,
                timestamp=datetime.now(),
                transaction_hash="0x1"
            )
        ]
        
        # No oracle updates
        oracle_updates = []
        
        anomaly = detector.detect_unbacked_minting(mint_events, oracle_updates)
        
        assert anomaly is not None
        assert anomaly.anomaly_type == "unbacked_minting"
        assert anomaly.severity == "critical"
    
    def test_detect_supply_inflation(self):
        """Test supply inflation detection"""
        detector = InfiniteMintDetector(inflation_threshold=100.0)
        
        events = [
            MintBurnEvent(
                token_address="0x1234567890",
                event_type=MintBurnEventType.MINT,
                amount=5000000.0,
                timestamp=datetime.now() - timedelta(hours=1),
                transaction_hash="0x1",
                total_supply_after=15000000.0
            ),
            MintBurnEvent(
                token_address="0x1234567890",
                event_type=MintBurnEventType.MINT,
                amount=5000000.0,
                timestamp=datetime.now(),
                transaction_hash="0x2",
                total_supply_after=20000000.0
            )
        ]
        
        anomaly = detector.detect_supply_inflation(events)
        
        assert anomaly is not None
        assert anomaly.anomaly_type == "supply_inflation"


class TestLendingPoolRiskModifier:
    """Test lending pool risk score modification"""
    
    def test_calculate_risk_modifier_standard_pool(self):
        """Test risk modifier for standard lending pool"""
        modifier = LendingPoolRiskModifier(":memory:")
        
        result = modifier.calculate_risk_modifier(
            pool_address="0x1234567890",
            pool_type=PoolType.STANDARD_LENDING,
            base_risk_score=0.3
        )
        
        assert result.pool_address == "0x1234567890"
        assert result.pool_type == PoolType.STANDARD_LENDING
        assert 0.0 <= result.modified_risk_score <= 1.0
        assert result.risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        modifier.close()
    
    def test_calculate_risk_modifier_rwa_pool(self):
        """Test risk modifier for RWA tokenized pool (higher risk)"""
        modifier = LendingPoolRiskModifier(":memory:")
        
        result = modifier.calculate_risk_modifier(
            pool_address="0x1234567890",
            pool_type=PoolType.RWA_TOKENIZED,
            base_risk_score=0.3
        )
        
        # RWA pools should have higher modifier
        assert result.pool_type == PoolType.RWA_TOKENIZED
        
        modifier.close()
    
    def test_calculate_risk_modifier_yield_pool(self):
        """Test risk modifier for yield pool (higher risk)"""
        modifier = LendingPoolRiskModifier(":memory:")
        
        result = modifier.calculate_risk_modifier(
            pool_address="0x1234567890",
            pool_type=PoolType.YIELD_POOL,
            base_risk_score=0.3
        )
        
        assert result.pool_type == PoolType.YIELD_POOL
        
        modifier.close()
    
    def test_risk_factor_gathering(self):
        """Test gathering of risk factors"""
        modifier = LendingPoolRiskModifier(":memory:")
        
        risk_factors = modifier._gather_risk_factors(
            "0x1234567890",
            PoolType.STANDARD_LENDING
        )
        
        assert risk_factors.pool_address == "0x1234567890"
        assert risk_factors.pool_type == PoolType.STANDARD_LENDING
        assert 0.0 <= risk_factors.tvl_anomaly_score <= 1.0
        assert 0.0 <= risk_factors.infinite_mint_risk <= 1.0
        
        modifier.close()
    
    def test_collateral_withdrawal_risk_calculation(self):
        """Test collateral withdrawal risk calculation"""
        modifier = LendingPoolRiskModifier(":memory:")
        
        # Create mock anomalies
        anomalies = [
            TVLAnomaly(
                pool_address="0x1234567890",
                anomaly_type=AnomalyType.SPIKE_WITHDRAWAL,
                severity="high",
                timestamp=datetime.now(),
                previous_tvl=1000000.0,
                current_tvl=600000.0,
                percentage_change=-40.0,
                description="Test anomaly"
            )
        ]
        
        risk = modifier._calculate_collateral_withdrawal_risk(anomalies)
        
        assert 0.0 < risk <= 1.0
        
        modifier.close()
    
    def test_tvl_volatility_calculation(self):
        """Test TVL volatility calculation"""
        tracker = TVLTracker(":memory:")
        modifier = LendingPoolRiskModifier(":memory:")
        
        # Add some snapshots with varying TVL
        for i in range(10):
            snapshot = TVLSnapshot(
                pool_address="0x1234567890",
                timestamp=datetime.now() - timedelta(days=i),
                total_value_locked=1000000.0 + (i * 100000.0),
                collateral_amount=800000.0,
                borrowed_amount=300000.0,
                liquidity_tokens=500000.0,
                token_prices={"USDC": 1.0}
            )
            tracker.record_snapshot(snapshot)
        
        volatility = modifier._calculate_tvl_volatility("0x1234567890")
        
        assert 0.0 <= volatility <= 1.0
        
        tracker.close()
        modifier.close()
    
    def test_recommendation_generation(self):
        """Test recommendation generation based on risk factors"""
        modifier = LendingPoolRiskModifier(":memory:")
        
        # High risk factors
        risk_factors = LendingPoolRiskFactors(
            pool_address="0x1234567890",
            pool_type=PoolType.STANDARD_LENDING,
            tvl_anomaly_score=0.7,
            infinite_mint_risk=0.8,
            oracle_manipulation_risk=0.6,
            collateral_withdrawal_risk=0.5
        )
        
        recommendations = modifier._generate_recommendations(risk_factors, "HIGH")
        
        assert len(recommendations) > 0
        assert any("TVL" in rec for rec in recommendations)
        assert any("mint" in rec.lower() for rec in recommendations)
        
        modifier.close()
    
    def test_risk_level_determination(self):
        """Test risk level determination from score"""
        modifier = LendingPoolRiskModifier(":memory:")
        
        assert modifier._get_risk_level(0.9) == "CRITICAL"
        assert modifier._get_risk_level(0.7) == "HIGH"
        assert modifier._get_risk_level(0.5) == "MEDIUM"
        assert modifier._get_risk_level(0.2) == "LOW"
        
        modifier.close()


class TestLendingPoolScenarios:
    """Test realistic lending pool risk scenarios"""
    
    def test_collateral_drain_scenario(self):
        """Test detection of collateral drain attack"""
        tracker = TVLTracker(":memory:")
        
        pool_address = "0xPOOL1234567890"
        
        # Normal TVL
        for i in range(5):
            snapshot = TVLSnapshot(
                pool_address=pool_address,
                timestamp=datetime.now() - timedelta(days=i),
                total_value_locked=10000000.0,
                collateral_amount=8000000.0,
                borrowed_amount=3000000.0,
                liquidity_tokens=5000000.0,
                token_prices={"USDC": 1.0}
            )
            tracker.record_snapshot(snapshot)
        
        # Sudden drain
        drain_snapshot = TVLSnapshot(
            pool_address=pool_address,
            timestamp=datetime.now(),
            total_value_locked=3000000.0,  # 70% drop
            collateral_amount=1000000.0,
            borrowed_amount=3000000.0,
            liquidity_tokens=5000000.0,
            token_prices={"USDC": 1.0}
        )
        
        anomalies = tracker.record_snapshot(drain_snapshot)
        
        assert len(anomalies) > 0
        assert any(a.anomaly_type == AnomalyType.COLLATERAL_DRAIN for a in anomalies)
        
        tracker.close()
    
    def test_infinite_minting_scenario(self):
        """Test detection of infinite minting attack"""
        monitor = OracleMintMonitor(":memory:")
        
        token_address = "0xTOKEN1234567890"
        
        # Rapid minting without oracle updates
        for i in range(5):
            event = MintBurnEvent(
                token_address=token_address,
                event_type=MintBurnEventType.MINT,
                amount=1000000.0 * (i + 1),
                timestamp=datetime.now() - timedelta(minutes=i * 5),
                transaction_hash=f"0x{i:064x}",
                total_supply_after=10000000.0 + (1000000.0 * (i + 1))
            )
            anomalies = monitor.record_mint_burn_event(event)
        
        # Check for anomalies
        anomalies = monitor.get_token_anomalies(token_address)
        
        assert len(anomalies) > 0
        assert any(a.anomaly_type == "rapid_minting" for a in anomalies)
        
        monitor.close()
    
    def test_oracle_manipulation_scenario(self):
        """Test detection of oracle manipulation followed by minting"""
        monitor = OracleMintMonitor(":memory:")
        
        token_address = "0xTOKEN1234567890"
        
        # Oracle price update (manipulation)
        price_update = OracleUpdate(
            asset_id=token_address,
            update_type=OracleUpdateType.PRICE_UPDATE,
            old_value=100.0,
            new_value=200.0,  # 100% increase
            timestamp=datetime.now() - timedelta(minutes=10),
            oracle_address="0xoracle123"
        )
        monitor.record_oracle_update(price_update)
        
        # Minting shortly after
        mint_event = MintBurnEvent(
            token_address=token_address,
            event_type=MintBurnEventType.MINT,
            amount=5000000.0,
            timestamp=datetime.now() - timedelta(minutes=5),
            transaction_hash="0xabcdef"
        )
        monitor.record_mint_burn_event(mint_event)
        
        # Check for manipulation detection
        anomalies = monitor.get_token_anomalies(token_address)
        
        assert len(anomalies) > 0
        assert any(a.anomaly_type == "oracle_price_manipulation" for a in anomalies)
        
        monitor.close()


def test_convenience_function():
    """Test the convenience function for lending pool analysis"""
    from lending_pool_risk import analyze_lending_pool_risk
    
    result = analyze_lending_pool_risk(
        pool_address="0x1234567890",
        pool_type=PoolType.RWA_TOKENIZED,
        base_risk_score=0.4
    )
    
    assert result.pool_address == "0x1234567890"
    assert result.pool_type == PoolType.RWA_TOKENIZED
    assert result.base_risk_score == 0.4
    assert 0.0 <= result.modified_risk_score <= 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
