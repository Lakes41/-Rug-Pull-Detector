"""
Test cases for Event Validator and Validated Scoring
Tests transaction receipt validation, event verification, and spoofing detection.
"""

import pytest
from datetime import datetime
from event_validator import (
    TransactionReceiptValidator,
    EventAddressVerifier,
    EventSpoofDetector,
    TransactionReceipt,
    EventLog,
    StateChange,
    EventType,
    ValidationResult
)
from validated_scoring import (
    ValidatedScoringEngine,
    EnhancedRiskAnalyzer,
    ValidatedMetrics,
    ScoringResult
)


class TestTransactionReceiptValidator:
    """Test transaction receipt validation"""
    
    def test_validate_valid_transfer_event(self):
        """Test validation of a valid transfer event"""
        validator = TransactionReceiptValidator()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        validations = validator.validate_receipt(receipt)
        
        assert len(validations) == 1
        assert validations["0"].is_valid == True
        assert validations["0"].result == ValidationResult.VALID
    
    def test_validate_spoofed_transfer_event(self):
        """Test detection of spoofed transfer event"""
        validator = TransactionReceiptValidator()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xFAKE123",  # Wrong address
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x5000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                # No state changes for the spoofed event
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        validations = validator.validate_receipt(receipt)
        
        assert len(validations) == 1
        assert validations["0"].is_valid == False
        assert validations["0"].result == ValidationResult.SPOOFED
    
    def test_validate_mint_without_supply_change(self):
        """Test detection of mint event without supply change"""
        validator = TransactionReceiptValidator()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.MINT,
                    topics=["0xMint", "0xABC123"],
                    data="0x10000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                # No supply change
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        validations = validator.validate_receipt(receipt)
        
        assert len(validations) == 1
        assert validations["0"].is_valid == False
        assert "No total supply state change found" in validations["0"].discrepancies[0]
    
    def test_validate_burn_without_supply_change(self):
        """Test detection of burn event without supply change"""
        validator = TransactionReceiptValidator()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.BURN,
                    topics=["0xBurn", "0xABC123"],
                    data="0x10000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                # No supply change
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        validations = validator.validate_receipt(receipt)
        
        assert len(validations) == 1
        assert validations["0"].is_valid == False
        assert "No total supply state change found" in validations["0"].discrepancies[0]
    
    def test_get_valid_events(self):
        """Test filtering valid events"""
        validator = TransactionReceiptValidator()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x5000000000000000000",
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        valid_events = validator.get_valid_events(receipt)
        
        assert len(valid_events) == 1
        assert valid_events[0].log_index == 0


class TestEventAddressVerifier:
    """Test event address verification"""
    
    def test_verify_valid_transfer_addresses(self):
        """Test verification of valid transfer addresses"""
        verifier = EventAddressVerifier()
        
        event = EventLog(
            address="0xCONTRACT",
            event_type=EventType.TRANSFER,
            topics=["0xTransfer", "0xABC123", "0xDEF456"],
            data="0x1000000000000000000",
            log_index=0,
            transaction_hash="0x123",
            block_number=12345
        )
        
        is_valid, issues = verifier.verify_event_addresses(
            event,
            msg_sender="0xABC123",
            contract_address="0xCONTRACT"
        )
        
        assert is_valid == True
        assert len(issues) == 0
    
    def test_verify_wrong_contract_address(self):
        """Test detection of wrong contract address"""
        verifier = EventAddressVerifier()
        
        event = EventLog(
            address="0xFAKE123",
            event_type=EventType.TRANSFER,
            topics=["0xTransfer", "0xABC123", "0xDEF456"],
            data="0x1000000000000000000",
            log_index=0,
            transaction_hash="0x123",
            block_number=12345
        )
        
        is_valid, issues = verifier.verify_event_addresses(
            event,
            msg_sender="0xABC123",
            contract_address="0xCONTRACT"
        )
        
        assert is_valid == False
        assert len(issues) > 0
        assert "does not match contract address" in issues[0]
    
    def test_verify_mint_from_wrong_address(self):
        """Test detection of mint from wrong address"""
        verifier = EventAddressVerifier()
        
        event = EventLog(
            address="0xFAKE123",
            event_type=EventType.MINT,
            topics=["0xMint", "0xABC123"],
            data="0x1000000000000000000",
            log_index=0,
            transaction_hash="0x123",
            block_number=12345
        )
        
        is_valid, issues = verifier.verify_event_addresses(
            event,
            msg_sender="0xABC123",
            contract_address="0xCONTRACT"
        )
        
        assert is_valid == False
        assert len(issues) > 0


class TestEventSpoofDetector:
    """Test comprehensive spoofing detection"""
    
    def test_detect_no_spoofing(self):
        """Test detection with no spoofing"""
        detector = EventSpoofDetector()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        detection = detector.detect_spoofing(receipt)
        
        assert detection["total_events"] == 1
        assert detection["valid_events"] == 1
        assert detection["spoofed_events"] == 0
        assert detection["is_likely_spoofed"] == False
    
    def test_detect_spoofing(self):
        """Test detection with spoofed events"""
        detector = EventSpoofDetector()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x5000000000000000000",
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        detection = detector.detect_spoofing(receipt)
        
        assert detection["total_events"] == 2
        assert detection["valid_events"] == 1
        assert detection["spoofed_events"] == 1
        assert detection["is_likely_spoofed"] == True
    
    def test_get_trusted_events(self):
        """Test filtering trusted events"""
        detector = EventSpoofDetector()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x5000000000000000000",
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        trusted_events = detector.get_trusted_events(receipt)
        
        assert len(trusted_events) == 1
        assert trusted_events[0].log_index == 0


class TestValidatedScoringEngine:
    """Test validated scoring engine"""
    
    def test_calculate_validated_score_no_spoofing(self):
        """Test scoring with no spoofing"""
        engine = ValidatedScoringEngine()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        result = engine.calculate_validated_score(receipt, base_score=0.3)
        
        assert result.is_manipulated == False
        assert result.confidence == "high"
        assert result.spoofed_event_count == 0
    
    def test_calculate_validated_score_with_spoofing(self):
        """Test scoring with spoofing"""
        engine = ValidatedScoringEngine()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x5000000000000000000",
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        result = engine.calculate_validated_score(receipt, base_score=0.3)
        
        assert result.is_manipulated == True
        assert result.spoofed_event_count == 1
        assert result.total_event_count == 2
        assert result.validated_score != result.raw_score
    
    def test_get_volume_adjustment(self):
        """Test volume adjustment calculation"""
        engine = ValidatedScoringEngine()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x5000000000000000000",
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        adjustment = engine.get_volume_adjustment(receipt)
        
        assert adjustment["raw_volume"] > adjustment["validated_volume"]
        assert adjustment["adjustment_ratio"] < 1.0
        assert adjustment["is_volume_manipulated"] == True


class TestEnhancedRiskAnalyzer:
    """Test enhanced risk analyzer with event validation"""
    
    def test_analyze_with_validation_no_manipulation(self):
        """Test analysis with no manipulation"""
        analyzer = EnhancedRiskAnalyzer()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        result = analyzer.analyze_with_validation(receipt, base_risk_score=0.3)
        
        assert result["is_manipulated"] == False
        assert result["confidence"] == "high"
        assert result["final_score"] == result["raw_score"]
    
    def test_analyze_with_validation_manipulation(self):
        """Test analysis with manipulation detected"""
        analyzer = EnhancedRiskAnalyzer()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x5000000000000000000",
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        result = analyzer.analyze_with_validation(receipt, base_risk_score=0.3)
        
        assert result["is_manipulated"] == True
        assert result["final_score"] == result["validated_score"]
        assert len(result["recommendations"]) > 0
        assert any("spoofing" in rec.lower() for rec in result["recommendations"])


class TestSpoofingScenarios:
    """Test realistic spoofing scenarios"""
    
    def test_fake_volume_scenario(self):
        """Test fake volume inflation scenario"""
        analyzer = EnhancedRiskAnalyzer()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                # One real transfer
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000",  # 1 token
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                # Multiple fake transfers to inflate volume
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xABC123", "0xDEF456"],
                    data="0x1000000000000000000000",  # 1000 tokens fake
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.TRANSFER,
                    topics=["0xTransfer", "0xDEF456", "0xABC123"],
                    data="0x1000000000000000000000",  # 1000 tokens fake
                    log_index=2,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                # Only state changes for the real transfer
                StateChange(
                    address="0xABC123",
                    key="balance",
                    old_value="1000000000000000000",
                    new_value="0",
                    change_type="balance"
                ),
                StateChange(
                    address="0xDEF456",
                    key="balance",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="balance"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        result = analyzer.analyze_with_validation(receipt, base_risk_score=0.3)
        
        assert result["is_manipulated"] == True
        assert result["volume_adjustment"]["is_volume_manipulated"] == True
        assert result["volume_adjustment"]["adjustment_ratio"] < 0.5
    
    def test_fake_liquidity_scenario(self):
        """Test fake liquidity scenario"""
        analyzer = EnhancedRiskAnalyzer()
        
        receipt = TransactionReceipt(
            transaction_hash="0x123",
            from_address="0xABC123",
            to_address="0xCONTRACT",
            contract_address="0xCONTRACT",
            status="success",
            gas_used=50000,
            logs=[
                EventLog(
                    address="0xCONTRACT",
                    event_type=EventType.ADD_LIQUIDITY,
                    topics=["0xAddLiquidity", "0xABC123"],
                    data="0x1000000000000000000",
                    log_index=0,
                    transaction_hash="0x123",
                    block_number=12345
                ),
                EventLog(
                    address="0xFAKE123",
                    event_type=EventType.ADD_LIQUIDITY,
                    topics=["0xAddLiquidity", "0xABC123"],
                    data="0x10000000000000000000",
                    log_index=1,
                    transaction_hash="0x123",
                    block_number=12345
                )
            ],
            state_changes=[
                StateChange(
                    address="0xCONTRACT",
                    key="liquidity",
                    old_value="0",
                    new_value="1000000000000000000",
                    change_type="liquidity"
                )
            ],
            block_number=12345,
            timestamp=datetime.now()
        )
        
        result = analyzer.analyze_with_validation(receipt, base_risk_score=0.3)
        
        assert result["is_manipulated"] == True
        assert result["liquidity_adjustment"]["is_liquidity_manipulated"] == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
