"""
Test suite for Proxy Pattern Analyzer
Tests storage slot resolution, timelock verification, and risk detection.
"""

import pytest
from proxy_pattern_analyzer import (
    ProxyPatternAnalyzer,
    ProxyStorageResolver,
    TimelockGovernanceVerifier,
    ProxyType,
    ProxyRiskType,
    ProxyStorageSlot,
    TimelockInfo,
    PROXY_STORAGE_SLOTS,
    analyze_proxy_contract
)


class TestProxyStorageResolver:
    """Test proxy storage slot resolution"""
    
    def test_storage_slot_configurations(self):
        """Test that storage slot configurations are properly defined"""
        assert ProxyType.EIP_1967 in PROXY_STORAGE_SLOTS
        assert ProxyType.EIP_897 in PROXY_STORAGE_SLOTS
        assert ProxyType.BEACON in PROXY_STORAGE_SLOTS
        
        # Check EIP-1967 implementation slot
        eip1967_slots = PROXY_STORAGE_SLOTS[ProxyType.EIP_1967]
        implementation_slot = eip1967_slots[0]
        assert implementation_slot.name == "EIP_1967_IMPLEMENTATION"
        assert implementation_slot.slot_address == "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        
        # Check EIP-1967 admin slot
        admin_slot = eip1967_slots[2]
        assert admin_slot.name == "EIP_1967_ADMIN"
        assert admin_slot.slot_address == "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
    
    def test_storage_slot_initialization(self):
        """Test storage resolver initialization"""
        resolver = ProxyStorageResolver()
        assert resolver.web3 is not None
        assert resolver.detected_proxies == {}
    
    def test_detect_proxy_type_without_web3(self):
        """Test proxy type detection without actual Web3 connection"""
        resolver = ProxyStorageResolver()
        proxy_type, implementation = resolver.detect_proxy_type("0x1234567890abcdef")
        
        # Without actual Web3 connection, should return unknown
        assert proxy_type == ProxyType.UNKNOWN
        assert implementation is None


class TestTimelockGovernanceVerifier:
    """Test timelock governance verification"""
    
    def test_minimum_delay_constant(self):
        """Test that minimum delay is set to 24 hours"""
        verifier = TimelockGovernanceVerifier()
        assert verifier.MINIMUM_DELAY_SECONDS == 24 * 60 * 60  # 24 hours in seconds
    
    def test_timelock_info_initialization(self):
        """Test timelock info initialization"""
        timelock_info = TimelockInfo(
            has_timelock=False,
            minimum_delay=0,
            is_governance_delay_sufficient=False
        )
        
        assert timelock_info.has_timelock == False
        assert timelock_info.minimum_delay == 0
        assert timelock_info.is_governance_delay_sufficient == False
        assert timelock_info.timelock_address is None
        assert timelock_info.admins == []
    
    def test_verify_timelock_without_web3(self):
        """Test timelock verification without actual Web3 connection"""
        verifier = TimelockGovernanceVerifier()
        timelock_info = verifier.verify_timelock("0x1234567890abcdef")
        
        # Without actual Web3 connection, should return no timelock
        assert timelock_info.has_timelock == False
        assert timelock_info.minimum_delay == 0
        assert timelock_info.is_governance_delay_sufficient == False
    
    def test_delay_sufficiency_check(self):
        """Test delay sufficiency logic"""
        verifier = TimelockGovernanceVerifier()
        
        # Test sufficient delay (24 hours)
        sufficient_info = TimelockInfo(
            has_timelock=True,
            minimum_delay=24 * 60 * 60,
            is_governance_delay_sufficient=False
        )
        sufficient_info.is_governance_delay_sufficient = (
            sufficient_info.minimum_delay >= verifier.MINIMUM_DELAY_SECONDS
        )
        assert sufficient_info.is_governance_delay_sufficient == True
        
        # Test insufficient delay (12 hours)
        insufficient_info = TimelockInfo(
            has_timelock=True,
            minimum_delay=12 * 60 * 60,
            is_governance_delay_sufficient=False
        )
        insufficient_info.is_governance_delay_sufficient = (
            insufficient_info.minimum_delay >= verifier.MINIMUM_DELAY_SECONDS
        )
        assert insufficient_info.is_governance_delay_sufficient == False


class TestProxyPatternAnalyzer:
    """Test main proxy pattern analyzer"""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        analyzer = ProxyPatternAnalyzer()
        assert analyzer.web3 is not None
        assert analyzer.storage_resolver is not None
        assert analyzer.timelock_verifier is not None
        assert analyzer.detected_risks == []
        assert analyzer.proxy_history == {}
    
    def test_analyze_non_proxy_contract(self):
        """Test analysis of non-proxy contract"""
        analyzer = ProxyPatternAnalyzer()
        result = analyzer.analyze_proxy_contract("0x1234567890abcdef")
        
        # Without actual Web3 connection, should return non-proxy
        assert result["is_proxy"] == False
        assert result["proxy_type"] == "unknown"
        assert result["risks"] == []
        assert result["risk_multiplier"] == 1.0
    
    def test_risk_multiplier_calculation(self):
        """Test risk multiplier calculation"""
        analyzer = ProxyPatternAnalyzer()
        
        # No risks
        analyzer.detected_risks = []
        assert analyzer._calculate_risk_multiplier() == 1.0
        
        # Single risk with multiplier
        from proxy_pattern_analyzer import ProxyRisk
        analyzer.detected_risks = [
            ProxyRisk(
                contract_id="test",
                risk_type=ProxyRiskType.INSTANT_LOGIC_SWAP,
                description="Test",
                severity="critical",
                risk_multiplier=3.0
            )
        ]
        assert analyzer._calculate_risk_multiplier() == 3.0
        
        # Multiple risks
        analyzer.detected_risks = [
            ProxyRisk(
                contract_id="test",
                risk_type=ProxyRiskType.INSTANT_LOGIC_SWAP,
                description="Test",
                severity="critical",
                risk_multiplier=3.0
            ),
            ProxyRisk(
                contract_id="test",
                risk_type=ProxyRiskType.ADMIN_CAN_UPGRADE,
                description="Test",
                severity="medium",
                risk_multiplier=1.5
            )
        ]
        multiplier = analyzer._calculate_risk_multiplier()
        assert abs(multiplier - 3.6) < 0.01  # 3.0 * 1.2 for multiple risks (floating point tolerance)
    
    def test_risk_multiplier_capping(self):
        """Test that risk multiplier is capped at 5.0"""
        analyzer = ProxyPatternAnalyzer()
        
        from proxy_pattern_analyzer import ProxyRisk
        analyzer.detected_risks = [
            ProxyRisk(
                contract_id="test",
                risk_type=ProxyRiskType.INSTANT_LOGIC_SWAP,
                description="Test",
                severity="critical",
                risk_multiplier=5.0
            )
        ]
        assert analyzer._calculate_risk_multiplier() == 5.0
        
        # Try with higher multiplier
        analyzer.detected_risks = [
            ProxyRisk(
                contract_id="test",
                risk_type=ProxyRiskType.INSTANT_LOGIC_SWAP,
                description="Test",
                severity="critical",
                risk_multiplier=10.0
            )
        ]
        assert analyzer._calculate_risk_multiplier() == 5.0  # Should be capped
    
    def test_recommendation_generation(self):
        """Test security recommendation generation"""
        analyzer = ProxyPatternAnalyzer()
        
        from proxy_pattern_analyzer import ProxyRisk
        analyzer.detected_risks = [
            ProxyRisk(
                contract_id="test",
                risk_type=ProxyRiskType.INSTANT_LOGIC_SWAP,
                description="Test",
                severity="critical",
                risk_multiplier=3.0
            ),
            ProxyRisk(
                contract_id="test",
                risk_type=ProxyRiskType.ADMIN_CAN_UPGRADE,
                description="Test",
                severity="medium",
                risk_multiplier=1.5
            )
        ]
        
        recommendations = analyzer._generate_recommendations()
        assert len(recommendations) > 0
        assert any("timelock" in rec.lower() for rec in recommendations)
        assert any("governance" in rec.lower() for rec in recommendations)
    
    def test_risk_formatting(self):
        """Test risk formatting for JSON serialization"""
        analyzer = ProxyPatternAnalyzer()
        
        from proxy_pattern_analyzer import ProxyRisk
        risk = ProxyRisk(
            contract_id="0x1234567890abcdef",
            risk_type=ProxyRiskType.INSTANT_LOGIC_SWAP,
            description="Test risk",
            severity="critical",
            risk_multiplier=3.0,
            technical_details={"test": "data"}
        )
        
        formatted = analyzer._format_risk(risk)
        assert formatted["contract_id"] == "0x1234567890abcdef"
        assert formatted["risk_type"] == "instant_logic_swap"
        assert formatted["description"] == "Test risk"
        assert formatted["severity"] == "critical"
        assert formatted["risk_multiplier"] == 3.0
        assert formatted["technical_details"] == {"test": "data"}


class TestConvenienceFunction:
    """Test convenience functions"""
    
    def test_analyze_proxy_contract_convenience(self):
        """Test the convenience function"""
        contract_address = "0x1234567890abcdef"
        
        result = analyze_proxy_contract(contract_address)
        
        assert result["contract_address"] == contract_address
        assert "is_proxy" in result
        assert "risks" in result
        assert "risk_multiplier" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])