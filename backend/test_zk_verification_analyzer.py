"""
Test suite for Zero-Knowledge Verification Analyzer
Tests bytecode parsing, commitment tree auditing, and risk detection.
"""

import pytest
from zk_verification_analyzer import (
    ZKVerificationAnalyzer,
    BytecodeParser,
    CommitmentTreeAuditor,
    ZKCurveType,
    ZKRiskType,
    ShieldedPoolInfo,
    analyze_zk_contract
)


class TestBytecodeParser:
    """Test bytecode parsing for cryptographic pairings"""
    
    def test_parse_valid_bn254_bytecode(self):
        """Test parsing bytecode with BN254 pairing pattern"""
        parser = BytecodeParser()
        bytecode = "0x600a600f600039600a6000f3"  # BN254 pattern
        result = parser.parse_bytecode(bytecode)
        
        assert result["is_standard"] == True
        assert ZKCurveType.BN254 in result["detected_curves"]
        assert result["pairing_count"] >= 1
    
    def test_parse_empty_bytecode(self):
        """Test parsing empty bytecode"""
        parser = BytecodeParser()
        result = parser.parse_bytecode("0x")
        
        assert result["is_standard"] == False
        assert ZKCurveType.UNKNOWN in result["detected_curves"]
        assert result["pairing_count"] == 0
    
    def test_parse_invalid_bytecode(self):
        """Test parsing invalid bytecode"""
        parser = BytecodeParser()
        result = parser.parse_bytecode("0xinvalidhex")
        
        assert result["is_standard"] == False
        assert "error" in result
    
    def test_parse_alt_bn128_bytecode(self):
        """Test parsing bytecode with ALT_BN128 pairing pattern"""
        parser = BytecodeParser()
        bytecode = "0x6008600c60003960086000f3"  # ALT_BN128 pattern
        result = parser.parse_bytecode(bytecode)
        
        assert result["is_standard"] == True
        assert ZKCurveType.ALT_BN128 in result["detected_curves"]


class TestCommitmentTreeAuditor:
    """Test commitment tree state update auditing"""
    
    def test_initialize_tree(self):
        """Test commitment tree initialization"""
        auditor = CommitmentTreeAuditor()
        contract_id = "test_contract"
        initial_root = "a1b2c3d4" * 8  # 32 bytes
        
        auditor.initialize_tree(contract_id, initial_root, 100)
        
        assert contract_id in auditor.commitment_states
        assert auditor.commitment_states[contract_id].root == initial_root
        assert auditor.commitment_states[contract_id].latest_block == 100
    
    def test_detect_unverified_proof_submission(self):
        """Test detection of unverified proof submissions"""
        auditor = CommitmentTreeAuditor()
        contract_id = "test_contract"
        initial_root = "a1b2c3d4" * 8
        
        auditor.initialize_tree(contract_id, initial_root, 100)
        
        new_root = "b2c3d4e5" * 8
        risks = auditor.audit_state_update(
            contract_id, new_root, "proof_hash", ["nullifier1"], 101, proof_verified=False
        )
        
        assert len(risks) > 0
        assert any(risk["risk_type"] == "unverified_proof_submission" for risk in risks)
    
    def test_detect_nullifier_reuse(self):
        """Test detection of nullifier reuse"""
        auditor = CommitmentTreeAuditor()
        contract_id = "test_contract"
        initial_root = "a1b2c3d4" * 8
        
        auditor.initialize_tree(contract_id, initial_root, 100)
        
        # First use of nullifier
        new_root = "b2c3d4e5" * 8
        risks1 = auditor.audit_state_update(
            contract_id, new_root, "proof_hash", ["nullifier1"], 101, proof_verified=True
        )
        
        # Reuse the same nullifier
        new_root2 = "c3d4e5f6" * 8
        risks2 = auditor.audit_state_update(
            contract_id, new_root2, "proof_hash2", ["nullifier1"], 102, proof_verified=True
        )
        
        assert len(risks2) > 0
        assert any(risk["risk_type"] == "nullifier_reuse" for risk in risks2)
    
    def test_detect_root_anchor_mismatch(self):
        """Test detection of root anchor mismatch"""
        auditor = CommitmentTreeAuditor()
        contract_id = "test_contract"
        initial_root = "a1b2c3d4" * 8
        
        auditor.initialize_tree(contract_id, initial_root, 100)
        
        # Invalid root (too short)
        new_root = "invalid"
        risks = auditor.audit_state_update(
            contract_id, new_root, "proof_hash", ["nullifier1"], 101, proof_verified=True
        )
        
        assert len(risks) > 0
        assert any(risk["risk_type"] == "root_anchor_mismatch" for risk in risks)


class TestZKVerificationAnalyzer:
    """Test main ZK verification analyzer"""
    
    def test_analyze_contract_with_valid_bytecode(self):
        """Test contract analysis with valid bytecode"""
        analyzer = ZKVerificationAnalyzer()
        contract_id = "test_contract"
        bytecode = "0x600a600f600039600a6000f3"  # BN254 pattern
        
        result = analyzer.analyze_contract(contract_id, bytecode)
        
        assert result["contract_id"] == contract_id
        assert result["bytecode_analysis"]["is_standard"] == True
        assert "privacy_risk_level" in result
    
    def test_analyze_contract_with_shielded_pool_risk(self):
        """Test contract analysis with shielded pool risks"""
        analyzer = ZKVerificationAnalyzer()
        contract_id = "test_contract"
        bytecode = "0x600a600f600039600a6000f3"
        
        pool_info = ShieldedPoolInfo(
            contract_id=contract_id,
            total_shielded=1000000,
            commitment_tree_depth=20,
            recent_proof_count=50,
            verification_enabled=False  # Disabled verification
        )
        
        result = analyzer.analyze_contract(contract_id, bytecode, pool_info)
        
        assert len(result["shielded_pool_risks"]) > 0
        assert result["privacy_risk_level"] in ["HIGH", "CRITICAL"]
    
    def test_audit_transaction(self):
        """Test transaction auditing"""
        analyzer = ZKVerificationAnalyzer()
        contract_id = "test_contract"
        
        transaction_data = {
            "new_root": "a1b2c3d4e5f67890" * 4,
            "proof_hash": "fedcba0987654321" * 4,
            "nullifiers": ["nullifier1", "nullifier2"],
            "block": 12345,
            "proof_verified": True
        }
        
        result = analyzer.audit_transaction(contract_id, transaction_data)
        
        assert result["transaction_audited"] == True
        assert "commitment_state" in result
        assert result["contract_id"] == contract_id
    
    def test_generate_privacy_disclosure(self):
        """Test privacy disclosure generation"""
        analyzer = ZKVerificationAnalyzer()
        contract_id = "test_contract"
        bytecode = "0x600a600f600039600a6000f3"
        
        result = analyzer.analyze_contract(contract_id, bytecode)
        disclosure = analyzer.generate_privacy_disclosure(result)
        
        assert "ZERO-KNOWLEDGE PRIVACY RISK DISCLOSURE" in disclosure
        assert contract_id in disclosure
        assert "Privacy Risk Level" in disclosure
    
    def test_calculate_privacy_risk_level(self):
        """Test privacy risk level calculation"""
        analyzer = ZKVerificationAnalyzer()
        
        # No risks
        analyzer.detected_risks = []
        assert analyzer._calculate_privacy_risk_level() == "LOW"
        
        # High risk
        from zk_verification_analyzer import ZKVerificationRisk
        analyzer.detected_risks = [
            ZKVerificationRisk(
                contract_id="test",
                risk_type=ZKRiskType.MISSING_PROOF_VERIFICATION,
                description="Test",
                severity="high"
            )
        ]
        assert analyzer._calculate_privacy_risk_level() == "HIGH"
        
        # Critical risk
        analyzer.detected_risks = [
            ZKVerificationRisk(
                contract_id="test",
                risk_type=ZKRiskType.UNVERIFIED_PROOF_SUBMISSION,
                description="Test",
                severity="critical"
            )
        ]
        assert analyzer._calculate_privacy_risk_level() == "CRITICAL"


class TestConvenienceFunction:
    """Test convenience functions"""
    
    def test_analyze_zk_contract_convenience(self):
        """Test the convenience function"""
        contract_id = "test_contract"
        bytecode = "0x600a600f600039600a6000f3"
        
        result = analyze_zk_contract(contract_id, bytecode)
        
        assert result["contract_id"] == contract_id
        assert "bytecode_analysis" in result
        assert "risks" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])