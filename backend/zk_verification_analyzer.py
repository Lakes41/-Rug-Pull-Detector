"""
Zero-Knowledge Verification Analyzer
Analyzes ZK verification contracts to detect privacy layer vulnerabilities.
Parses bytecode for cryptographic pairings and audits commitment tree state updates.
"""

import json
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ZKCurveType(Enum):
    """Supported ZK curve types"""
    BN254 = "bn254"
    ALT_BN128 = "alt_bn128"
    BLS12_381 = "bls12_381"
    EDWARDS = "edwards"
    UNKNOWN = "unknown"


class ZKRiskType(Enum):
    """Types of ZK-related privacy risks"""
    UNVERIFIED_PROOF_SUBMISSION = "unverified_proof_submission"
    NULLIFIER_REUSE = "nullifier_reuse"
    ROOT_ANCHOR_MISMATCH = "root_anchor_mismatch"
    NON_STANDARD_PAIRING = "non_standard_pairing"
    COMMITMENT_TREE_TAMPERING = "commitment_tree_tampering"
    MISSING_PROOF_VERIFICATION = "missing_proof_verification"
    PRIVACY_POOL_DRAIN_RISK = "privacy_pool_drain_risk"


@dataclass
class BytecodePattern:
    """Represents a bytecode pattern for cryptographic operations"""
    name: str
    pattern: bytes
    curve_type: ZKCurveType
    description: str


@dataclass
class CommitmentState:
    """Represents the state of a commitment tree"""
    root: str
    commitment_count: int
    latest_block: int
    nullifiers: Set[str] = field(default_factory=set)
    last_verified: Optional[str] = None


@dataclass
class ZKVerificationRisk:
    """Represents a ZK verification risk"""
    contract_id: str
    risk_type: ZKRiskType
    description: str
    severity: str  # "critical", "high", "medium", "low"
    affected_functions: List[str] = field(default_factory=list)
    technical_details: Dict = field(default_factory=dict)


@dataclass
class ShieldedPoolInfo:
    """Information about shielded pool balances"""
    contract_id: str
    total_shielded: int
    commitment_tree_depth: int
    recent_proof_count: int
    verification_enabled: bool


class BytecodeParser:
    """Parses verification contract bytecodes for cryptographic pairings"""
    
    # Known bytecode patterns for common ZK curve operations
    CURVE_PATTERNS = [
        BytecodePattern(
            name="BN254_PAIRING",
            pattern=bytes.fromhex("600a600f600039600a6000f3"),  # Common BN254 pairing signature
            curve_type=ZKCurveType.BN254,
            description="BN254 elliptic curve pairing operation"
        ),
        BytecodePattern(
            name="ALT_BN128_PAIRING",
            pattern=bytes.fromhex("6008600c60003960086000f3"),  # ALT_BN128 pairing signature
            curve_type=ZKCurveType.ALT_BN128,
            description="ALT_BN128 elliptic curve pairing operation"
        ),
        BytecodePattern(
            name="BLS12_381_PAIRING",
            pattern=bytes.fromhex("600c6010600039600c6000f3"),  # BLS12-381 pairing signature
            curve_type=ZKCurveType.BLS12_381,
            description="BLS12-381 elliptic curve pairing operation"
        ),
    ]
    
    def __init__(self):
        self.detected_curves: List[ZKCurveType] = []
        self.pairing_count: int = 0
        self.verification_functions: List[str] = []
    
    def parse_bytecode(self, bytecode: str) -> Dict:
        """
        Parse contract bytecode to detect cryptographic pairings
        
        Args:
            bytecode: Hex string of contract bytecode
            
        Returns:
            Dictionary with detected curve types and verification functions
        """
        if not bytecode or bytecode == "0x":
            return {
                "detected_curves": [ZKCurveType.UNKNOWN],
                "pairing_count": 0,
                "verification_functions": [],
                "is_standard": False
            }
        
        # Remove 0x prefix if present
        clean_bytecode = bytecode.replace("0x", "")
        
        try:
            bytecode_bytes = bytes.fromhex(clean_bytecode)
        except ValueError:
            return {
                "detected_curves": [ZKCurveType.UNKNOWN],
                "pairing_count": 0,
                "verification_functions": [],
                "is_standard": False,
                "error": "Invalid bytecode format"
            }
        
        self.detected_curves = []
        self.pairing_count = 0
        self.verification_functions = []
        
        # Detect curve patterns
        for pattern in self.CURVE_PATTERNS:
            occurrences = self._count_pattern_occurrences(bytecode_bytes, pattern.pattern)
            if occurrences > 0:
                self.detected_curves.append(pattern.curve_type)
                self.pairing_count += occurrences
        
        # Detect verification function signatures
        self._detect_verification_functions(bytecode_bytes)
        
        return {
            "detected_curves": self.detected_curves,
            "pairing_count": self.pairing_count,
            "verification_functions": self.verification_functions,
            "is_standard": len(self.detected_curves) > 0 and ZKCurveType.UNKNOWN not in self.detected_curves
        }
    
    def _count_pattern_occurrences(self, bytecode: bytes, pattern: bytes) -> int:
        """Count occurrences of a pattern in bytecode"""
        count = 0
        start = 0
        while True:
            start = bytecode.find(pattern, start)
            if start == -1:
                break
            count += 1
            start += len(pattern)
        return count
    
    def _detect_verification_functions(self, bytecode: bytes):
        """Detect common verification function signatures in bytecode"""
        # Common verification function selectors (first 4 bytes of function hash)
        verification_selectors = [
            bytes.fromhex("e9bb2e8d"),  # verifyProof
            bytes.fromhex("19013b55"),  # verify
            bytes.fromhex("8205bf6a"),  # verifyProofs
            bytes.fromhex("3b8f5b61"),  # verifyBatch
            bytes.fromhex("c4a5b1c2"),  # verifyMerkleProof
            bytes.fromhex("7b8e9d3f"),  # verifyZKProof
        ]
        
        for selector in verification_selectors:
            if selector in bytecode:
                self.verification_functions.append(selector.hex())


class CommitmentTreeAuditor:
    """Audits commitment tree state updates for ZK verification integrity"""
    
    def __init__(self):
        self.commitment_states: Dict[str, CommitmentState] = {}
        self.nullifier_history: Dict[str, List[str]] = {}
        self.root_anchors: Dict[str, List[str]] = {}
    
    def initialize_tree(self, contract_id: str, initial_root: str, block: int):
        """Initialize a commitment tree for tracking"""
        self.commitment_states[contract_id] = CommitmentState(
            root=initial_root,
            commitment_count=0,
            latest_block=block
        )
        self.root_anchors[contract_id] = [initial_root]
    
    def audit_state_update(self, contract_id: str, new_root: str, 
                          proof_hash: str, nullifiers: List[str], 
                          block: int, proof_verified: bool = False) -> List[Dict]:
        """
        Audit a commitment tree state update for potential vulnerabilities
        
        Args:
            contract_id: Contract identifier
            new_root: New commitment tree root
            proof_hash: Hash of the ZK proof
            nullifiers: List of nullifiers used in the transaction
            block: Block number
            proof_verified: Whether the proof was cryptographically verified
            
        Returns:
            List of detected risks (as dicts for JSON serialization)
        """
        risks = []
        
        if contract_id not in self.commitment_states:
            self.initialize_tree(contract_id, new_root, block)
        
        current_state = self.commitment_states[contract_id]
        
        # Check for unverified proof submission
        if not proof_verified:
            risk = {
                "contract_id": contract_id,
                "risk_type": ZKRiskType.UNVERIFIED_PROOF_SUBMISSION.value,
                "description": f"Commitment tree updated without cryptographic proof verification at block {block}",
                "severity": "critical",
                "affected_functions": [],
                "technical_details": {
                    "new_root": new_root,
                    "proof_hash": proof_hash,
                    "block": block
                }
            }
            risks.append(risk)
        
        # Check for nullifier reuse
        for nullifier in nullifiers:
            if nullifier in current_state.nullifiers:
                risk = {
                    "contract_id": contract_id,
                    "risk_type": ZKRiskType.NULLIFIER_REUSE.value,
                    "description": f"Nullifier {nullifier[:16]}... reused at block {block} - potential double-spend attack",
                    "severity": "critical",
                    "affected_functions": [],
                    "technical_details": {
                        "nullifier": nullifier,
                        "block": block,
                        "previous_use": self.nullifier_history.get(nullifier, [])
                    }
                }
                risks.append(risk)
            else:
                current_state.nullifiers.add(nullifier)
                if nullifier not in self.nullifier_history:
                    self.nullifier_history[nullifier] = []
                self.nullifier_history[nullifier].append(f"block_{block}")
        
        # Check for root anchor mismatch
        if new_root not in self.root_anchors[contract_id]:
            # Verify this is a valid state transition
            if not self._is_valid_root_transition(contract_id, new_root):
                risk = {
                    "contract_id": contract_id,
                    "risk_type": ZKRiskType.ROOT_ANCHOR_MISMATCH.value,
                    "description": f"New root {new_root[:16]}... does not match expected anchor chain at block {block}",
                    "severity": "high",
                    "affected_functions": [],
                    "technical_details": {
                        "new_root": new_root,
                        "expected_roots": self.root_anchors[contract_id][-3:],
                        "block": block
                    }
                }
                risks.append(risk)
            else:
                self.root_anchors[contract_id].append(new_root)
        
        # Update state
        current_state.root = new_root
        current_state.commitment_count += len(nullifiers)
        current_state.latest_block = block
        if proof_verified:
            current_state.last_verified = proof_hash
        
        return risks
    
    def _is_valid_root_transition(self, contract_id: str, new_root: str) -> bool:
        """Check if root transition is valid (simplified validation)"""
        # In production, this would verify the Merkle path or SNARK proof
        # For now, we'll do basic length and format checks
        if len(new_root) != 64:  # 32 bytes = 64 hex chars
            return False
        
        # Check if it's a valid hex string
        try:
            int(new_root, 16)
        except ValueError:
            return False
        
        return True
    
    def detect_commitment_tree_tampering(self, contract_id: str) -> Optional[Dict]:
        """Detect potential commitment tree tampering"""
        if contract_id not in self.commitment_states:
            return None
        
        state = self.commitment_states[contract_id]
        
        # Check for suspicious patterns (e.g., rapid root changes without verification)
        recent_roots = self.root_anchors[contract_id][-10:]
        if len(recent_roots) > 5 and state.last_verified is None:
            risk = ZKVerificationRisk(
                contract_id=contract_id,
                risk_type=ZKRiskType.COMMITMENT_TREE_TAMPERING,
                description=f"Multiple root updates without proof verification detected in recent blocks",
                severity="high",
                technical_details={
                    "recent_roots": recent_roots,
                    "total_updates": len(recent_roots)
                }
            )
            return {
                "contract_id": risk.contract_id,
                "risk_type": risk.risk_type.value,
                "description": risk.description,
                "severity": risk.severity,
                "affected_functions": risk.affected_functions,
                "technical_details": risk.technical_details
            }
        
        return None


class ZKVerificationAnalyzer:
    """Main analyzer for ZK verification contracts and privacy layers"""
    
    def __init__(self):
        self.bytecode_parser = BytecodeParser()
        self.commitment_auditor = CommitmentTreeAuditor()
        self.detected_risks: List[ZKVerificationRisk] = []
    
    def analyze_contract(self, contract_id: str, bytecode: str, 
                        shielded_pool_info: Optional[ShieldedPoolInfo] = None) -> Dict:
        """
        Analyze a ZK verification contract for privacy risks
        
        Args:
            contract_id: Contract identifier
            bytecode: Contract bytecode in hex format
            shielded_pool_info: Optional shielded pool information
            
        Returns:
            Analysis results with risks and recommendations
        """
        self.detected_risks = []
        
        # Parse bytecode for cryptographic pairings
        bytecode_analysis = self.bytecode_parser.parse_bytecode(bytecode)
        
        # Check for non-standard pairings
        if not bytecode_analysis["is_standard"]:
            risk = ZKVerificationRisk(
                contract_id=contract_id,
                risk_type=ZKRiskType.NON_STANDARD_PAIRING,
                description="Contract uses non-standard or unrecognized cryptographic pairings",
                severity="medium",
                technical_details=bytecode_analysis
            )
            self.detected_risks.append(risk)
        
        # Check for missing proof verification functions
        if not bytecode_analysis["verification_functions"]:
            risk = ZKVerificationRisk(
                contract_id=contract_id,
                risk_type=ZKRiskType.MISSING_PROOF_VERIFICATION,
                description="No standard proof verification functions detected in bytecode",
                severity="high",
                technical_details=bytecode_analysis
            )
            self.detected_risks.append(risk)
        
        # Analyze shielded pool information if provided
        pool_risks = []
        if shielded_pool_info:
            pool_risks = self._analyze_shielded_pool(shielded_pool_info)
            self.detected_risks.extend(pool_risks)
        
        return {
            "contract_id": contract_id,
            "bytecode_analysis": bytecode_analysis,
            "risks": self.detected_risks,
            "shielded_pool_risks": pool_risks,
            "privacy_risk_level": self._calculate_privacy_risk_level(),
            "recommendations": self._generate_recommendations()
        }
    
    def audit_transaction(self, contract_id: str, transaction_data: Dict) -> Dict:
        """
        Audit a transaction involving ZK proof submission
        
        Args:
            contract_id: Contract identifier
            transaction_data: Transaction data including proof, nullifiers, and state updates
            
        Returns:
            Audit results with detected risks
        """
        new_root = transaction_data.get("new_root")
        proof_hash = transaction_data.get("proof_hash")
        nullifiers = transaction_data.get("nullifiers", [])
        block = transaction_data.get("block", 0)
        proof_verified = transaction_data.get("proof_verified", False)
        
        risks = self.commitment_auditor.audit_state_update(
            contract_id, new_root, proof_hash, nullifiers, block, proof_verified
        )
        
        # Check for commitment tree tampering
        tampering_risk = self.commitment_auditor.detect_commitment_tree_tampering(contract_id)
        if tampering_risk:
            # tampering_risk is already formatted as a dict
            risks.append(tampering_risk)
        
        # Format commitment state for serialization
        commitment_state = None
        if contract_id in self.commitment_auditor.commitment_states:
            state = self.commitment_auditor.commitment_states[contract_id]
            commitment_state = {
                "root": state.root,
                "commitment_count": state.commitment_count,
                "latest_block": state.latest_block,
                "nullifier_count": len(state.nullifiers),
                "last_verified": state.last_verified
            }
        
        # Format risks for serialization
        formatted_risks = []
        for risk in risks:
            formatted_risks.append({
                "contract_id": risk.contract_id,
                "risk_type": risk.risk_type.value,
                "description": risk.description,
                "severity": risk.severity,
                "affected_functions": risk.affected_functions,
                "technical_details": risk.technical_details
            })
        
        return {
            "contract_id": contract_id,
            "transaction_audited": True,
            "risks_detected": len(risks),
            "risks": formatted_risks,
            "commitment_state": commitment_state
        }
    
    def _analyze_shielded_pool(self, pool_info: ShieldedPoolInfo) -> List[ZKVerificationRisk]:
        """Analyze shielded pool for privacy risks"""
        risks = []
        
        # Check if verification is disabled
        if not pool_info.verification_enabled:
            risk = ZKVerificationRisk(
                contract_id=pool_info.contract_id,
                risk_type=ZKRiskType.PRIVACY_POOL_DRAIN_RISK,
                description=f"Shielded pool has proof verification disabled - high drain risk",
                severity="critical",
                technical_details={
                    "total_shielded": pool_info.total_shielded,
                    "recent_proof_count": pool_info.recent_proof_count
                }
            )
            risks.append(risk)
        
        # Check for suspicious activity patterns
        if pool_info.recent_proof_count > 100 and pool_info.verification_enabled:
            risk = ZKVerificationRisk(
                contract_id=pool_info.contract_id,
                risk_type=ZKRiskType.PRIVACY_POOL_DRAIN_RISK,
                description=f"High volume of recent proofs ({pool_info.recent_proof_count}) - potential drain attack",
                severity="medium",
                technical_details={
                    "recent_proof_count": pool_info.recent_proof_count,
                    "total_shielded": pool_info.total_shielded
                }
            )
            risks.append(risk)
        
        return risks
    
    def _calculate_privacy_risk_level(self) -> str:
        """Calculate overall privacy risk level based on detected risks"""
        if not self.detected_risks:
            return "LOW"
        
        critical_count = sum(1 for r in self.detected_risks if r.severity == "critical")
        high_count = sum(1 for r in self.detected_risks if r.severity == "high")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 0:
            return "HIGH"
        elif len(self.detected_risks) > 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on detected risks"""
        recommendations = []
        
        for risk in self.detected_risks:
            if risk.risk_type == ZKRiskType.NON_STANDARD_PAIRING:
                recommendations.append(
                    "Use standard cryptographic pairings (BN254/ALT_BN128) for better auditability"
                )
            elif risk.risk_type == ZKRiskType.MISSING_PROOF_VERIFICATION:
                recommendations.append(
                    "Implement proper proof verification functions before accepting state updates"
                )
            elif risk.risk_type == ZKRiskType.UNVERIFIED_PROOF_SUBMISSION:
                recommendations.append(
                    "Enable mandatory cryptographic verification for all proof submissions"
                )
            elif risk.risk_type == ZKRiskType.NULLIFIER_REUSE:
                recommendations.append(
                    "Implement nullifier tracking to prevent double-spend attacks"
                )
            elif risk.risk_type == ZKRiskType.ROOT_ANCHOR_MISMATCH:
                recommendations.append(
                    "Verify root anchor chain consistency before accepting state transitions"
                )
            elif risk.risk_type == ZKRiskType.PRIVACY_POOL_DRAIN_RISK:
                recommendations.append(
                    "Implement rate limiting and monitoring for shielded pool operations"
                )
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def generate_privacy_disclosure(self, analysis_result: Dict) -> str:
        """
        Generate privacy risk disclosure for dashboard display
        
        Args:
            analysis_result: Result from analyze_contract
            
        Returns:
            Formatted disclosure string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("ZERO-KNOWLEDGE PRIVACY RISK DISCLOSURE")
        lines.append("=" * 60)
        lines.append(f"Contract: {analysis_result['contract_id']}")
        lines.append(f"Privacy Risk Level: {analysis_result['privacy_risk_level']}")
        lines.append("")
        
        if analysis_result["bytecode_analysis"]["detected_curves"]:
            lines.append("Detected Cryptographic Pairings:")
            for curve in analysis_result["bytecode_analysis"]["detected_curves"]:
                lines.append(f"  - {curve.value}")
            lines.append("")
        
        if analysis_result["risks"]:
            lines.append("DETECTED PRIVACY RISKS:")
            lines.append("-" * 60)
            for risk in analysis_result["risks"]:
                lines.append(f"\n[{risk.severity.upper()}] {risk.risk_type.value}")
                lines.append(f"Description: {risk.description}")
                if risk.affected_functions:
                    lines.append(f"Affected Functions: {', '.join(risk.affected_functions)}")
        else:
            lines.append("✓ No privacy risks detected")
        
        if analysis_result["recommendations"]:
            lines.append("\n" + "=" * 60)
            lines.append("SECURITY RECOMMENDATIONS:")
            lines.append("-" * 60)
            for i, rec in enumerate(analysis_result["recommendations"], 1):
                lines.append(f"{i}. {rec}")
        
        lines.append("=" * 60)
        return "\n".join(lines)


def analyze_zk_contract(contract_id: str, bytecode: str, 
                       shielded_pool_info: Optional[Dict] = None) -> Dict:
    """
    Convenience function to analyze a ZK verification contract
    
    Args:
        contract_id: Contract identifier
        bytecode: Contract bytecode in hex format
        shielded_pool_info: Optional shielded pool information dictionary
        
    Returns:
        Analysis results
    """
    analyzer = ZKVerificationAnalyzer()
    
    pool_info = None
    if shielded_pool_info:
        pool_info = ShieldedPoolInfo(**shielded_pool_info)
    
    return analyzer.analyze_contract(contract_id, bytecode, pool_info)


if __name__ == "__main__":
    # Example usage with mock data
    mock_bytecode = "0x600a600f600039600a6000f3"  # BN254 pairing pattern
    mock_pool_info = {
        "contract_id": "0x1234567890abcdef",
        "total_shielded": 1000000,
        "commitment_tree_depth": 20,
        "recent_proof_count": 50,
        "verification_enabled": True
    }
    
    result = analyze_zk_contract("0x1234567890abcdef", mock_bytecode, mock_pool_info)
    analyzer = ZKVerificationAnalyzer()
    print(analyzer.generate_privacy_disclosure(result))
    
    # Example transaction audit
    mock_transaction = {
        "new_root": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        "proof_hash": "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        "nullifiers": ["nullifier_1", "nullifier_2"],
        "block": 12345,
        "proof_verified": True
    }
    
    audit_result = analyzer.audit_transaction("0x1234567890abcdef", mock_transaction)
    print("\nTransaction Audit Result:")
    print(json.dumps(audit_result, indent=2))