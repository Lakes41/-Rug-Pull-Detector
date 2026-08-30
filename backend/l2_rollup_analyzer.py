"""
Layer 2 Rollup Centralization & Exit Risk Analyzer
Evaluates target L2 token contracts for force-inclusion mechanisms and L1 escape hatch functions,
tracks active sequencer status, computes finality risk ratings based on bridge withdrawal challenge delays,
and generates L2 centralization parameters and sequencer dependency warnings.
"""

import json
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum


class SequencerStatus(Enum):
    """Active sequencer operating status"""
    ACTIVE = "active"
    HALTED = "halted"
    DEGRADED = "degraded"
    DOWN = "down"


class RollupType(Enum):
    """Layer 2 Rollup architecture type"""
    OPTIMISTIC = "optimistic"
    ZK_ROLLUP = "zk_rollup"
    VALIDIUM = "validium"
    UNKNOWN = "unknown"


class FinalityRiskLevel(Enum):
    """Finality risk rating level"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class L2CentralizationParams:
    """Centralization and escape parameters for L2 deployment"""
    rollup_type: str
    sequencer_status: str
    challenge_window_seconds: int
    challenge_window_days: float
    force_inclusion_enabled: bool
    escape_hatch_available: bool
    sequencer_address: Optional[str] = None
    l1_bridge_address: Optional[str] = None


class ContractEvaluator:
    """Evaluates target L2 token contracts for force-inclusion mechanisms and L1 escape hatch functions"""

    # Function signatures & method names for force inclusion
    FORCE_INCLUSION_SIGNATURES = [
        "forceinclusion",
        "forceincludetx",
        "deposittransaction",
        "enqueuetransaction",
        "enqueue",
        "forceinclusionenabled",
        "force_inclusion",
        "force_include",
        "l1toL2message",
    ]

    # Function signatures & method names for L1 escape hatches
    ESCAPE_HATCH_SIGNATURES = [
        "escapehatch",
        "withdrawtol1",
        "emergencyexit",
        "forcewithdraw",
        "exittol1",
        "emergencywithdrawal",
        "l1escapehatch",
        "withdrawtoparent",
        "directexit",
    ]

    # Bytecode function selectors (first 4 bytes hex)
    FORCE_INCLUSION_SELECTORS = [
        "4914041b",  # depositTransaction
        "0b53d100",  # forceInclusion
        "d0e30db0",  # enqueue
        "6c4f039a",  # forceIncludeTx
    ]

    ESCAPE_HATCH_SELECTORS = [
        "3d7199c0",  # escapeHatch
        "822c6080",  # withdrawToL1
        "d0e30db0",  # emergencyExit
        "5b119106",  # forceWithdraw
    ]

    def evaluate_contract(
        self, bytecode: str = "", abi_methods: Optional[List[str]] = None
    ) -> Dict:
        """
        Evaluates contract bytecode and ABI methods for force-inclusion & escape hatch features.

        Args:
            bytecode: Contract bytecode hex string
            abi_methods: Optional list of function/method names

        Returns:
            Dict containing evaluation results
        """
        detected_force_methods: List[str] = []
        detected_escape_methods: List[str] = []

        clean_bytecode = bytecode.replace("0x", "").lower() if bytecode else ""
        abi_list = abi_methods or []

        # Check ABI methods
        for method in abi_list:
            clean_m = method.lower().replace("_", "").replace("-", "")
            for sig in self.FORCE_INCLUSION_SIGNATURES:
                if sig in clean_m:
                    detected_force_methods.append(method)
                    break
            for sig in self.ESCAPE_HATCH_SIGNATURES:
                if sig in clean_m:
                    detected_escape_methods.append(method)
                    break

        # Check bytecode selectors/patterns
        for selector in self.FORCE_INCLUSION_SELECTORS:
            if selector in clean_bytecode and selector not in detected_force_methods:
                detected_force_methods.append(f"selector_0x{selector}")

        for selector in self.ESCAPE_HATCH_SELECTORS:
            if selector in clean_bytecode and selector not in detected_escape_methods:
                detected_escape_methods.append(f"selector_0x{selector}")

        # Check raw text patterns in bytecode/abi if string representation supplied
        if clean_bytecode:
            for sig in self.FORCE_INCLUSION_SIGNATURES:
                if sig in clean_bytecode and sig not in detected_force_methods:
                    detected_force_methods.append(sig)
            for sig in self.ESCAPE_HATCH_SIGNATURES:
                if sig in clean_bytecode and sig not in detected_escape_methods:
                    detected_escape_methods.append(sig)

        force_inclusion_supported = len(detected_force_methods) > 0
        escape_hatch_supported = len(detected_escape_methods) > 0

        return {
            "force_inclusion_supported": force_inclusion_supported,
            "escape_hatch_supported": escape_hatch_supported,
            "detected_force_methods": list(set(detected_force_methods)),
            "detected_escape_methods": list(set(detected_escape_methods)),
        }


class SequencerTracker:
    """Tracks active sequencer operating status and heartbeat metrics"""

    def __init__(self):
        self._sequencer_statuses: Dict[str, SequencerStatus] = {}
        self._uptimes: Dict[str, float] = {}
        self._last_heartbeats: Dict[str, int] = {}

    def get_sequencer_status(self, sequencer_id: str = "default") -> SequencerStatus:
        """Get active status for specified sequencer ID"""
        return self._sequencer_statuses.get(sequencer_id, SequencerStatus.ACTIVE)

    def set_sequencer_status(
        self, sequencer_id: str, status: SequencerStatus, uptime: float = 100.0, timestamp: int = 0
    ):
        """Set active status and telemetry for sequencer ID"""
        self._sequencer_statuses[sequencer_id] = status
        self._uptimes[sequencer_id] = uptime
        self._last_heartbeats[sequencer_id] = timestamp

    def get_uptime(self, sequencer_id: str = "default") -> float:
        """Get uptime percentage for sequencer ID"""
        return self._uptimes.get(sequencer_id, 99.9)


class FinalityRiskCalculator:
    """Computes finality risk ratings based on bridge withdrawal challenge delays and L2 mechanisms"""

    DEFAULT_OPTIMISTIC_DELAY_SECONDS = 604800  # 7 days
    DEFAULT_ZK_DELAY_SECONDS = 3600            # 1 hour

    def compute_finality_risk(
        self,
        withdrawal_delay_seconds: int,
        sequencer_status: SequencerStatus,
        escape_hatch_supported: bool,
        force_inclusion_supported: bool,
        rollup_type: RollupType = RollupType.OPTIMISTIC,
    ) -> Tuple[FinalityRiskLevel, float]:
        """
        Compute finality risk rating and normalized score (0.0 to 1.0).

        Args:
            withdrawal_delay_seconds: Delay in seconds before bridge withdrawals finalize on L1
            sequencer_status: Current status of active sequencer
            escape_hatch_supported: Whether contract supports L1 emergency exit
            force_inclusion_supported: Whether force inclusion is supported
            rollup_type: Type of rollup architecture

        Returns:
            Tuple of (FinalityRiskLevel, risk_score)
        """
        score = 0.0

        # Base score from withdrawal delay
        # 7 days (604800s) = 0.35 base delay score
        delay_ratio = min(withdrawal_delay_seconds / 604800.0, 1.0)
        score += delay_ratio * 0.35

        # Sequencer status impact
        if sequencer_status in (SequencerStatus.HALTED, SequencerStatus.DOWN):
            if not escape_hatch_supported:
                score += 0.65  # Maximum risk if sequencer down and no exit
            else:
                score += 0.40  # High risk even with exit
        elif sequencer_status == SequencerStatus.DEGRADED:
            if not force_inclusion_supported:
                score += 0.40
            else:
                score += 0.20
        else:
            # Active sequencer
            if not force_inclusion_supported:
                score += 0.20
            if not escape_hatch_supported:
                score += 0.15

        # Architecture type modifier
        if rollup_type == RollupType.OPTIMISTIC and withdrawal_delay_seconds >= 604800 and not escape_hatch_supported:
            score += 0.15
        elif rollup_type == RollupType.ZK_ROLLUP and escape_hatch_supported:
            score = max(0.0, score - 0.10)

        normalized_score = min(max(score, 0.0), 1.0)

        if normalized_score >= 0.80:
            rating = FinalityRiskLevel.CRITICAL
        elif normalized_score >= 0.55:
            rating = FinalityRiskLevel.HIGH
        elif normalized_score >= 0.30:
            rating = FinalityRiskLevel.MEDIUM
        else:
            rating = FinalityRiskLevel.LOW

        return rating, round(normalized_score, 2)


class L2RollupAnalyzer:
    """Main detector for Layer 2 rollup centralization and exit risks"""

    def __init__(self):
        self.evaluator = ContractEvaluator()
        self.sequencer_tracker = SequencerTracker()
        self.risk_calculator = FinalityRiskCalculator()

    def analyze_l2_contract(
        self,
        contract_id: str,
        bytecode: str = "",
        abi_methods: Optional[List[str]] = None,
        rollup_info: Optional[Dict] = None,
    ) -> Dict:
        """
        Analyze an L2 token contract for centralization parameters, force inclusion, escape hatches,
        sequencer status, and bridge withdrawal finality risk.

        Args:
            contract_id: Token contract address or ID
            bytecode: Hex string of contract bytecode
            abi_methods: Optional list of ABI method names
            rollup_info: Optional dict with rollup metadata (type, challenge delay, sequencer status, etc.)

        Returns:
            Dict containing complete L2 evaluation report
        """
        r_info = rollup_info or {}

        # 1. Evaluate contract features
        evaluation = self.evaluator.evaluate_contract(bytecode, abi_methods)
        force_inclusion = evaluation["force_inclusion_supported"] or r_info.get("force_inclusion_enabled", False)
        escape_hatch = evaluation["escape_hatch_supported"] or r_info.get("escape_hatch_available", False)

        # 2. Determine sequencer status
        seq_id = r_info.get("sequencer_id", contract_id)
        raw_status = r_info.get("sequencer_status")
        if raw_status:
            if isinstance(raw_status, SequencerStatus):
                status = raw_status
            else:
                try:
                    status = SequencerStatus(str(raw_status).lower())
                except ValueError:
                    status = SequencerStatus.ACTIVE
        else:
            status = self.sequencer_tracker.get_sequencer_status(seq_id)

        # 3. Determine rollup architecture and challenge delay
        raw_rollup_type = r_info.get("rollup_type", "optimistic")
        if isinstance(raw_rollup_type, RollupType):
            rollup_type = raw_rollup_type
        else:
            try:
                rollup_type = RollupType(str(raw_rollup_type).lower())
            except ValueError:
                rollup_type = RollupType.OPTIMISTIC

        default_delay = (
            FinalityRiskCalculator.DEFAULT_OPTIMISTIC_DELAY_SECONDS
            if rollup_type == RollupType.OPTIMISTIC
            else FinalityRiskCalculator.DEFAULT_ZK_DELAY_SECONDS
        )
        delay_seconds = int(r_info.get("challenge_window_seconds", default_delay))
        delay_days = round(delay_seconds / 86400.0, 2)

        # 4. Compute finality risk rating
        finality_rating, risk_score = self.risk_calculator.compute_finality_risk(
            withdrawal_delay_seconds=delay_seconds,
            sequencer_status=status,
            escape_hatch_supported=escape_hatch,
            force_inclusion_supported=force_inclusion,
            rollup_type=rollup_type,
        )

        # 5. Extract explicit L2 centralization parameters
        centralization_params = L2CentralizationParams(
            rollup_type=rollup_type.value,
            sequencer_status=status.value,
            challenge_window_seconds=delay_seconds,
            challenge_window_days=delay_days,
            force_inclusion_enabled=force_inclusion,
            escape_hatch_available=escape_hatch,
            sequencer_address=r_info.get("sequencer_address"),
            l1_bridge_address=r_info.get("l1_bridge_address"),
        )

        # 6. Generate sequencer dependency warnings
        warnings = self._generate_warnings(
            status=status,
            force_inclusion=force_inclusion,
            escape_hatch=escape_hatch,
            delay_seconds=delay_seconds,
            rollup_type=rollup_type,
        )

        # 7. Generate recommendations
        recommendations = self._generate_recommendations(
            force_inclusion=force_inclusion,
            escape_hatch=escape_hatch,
            status=status,
            finality_rating=finality_rating,
        )

        return {
            "contract_id": contract_id,
            "force_inclusion_supported": force_inclusion,
            "escape_hatch_supported": escape_hatch,
            "detected_force_methods": evaluation["detected_force_methods"],
            "detected_escape_methods": evaluation["detected_escape_methods"],
            "sequencer_status": status.value,
            "rollup_type": rollup_type.value,
            "challenge_window_seconds": delay_seconds,
            "challenge_window_days": delay_days,
            "finality_risk_rating": finality_rating.value,
            "finality_risk_score": risk_score,
            "centralization_parameters": {
                "rollup_type": centralization_params.rollup_type,
                "sequencer_status": centralization_params.sequencer_status,
                "challenge_window_seconds": centralization_params.challenge_window_seconds,
                "challenge_window_days": centralization_params.challenge_window_days,
                "force_inclusion_enabled": centralization_params.force_inclusion_enabled,
                "escape_hatch_available": centralization_params.escape_hatch_available,
                "sequencer_address": centralization_params.sequencer_address,
                "l1_bridge_address": centralization_params.l1_bridge_address,
            },
            "warnings": warnings,
            "recommendations": recommendations,
        }

    def _generate_warnings(
        self,
        status: SequencerStatus,
        force_inclusion: bool,
        escape_hatch: bool,
        delay_seconds: int,
        rollup_type: RollupType,
    ) -> List[str]:
        """Generate explicit sequencer dependency and centralization warnings"""
        warnings = []

        if status in (SequencerStatus.HALTED, SequencerStatus.DOWN):
            if not escape_hatch:
                warnings.append(
                    "CRITICAL WARNING: Sequencer is HALTED and contract lacks L1 escape hatch functions. User funds are locked until sequencer recovers."
                )
            else:
                warnings.append(
                    "HIGH WARNING: Sequencer is HALTED. Emergency L1 escape hatch available, but withdrawals may incur bridge delay."
                )
        elif status == SequencerStatus.DEGRADED:
            warnings.append(
                "WARNING: Centralized sequencer is operating in DEGRADED status. Transaction throughput may be compromised."
            )

        if not force_inclusion:
            warnings.append(
                "CENTRALIZATION RISK: No force-inclusion mechanism detected. Sequencer can censor user transactions indefinitely."
            )

        if not escape_hatch:
            warnings.append(
                "EXIT RISK: No explicit L1 escape hatch functions detected for emergency asset retrieval if sequencer halts."
            )

        if delay_seconds >= 604800:
            warnings.append(
                f"FINALITY DELAY: Bridge withdrawal challenge window is {round(delay_seconds / 86400.0, 1)} days ({delay_seconds} seconds). Finality is heavily delayed on L1."
            )

        return warnings

    def _generate_recommendations(
        self,
        force_inclusion: bool,
        escape_hatch: bool,
        status: SequencerStatus,
        finality_rating: FinalityRiskLevel,
    ) -> List[str]:
        """Generate security and exit recommendations"""
        recs = []

        if not force_inclusion:
            recs.append("Implement L1 force-inclusion transactions via canonical bridge contract.")
        if not escape_hatch:
            recs.append("Add L1 emergency escape hatch functions allowing user withdrawals upon sequencer outage.")
        if status != SequencerStatus.ACTIVE:
            recs.append("Monitor L1 rollup heartbeat contracts for active sequencer state recovery.")
        if finality_rating in (FinalityRiskLevel.CRITICAL, FinalityRiskLevel.HIGH):
            recs.append("Avoid large liquidity deposits until force-inclusion or escape hatch mechanisms are verified.")

        return recs

    def generate_l2_report(self, analysis_result: Dict) -> str:
        """
        Generate explicit L2 centralization parameters and sequencer dependency warnings report.

        Args:
            analysis_result: Result from analyze_l2_contract

        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("L2 ROLLUP CENTRALIZATION & EXIT RISK REPORT")
        lines.append("=" * 60)
        lines.append(f"Contract ID: {analysis_result['contract_id']}")
        lines.append(f"Rollup Architecture: {analysis_result['rollup_type'].upper()}")
        lines.append(f"Active Sequencer Status: {analysis_result['sequencer_status'].upper()}")
        lines.append(f"Bridge Withdrawal Challenge Delay: {analysis_result['challenge_window_days']} days ({analysis_result['challenge_window_seconds']}s)")
        lines.append(f"Finality Risk Rating: {analysis_result['finality_risk_rating'].upper()} (Score: {analysis_result['finality_risk_score']})")
        lines.append("")
        lines.append("CENTRALIZATION & EXIT PARAMETERS:")
        lines.append("-" * 60)
        params = analysis_result["centralization_parameters"]
        lines.append(f"  - Force Inclusion Enabled: {'YES' if params['force_inclusion_enabled'] else 'NO'}")
        lines.append(f"  - L1 Escape Hatch Available: {'YES' if params['escape_hatch_available'] else 'NO'}")
        if params["sequencer_address"]:
            lines.append(f"  - Sequencer Address: {params['sequencer_address']}")
        if params["l1_bridge_address"]:
            lines.append(f"  - L1 Bridge Address: {params['l1_bridge_address']}")
        lines.append("")

        if analysis_result["warnings"]:
            lines.append("SEQUENCER DEPENDENCY & EXIT WARNINGS:")
            lines.append("-" * 60)
            for w in analysis_result["warnings"]:
                lines.append(f"  ⚠ {w}")
            lines.append("")
        else:
            lines.append("✓ No severe sequencer dependency warnings detected")
            lines.append("")

        if analysis_result["recommendations"]:
            lines.append("RECOMMENDATIONS:")
            lines.append("-" * 60)
            for i, rec in enumerate(analysis_result["recommendations"], 1):
                lines.append(f"  {i}. {rec}")

        lines.append("=" * 60)
        return "\n".join(lines)


def analyze_l2_token_contract(
    contract_id: str,
    bytecode: str = "",
    abi_methods: Optional[List[str]] = None,
    rollup_info: Optional[Dict] = None,
) -> Dict:
    """
    Convenience function to analyze an L2 token contract for rollup centralization and escape risks.
    """
    analyzer = L2RollupAnalyzer()
    return analyzer.analyze_l2_contract(contract_id, bytecode, abi_methods, rollup_info)
