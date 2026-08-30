"""
Test cases for Layer 2 Rollup Centralization & Exit Risk Analyzer
Tests force-inclusion evaluation, L1 escape hatch detection, active sequencer tracking,
finality risk rating computation, and explicit L2 report generation.
"""

import pytest
from l2_rollup_analyzer import (
    ContractEvaluator,
    SequencerTracker,
    FinalityRiskCalculator,
    L2RollupAnalyzer,
    SequencerStatus,
    RollupType,
    FinalityRiskLevel,
    analyze_l2_token_contract,
)


class TestContractEvaluator:
    """Test evaluation of target L2 token contracts for force inclusion and escape hatch functions"""

    def test_evaluate_contract_with_force_and_escape_methods(self):
        evaluator = ContractEvaluator()
        abi_methods = ["forceInclusion", "escapeHatch", "transfer"]
        res = evaluator.evaluate_contract(abi_methods=abi_methods)

        assert res["force_inclusion_supported"] is True
        assert res["escape_hatch_supported"] is True
        assert "forceInclusion" in res["detected_force_methods"]
        assert "escapeHatch" in res["detected_escape_methods"]

    def test_evaluate_contract_with_selectors(self):
        evaluator = ContractEvaluator()
        # 0x0b53d100 (forceInclusion) and 0x3d7199c0 (escapeHatch)
        bytecode = "0x60806040520b53d1003d7199c0"
        res = evaluator.evaluate_contract(bytecode=bytecode)

        assert res["force_inclusion_supported"] is True
        assert res["escape_hatch_supported"] is True

    def test_evaluate_contract_lacks_mechanisms(self):
        evaluator = ContractEvaluator()
        abi_methods = ["transfer", "approve", "balanceOf"]
        res = evaluator.evaluate_contract(bytecode="0x12345678", abi_methods=abi_methods)

        assert res["force_inclusion_supported"] is False
        assert res["escape_hatch_supported"] is False
        assert len(res["detected_force_methods"]) == 0
        assert len(res["detected_escape_methods"]) == 0


class TestSequencerTracker:
    """Test tracking active sequencer operating status"""

    def test_default_sequencer_status(self):
        tracker = SequencerTracker()
        assert tracker.get_sequencer_status("seq_1") == SequencerStatus.ACTIVE
        assert tracker.get_uptime("seq_1") == 99.9

    def test_update_sequencer_status(self):
        tracker = SequencerTracker()
        tracker.set_sequencer_status("seq_1", SequencerStatus.HALTED, uptime=85.0, timestamp=1000)

        assert tracker.get_sequencer_status("seq_1") == SequencerStatus.HALTED
        assert tracker.get_uptime("seq_1") == 85.0


class TestFinalityRiskCalculator:
    """Test finality risk rating computation based on bridge withdrawal challenge delays"""

    def test_compute_finality_risk_active_optimistic_no_escape(self):
        calc = FinalityRiskCalculator()
        rating, score = calc.compute_finality_risk(
            withdrawal_delay_seconds=604800,
            sequencer_status=SequencerStatus.ACTIVE,
            escape_hatch_supported=False,
            force_inclusion_supported=False,
            rollup_type=RollupType.OPTIMISTIC,
        )

        assert rating in (FinalityRiskLevel.HIGH, FinalityRiskLevel.CRITICAL)
        assert score >= 0.55

    def test_compute_finality_risk_halted_sequencer_no_escape(self):
        calc = FinalityRiskCalculator()
        rating, score = calc.compute_finality_risk(
            withdrawal_delay_seconds=604800,
            sequencer_status=SequencerStatus.HALTED,
            escape_hatch_supported=False,
            force_inclusion_supported=False,
            rollup_type=RollupType.OPTIMISTIC,
        )

        assert rating == FinalityRiskLevel.CRITICAL
        assert score >= 0.80

    def test_compute_finality_risk_zk_with_escape(self):
        calc = FinalityRiskCalculator()
        rating, score = calc.compute_finality_risk(
            withdrawal_delay_seconds=3600,
            sequencer_status=SequencerStatus.ACTIVE,
            escape_hatch_supported=True,
            force_inclusion_supported=True,
            rollup_type=RollupType.ZK_ROLLUP,
        )

        assert rating == FinalityRiskLevel.LOW
        assert score < 0.30


class TestL2RollupAnalyzer:
    """Test main L2RollupAnalyzer implementation"""

    def test_analyze_l2_contract_full(self):
        analyzer = L2RollupAnalyzer()
        contract_id = "0xL2TokenContract123"
        abi_methods = ["enqueueTransaction", "withdrawToL1"]
        rollup_info = {
            "rollup_type": "optimistic",
            "sequencer_status": "active",
            "challenge_window_seconds": 604800,
            "sequencer_address": "0xSequencerAdmin",
            "l1_bridge_address": "0xCanonicalL1Bridge",
        }

        res = analyzer.analyze_l2_contract(contract_id, abi_methods=abi_methods, rollup_info=rollup_info)

        assert res["contract_id"] == contract_id
        assert res["force_inclusion_supported"] is True
        assert res["escape_hatch_supported"] is True
        assert res["sequencer_status"] == "active"
        assert res["rollup_type"] == "optimistic"
        assert res["challenge_window_days"] == 7.0
        assert "centralization_parameters" in res
        assert res["centralization_parameters"]["force_inclusion_enabled"] is True
        assert res["centralization_parameters"]["escape_hatch_available"] is True

    def test_generate_l2_report_output(self):
        analyzer = L2RollupAnalyzer()
        res = analyzer.analyze_l2_contract(
            "0xRiskToken",
            abi_methods=[],
            rollup_info={
                "rollup_type": "optimistic",
                "sequencer_status": "halted",
                "challenge_window_seconds": 604800,
            },
        )
        report = analyzer.generate_l2_report(res)

        assert "L2 ROLLUP CENTRALIZATION & EXIT RISK REPORT" in report
        assert "Active Sequencer Status: HALTED" in report
        assert "CRITICAL WARNING" in report
        assert "CENTRALIZATION RISK" in report

    def test_convenience_function(self):
        res = analyze_l2_token_contract(
            "0xConvenienceToken",
            abi_methods=["depositTransaction"],
            rollup_info={"sequencer_status": "active"},
        )

        assert res["force_inclusion_supported"] is True
        assert res["sequencer_status"] == "active"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
