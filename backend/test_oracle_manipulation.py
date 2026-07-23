"""
Oracle Manipulation Risk Detector — Test Suite

Tests for flash loan pattern recognition, price sensitivity analysis,
and TWAP oracle protection detection logic.
"""

import pytest
import json
import math


class OracleManipulationDetector:
    """Server-side oracle manipulation risk detection logic mirrored from frontend."""

    FLASH_LOAN_SIGNATURES = [
        "flashloan", "flash_loan", "flashLoan", "executeOperation",
        "makerdao", "dssflash", "balancerFlashLoan", "aave",
        "uniswapV2FlashSwap", "uniswapV3Flash",
    ]

    LENDING_PROTOCOLS = [
        "aave", "compound", "makerdao", "dydx", "euler",
        "radiant", "silicon", "spark",
    ]

    TWAP_ORACLE_KEYWORDS = [
        "twap", "timeweighted", "time_weighted", "chainlink",
        "pricefeed", "price_feed", "latestRoundData", "getRoundData",
        "accumulator", "observation", "consume", "liquiditycheck", "oracle",
    ]

    SWAP_OPERATIONS = [
        "swap", "swapexacttokensforeth", "swapexacttokensfortokens",
        "swapexactethfortokens", "swaptokensforexacteth",
        "swaptokensforexacttokens", "exactinput", "exactoutput",
    ]

    @classmethod
    def detect_flash_loan_patterns(cls, traces):
        findings = {
            "detected": False,
            "flash_loan_calls": [],
            "swap_calls": [],
            "transfer_calls": [],
            "pattern_type": None,
            "confidence": 0.0,
            "details": [],
        }

        if not traces:
            findings["details"].append("No traces available for analysis")
            return findings

        def normalize(s):
            return s.lower().replace(" ", "").replace("_", "").replace("-", "")

        for trace in traces:
            op = normalize(trace.get("operation", ""))
            tx_hash = trace.get("hash", "")

            # Check flash loan signatures
            for sig in cls.FLASH_LOAN_SIGNATURES:
                if normalize(sig) in op:
                    findings["flash_loan_calls"].append(trace)
                    break
            else:
                # Check lending protocol references
                full_text = json.dumps(trace).lower()
                if any(proto in full_text for proto in cls.LENDING_PROTOCOLS) and "loan" in full_text:
                    findings["flash_loan_calls"].append(trace)

            # Check swap operations
            if any(normalize(s) in op for s in cls.SWAP_OPERATIONS):
                if not trace.get("reverted"):
                    findings["swap_calls"].append(trace)

        has_flash_loan = len(findings["flash_loan_calls"]) > 0
        has_swap = len(findings["swap_calls"]) > 1

        if has_flash_loan and has_swap:
            findings["detected"] = True
            findings["confidence"] = round(
                0.5 + (0.3 if len(findings["swap_calls"]) >= 2 else 0) +
                (0.1 if len(findings["flash_loan_calls"]) >= 1 else 0) +
                (0.1 if len(findings["swap_calls"]) >= 3 else 0), 2
            )
            findings["pattern_type"] = "classic_triangle"
            findings["details"].append(
                f"Detected classic flash loan triangle: {len(findings['flash_loan_calls'])} borrow → "
                f"{len(findings['swap_calls'])} swap operations"
            )
        elif has_swap and len(findings["swap_calls"]) >= 3:
            findings["detected"] = True
            findings["confidence"] = 0.3
            findings["pattern_type"] = "sandwich"
            findings["details"].append(
                "No explicit flash loan calls but high swap density detected"
            )
        else:
            findings["details"].append("No flash loan patterns detected")

        return findings

    @classmethod
    def calculate_price_sensitivity(cls, reserve0, reserve1):
        if reserve0 <= 0 or reserve1 <= 0:
            return None

        k = reserve0 * reserve1
        spot_price = reserve1 / reserve0

        swap_sizes = [0.01, 0.05, 0.10, 0.25, 0.50]
        impact_levels = []

        for pct in swap_sizes:
            amount_in = reserve0 * pct
            amount_out = (amount_in * reserve1) / (reserve0 + amount_in)
            execution_price = amount_out / amount_in
            price_impact_bps = abs((execution_price - spot_price) / spot_price) * 10000

            impact_levels.append({
                "swap_size_pct": pct * 100,
                "amount_in": amount_in,
                "amount_out": amount_out,
                "execution_price": execution_price,
                "price_impact_bps": round(price_impact_bps),
            })

        max_deviation = impact_levels[-1]["price_impact_bps"]

        sensitivity_level = (
            "low" if max_deviation < 100 else
            "medium" if max_deviation < 500 else
            "high" if max_deviation < 2000 else
            "critical"
        )

        return {
            "spot_price": spot_price,
            "reserve0": reserve0,
            "reserve1": reserve1,
            "k": k,
            "impact_levels": impact_levels,
            "max_single_block_deviation": max_deviation,
            "sensitivity_level": sensitivity_level,
        }

    @classmethod
    def check_twap_protection(cls, contract_data):
        findings = {
            "has_twap": False,
            "protection_level": "none",
            "oracle_references": [],
            "details": [],
        }

        full_text = json.dumps(contract_data).lower()

        for keyword in cls.TWAP_ORACLE_KEYWORDS:
            if keyword in full_text:
                findings["oracle_references"].append(keyword)

        refs = set(r.lower() for r in findings["oracle_references"])

        if any(kw in refs for kw in ["twap", "timeweighted", "time_weighted", "accumulator", "observation"]):
            findings["has_twap"] = True
            findings["protection_level"] = "full"
            findings["details"].append("TWAP oracle detected")
        elif any(kw in refs for kw in ["chainlink", "pricefeed", "price_feed"]):
            findings["has_twap"] = True
            findings["protection_level"] = "partial"
            findings["details"].append("Chainlink-style price feed detected")
        elif refs:
            findings["has_twap"] = False
            findings["protection_level"] = "partial"
            findings["details"].append("Unclear oracle references found")
        else:
            findings["has_twap"] = False
            findings["protection_level"] = "none"
            findings["details"].append("No TWAP oracle detected")

        return findings

    @classmethod
    def analyze_risk(cls, chain_data):
        # 1. Flash loan detection
        traces = chain_data.get("traces", [])
        flash_loan = cls.detect_flash_loan_patterns(traces)

        # 2. Price sensitivity
        reserves = chain_data.get("reserves", {})
        price_sensitivity = cls.calculate_price_sensitivity(
            reserves.get("reserve0", 0),
            reserves.get("reserve1", 0),
        )

        # 3. TWAP protection
        twap = cls.check_twap_protection(chain_data.get("contract_data", {}))

        # 4. Score calculation
        score = 0.0
        warnings = []

        if flash_loan["detected"]:
            score += flash_loan["confidence"] * 0.35
            warnings.append("Flash loan pattern detected")

        if price_sensitivity:
            if price_sensitivity["sensitivity_level"] == "critical":
                score += 0.35
                warnings.append("Critical price sensitivity")
            elif price_sensitivity["sensitivity_level"] == "high":
                score += 0.25
            elif price_sensitivity["sensitivity_level"] == "medium":
                score += 0.15
        else:
            score += 0.2
            warnings.append("Unable to calculate reserves")

        if twap["protection_level"] == "none":
            score += 0.3
            warnings.append("No TWAP protection")
        elif twap["protection_level"] == "partial":
            score += 0.15

        score = min(round(score, 2), 1.0)
        flagged = score >= 0.35

        severity = (
            "critical" if score >= 0.75 else
            "high" if score >= 0.55 else
            "medium" if score >= 0.35 else
            "low"
        )

        return {
            "score": score,
            "flagged": flagged,
            "severity": severity,
            "flash_loan_analysis": flash_loan,
            "price_sensitivity": price_sensitivity,
            "twap_protection": twap,
            "warnings": warnings,
        }


class TestOracleManipulationDetector:
    """Tests for OracleManipulationDetector"""

    def test_flash_loan_clean_traces_no_detection(self):
        traces = [
            {"operation": "transfer", "hash": "0x1", "reverted": False},
            {"operation": "transfer", "hash": "0x2", "reverted": False},
            {"operation": "approve", "hash": "0x3", "reverted": False},
        ]
        result = OracleManipulationDetector.detect_flash_loan_patterns(traces)
        assert result["detected"] is False
        assert result["confidence"] == 0.0

    def test_flash_loan_classic_triangle_detected(self):
        traces = [
            {"operation": "flashLoan", "hash": "0xaave1", "reverted": False},
            {"operation": "swapExactTokensForETH", "hash": "0xswap1", "reverted": False},
            {"operation": "swapExactTokensForTokens", "hash": "0xswap2", "reverted": False},
            {"operation": "transfer", "hash": "0xrepay", "reverted": False},
        ]
        result = OracleManipulationDetector.detect_flash_loan_patterns(traces)
        assert result["detected"] is True
        assert result["pattern_type"] == "classic_triangle"
        assert result["confidence"] >= 0.5
        assert len(result["flash_loan_calls"]) >= 1
        assert len(result["swap_calls"]) >= 2

    def test_flash_loan_sandwich_pattern(self):
        traces = [
            {"operation": "swap", "hash": "0xfront", "reverted": False},
            {"operation": "swap", "hash": "0xvictim", "reverted": False},
            {"operation": "swap", "hash": "0xback", "reverted": False},
        ]
        result = OracleManipulationDetector.detect_flash_loan_patterns(traces)
        assert result["detected"] is True
        assert result["pattern_type"] == "sandwich"

    def test_price_sensitivity_low_impact(self):
        # Deep pool: 10M / 10M — large reserves
        result = OracleManipulationDetector.calculate_price_sensitivity(10_000_000, 10_000_000)
        assert result is not None
