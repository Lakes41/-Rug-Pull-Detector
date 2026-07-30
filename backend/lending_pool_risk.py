"""
Lending Pool Risk Score Modifier
Implements specialized risk scoring for lending pools with weighted modifiers
for collateral manipulation, TVL anomalies, and mint/burn vulnerabilities.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from tvl_tracker import TVLTracker, TVLAnomaly, AnomalyType
from oracle_mint_monitor import OracleMintMonitor, MintBurnAnomaly


class PoolType(Enum):
    """Types of lending pools"""
    STANDARD_LENDING = "standard_lending"
    LIQUIDITY_POOL = "liquidity_pool"
    STABLE_POOL = "stable_pool"
    YIELD_POOL = "yield_pool"
    RWA_TOKENIZED = "rwa_tokenized"


@dataclass
class LendingPoolRiskFactors:
    """Risk factors specific to lending pools"""
    pool_address: str
    pool_type: PoolType
    
    # TVL-related risks
    tvl_anomaly_score: float = 0.0
    tvl_volatility: float = 0.0
    collateral_withdrawal_risk: float = 0.0
    
    # Oracle/mint risks
    infinite_mint_risk: float = 0.0
    oracle_manipulation_risk: float = 0.0
    unbacked_mint_risk: float = 0.0
    
    # Pool-specific risks
    liquidity_utilization: float = 0.0
    collateral_ratio: float = 0.0
    bad_debt_ratio: float = 0.0
    
    # General risks
    smart_contract_risk: float = 0.0
    governance_risk: float = 0.0


@dataclass
class LendingPoolRiskResult:
    """Complete risk analysis result for a lending pool"""
    pool_address: str
    pool_type: PoolType
    base_risk_score: float
    modified_risk_score: float
    risk_level: str
    risk_factors: LendingPoolRiskFactors
    detected_anomalies: List[str]
    recommendations: List[str]
    timestamp: datetime


class LendingPoolRiskModifier:
    """Modifies risk scores for lending pools based on specialized factors"""
    
    def __init__(self):
        self.tvl_tracker = TVLTracker()
        self.oracle_monitor = OracleMintMonitor()
        
        # Risk weights for different pool types
        self.pool_type_weights = {
            PoolType.STANDARD_LENDING: 1.0,
            PoolType.LIQUIDITY_POOL: 1.2,
            PoolType.STABLE_POOL: 0.8,
            PoolType.YIELD_POOL: 1.5,
            PoolType.RWA_TOKENIZED: 1.3
        }
        
        # Risk factor weights
        self.risk_factor_weights = {
            "tvl_anomaly": 0.25,
            "infinite_mint": 0.30,
            "oracle_manipulation": 0.20,
            "collateral_withdrawal": 0.15,
            "liquidity_utilization": 0.10
        }
    
    def calculate_risk_modifier(self, pool_address: str, 
                               pool_type: PoolType,
                               base_risk_score: float) -> LendingPoolRiskResult:
        """
        Calculate modified risk score for a lending pool
        
        Args:
            pool_address: Pool contract address
            pool_type: Type of lending pool
            base_risk_score: Base risk score from general analysis
            
        Returns:
            LendingPoolRiskResult with modified score and factors
        """
        # Gather risk factors
        risk_factors = self._gather_risk_factors(pool_address, pool_type)
        
        # Calculate modifier
        modifier = self._calculate_modifier(risk_factors, pool_type)
        
        # Apply modifier to base score
        modified_score = self._apply_modifier(base_risk_score, modifier)
        
        # Determine risk level
        risk_level = self._get_risk_level(modified_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_factors, risk_level)
        
        # Collect detected anomalies
        detected_anomalies = self._collect_detected_anomalies(pool_address)
        
        return LendingPoolRiskResult(
            pool_address=pool_address,
            pool_type=pool_type,
            base_risk_score=base_risk_score,
            modified_risk_score=modified_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            detected_anomalies=detected_anomalies,
            recommendations=recommendations,
            timestamp=datetime.now()
        )
    
    def _gather_risk_factors(self, pool_address: str, 
                            pool_type: PoolType) -> LendingPoolRiskFactors:
        """Gather all risk factors for the pool"""
        # Get TVL risk score
        tvl_risk_score = self.tvl_tracker.get_risk_score(pool_address)
        
        # Get oracle/mint risk score
        oracle_risk_score = self.oracle_monitor.get_risk_score(pool_address)
        
        # Get TVL anomalies for detailed analysis
        tvl_anomalies = self.tvl_tracker.get_pool_anomalies(pool_address)
        
        # Calculate specific risk factors
        collateral_withdrawal_risk = self._calculate_collateral_withdrawal_risk(tvl_anomalies)
        tvl_volatility = self._calculate_tvl_volatility(pool_address)
        
        # Get mint/burn anomalies
        mint_anomalies = self.oracle_monitor.get_token_anomalies(pool_address)
        
        infinite_mint_risk = self._calculate_infinite_mint_risk(mint_anomalies)
        oracle_manipulation_risk = self._calculate_oracle_manipulation_risk(mint_anomalies)
        unbacked_mint_risk = self._calculate_unbacked_mint_risk(mint_anomalies)
        
        return LendingPoolRiskFactors(
            pool_address=pool_address,
            pool_type=pool_type,
            tvl_anomaly_score=tvl_risk_score,
            tvl_volatility=tvl_volatility,
            collateral_withdrawal_risk=collateral_withdrawal_risk,
            infinite_mint_risk=infinite_mint_risk,
            oracle_manipulation_risk=oracle_manipulation_risk,
            unbacked_mint_risk=unbacked_mint_risk,
            # Default values for factors that would need additional data sources
            liquidity_utilization=0.5,
            collateral_ratio=0.8,
            bad_debt_ratio=0.1,
            smart_contract_risk=0.3,
            governance_risk=0.2
        )
    
    def _calculate_collateral_withdrawal_risk(self, anomalies: List[TVLAnomaly]) -> float:
        """Calculate risk based on collateral withdrawal anomalies"""
        if not anomalies:
            return 0.0
        
        # Weight different anomaly types
        withdrawal_anomalies = [
            a for a in anomalies 
            if a.anomaly_type in [AnomalyType.SPIKE_WITHDRAWAL, AnomalyType.COLLATERAL_DRAIN]
        ]
        
        if not withdrawal_anomalies:
            return 0.0
        
        # Calculate weighted risk
        risk = 0.0
        for anomaly in withdrawal_anomalies:
            severity_weight = {
                "critical": 0.5,
                "high": 0.3,
                "medium": 0.15,
                "low": 0.05
            }.get(anomaly.severity, 0.1)
            
            # Higher weight for larger percentage drops
            magnitude_weight = min(abs(anomaly.percentage_change) / 100, 1.0)
            
            risk += severity_weight * magnitude_weight
        
        return min(risk, 1.0)
    
    def _calculate_tvl_volatility(self, pool_address: str) -> float:
        """Calculate TVL volatility from historical data"""
        snapshots = self.tvl_tracker.get_pool_history(pool_address, days=30)
        
        if len(snapshots) < 2:
            return 0.0
        
        tvl_values = [s.total_value_locked for s in snapshots]
        
        if not tvl_values:
            return 0.0
        
        # Calculate coefficient of variation
        mean = sum(tvl_values) / len(tvl_values)
        if mean == 0:
            return 0.0
        
        variance = sum((x - mean) ** 2 for x in tvl_values) / len(tvl_values)
        std_dev = variance ** 0.5
        cv = std_dev / mean
        
        # Normalize to 0-1 range (CV > 1 is very volatile)
        return min(cv, 1.0)
    
    def _calculate_infinite_mint_risk(self, anomalies: List[MintBurnAnomaly]) -> float:
        """Calculate risk based on infinite minting anomalies"""
        if not anomalies:
            return 0.0
        
        infinite_mint_anomalies = [
            a for a in anomalies 
            if a.anomaly_type in ["rapid_minting", "unbacked_minting", "supply_inflation"]
        ]
        
        if not infinite_mint_anomalies:
            return 0.0
        
        risk = 0.0
        for anomaly in infinite_mint_anomalies:
            severity_weight = {
                "critical": 0.6,
                "high": 0.3,
                "medium": 0.1
            }.get(anomaly.severity, 0.1)
            
            # Extra weight for unbacked minting
            if anomaly.anomaly_type == "unbacked_minting":
                severity_weight *= 1.5
            
            risk += severity_weight
        
        return min(risk, 1.0)
    
    def _calculate_oracle_manipulation_risk(self, anomalies: List[MintBurnAnomaly]) -> float:
        """Calculate risk based on oracle manipulation anomalies"""
        if not anomalies:
            return 0.0
        
        oracle_anomalies = [
            a for a in anomalies 
            if a.anomaly_type == "oracle_price_manipulation"
        ]
        
        if not oracle_anomalies:
            return 0.0
        
        risk = 0.0
        for anomaly in oracle_anomalies:
            severity_weight = {
                "critical": 0.5,
                "high": 0.3,
                "medium": 0.2
            }.get(anomaly.severity, 0.1)
            risk += severity_weight
        
        return min(risk, 1.0)
    
    def _calculate_unbacked_mint_risk(self, anomalies: List[MintBurnAnomaly]) -> float:
        """Calculate risk based on unbacked minting"""
        if not anomalies:
            return 0.0
        
        unbacked_anomalies = [
            a for a in anomalies 
            if a.anomaly_type == "unbacked_minting"
        ]
        
        if not unbacked_anomalies:
            return 0.0
        
        # Unbacked minting is always high risk
        return min(len(unbacked_anomalies) * 0.4, 1.0)
    
    def _calculate_modifier(self, risk_factors: LendingPoolRiskFactors, 
                           pool_type: PoolType) -> float:
        """Calculate the risk modifier based on all factors"""
        # Get pool type weight
        pool_weight = self.pool_type_weights.get(pool_type, 1.0)
        
        # Calculate weighted sum of risk factors
        modifier = (
            risk_factors.tvl_anomaly_score * self.risk_factor_weights["tvl_anomaly"] +
            risk_factors.infinite_mint_risk * self.risk_factor_weights["infinite_mint"] +
            risk_factors.oracle_manipulation_risk * self.risk_factor_weights["oracle_manipulation"] +
            risk_factors.collateral_withdrawal_risk * self.risk_factor_weights["collateral_withdrawal"] +
            risk_factors.liquidity_utilization * self.risk_factor_weights["liquidity_utilization"]
        )
        
        # Apply pool type weight
        modifier *= pool_weight
        
        # Add extra risk for RWA tokenized pools (off-chain asset risk)
        if pool_type == PoolType.RWA_TOKENIZED:
            modifier *= 1.2
        
        return modifier
    
    def _apply_modifier(self, base_score: float, modifier: float) -> float:
        """Apply the modifier to the base risk score"""
        # Combine base score with modifier
        # Base score accounts for 60%, modifier for 40%
        combined = (base_score * 0.6) + (modifier * 0.4)
        
        # Ensure result is in valid range
        return max(0.0, min(combined, 1.0))
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, risk_factors: LendingPoolRiskFactors,
                                  risk_level: str) -> List[str]:
        """Generate recommendations based on risk factors"""
        recommendations = []
        
        if risk_factors.tvl_anomaly_score > 0.5:
            recommendations.append("Monitor TVL closely for sudden drops")
        
        if risk_factors.infinite_mint_risk > 0.5:
            recommendations.append("Investigate mint/burn mechanisms for potential infinite minting")
        
        if risk_factors.oracle_manipulation_risk > 0.5:
            recommendations.append("Review oracle update mechanisms and price feeds")
        
        if risk_factors.collateral_withdrawal_risk > 0.5:
            recommendations.append("Implement additional collateral withdrawal safeguards")
        
        if risk_factors.unbacked_mint_risk > 0.3:
            recommendations.append("Ensure all minting is backed by proper oracle updates")
        
        if risk_factors.liquidity_utilization > 0.8:
            recommendations.append("High liquidity utilization - consider adding liquidity")
        
        if risk_level == "CRITICAL":
            recommendations.append("CRITICAL: Immediate investigation required")
        elif risk_level == "HIGH":
            recommendations.append("HIGH: Increased monitoring recommended")
        
        if not recommendations:
            recommendations.append("No specific recommendations - risk levels are acceptable")
        
        return recommendations
    
    def _collect_detected_anomalies(self, pool_address: str) -> List[str]:
        """Collect descriptions of detected anomalies"""
        anomalies = []
        
        # TVL anomalies
        tvl_anomalies = self.tvl_tracker.get_pool_anomalies(pool_address)
        for anomaly in tvl_anomalies[:5]:  # Limit to 5 most recent
            anomalies.append(f"TVL: {anomaly.anomaly_type.value} - {anomaly.description}")
        
        # Mint/burn anomalies
        mint_anomalies = self.oracle_monitor.get_token_anomalies(pool_address)
        for anomaly in mint_anomalies[:5]:  # Limit to 5 most recent
            anomalies.append(f"Mint/Burn: {anomaly.anomaly_type} - {anomaly.description}")
        
        return anomalies
    
    def close(self):
        """Close database connections"""
        self.tvl_tracker.close()
        self.oracle_monitor.close()


def analyze_lending_pool_risk(pool_address: str, 
                            pool_type: PoolType = PoolType.STANDARD_LENDING,
                            base_risk_score: float = 0.3) -> LendingPoolRiskResult:
    """
    Convenience function to analyze lending pool risk
    
    Args:
        pool_address: Pool contract address
        pool_type: Type of lending pool
        base_risk_score: Base risk score from general analysis
        
    Returns:
        LendingPoolRiskResult with complete analysis
    """
    modifier = LendingPoolRiskModifier()
    try:
        result = modifier.calculate_risk_modifier(pool_address, pool_type, base_risk_score)
        return result
    finally:
        modifier.close()


if __name__ == "__main__":
    # Example usage
    result = analyze_lending_pool_risk(
        pool_address="0x1234567890abcdef",
        pool_type=PoolType.RWA_TOKENIZED,
        base_risk_score=0.4
    )
    
    print(f"Pool: {result.pool_address}")
    print(f"Type: {result.pool_type.value}")
    print(f"Base Risk Score: {result.base_risk_score:.2f}")
    print(f"Modified Risk Score: {result.modified_risk_score:.2f}")
    print(f"Risk Level: {result.risk_level}")
    print(f"\nRisk Factors:")
    print(f"  TVL Anomaly Score: {result.risk_factors.tvl_anomaly_score:.2f}")
    print(f"  Infinite Mint Risk: {result.risk_factors.infinite_mint_risk:.2f}")
    print(f"  Oracle Manipulation Risk: {result.risk_factors.oracle_manipulation_risk:.2f}")
    print(f"  Collateral Withdrawal Risk: {result.risk_factors.collateral_withdrawal_risk:.2f}")
    print(f"\nRecommendations:")
    for rec in result.recommendations:
        print(f"  - {rec}")
