"""
Token Holder Concentration Analyzer
Implements granular tracking of top token holders and distribution metrics.
"""

from typing import List, Dict, Set
from dataclasses import dataclass
import math


@dataclass
class Holder:
    """Represents a token holder with their balance"""
    address: str
    balance: float
    percentage: float


class TokenHolderAnalyzer:
    """Analyzes token holder concentration and distribution metrics"""
    
    # Known burn addresses across different chains
    BURN_ADDRESSES: Set[str] = {
        # Ethereum
        "0x0000000000000000000000000000000000000000",
        "0x000000000000000000000000000000000000dEaD",
        "0x000000000000000000000000000000000000dead",
        # BSC
        "0x0000000000000000000000000000000000000000",
        "0x000000000000000000000000000000000000dead",
        # Polygon
        "0x0000000000000000000000000000000000000000",
        "0x000000000000000000000000000000000000dead",
    }
    
    def __init__(self, exclude_burn_addresses: bool = True, exclude_locked_liquidity: bool = True):
        self.exclude_burn_addresses = exclude_burn_addresses
        self.exclude_locked_liquidity = exclude_locked_liquidity
        self.locked_liquidity_addresses: Set[str] = set()
    
    def add_locked_liquidity_address(self, address: str):
        """Add a locked liquidity pool address to exclusion list"""
        self.locked_liquidity_addresses.add(address.lower())
    
    def add_locked_liquidity_addresses(self, addresses: List[str]):
        """Add multiple locked liquidity pool addresses to exclusion list"""
        for address in addresses:
            self.locked_liquidity_addresses.add(address.lower())
    
    def _should_exclude_address(self, address: str) -> bool:
        """Check if an address should be excluded from analysis"""
        address_lower = address.lower()
        
        if self.exclude_burn_addresses and address_lower in {addr.lower() for addr in self.BURN_ADDRESSES}:
            return True
        
        if self.exclude_locked_liquidity and address_lower in self.locked_liquidity_addresses:
            return True
        
        return False
    
    def get_top_holders(
        self, 
        holders: List[Dict[str, any]], 
        total_supply: float, 
        top_n: int = 50
    ) -> List[Holder]:
        """
        Get top N token holders by balance, excluding specified addresses
        
        Args:
            holders: List of holder dictionaries with 'address' and 'balance' keys
            total_supply: Total token supply
            top_n: Number of top holders to return (default: 50)
        
        Returns:
            List of Holder objects sorted by balance (descending)
        """
        # Filter out excluded addresses
        filtered_holders = [
            h for h in holders 
            if not self._should_exclude_address(h.get('address', ''))
        ]
        
        # Sort by balance (descending)
        sorted_holders = sorted(filtered_holders, key=lambda x: x.get('balance', 0), reverse=True)
        
        # Take top N
        top_holders = sorted_holders[:top_n]
        
        # Calculate percentages
        result = []
        for holder in top_holders:
            balance = holder.get('balance', 0)
            percentage = (balance / total_supply * 100) if total_supply > 0 else 0
            result.append(Holder(
                address=holder.get('address', ''),
                balance=balance,
                percentage=percentage
            ))
        
        return result
    
    def calculate_gini_coefficient(self, balances: List[float]) -> float:
        """
        Calculate Gini coefficient for token distribution
        
        Args:
            balances: List of token balances
        
        Returns:
            Gini coefficient (0 = perfect equality, 1 = perfect inequality)
        """
        if not balances or sum(balances) == 0:
            return 0.0
        
        # Sort balances
        sorted_balances = sorted(balances)
        n = len(sorted_balances)
        
        # Calculate Gini coefficient using the formula:
        # G = (2 * sum(i * x_i)) / (n * sum(x_i)) - (n + 1) / n
        # where i is the rank (1-indexed) and x_i is the balance at rank i
        
        cumulative_sum = sum((i + 1) * balance for i, balance in enumerate(sorted_balances))
        total_sum = sum(sorted_balances)
        
        if total_sum == 0:
            return 0.0
        
        gini = (2 * cumulative_sum) / (n * total_sum) - (n + 1) / n
        return max(0.0, min(1.0, gini))
    
    def calculate_concentration_metrics(
        self, 
        holders: List[Dict[str, any]], 
        total_supply: float,
        top_n: int = 50
    ) -> Dict[str, any]:
        """
        Calculate comprehensive concentration metrics for token holders
        
        Args:
            holders: List of holder dictionaries with 'address' and 'balance' keys
            total_supply: Total token supply
            top_n: Number of top holders to analyze (default: 50)
        
        Returns:
            Dictionary containing concentration metrics
        """
        # Get top holders
        top_holders = self.get_top_holders(holders, total_supply, top_n)
        
        # Extract balances for Gini calculation
        all_balances = [h.get('balance', 0) for h in holders if not self._should_exclude_address(h.get('address', ''))]
        
        # Calculate metrics
        top_1_percentage = sum(h.percentage for h in top_holders[:1]) if top_holders else 0
        top_10_percentage = sum(h.percentage for h in top_holders[:10]) if top_holders else 0
        top_50_percentage = sum(h.percentage for h in top_holders[:50]) if top_holders else 0
        
        gini_coefficient = self.calculate_gini_coefficient(all_balances)
        
        # Calculate Herfindahl-Hirschman Index (HHI)
        # HHI = sum of squared market shares (as decimals)
        market_shares = [balance / total_supply for balance in all_balances if total_supply > 0]
        hhi = sum(share ** 2 for share in market_shares)
        
        # Calculate effective number of holders (reciprocal of HHI)
        effective_holders = 1 / hhi if hhi > 0 else 0
        
        return {
            'top_holders': [
                {
                    'address': h.address,
                    'balance': h.balance,
                    'percentage': h.percentage
                }
                for h in top_holders
            ],
            'top_1_percentage': round(top_1_percentage, 2),
            'top_10_percentage': round(top_10_percentage, 2),
            'top_50_percentage': round(top_50_percentage, 2),
            'gini_coefficient': round(gini_coefficient, 4),
            'hhi': round(hhi, 4),
            'effective_holders': round(effective_holders, 2),
            'total_holders_analyzed': len(all_balances),
            'excluded_addresses': len(holders) - len(all_balances)
        }
    
    def assess_concentration_risk(self, metrics: Dict[str, any]) -> Dict[str, any]:
        """
        Assess the risk level based on concentration metrics
        
        Args:
            metrics: Concentration metrics from calculate_concentration_metrics
        
        Returns:
            Risk assessment dictionary
        """
        risk_score = 0.0
        risk_factors = []
        
        # Top 1 holder concentration
        if metrics['top_1_percentage'] > 50:
            risk_score += 0.4
            risk_factors.append('extreme_top_1_concentration')
        elif metrics['top_1_percentage'] > 30:
            risk_score += 0.2
            risk_factors.append('high_top_1_concentration')
        
        # Top 10 holder concentration
        if metrics['top_10_percentage'] > 80:
            risk_score += 0.3
            risk_factors.append('extreme_top_10_concentration')
        elif metrics['top_10_percentage'] > 60:
            risk_score += 0.15
            risk_factors.append('high_top_10_concentration')
        
        # Gini coefficient
        if metrics['gini_coefficient'] > 0.9:
            risk_score += 0.3
            risk_factors.append('extreme_inequality')
        elif metrics['gini_coefficient'] > 0.7:
            risk_score += 0.15
            risk_factors.append('high_inequality')
        
        # Effective holders
        if metrics['effective_holders'] < 10:
            risk_score += 0.2
            risk_factors.append('low_effective_holders')
        elif metrics['effective_holders'] < 20:
            risk_score += 0.1
            risk_factors.append('moderate_low_effective_holders')
        
        # Cap risk score at 1.0
        risk_score = min(risk_score, 1.0)
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = 'HIGH'
        elif risk_score >= 0.4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'concentration_risk_score': round(risk_score, 2),
            'concentration_risk_level': risk_level,
            'risk_factors': risk_factors
        }


def analyze_token_concentration(
    holders: List[Dict[str, any]],
    total_supply: float,
    locked_liquidity_addresses: List[str] = None,
    top_n: int = 50
) -> Dict[str, any]:
    """
    Convenience function to analyze token concentration in one call
    
    Args:
        holders: List of holder dictionaries with 'address' and 'balance' keys
        total_supply: Total token supply
        locked_liquidity_addresses: List of locked liquidity pool addresses to exclude
        top_n: Number of top holders to analyze (default: 50)
    
    Returns:
        Complete analysis including metrics and risk assessment
    """
    analyzer = TokenHolderAnalyzer()
    
    if locked_liquidity_addresses:
        analyzer.add_locked_liquidity_addresses(locked_liquidity_addresses)
    
    metrics = analyzer.calculate_concentration_metrics(holders, total_supply, top_n)
    risk_assessment = analyzer.assess_concentration_risk(metrics)
    
    return {
        **metrics,
        **risk_assessment
    }
