"""
Demonstration script for Token Holder Analyzer
Run this script to see the token holder concentration analyzer in action.
"""

from token_holder_analyzer import TokenHolderAnalyzer, analyze_token_concentration


def demo_basic_usage():
    """Basic usage demonstration"""
    print("=" * 60)
    print("Token Holder Analyzer - Basic Usage Demo")
    print("=" * 60)
    
    # Sample holder data
    holders = [
        {'address': '0xDeployer1234567890ABCDEF1234567890ABCDEF1234', 'balance': 600000},
        {'address': '0xHolder2234567890ABCDEF1234567890ABCDEF1234', 'balance': 200000},
        {'address': '0xHolder3234567890ABCDEF1234567890ABCDEF1234', 'balance': 100000},
        {'address': '0xHolder4234567890ABCDEF1234567890ABCDEF1234', 'balance': 50000},
        {'address': '0xHolder5234567890ABCDEF1234567890ABCDEF1234', 'balance': 30000},
        {'address': '0xHolder6234567890ABCDEF1234567890ABCDEF1234', 'balance': 20000},
    ]
    
    total_supply = 1000000
    
    analyzer = TokenHolderAnalyzer()
    metrics = analyzer.calculate_concentration_metrics(holders, total_supply, top_n=50)
    
    print(f"\nTotal Supply: {total_supply:,}")
    print(f"Total Holders Analyzed: {metrics['total_holders_analyzed']}")
    print(f"\nTop 1 Holder: {metrics['top_1_percentage']}%")
    print(f"Top 10 Holders: {metrics['top_10_percentage']}%")
    print(f"Top 50 Holders: {metrics['top_50_percentage']}%")
    print(f"\nGini Coefficient: {metrics['gini_coefficient']}")
    print(f"Herfindahl-Hirschman Index (HHI): {metrics['hhi']}")
    print(f"Effective Number of Holders: {metrics['effective_holders']}")
    
    print("\nTop 5 Holders:")
    for i, holder in enumerate(metrics['top_holders'][:5], 1):
        print(f"  {i}. {holder['address']}: {holder['balance']:,} ({holder['percentage']:.2f}%)")
    
    risk = analyzer.assess_concentration_risk(metrics)
    print(f"\nConcentration Risk Assessment:")
    print(f"  Risk Score: {risk['concentration_risk_score']}")
    print(f"  Risk Level: {risk['concentration_risk_level']}")
    print(f"  Risk Factors: {', '.join(risk['risk_factors']) if risk['risk_factors'] else 'None'}")


def demo_with_exclusions():
    """Demonstration with address exclusions"""
    print("\n" + "=" * 60)
    print("Token Holder Analyzer - With Address Exclusions Demo")
    print("=" * 60)
    
    holders = [
        {'address': '0x0000000000000000000000000000000000000000', 'balance': 500000},  # Burn address
        {'address': '0x000000000000000000000000000000000000dEaD', 'balance': 200000},  # Burn address
        {'address': '0xLP1234567890ABCDEF1234567890ABCDEF1234', 'balance': 150000},   # Locked LP
        {'address': '0xHolder1234567890ABCDEF1234567890ABCDEF1234', 'balance': 100000},
        {'address': '0xHolder2234567890ABCDEF1234567890ABCDEF1234', 'balance': 50000},
    ]
    
    total_supply = 1000000
    
    # Create analyzer with exclusions
    analyzer = TokenHolderAnalyzer(exclude_burn_addresses=True, exclude_locked_liquidity=True)
    analyzer.add_locked_liquidity_address('0xLP1234567890ABCDEF1234567890ABCDEF1234')
    
    metrics = analyzer.calculate_concentration_metrics(holders, total_supply, top_n=50)
    
    print(f"\nTotal Supply: {total_supply:,}")
    print(f"Total Holders (before exclusion): {len(holders)}")
    print(f"Total Holders (after exclusion): {metrics['total_holders_analyzed']}")
    print(f"Excluded Addresses: {metrics['excluded_addresses']}")
    
    print(f"\nTop 1 Holder (after exclusions): {metrics['top_1_percentage']}%")
    print(f"Gini Coefficient (after exclusions): {metrics['gini_coefficient']}")
    
    print("\nTop Holders (after exclusions):")
    for i, holder in enumerate(metrics['top_holders'], 1):
        print(f"  {i}. {holder['address']}: {holder['balance']:,} ({holder['percentage']:.2f}%)")


def demo_convenience_function():
    """Demonstration of convenience function"""
    print("\n" + "=" * 60)
    print("Token Holder Analyzer - Convenience Function Demo")
    print("=" * 60)
    
    holders = [
        {'address': '0xWhale1234567890ABCDEF1234567890ABCDEF1234', 'balance': 800000},
        {'address': '0xHolder2234567890ABCDEF1234567890ABCDEF1234', 'balance': 100000},
        {'address': '0xHolder3234567890ABCDEF1234567890ABCDEF1234', 'balance': 50000},
        {'address': '0xLP1234567890ABCDEF1234567890ABCDEF1234', 'balance': 50000},
    ]
    
    total_supply = 1000000
    locked_addresses = ['0xLP1234567890ABCDEF1234567890ABCDEF1234']
    
    result = analyze_token_concentration(holders, total_supply, locked_addresses, top_n=50)
    
    print(f"\nComplete Analysis Results:")
    print(f"  Top 1%: {result['top_1_percentage']}%")
    print(f"  Top 10%: {result['top_10_percentage']}%")
    print(f"  Gini Coefficient: {result['gini_coefficient']}")
    print(f"  HHI: {result['hhi']}")
    print(f"  Effective Holders: {result['effective_holders']}")
    print(f"  Concentration Risk Score: {result['concentration_risk_score']}")
    print(f"  Concentration Risk Level: {result['concentration_risk_level']}")


def demo_gini_coefficient():
    """Demonstration of Gini coefficient calculation"""
    print("\n" + "=" * 60)
    print("Token Holder Analyzer - Gini Coefficient Demo")
    print("=" * 60)
    
    analyzer = TokenHolderAnalyzer()
    
    # Perfect equality
    equal_balances = [100, 100, 100, 100, 100]
    gini_equal = analyzer.calculate_gini_coefficient(equal_balances)
    print(f"\nPerfect Equality (all balances equal): {gini_equal}")
    
    # Perfect inequality
    unequal_balances = [500, 0, 0, 0, 0]
    gini_unequal = analyzer.calculate_gini_coefficient(unequal_balances)
    print(f"Perfect Inequality (one holder has everything): {gini_unequal}")
    
    # Realistic distribution
    realistic_balances = [400, 200, 150, 100, 100, 50]
    gini_realistic = analyzer.calculate_gini_coefficient(realistic_balances)
    print(f"Realistic Distribution: {gini_realistic}")


if __name__ == "__main__":
    demo_basic_usage()
    demo_with_exclusions()
    demo_convenience_function()
    demo_gini_coefficient()
    
    print("\n" + "=" * 60)
    print("Demo completed successfully!")
    print("=" * 60)
