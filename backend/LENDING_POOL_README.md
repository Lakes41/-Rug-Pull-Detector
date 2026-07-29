# Lending Pool Risk Analysis System

Specialized risk scoring for DeFi lending pools, decentralized invoice factoring, and Real-World Asset (RWA) tokenization with TVL tracking, collateral manipulation detection, and oracle monitoring.

## Overview

This system implements specialized risk models for complex DeFi structures, tracking historical Total Value Locked (TVL), detecting sudden collateral withdrawals, and monitoring off-chain oracle updates vs on-chain mint/burn functions to detect infinite minting vulnerabilities.

## Components

### 1. TVL Tracker (`tvl_tracker.py`)

**Classes:**
- `TVLSnapshot` - Represents TVL state at a point in time
- `TVLAnomaly` - Represents detected TVL anomalies
- `TVLDatabase` - SQLite storage for historical TVL data
- `AnomalyDetector` - Detects various TVL anomaly patterns
- `TVLTracker` - Main TVL tracking system

**Anomaly Types Detected:**
- **SUDDEN_DROP** - Rapid TVL decrease from historical average
- **GRADUAL_DECLINE** - Consistent but gradual TVL decrease
- **SPIKE_WITHDRAWAL** - Sudden collateral withdrawal spikes
- **COLLATERAL_DRAIN** - Rapid collateral drain over short time periods
- **UNUSUAL_PATTERN** - Other abnormal TVL patterns

### 2. Oracle/Mint Monitor (`oracle_mint_monitor.py`)

**Classes:**
- `MintBurnEvent` - On-chain mint/burn event tracking
- `OracleUpdate` - Off-chain oracle update tracking
- `MintBurnAnomaly` - Detected mint/burn anomalies
- `OracleMintDatabase` - Storage for oracle and mint/burn data
- `InfiniteMintDetector` - Detects infinite minting vulnerabilities
- `OracleMintMonitor` - Main monitoring system

**Vulnerabilities Detected:**
- **Rapid Minting** - Excessive minting within short time windows
- **Oracle Price Manipulation** - Price changes correlated with minting
- **Unbacked Minting** - Minting without corresponding oracle updates
- **Supply Inflation** - Excessive supply inflation over time

### 3. Lending Pool Risk Modifier (`lending_pool_risk.py`)

**Classes:**
- `PoolType` - Types of lending pools (Standard, Liquidity, Stable, Yield, RWA)
- `LendingPoolRiskFactors` - Comprehensive risk factors for pools
- `LendingPoolRiskResult` - Complete risk analysis result
- `LendingPoolRiskModifier` - Risk score modification logic

**Pool Types:**
- **STANDARD_LENDING** - Standard lending pools (weight: 1.0)
- **LIQUIDITY_POOL** - Liquidity pools (weight: 1.2)
- **STABLE_POOL** - Stable pools (weight: 0.8)
- **YIELD_POOL** - Yield pools (weight: 1.5)
- **RWA_TOKENIZED** - RWA tokenized assets (weight: 1.3)

**Risk Factors:**
- TVL anomaly score and volatility
- Collateral withdrawal risk
- Infinite minting risk
- Oracle manipulation risk
- Unbacked minting risk
- Liquidity utilization
- Collateral ratio
- Bad debt ratio

### 4. API Endpoint (`lending_pool_api.py`)

FastAPI endpoint for lending pool risk analysis:
- `POST /api/lending-pool-risk` - Analyze lending pool risk
- `GET /health` - Health check

### 5. Frontend Integration (`TokenAnalyzer.jsx`)

Enhanced TokenAnalyzer with lending pool detection:
- Checkbox to enable lending pool analysis
- Pool type selector (Standard, Liquidity, Stable, Yield, RWA)
- Integration with existing risk analysis pipeline

## Installation

```bash
cd backend
pip install -r requirements.txt
```

## Usage

### Python Backend

#### Running the TVL Tracker

```python
from tvl_tracker import TVLTracker, TVLSnapshot
from datetime import datetime

tracker = TVLTracker()

# Record a TVL snapshot
snapshot = TVLSnapshot(
    pool_address="0x1234567890",
    timestamp=datetime.now(),
    total_value_locked=1000000.0,
    collateral_amount=800000.0,
    borrowed_amount=300000.0,
    liquidity_tokens=500000.0,
    token_prices={"USDC": 1.0, "ETH": 2000.0}
)

anomalies = tracker.record_snapshot(snapshot)
if anomalies:
    for anomaly in anomalies:
        print(f"Anomaly: {anomaly.anomaly_type.value} - {anomaly.description}")

# Get pool history
history = tracker.get_pool_history("0x1234567890", days=30)

# Get risk score
risk_score = tracker.get_risk_score("0x1234567890")

tracker.close()
```

#### Running the Oracle/Mint Monitor

```python
from oracle_mint_monitor import OracleMintMonitor, MintBurnEvent, OracleUpdate
from datetime import datetime

monitor = OracleMintMonitor()

# Record a mint event
mint_event = MintBurnEvent(
    token_address="0x1234567890",
    event_type=MintBurnEventType.MINT,
    amount=1000000.0,
    timestamp=datetime.now(),
    transaction_hash="0xabcdef",
    total_supply_after=11000000.0
)

anomalies = monitor.record_mint_burn_event(mint_event)

# Record an oracle update
oracle_update = OracleUpdate(
    asset_id="0x1234567890",
    update_type=OracleUpdateType.PRICE_UPDATE,
    old_value=100.0,
    new_value=110.0,
    timestamp=datetime.now(),
    oracle_address="0xoracle123"
)

monitor.record_oracle_update(oracle_update)

# Get risk score
risk_score = monitor.get_risk_score("0x1234567890")

monitor.close()
```

#### Running the Lending Pool Risk Modifier

```python
from lending_pool_risk import analyze_lending_pool_risk, PoolType

result = analyze_lending_pool_risk(
    pool_address="0x1234567890",
    pool_type=PoolType.RWA_TOKENIZED,
    base_risk_score=0.4
)

print(f"Base Risk Score: {result.base_risk_score:.2f}")
print(f"Modified Risk Score: {result.modified_risk_score:.2f}")
print(f"Risk Level: {result.risk_level}")
print(f"\nRisk Factors:")
print(f"  TVL Anomaly Score: {result.risk_factors.tvl_anomaly_score:.2f}")
print(f"  Infinite Mint Risk: {result.risk_factors.infinite_mint_risk:.2f}")
print(f"  Oracle Manipulation Risk: {result.risk_factors.oracle_manipulation_risk:.2f}")
print(f"\nRecommendations:")
for rec in result.recommendations:
    print(f"  - {rec}")
```

#### Running the API Server

```bash
cd backend
python lending_pool_api.py
```

The API will be available at `http://localhost:8001`

### Frontend

The TokenAnalyzer component now includes lending pool analysis:

1. Check "This is a Lending Pool" to enable specialized analysis
2. Select the pool type from the dropdown
3. Analyze as normal - the system will automatically apply lending pool risk modifiers

## Testing

Run the test suite:

```bash
cd backend
pytest test_lending_pool_risk.py -v
```

## Risk Scenarios Detected

### 1. Collateral Drain Attacks
Detects rapid withdrawal of collateral from lending pools:
- Sudden TVL drops exceeding threshold (default 20%)
- Rapid collateral drain over short time periods
- Collateral withdrawal spikes while borrowing remains stable

### 2. Infinite Minting Vulnerabilities
Detects tokenized assets with minting vulnerabilities:
- Rapid minting within short time windows
- Minting without corresponding oracle updates (unbacked minting)
- Excessive supply inflation over time
- Oracle price manipulation correlated with minting

### 3. Oracle Manipulation
Detects manipulation of off-chain oracles:
- Price updates followed by suspicious minting
- Lack of oracle updates before minting events
- Correlation between oracle changes and token operations

### 4. TVL Volatility
Monitors Total Value Locked stability:
- Sudden drops from historical averages
- Gradual but consistent declines
- Unusual patterns in TVL movement

## API Response Format

```json
{
  "poolAddress": "0x1234567890",
  "poolType": "rwa",
  "baseRiskScore": 0.4,
  "modifiedRiskScore": 0.65,
  "riskLevel": "HIGH",
  "riskFactors": {
    "tvlAnomalyScore": 0.3,
    "infiniteMintRisk": 0.7,
    "oracleManipulationRisk": 0.5,
    "collateralWithdrawalRisk": 0.4,
    "tvlVolatility": 0.2,
    "liquidityUtilization": 0.5,
    "collateralRatio": 0.8
  },
  "detectedAnomalies": [
    "TVL: sudden_drop - TVL dropped by 35.00% from historical average",
    "Mint/Burn: rapid_minting - Rapid minting detected: 150.00% supply increase"
  ],
  "recommendations": [
    "Monitor TVL closely for sudden drops",
    "Investigate mint/burn mechanisms for potential infinite minting",
    "Review oracle update mechanisms and price feeds"
  ]
}
```

## Risk Score Calculation

The modified risk score is calculated as:

```
modified_score = (base_score * 0.6) + (modifier * 0.4)

modifier = (
    tvl_anomaly_score * 0.25 +
    infinite_mint_risk * 0.30 +
    oracle_manipulation_risk * 0.20 +
    collateral_withdrawal_risk * 0.15 +
    liquidity_utilization * 0.10
) * pool_type_weight
```

Pool type weights:
- Standard Lending: 1.0
- Liquidity Pool: 1.2
- Stable Pool: 0.8
- Yield Pool: 1.5
- RWA Tokenized: 1.3

## Integration with Existing System

The lending pool risk system integrates with the existing rug pull detector:

1. **Frontend** - Enhanced TokenAnalyzer with lending pool detection
2. **API** - New endpoint `/api/lending-pool-risk` for specialized analysis
3. **Backend** - Python modules for TVL tracking and oracle monitoring
4. **Risk Dashboard** - Lending pool risks displayed alongside traditional metrics

## Database Schema

### TVL Snapshots Table
- `pool_address` - Pool contract address
- `timestamp` - Snapshot timestamp
- `total_value_locked` - Total TVL
- `collateral_amount` - Collateral amount
- `borrowed_amount` - Borrowed amount
- `liquidity_tokens` - Liquidity token amount
- `token_prices` - JSON of token prices
- `block_number` - Block number (optional)

### Oracle Updates Table
- `asset_id` - Asset/token ID
- `update_type` - Type of update (price, collateral, asset value)
- `old_value` - Previous value
- `new_value` - New value
- `timestamp` - Update timestamp
- `oracle_address` - Oracle contract address
- `signature` - Update signature (optional)
- `update_source` - Source of update (optional)

### Anomalies Tables
- Separate tables for TVL and mint/burn anomalies
- Store anomaly type, severity, description, and affected assets

## Future Enhancements

- Real-time TVL monitoring with WebSocket alerts
- Integration with multiple oracle providers
- Machine learning models for anomaly prediction
- Cross-chain lending pool analysis
- Automated alerting for high-risk pools
- Historical trend analysis and reporting
