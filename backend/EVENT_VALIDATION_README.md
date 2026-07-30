# Event Validation and Spoofing Detection System

Validates transaction receipts against internal state changes to detect fake Transfer, Approval, or Mint events that trick off-chain indexers into displaying false volume or liquidity metrics.

## Overview

This system refactors transaction parsing to validate receipts against state changes rather than relying solely on emitted event logs. It ensures msg.sender and contract address alignment with event data, and the scoring engine ignores spoofed events during calculations.

## Components

### 1. Event Validator (`event_validator.py`)

**Classes:**
- `TransactionReceipt` - Represents a complete transaction receipt
- `EventLog` - Represents an event log from transaction
- `StateChange` - Represents a state change from transaction receipt
- `TransactionReceiptValidator` - Validates receipts against state changes
- `EventAddressVerifier` - Verifies msg.sender and contract address alignment
- `EventSpoofDetector` - Comprehensive spoofing detection

**Validation Logic:**
- Compares event addresses against contract addresses
- Validates state changes match event types (e.g., transfers require balance changes)
- Checks mint/burn events have corresponding supply changes
- Verifies approval events have allowance state changes
- Detects events emitted from wrong addresses

### 2. Validated Scoring Engine (`validated_scoring.py`)

**Classes:**
- `ValidatedMetrics` - Metrics calculated from validated events only
- `ScoringResult` - Result of scoring with event validation
- `ValidatedScoringEngine` - Scoring engine that ignores spoofed events
- `EnhancedRiskAnalyzer` - Enhanced risk analyzer with event validation

**Features:**
- Calculates metrics using only validated (trusted) events
- Provides volume adjustment based on spoofed event detection
- Provides liquidity adjustment based on spoofed event detection
- Generates confidence scores based on validation results
- Recommends actions when manipulation is detected

### 3. API Endpoint (`event_validation_api.py`)

FastAPI endpoint for event validation:
- `POST /api/event-validation` - Validate transaction events
- `POST /api/validated-scoring` - Calculate validated risk score
- `GET /health` - Health check

## Installation

```bash
cd backend
pip install -r requirements.txt
```

## Usage

### Python Backend

#### Validating Transaction Receipts

```python
from event_validator import EventSpoofDetector, TransactionReceipt, EventLog, StateChange, EventType
from datetime import datetime

detector = EventSpoofDetector()

# Create a transaction receipt
receipt = TransactionReceipt(
    transaction_hash="0x1234567890abcdef",
    from_address="0xABC123",
    to_address="0xCONTRACT",
    contract_address="0xCONTRACT",
    status="success",
    gas_used=50000,
    logs=[
        EventLog(
            address="0xCONTRACT",
            event_type=EventType.TRANSFER,
            topics=["0xTransfer", "0xABC123", "0xDEF456"],
            data="0x1000000000000000000",
            log_index=0,
            transaction_hash="0x1234567890abcdef",
            block_number=12345
        )
    ],
    state_changes=[
        StateChange(
            address="0xABC123",
            key="balance",
            old_value="1000000000000000000",
            new_value="0",
            change_type="balance"
        ),
        StateChange(
            address="0xDEF456",
            key="balance",
            old_value="0",
            new_value="1000000000000000000",
            change_type="balance"
        )
    ],
    block_number=12345,
    timestamp=datetime.now()
)

# Detect spoofing
detection = detector.detect_spoofing(receipt)

print(f"Total events: {detection['total_events']}")
print(f"Valid events: {detection['valid_events']}")
print(f"Spoofed events: {detection['spoofed_events']}")
print(f"Likely spoofed: {detection['is_likely_spoofed']}")

# Get only trusted events
trusted_events = detector.get_trusted_events(receipt)
print(f"Trusted events: {len(trusted_events)}")
```

#### Validated Risk Scoring

```python
from validated_scoring import EnhancedRiskAnalyzer

analyzer = EnhancedRiskAnalyzer()

# Analyze with validation
result = analyzer.analyze_with_validation(receipt, base_risk_score=0.3)

print(f"Base Risk Score: {result['base_risk_score']:.2f}")
print(f"Raw Score: {result['raw_score']:.2f}")
print(f"Validated Score: {result['validated_score']:.2f}")
print(f"Final Score: {result['final_score']:.2f}")
print(f"Risk Level: {result['risk_level']}")
print(f"Is Manipulated: {result['is_manipulated']}")
print(f"Confidence: {result['confidence']}")

print(f"\nVolume Adjustment:")
print(f"  Raw: {result['volume_adjustment']['raw_volume']}")
print(f"  Validated: {result['volume_adjustment']['validated_volume']}")
print(f"  Adjustment Ratio: {result['volume_adjustment']['adjustment_ratio']:.2%}")

print(f"\nRecommendations:")
for rec in result['recommendations']:
    print(f"  - {rec}")
```

#### Running the API Server

```bash
cd backend
python event_validation_api.py
```

The API will be available at `http://localhost:8002`

## Validation Rules

### Transfer Events
- Must have corresponding balance state changes
- Sender balance must decrease
- Recipient balance must increase
- Event address must match contract address

### Approval Events
- Must have corresponding allowance state change
- Event address must match contract address
- Owner/spender addresses must be valid

### Mint Events
- Must have corresponding total supply increase
- Event address must match contract address
- Supply state change is required

### Burn Events
- Must have corresponding total supply decrease
- Event address must match contract address
- Supply state change is required

### Address Verification
- Event emitter address must match contract address
- Transfer sender should match msg.sender or be approved spender
- Mint events must originate from contract itself

## API Response Format

### Event Validation Response

```json
{
  "transactionHash": "0x1234567890abcdef",
  "totalEvents": 3,
  "validEvents": 1,
  "spoofedEvents": 2,
  "suspiciousEvents": 0,
  "isLikelySpoofed": true,
  "spoofedDetails": [
    {
      "log_index": "1",
      "event_type": "Transfer",
      "discrepancies": ["Event address does not match contract address"],
      "address_issues": []
    }
  ],
  "suspiciousDetails": [],
  "validDetails": [
    {
      "log_index": "0",
      "event_type": "Transfer"
    }
  ]
}
```

### Validated Scoring Response

```json
{
  "baseRiskScore": 0.3,
  "rawScore": 0.25,
  "validatedScore": 0.35,
  "finalScore": 0.35,
  "riskLevel": "MEDIUM",
  "isManipulated": true,
  "confidence": "medium",
  "spoofedEventCount": 2,
  "totalEventCount": 3,
  "spoofedEventTypes": ["Transfer", "Mint"],
  "volumeAdjustment": {
    "rawVolume": 6000000000000000000,
    "validatedVolume": 1000000000000000000,
    "adjustmentRatio": 0.1667,
    "spoofedVolume": 5000000000000000000,
    "isVolumeManipulated": true
  },
  "liquidityAdjustment": {
    "rawLiquidityEvents": 2,
    "validatedLiquidityEvents": 1,
    "adjustmentRatio": 0.5,
    "isLiquidityManipulated": true
  },
  "recommendations": [
    "Event spoofing detected - metrics may be manipulated",
    "Volume metrics may be inflated by spoofed events",
    "Liquidity metrics may be inflated by spoofed events"
  ]
}
```

## Testing

Run the test suite:

```bash
cd backend
pytest test_event_validator.py -v
```

## Spoofing Scenarios Detected

### 1. Fake Volume Inflation
Detects contracts emitting fake Transfer events to inflate volume:
- Events emitted from wrong addresses
- Transfer events without balance state changes
- Large amounts in event data without corresponding state changes

### 2. Fake Liquidity Metrics
Detects contracts emitting fake AddLiquidity/RemoveLiquidity events:
- Liquidity events without corresponding state changes
- Events from unauthorized addresses
- Mismatched liquidity amounts

### 3. Fake Mint/Burn Events
Detects contracts emitting fake Mint or Burn events:
- Mint events without total supply increase
- Burn events without total supply decrease
- Events from wrong contract addresses

### 4. Address Mismatches
Detects events with address inconsistencies:
- Event emitter address != contract address
- Transfer sender != msg.sender (without approval)
- Mint events from non-contract addresses

## Integration with Existing System

The event validation system can be integrated with the existing risk analysis:

1. **Transaction Analysis** - Validate receipts before calculating metrics
2. **Volume Calculation** - Use only validated events for volume metrics
3. **Liquidity Calculation** - Use only validated events for liquidity metrics
4. **Risk Scoring** - Apply validated scoring to get accurate risk scores
5. **Alert Generation** - Trigger alerts when spoofing is detected

## Confidence Levels

- **HIGH** - Less than 20% of events are spoofed
- **MEDIUM** - 20-50% of events are spoofed
- **LOW** - More than 50% of events are spoofed

## Volume/Liquidity Adjustment

When spoofing is detected, the system provides adjustment ratios:

- **Volume Adjustment Ratio** = Validated Volume / Raw Volume
- **Liquidity Adjustment Ratio** = Validated Liquidity Events / Raw Liquidity Events

If adjustment ratio < 0.8, metrics are considered manipulated.

## Future Enhancements

- Real-time event validation for mempool transactions
- Integration with blockchain node for direct state access
- Machine learning model to detect sophisticated spoofing patterns
- Cross-referencing with multiple data sources
- Automated alerting for high spoofing rates
- Historical analysis of spoofing patterns
