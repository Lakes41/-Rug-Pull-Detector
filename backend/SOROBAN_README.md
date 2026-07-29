# Soroban Authorization Analyzer

A comprehensive system for analyzing Soroban smart contract authorization vectors to detect potential rug pulls on the Stellar network.

## Overview

This system parses Soroban footprint metadata and invocation trees from transaction traces, builds directed acyclic graphs (DAGs) representing multi-contract execution pathways, and flags contracts where target functions bypass signature verification or pass arbitrary sub-invocations without host checks.

## Components

### 1. Core Analyzer (`soroban_auth_analyzer.py`)

**Classes:**
- `SorobanTraceParser` - Parses footprint metadata and invocation trees from soroban-env-host
- `ExecutionDAGBuilder` - Builds DAGs of multi-contract execution pathways
- `AuthorizationVectorDetector` - Detects authorization risks and vulnerabilities
- `SorobanAuthAnalyzer` - Main analyzer orchestrating the analysis pipeline

**Risk Types Detected:**
- **SIGNATURE_BYPASS** - Functions requiring auth but bypassing signature verification
- **UNCHECKED_SUB_INVOCATION** - Sub-invocations without host authorization checks
- **PRIVILEGED_AUTH_VECTOR** - Admin/maintainer functions callable without user signature
- **ARBITRARY_CALL_FORWARDING** - Arbitrary call forwarding without proper validation
- **MISSING_HOST_CHECK** - Critical operations missing host authorization

### 2. Integration Layer (`soroban_integration.py`)

**Classes:**
- `SorobanRPCClient` - Async client for Soroban RPC endpoints
- `SorobanContractAnalyzer` - High-level contract analysis
- `SorobanRiskEvaluator` - Risk scoring and evaluation

### 3. API Endpoint (`soroban_api.py`)

FastAPI endpoint for Soroban authorization analysis:
- `POST /api/soroban-auth-analyze` - Analyze contract authorization risks
- `GET /health` - Health check

### 4. Frontend Integration (`stellarAdapter.js`)

Enhanced Stellar adapter with Soroban authorization analysis:
- `analyzeSorobanAuthorization()` - Analyze authorization risks
- `analyzeSorobanContractRisk()` - Combined risk analysis

## Installation

```bash
cd backend
pip install -r requirements.txt
```

## Usage

### Python Backend

#### Running the API Server

```bash
cd backend
python soroban_api.py
```

The API will be available at `http://localhost:8000`

#### Programmatic Usage

```python
from soroban_auth_analyzer import SorobanAuthAnalyzer

# Create analyzer
analyzer = SorobanAuthAnalyzer()

# Analyze a transaction trace
transaction_trace = {
    "footprint": {
        "contract_id": "CABCD1234567890",
        "read": [...],
        "write": [...],
        "auth": [...]
    },
    "invocation_tree": {
        "root": {...},
        "children": [...]
    }
}

result = analyzer.analyze_transaction(transaction_trace)
report = analyzer.generate_report(result)
print(report)
```

#### Using the Integration Layer

```python
import asyncio
from soroban_integration import SorobanContractAnalyzer

async def analyze_contract():
    analyzer = SorobanContractAnalyzer()
    
    # Analyze by transaction hash
    result = await analyzer.analyze_contract_by_transaction("YOUR_TX_HASH")
    print(result["risk_report"])
    
    # Or analyze by simulation
    result = await analyzer.analyze_contract_by_simulation("BASE64_XDR")
    print(result["risk_report"])

asyncio.run(analyze_contract())
```

### Frontend

```javascript
import { stellarAdapter } from './lib/chains/stellarAdapter';

// Analyze Soroban contract authorization
const result = await stellarAdapter.analyzeSorobanAuthorization(
    'CABCD1234567890',
    'OPTIONAL_TX_HASH'
);

console.log(result.riskLevel);
console.log(result.riskVectors);

// Full risk analysis
const fullAnalysis = await stellarAdapter.analyzeSorobanContractRisk(
    'CABCD1234567890'
);
```

## Testing

Run the test suite:

```bash
cd backend
pytest test_soroban_auth_analyzer.py -v
```

## Example Output

```
============================================================
SOROBAN AUTHORIZATION RISK ANALYSIS REPORT
============================================================
Total Contracts Analyzed: 2
Critical Risks Found: 2
High Risks Found: 0

RISK VECTORS DETECTED:
------------------------------------------------------------

[CRITICAL] signature_bypass
Contract: CABCD1234567890
Function: transfer
Description: Function requires auth but signature verification is bypassed

[CRITICAL] privileged_auth_vector
Contract: CABCD1234567890
Function: admin_drain
Description: Privileged function can be called without user signature verification
============================================================
```

## Risk Scenarios Detected

### 1. Drain Attacks
Detects functions that can drain reserves without proper signature verification:
- Admin functions callable without user signature
- Bypassed signature checks on critical operations

### 2. Reentrancy
Detects cycles in execution graphs that may indicate reentrancy vulnerabilities:
- Circular call patterns between contracts
- Unchecked callback invocations

### 3. Arbitrary Call Forwarding
Identifies functions that forward calls to arbitrary contracts:
- Delegate call patterns without validation
- Multiple unchecked sub-invocations

### 4. Missing Authorization Checks
Flags critical operations missing host authorization:
- Transfer/burn/mint operations without `require_auth`
- Liquidity manipulation functions

## API Response Format

```json
{
  "contractId": "CABCD1234567890",
  "riskScore": 0.65,
  "riskLevel": "HIGH",
  "riskVectors": [
    {
      "contractId": "CABCD1234567890",
      "functionName": "transfer",
      "riskType": "signature_bypass",
      "description": "...",
      "severity": "critical",
      "affectedContracts": []
    }
  ],
  "executionGraph": {
    "nodes": [...],
    "edges": [...]
  },
  "report": "..."
}
```

## Integration with Existing System

The Soroban analyzer integrates with the existing rug pull detector:

1. **Frontend** - Enhanced `stellarAdapter.js` with Soroban-specific methods
2. **API** - New endpoint `/api/soroban-auth-analyze` for authorization analysis
3. **Backend** - Python modules for deep contract analysis
4. **Risk Dashboard** - Authorization risks displayed alongside traditional risk metrics

## Future Enhancements

- Real-time monitoring of Soroban contract deployments
- Historical analysis of contract authorization patterns
- Machine learning model for risk prediction
- Integration with Soroban contract source code analysis
- Automated alerting for high-risk authorization vectors
