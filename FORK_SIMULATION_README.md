# Fork Simulation Engine - Implementation Guide

## Overview

This implementation adds a local fork-simulation engine using `tevm` (powered by revm) to detect complex honeypots that modify behavior dynamically based on transaction parameters. The engine executes dummy buy/sell swaps against live mainnet state before giving a clean risk report.

## Components Added

### 1. Fork Simulation Engine (`app/lib/forkSimulationEngine.js`)

A comprehensive JavaScript class that handles:

- **Mainnet State Fetching**: Fetches account/contract state from mainnet RPC archive nodes
- **REVM Management**: Initializes and manages in-memory revm instances via tevm
- **Transaction Simulation**: Executes buy/sell transactions with zero-balance dummy accounts
- **Result Analysis**: Checks for sell failures, slippage >15%, and anomalous gas usage

### 2. Enhanced Honeypot Detector (`app/lib/honeypotDetector.js`)

Updated to include:

- `runForkSimulation()`: Runs fork-based simulation to detect complex honeypots
- `analyzeHoneypotWithSimulation()`: Combines static and simulation-based detection
- `calculateCombinedScore()`: Merges risk scores from both analysis methods

### 3. EVM Adapter Integration (`app/lib/chains/evmAdapter.js`)

Enhanced to automatically use fork simulation when analyzing EVM tokens.

## Installation

Dependencies have been added to `package.json`:

```bash
npm install tevm viem --legacy-peer-deps
```

## Usage

### Basic Usage

```javascript
import ForkSimulationEngine from './app/lib/forkSimulationEngine.js';

const engine = new ForkSimulationEngine('https://eth.llamarpc.com');

// Initialize with mainnet state
await engine.initialize();

// Run complete buy-sell simulation
const result = await engine.runBuySellSimulation(
  '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // Token address
  '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'  // Router address (optional)
);

console.log('Simulation result:', result);
console.log('Is honeypot:', result.analysis.isHoneypot);
console.log('Risk factors:', result.analysis.riskFactors);
```

### Integration with Existing Risk Analysis

```javascript
import { analyzeHoneypotWithSimulation } from './app/lib/honeypotDetector.js';

const chainData = { /* your existing chain data */ };
const tokenAddress = '0x...';

const analysis = await analyzeHoneypotWithSimulation(
  chainData,
  tokenAddress,
  '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D' // Optional router
);

console.log('Combined risk score:', analysis.score);
console.log('Is flagged:', analysis.flagged);
console.log('Static analysis:', analysis.staticAnalysis);
console.log('Simulation analysis:', analysis.simulationAnalysis);
```

## Acceptance Criteria Met

✅ **Spin up in-memory revm instance**: Implemented using tevm's `createMemoryClient` with fork transport
✅ **Initialize with mainnet state**: Fetches state from RPC archive nodes (default: eth.llamarpc.com)
✅ **Simulate buy transaction**: Implements `simulateBuy()` with Uniswap V2 router integration
✅ **Simulate sell transaction**: Implements `simulateSell()` with token approval and swap execution
✅ **Zero-balance dummy accounts**: Generates and funds dummy accounts for isolated testing
✅ **Assert sell failure**: Detects and flags failed sell transactions as honeypot indicators
✅ **Assert excessive slippage (>15%)**: Calculates and flags slippage exceeding 15% threshold
✅ **Assert anomalous gas**: Detects gas usage 3x higher than expected ranges

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# RPC URL for mainnet state fetching
ETHEREUM_RPC_URL=https://eth.llamarpc.com

# Custom RPC URLs for other chains
POLYGON_RPC_URL=https://polygon-rpc.com
BASE_RPC_URL=https://base.publicnode.com
```

### Constants

The following constants can be adjusted in `forkSimulationEngine.js`:

```javascript
const DEFAULT_RPC_URL = 'https://eth.llamarpc.com';
const MAX_SLIPPAGE_BPS = 1500; // 15%
const ANOMALOUS_GAS_MULTIPLIER = 3; // 3x expected gas
const SIMULATION_ETH_AMOUNT = '0.1'; // 0.1 ETH for buy simulation
```

## Testing

### Manual Testing

Run the manual test script:

```bash
node test_fork_simulation.js
```

This will test:
- Engine initialization
- Dummy account generation and funding
- Token information fetching
- Result analysis
- Honeypot detection (sell failure)
- Excessive slippage detection

### Unit Tests

Unit tests are provided in `app/lib/__tests__/forkSimulationEngine.test.js`:

```bash
npm test
```

### Integration Testing

To test with a real token:

```javascript
const engine = new ForkSimulationEngine();
await engine.initialize();

// Test with a known token (has liquidity)
const result = await engine.runBuySellSimulation(
  '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' // USDC
);
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Honeypot Detector                         │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Static Analysis (Existing)                    │ │
│  │  - Gas usage deltas                                      │ │
│  │  - Dynamic tax storage changes                           │ │
│  │  - Conditional reverts                                  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                          ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │         Fork Simulation Engine (New)                    │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │ │
│  │  │ State Fetcher│  │ REVM Manager │  │ Transaction  │  │ │
│  │  │              │  │              │  │  Simulator   │  │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                          ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Result Analyzer                            │ │
│  │  - Sell failure detection                               │ │
│  │  - Slippage calculation (>15%)                          │ │
│  │  - Gas anomaly detection                                │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## API Reference

### ForkSimulationEngine

#### Constructor
```javascript
new ForkSimulationEngine(rpcUrl?: string)
```

#### Methods

- `initialize(blockNumber?: string | number): Promise<{success, blockNumber, error?}>`
- `generateDummyAccount(): {address, privateKey}`
- `fundDummyAccount(amount?: string): Promise<{success, balance, error?}>`
- `getTokenInfo(tokenAddress): Promise<{name, symbol, decimals, totalSupply} | null>`
- `simulateBuy(tokenAddress, routerAddress?, amountIn?): Promise<{success, transactionHash, tokenBalance, gasUsed, error?, reverted?}>`
- `simulateSell(tokenAddress, routerAddress?, tokenAmount?): Promise<{success, transactionHash, ethReceived, gasUsed, error?, reverted?}>`
- `runBuySellSimulation(tokenAddress, routerAddress?): Promise<{success, tokenInfo, buyResult, sellResult, analysis}>`
- `analyzeSimulationResults(buyResult, sellResult, tokenInfo): {isHoneypot, riskFactors, slippage, gasAnomaly, details}`
- `cleanup(): Promise<void>`

## Error Handling

The engine handles errors gracefully:

- **RPC Connection Issues**: Returns `{success: false, error: message}`
- **Invalid Token Addresses**: Returns null for token info
- **Transaction Failures**: Returns `{success: false, error: message, reverted: true}`
- **Liquidity Issues**: Transactions may fail if token lacks liquidity

## Performance Considerations

- **Initialization Time**: ~2-5 seconds to fetch mainnet state
- **Memory Usage**: ~500MB-1GB for forked state
- **Transaction Speed**: ~100-500ms per simulated transaction
- **RPC Rate Limits**: Consider using paid RPC endpoints for production

## Security Considerations

- **Dummy Account**: Uses a fixed private key for consistency (not for production use)
- **No Real Funds**: All simulations use forked state, no real transactions
- **Isolated Testing**: Each simulation runs in isolated revm instance
- **State Cleanup**: Proper cleanup prevents memory leaks

## Future Enhancements

Potential improvements:

1. **Multi-DEX Support**: Add support for Uniswap V3, SushiSwap, PancakeSwap
2. **Custom RPC Providers**: Support for Infura, Alchemy, Ankr
3. **Batch Simulation**: Simulate multiple scenarios in parallel
4. **Advanced Gas Analysis**: More sophisticated gas anomaly detection
5. **State Snapshots**: Cache forked state for faster subsequent tests
6. **Custom Transaction Builders**: Support for custom DEX interactions

## Troubleshooting

### Common Issues

**Issue**: `Failed to initialize simulation engine`
- **Solution**: Check RPC URL is accessible and has archive data

**Issue**: `Buy transaction failed`
- **Solution**: Token may lack liquidity or use different router

**Issue**: `Sell transaction failed`
- **Solution**: This is expected for honeypots; check risk factors

**Issue**: High memory usage
- **Solution**: Clean up engine instances after use; limit concurrent simulations

## Contributing

When extending the fork simulation engine:

1. Maintain backward compatibility with existing honeypot detector
2. Add comprehensive tests for new features
3. Update this README with new functionality
4. Consider performance implications of changes
5. Handle errors gracefully with meaningful messages

## License

This implementation follows the same license as the parent project.