# RiskRegistry Smart Contract

## Overview

The RiskRegistry is a decentralized on-chain registry contract for risk assessment with staking, verification, and dispute resolution mechanisms. It eliminates centralized points of failure in risk assessment publication by using economic bonding mechanisms.

## Features

### 1. Oracle Registration & Staking
- Security oracles must stake a minimum bond (default: 10 ETH) to participate
- Oracles can add additional stake to increase their credibility
- Stakes are slashed for false reports
- Oracles can unstake after a cooldown period (if no active slashes)

### 2. Risk Assertion Submission
- Oracles submit cryptographically signed risk assertions
- Each assertion includes:
  - Target contract address
  - Risk score (0-100, higher = riskier)
  - Oracle's signature
  - Timestamp
- Signature verification ensures authenticity

### 3. Dispute Resolution Window
- 7-day window for third-party security researchers to challenge assertions
- Disputers must post a bond (default: 5 ETH)
- Only authorized disputers can initiate challenges

### 4. Slashing & Rewards
- If a dispute is successful:
  - Oracle's stake is slashed (80% of stake)
  - 90% of slashed amount goes to the successful disputer
  - 10% goes to protocol reserves
  - Disputer's bond is also returned
- If a dispute fails:
  - Disputer's bond is returned
  - Assertion is re-verified

### 5. Protocol Reserves
- Accumulated from dispute resolution fees
- Can be withdrawn by admin for emergency use
- Used to fund protocol development and incentives

## Contract Architecture

### Roles
- **DEFAULT_ADMIN_ROLE**: Can manage all roles and protocol parameters
- **ADMIN_ROLE**: Can resolve disputes, manage oracles, and withdraw reserves
- **ORACLE_ROLE**: Authorized to submit risk assertions
- **DISPUTER_ROLE**: Authorized to challenge assertions

### Key Data Structures

```solidity
struct RiskAssertion {
    address targetContract;
    uint256 riskScore;
    uint256 timestamp;
    address oracle;
    bool disputed;
    bool verified;
    uint256 disputeDeadline;
    bytes32 assertionHash;
}

struct OracleStake {
    uint256 amount;
    uint256 slashCount;
    bool active;
}

struct Dispute {
    uint256 assertionId;
    address challenger;
    uint256 bondAmount;
    uint256 timestamp;
    bool resolved;
    bool successful;
}
```

## Deployment

### Prerequisites
```bash
npm install
```

### Environment Variables
Create a `.env` file:
```
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID
PRIVATE_KEY=your_private_key
ETHERSCAN_API_KEY=your_etherscan_api_key
```

### Compile Contracts
```bash
npm run compile
```

### Run Tests
```bash
npm run test:contracts
```

### Deploy to Local Network
```bash
npm run deploy -- --network hardhat
```

### Deploy to Sepolia Testnet
```bash
npm run deploy -- --network sepolia
```

## Usage Examples

### Register an Oracle
```javascript
await riskRegistry.registerOracle(oracleAddress, stakeAmount);
```

### Submit a Risk Assertion
```javascript
const messageHash = ethers.solidityPackedKeccak256(
    ["address", "uint256", "uint256"],
    [targetContract, riskScore, timestamp]
);
const signature = await oracle.signMessage(ethers.getBytes(messageHash));

await riskRegistry.submitRiskAssertion(targetContract, riskScore, signature);
```

### Initiate a Dispute
```javascript
await riskRegistry.connect(disputer).initiateDispute(assertionId);
```

### Resolve a Dispute
```javascript
await riskRegistry.resolveDispute(disputeId, successful);
```

## Security Considerations

1. **Signature Verification**: All assertions must be signed by authorized oracles
2. **Reentrancy Protection**: Uses OpenZeppelin's ReentrancyGuard
3. **Access Control**: Role-based permissions for sensitive operations
4. **Economic Security**: Bonding mechanisms align incentives
5. **Time Windows**: Disputes must be initiated within 7 days

## Testing

The test suite covers:
- Oracle registration and staking
- Risk assertion submission with signature verification
- Dispute initiation and resolution
- Slashing mechanics
- Protocol reserve management
- Edge cases and error conditions

Run tests with:
```bash
npm run test:contracts
```

## Future Enhancements

- Multi-signature oracle committees
- On-chain governance for parameter changes
- Integration with prediction markets
- Cross-chain support
- Automated dispute resolution via Kleros
- Reputation system for oracles
