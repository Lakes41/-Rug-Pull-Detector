import { BaseChainAdapter } from './baseAdapter';
import {
  NormalizedRiskInput,
  NormalizedTokenData,
  NormalizedAccountData,
  CHAIN_IDS,
} from './types';
import { analyzeHoneypotWithSimulation } from '../honeypotDetector.js';

// EVM Adapter - wraps existing EVM functionality into the adapter interface
export class EVMAdapter extends BaseChainAdapter {
  constructor() {
    super(CHAIN_IDS.ETHEREUM);
    this.provider = null;
  }

  async connect(web3Provider = null) {
    // If no provider is passed, we can still do read-only operations via public RPC
    this.provider = web3Provider;
    return {
      connected: !!web3Provider,
      chainId: this.chainId,
    };
  }

  async disconnect() {
    this.provider = null;
  }

  async getAccountData(address) {
    // EVM-specific implementation (placeholder for now)
    return new NormalizedAccountData({
      address,
      balances: [],
      trustlines: [],
      transactions: [],
      chainId: this.chainId,
    });
  }

  async getTokenData(address) {
    // EVM-specific implementation (placeholder for now)
    return new NormalizedTokenData({
      address,
      symbol: '',
      name: '',
      decimals: 18,
      issuer: null,
      totalSupply: 0,
      createdAt: null,
      chainId: this.chainId,
    });
  }

  async getTransactionHistory(address) {
    // EVM-specific implementation (placeholder for now)
    return [];
  }

  async analyzeRiskForToken(tokenAddress, overrides = {}) {
    const defaults = {
      tokenAddress,
      tokenSymbol: '',
      totalSupply: 0,
      creatorBalance: 0,
      lockedLiquidity: 0,
      totalLiquidity: 0,
      isPotentialHoneypot: false,
    };

    const inputs = { ...defaults, ...overrides };

    // Run enhanced honeypot analysis with fork simulation
    const enhancedAnalysis = await analyzeHoneypotWithSimulation(
      inputs.rawChainData || {},
      tokenAddress,
      overrides.routerAddress
    );

    return new NormalizedRiskInput({
      ...inputs,
      chainId: this.chainId,
      rawChainData: {
        ...inputs.rawChainData,
        enhancedAnalysis,
      },
      isPotentialHoneypot: enhancedAnalysis.flagged,
      honeypotScore: enhancedAnalysis.score,
    });
  }
}

export const evmAdapter = new EVMAdapter();

