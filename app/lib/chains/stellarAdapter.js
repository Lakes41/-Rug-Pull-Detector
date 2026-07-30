import { Horizon } from 'stellar-sdk';
import { BaseChainAdapter } from './baseAdapter';
import {
  NormalizedRiskInput,
  NormalizedTokenData,
  NormalizedAccountData,
  NormalizedTransactionData,
  NormalizedTrustlineData,
  NormalizedIssuanceData,
  NormalizedContractData,
  CHAIN_IDS,
} from './types';

const HORIZON_URL = 'https://horizon.stellar.org';
const SOROBAN_RPC_URL = 'https://soroban-rpc.stellar.org';

export class StellarAdapter extends BaseChainAdapter {
  constructor() {
    super(CHAIN_IDS.STELLAR);
    this.horizonServer = new Horizon.Server(HORIZON_URL);
  }

  /**
   * Connect to Stellar network (no direct wallet connection needed for analysis,
   * but we keep the interface consistent for future wallet support)
   */
  async connect() {
    return {
      connected: true,
      chainId: this.chainId,
      network: 'Public',
    };
  }

  async disconnect() {
    return;
  }

  async rpcRequest(method, params) {
    const response = await fetch(SOROBAN_RPC_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: `${method}-${Date.now()}`,
        method,
        params,
      }),
      cache: 'no-store',
    });

    if (!response.ok) {
      throw new Error(`Soroban RPC request failed with status ${response.status}`);
    }

    const payload = await response.json();

    if (payload.error) {
      throw new Error(payload.error.message || `Soroban RPC ${method} failed`);
    }

    return payload.result;
  }

  /**
   * Parse Stellar asset code:issuer string
   */
  parseAssetString(assetString) {
    if (assetString === 'XLM') {
      return { code: 'XLM', issuer: null, native: true };
    }

    if (/^C[A-Z0-9]{10,}$/.test(assetString)) {
      return {
        code: assetString,
        issuer: null,
        native: false,
        contractId: assetString,
        isSorobanContract: true,
      };
    }

    const [code, issuer] = assetString.split(':');
    return {
      code,
      issuer,
      native: false,
      contractId: null,
      isSorobanContract: false,
    };
  }

  /**
   * Get token/asset data (Stellar-specific)
   * @param {string} assetString - Asset in "Code:Issuer" format, or "XLM"
   */
  async getTokenData(assetString) {
    const asset = this.parseAssetString(assetString);

    if (asset.native) {
      return new NormalizedTokenData({
        address: 'XLM',
        symbol: 'XLM',
        name: 'Lumen',
        decimals: 7,
        issuer: null,
        totalSupply: 50000000000, // approximate total XLM supply (circulating)
        createdAt: '2014-07-31',
        chainId: this.chainId,
      });
    }

    if (asset.isSorobanContract) {
      const contractData = await this.getSorobanContractData(asset.contractId);

      return new NormalizedTokenData({
        address: asset.contractId,
        symbol: 'SOROBAN',
        name: `Soroban Contract ${asset.contractId.slice(0, 8)}`,
        decimals: 7,
        issuer: null,
        totalSupply: 0,
        createdAt: null,
        chainId: this.chainId,
        contractData,
      });
    }

    try {
      // Find asset on Stellar network
      const assets = await this.horizonServer
        .assets()
        .forCode(asset.code)
        .forIssuer(asset.issuer)
        .call();

      if (!assets.records.length) {
        throw new Error(`Asset ${assetString} not found`);
      }

      const stellarAsset = assets.records[0];

      return new NormalizedTokenData({
        address: assetString,
        symbol: stellarAsset.asset_code,
        name: stellarAsset.asset_code,
        decimals: 7,
        issuer: stellarAsset.asset_issuer,
        totalSupply: Number(stellarAsset.amount || 0),
        createdAt: null, // Stellar doesn't expose asset creation time via Horizon directly
        chainId: this.chainId,
      });
    } catch (error) {
      console.error('Error fetching Stellar token data:', error);
      throw error;
    }
  }

  async getTrustlineData(accountId, assetFilter = null) {
    const account = await this.horizonServer.accounts().accountId(accountId).call();

    return account.balances
      .filter((balance) => balance.asset_type !== 'native')
      .filter((balance) => {
        if (!assetFilter) {
          return true;
        }

        return (
          balance.asset_code === assetFilter.code &&
          balance.asset_issuer === assetFilter.issuer
        );
      })
      .map(
        (balance) =>
          new NormalizedTrustlineData({
            assetCode: balance.asset_code,
            assetIssuer: balance.asset_issuer,
            limit: Number(balance.limit),
            balance: Number(balance.balance),
            authorized: balance.is_authorized,
            chainId: this.chainId,
          })
      );
  }

  async getAssetIssuanceData(assetString) {
    const asset = this.parseAssetString(assetString);

    if (asset.native || !asset.issuer) {
      return new NormalizedIssuanceData({
        assetCode: asset.code,
        assetIssuer: asset.issuer,
        issuedAmount: 0,
        distributionCount: 0,
        firstIssuedAt: null,
        lastIssuedAt: null,
        chainId: this.chainId,
      });
    }

    const operations = await this.horizonServer
      .operations()
      .forAccount(asset.issuer)
      .limit(200)
      .order('desc')
      .call();

    const issuanceOperations = operations.records.filter((operation) => {
      const matchesAsset =
        operation.asset_code === asset.code &&
        operation.asset_issuer === asset.issuer;

      return (
        matchesAsset &&
        (operation.type === 'payment' ||
          operation.type === 'path_payment_strict_send' ||
          operation.type === 'path_payment_strict_receive')
      );
    });

    const issuedAmount = issuanceOperations.reduce((sum, operation) => {
      return sum + Number(operation.amount || 0);
    }, 0);

    const sortedByDate = [...issuanceOperations].sort((left, right) => {
      return new Date(left.created_at).getTime() - new Date(right.created_at).getTime();
    });

    return new NormalizedIssuanceData({
      assetCode: asset.code,
      assetIssuer: asset.issuer,
      issuedAmount,
      distributionCount: issuanceOperations.length,
      firstIssuedAt: sortedByDate[0]?.created_at || null,
      lastIssuedAt: sortedByDate.at(-1)?.created_at || null,
      chainId: this.chainId,
    });
  }

  normalizeSorobanEvent(event) {
    return new NormalizedTransactionData({
      hash: event.txHash || `${event.ledger}-${event.id || 'event'}`,
      from: event.contractId || null,
      to: null,
      value: null,
      timestamp: Number(event.ledgerClosedAt || 0),
      type: `soroban_${event.type || 'event'}`,
      chainId: this.chainId,
      raw: event,
    });
  }

  async getSorobanContractData(contractId) {
    try {
      const latestLedger = await this.rpcRequest('getLatestLedger', {});
      const startLedger = Math.max(Number(latestLedger.sequence || 0) - 2000, 1);
      const events = await this.rpcRequest('getEvents', {
        startLedger,
        filters: [
          {
            type: 'contract',
            contractIds: [contractId],
          },
        ],
        pagination: {
          limit: 50,
        },
      });

      const normalizedEvents = (events.events || []).map((event) =>
        this.normalizeSorobanEvent(event)
      );

      return new NormalizedContractData({
        contractId,
        eventCount: normalizedEvents.length,
        latestLedger: Number(latestLedger.sequence || 0),
        transactions: normalizedEvents,
        metadata: {
          latestLedgerCloseTime: latestLedger.protocolVersion || null,
        },
        chainId: this.chainId,
      });
    } catch (_error) {
      return new NormalizedContractData({
        contractId,
        eventCount: 0,
        latestLedger: null,
        transactions: [],
        metadata: {
          unavailable: true,
        },
        chainId: this.chainId,
      });
    }
  }

  /**
   * Get account data including balances, trustlines, etc.
   * @param {string} accountId - Stellar public key (G...)
   */
  async getAccountData(accountId) {
    try {
      const account = await this.horizonServer
        .accounts()
        .accountId(accountId)
        .call();

      // Parse balances to normalized format
      const balances = account.balances.map((balance) => ({
        assetCode: balance.asset_code || 'XLM',
        assetIssuer: balance.asset_issuer || null,
        balance: Number(balance.balance),
        buyingLiabilities: Number(balance.buying_liabilities),
        sellingLiabilities: Number(balance.selling_liabilities),
      }));

      // Parse trustlines (non-native balances are trustlines)
      const trustlines = await this.getTrustlineData(accountId);

      // Get transaction history
      const transactions = await this.getTransactionHistory(accountId);

      return new NormalizedAccountData({
        address: accountId,
        balances,
        trustlines,
        transactions,
        chainId: this.chainId,
      });
    } catch (error) {
      console.error('Error fetching Stellar account data:', error);
      throw error;
    }
  }

  /**
   * Get transaction history for an account
   * @param {string} accountId
   */
  async getTransactionHistory(accountId) {
    try {
      const result = await this.horizonServer
        .transactions()
        .forAccount(accountId)
        .limit(50)
        .order('desc')
        .call();

      return result.records.map(
        (tx) =>
          new NormalizedTransactionData({
            hash: tx.hash,
            from: tx.source_account,
            to: null, // Stellar transactions have multiple operations, not just 1:1
            value: null,
            timestamp: new Date(tx.created_at).getTime(),
            type: 'stellar_transaction',
            chainId: this.chainId,
            raw: tx,
          })
      );
    } catch (error) {
      console.error('Error fetching Stellar transaction history:', error);
      throw error;
    }
  }

  /**
   * Analyze risk for a Stellar asset
   * @param {string} assetString - Asset in Code:Issuer format
   * @param {object} overrides - Manual overrides for risk inputs
   */
  async analyzeRiskForToken(assetString, overrides = {}) {
    const tokenData = await this.getTokenData(assetString);
    let issuerData = null;
    let issuanceData = null;
    let contractData = null;

    if (tokenData.address.startsWith('C')) {
      contractData = await this.getSorobanContractData(tokenData.address);
    } else if (tokenData.issuer) {
      issuerData = await this.getAccountData(tokenData.issuer);
      issuanceData = await this.getAssetIssuanceData(assetString);
      contractData = await this.getSorobanContractData(tokenData.issuer);
    }

    // Calculate reasonable defaults for risk inputs
    const defaults = {
      tokenAddress: tokenData.address,
      tokenSymbol: tokenData.symbol,
      totalSupply: tokenData.totalSupply,
      creatorBalance: issuerData
        ? this._getIssuerBalanceForAsset(issuerData, tokenData)
        : 0,
      lockedLiquidity: this._estimateLockedLiquidity(issuerData),
      totalLiquidity: this._estimateTotalLiquidity(issuerData),
      isPotentialHoneypot: this._detectHoneypotSignals(
        tokenData,
        issuerData,
        issuanceData,
        contractData
      ),
    };

    const inputs = { ...defaults, ...overrides };

    return new NormalizedRiskInput({
      ...inputs,
      chainId: this.chainId,
      rawChainData: {
        tokenData,
        issuerData,
        issuanceData,
        contractData,
      },
    });
  }

  /**
   * Helper: Get how much of their own asset the issuer still holds
   */
  _getIssuerBalanceForAsset(issuerAccount, tokenData) {
    const balance = issuerAccount.balances.find(
      (b) =>
        b.assetCode === tokenData.symbol && b.assetIssuer === tokenData.issuer
    );
    return balance ? balance.balance : 0;
  }

  _estimateLockedLiquidity(issuerData) {
    if (!issuerData) {
      return 0;
    }

    return issuerData.trustlines
      .filter((trustline) => trustline.authorized === true)
      .reduce((sum, trustline) => sum + Number(trustline.balance || 0), 0);
  }

  _estimateTotalLiquidity(issuerData) {
    if (!issuerData) {
      return 0;
    }

    return issuerData.trustlines.reduce(
      (sum, trustline) => sum + Number(trustline.balance || 0),
      0
    );
  }

  _detectHoneypotSignals(tokenData, issuerData, issuanceData, contractData) {
    const issuerBalance = issuerData
      ? this._getIssuerBalanceForAsset(issuerData, tokenData)
      : 0;
    const issuerOwnershipRatio =
      tokenData.totalSupply > 0 ? issuerBalance / tokenData.totalSupply : 0;
    const hasNoDistribution = (issuanceData?.distributionCount || 0) <= 1;
    const hasNoContractActivity = contractData && contractData.eventCount === 0;

    return issuerOwnershipRatio > 0.8 || hasNoDistribution || Boolean(hasNoContractActivity);
  }

  /**
   * Analyze Soroban contract authorization risks
   * @param {string} contractId - Soroban contract ID (starts with C...)
   * @param {string} transactionHash - Optional transaction hash to analyze
   */
  async analyzeSorobanAuthorization(contractId, transactionHash = null) {
    try {
      // Call backend API for Soroban authorization analysis
      const response = await fetch('/api/soroban-auth-analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contractId,
          transactionHash,
        }),
      });

      if (!response.ok) {
        throw new Error(`Soroban auth analysis failed with status ${response.status}`);
      }

      const result = await response.json();
      return {
        success: true,
        contractId,
        riskScore: result.riskScore || 0,
        riskLevel: result.riskLevel || 'UNKNOWN',
        riskVectors: result.riskVectors || [],
        executionGraph: result.executionGraph || null,
        report: result.report || null,
      };
    } catch (error) {
      console.error('Error analyzing Soroban authorization:', error);
      return {
        success: false,
        contractId,
        error: error.message,
      };
    }
  }

  /**
   * Enhanced risk analysis for Soroban contracts including authorization checks
   * @param {string} assetString - Asset string for Soroban contract
   */
  async analyzeSorobanContractRisk(assetString) {
    const asset = this.parseAssetString(assetString);

    if (!asset.isSorobanContract) {
      throw new Error('Asset is not a Soroban contract');
    }

    // Get basic token data
    const tokenData = await this.getTokenData(assetString);
    const contractData = await this.getSorobanContractData(asset.contractId);

    // Perform authorization analysis
    const authAnalysis = await this.analyzeSorobanAuthorization(asset.contractId);

    // Combine risks
    const baseRisk = await this.analyzeRiskForToken(assetString);
    const authRiskScore = authAnalysis.success ? authAnalysis.riskScore : 0;

    // Calculate combined risk score
    const combinedRiskScore = Math.max(
      baseRisk.isPotentialHoneypot ? 0.8 : 0.3,
      authRiskScore
    );

    return {
      ...baseRisk,
      authAnalysis,
      combinedRiskScore,
      riskLevel: this._getRiskLevelFromScore(combinedRiskScore),
    };
  }

  _getRiskLevelFromScore(score) {
    if (score >= 0.8) return 'CRITICAL';
    if (score >= 0.6) return 'HIGH';
    if (score >= 0.4) return 'MEDIUM';
    return 'LOW';
  }
}

export const stellarAdapter = new StellarAdapter();
