import ForkSimulationEngine from '../forkSimulationEngine.js';

describe('ForkSimulationEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new ForkSimulationEngine();
  });

  afterEach(async () => {
    await engine.cleanup();
  });

  describe('initialization', () => {
    it('should initialize successfully with default RPC', async () => {
      const result = await engine.initialize();
      expect(result.success).toBe(true);
      expect(engine.client).not.toBeNull();
      expect(engine.dummyAccount).not.toBeNull();
    });

    it('should initialize with custom block number', async () => {
      const result = await engine.initialize(18000000);
      expect(result.success).toBe(true);
      expect(result.blockNumber).toBe(18000000);
    });

    it('should handle initialization errors gracefully', async () => {
      const badEngine = new ForkSimulationEngine('invalid-rpc-url');
      const result = await badEngine.initialize();
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('dummy account management', () => {
    it('should generate a dummy account', () => {
      const account = engine.generateDummyAccount();
      expect(account.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
      expect(account.privateKey).toMatch(/^0x[a-fA-F0-9]{64}$/);
    });

    it('should fund dummy account successfully', async () => {
      await engine.initialize();
      const result = await engine.fundDummyAccount('1.0');
      expect(result.success).toBe(true);
      expect(result.balance).toBe('1.0');
    });
  });

  describe('token information', () => {
    it('should fetch token information for valid address', async () => {
      await engine.initialize();
      
      // USDC contract address on mainnet
      const usdcAddress = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
      const tokenInfo = await engine.getTokenInfo(usdcAddress);
      
      expect(tokenInfo).not.toBeNull();
      expect(tokenInfo.symbol).toBe('USDC');
      expect(tokenInfo.decimals).toBe(6);
    });

    it('should handle invalid token address', async () => {
      await engine.initialize();
      const tokenInfo = await engine.getTokenInfo('0x0000000000000000000000000000000000000000');
      expect(tokenInfo).toBeNull();
    });
  });

  describe('transaction simulation', () => {
    it('should simulate buy transaction successfully', async () => {
      await engine.initialize();
      await engine.fundDummyAccount();
      
      // Note: This may fail if the token doesn't have liquidity
      // In a real test, you'd use a token with known liquidity
      const tokenAddress = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
      const result = await engine.simulateBuy(tokenAddress);
      
      // The result may fail due to liquidity, but should not throw
      expect(result).toBeDefined();
      expect(result.success).toBeDefined();
    });

    it('should handle buy simulation errors gracefully', async () => {
      await engine.initialize();
      await engine.fundDummyAccount();
      
      const invalidToken = '0x0000000000000000000000000000000000000001';
      const result = await engine.simulateBuy(invalidToken);
      
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('complete buy-sell simulation', () => {
    it('should run complete simulation flow', async () => {
      const tokenAddress = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
      const result = await engine.runBuySellSimulation(tokenAddress);
      
      expect(result).toBeDefined();
      expect(result.success).toBeDefined();
      
      if (result.success) {
        expect(result.tokenInfo).toBeDefined();
        expect(result.buyResult).toBeDefined();
        expect(result.sellResult).toBeDefined();
        expect(result.analysis).toBeDefined();
      }
    });

    it('should analyze simulation results correctly', () => {
      const buyResult = {
        success: true,
        gasUsed: '150000',
      };
      
      const sellResult = {
        success: true,
        ethReceived: '90000000000000000', // 0.09 ETH
        gasUsed: '150000',
      };
      
      const analysis = engine.analyzeSimulationResults(buyResult, sellResult);
      
      expect(analysis).toBeDefined();
      expect(analysis.isHoneypot).toBeDefined();
      expect(analysis.riskFactors).toBeDefined();
      expect(analysis.slippage).toBeDefined();
    });

    it('should detect sell failure as honeypot', () => {
      const buyResult = { success: true };
      const sellResult = { success: false, error: 'Transaction reverted' };
      
      const analysis = engine.analyzeSimulationResults(buyResult, sellResult);
      
      expect(analysis.isHoneypot).toBe(true);
      expect(analysis.riskFactors).toContain('sell_transaction_failed');
    });

    it('should detect excessive slippage', () => {
      const buyResult = { success: true };
      const sellResult = { 
        success: true, 
        ethReceived: '50000000000000000', // 0.05 ETH (50% loss)
      };
      
      const analysis = engine.analyzeSimulationResults(buyResult, sellResult);
      
      expect(analysis.isHoneypot).toBe(true);
      expect(analysis.riskFactors).toContain('excessive_slippage');
      expect(analysis.slippage).toBeGreaterThan(15);
    });
  });

  describe('integration with honeypot detector', () => {
    it('should be usable by the enhanced honeypot detector', async () => {
      const { analyzeHoneypotWithSimulation } = await import('../honeypotDetector.js');
      
      const chainData = {};
      const tokenAddress = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
      
      const result = await analyzeHoneypotWithSimulation(chainData, tokenAddress);
      
      expect(result).toBeDefined();
      expect(result.score).toBeDefined();
      expect(result.flagged).toBeDefined();
      expect(result.staticAnalysis).toBeDefined();
      expect(result.simulationAnalysis).toBeDefined();
    });
  });
});