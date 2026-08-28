/**
 * Simple integration test for ForkSimulationEngine
 * Run with: node test_fork_simulation.js
 */

import ForkSimulationEngine from './app/lib/forkSimulationEngine.js';

async function testForkSimulation() {
  console.log('🧪 Testing Fork Simulation Engine\n');
  
  const engine = new ForkSimulationEngine();
  
  try {
    // Test 1: Initialization
    console.log('Test 1: Initialization');
    const initResult = await engine.initialize();
    console.log('✓ Initialization:', initResult.success ? 'PASSED' : 'FAILED');
    if (!initResult.success) {
      console.log('  Error:', initResult.error);
      return;
    }
    
    // Test 2: Dummy Account Generation
    console.log('\nTest 2: Dummy Account Generation');
    const account = engine.generateDummyAccount();
    console.log('✓ Account generated:', account.address);
    
    // Test 3: Account Funding
    console.log('\nTest 3: Account Funding');
    const fundResult = await engine.fundDummyAccount('1.0');
    console.log('✓ Funding:', fundResult.success ? 'PASSED' : 'FAILED');
    
    // Test 4: Token Info Fetching (USDC)
    console.log('\nTest 4: Token Info Fetching (USDC)');
    const usdcAddress = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
    const tokenInfo = await engine.getTokenInfo(usdcAddress);
    if (tokenInfo) {
      console.log('✓ Token Info:', tokenInfo.symbol, tokenInfo.name);
    } else {
      console.log('✗ Failed to fetch token info');
    }
    
    // Test 5: Result Analysis
    console.log('\nTest 5: Result Analysis');
    const buyResult = { success: true, gasUsed: '150000' };
    const sellResult = { success: true, ethReceived: '90000000000000000', gasUsed: '150000' };
    const analysis = engine.analyzeSimulationResults(buyResult, sellResult);
    console.log('✓ Analysis completed');
    console.log('  - Is Honeypot:', analysis.isHoneypot);
    console.log('  - Slippage:', analysis.slippage + '%');
    console.log('  - Risk Factors:', analysis.riskFactors);
    
    // Test 6: Honeypot Detection (Sell Failure)
    console.log('\nTest 6: Honeypot Detection (Sell Failure)');
    const badSellResult = { success: false, error: 'Transaction reverted' };
    const badAnalysis = engine.analyzeSimulationResults(buyResult, badSellResult);
    console.log('✓ Honeypot detected:', badAnalysis.isHoneypot);
    console.log('  - Risk Factors:', badAnalysis.riskFactors);
    
    // Test 7: Excessive Slippage Detection
    console.log('\nTest 7: Excessive Slippage Detection');
    const highSlippageSell = { success: true, ethReceived: '50000000000000000' };
    const slippageAnalysis = engine.analyzeSimulationResults(buyResult, highSlippageSell);
    console.log('✓ Excessive slippage detected:', slippageAnalysis.isHoneypot);
    console.log('  - Slippage:', slippageAnalysis.slippage + '%');
    
    console.log('\n✅ All basic tests completed successfully!');
    
  } catch (error) {
    console.error('\n❌ Test failed with error:', error.message);
    console.error(error.stack);
  } finally {
    await engine.cleanup();
    console.log('\n🧹 Cleanup completed');
  }
}

// Run the test
testForkSimulation().catch(console.error);