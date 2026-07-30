"""
Soroban Integration Module
Integrates Soroban authorization analysis with the existing stellar adapter infrastructure.
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional
from soroban_auth_analyzer import SorobanAuthAnalyzer, analyze_soroban_contract


class SorobanRPCClient:
    """Client for interacting with Soroban RPC endpoints"""
    
    def __init__(self, rpc_url: str = "https://soroban-rpc.stellar.org"):
        self.rpc_url = rpc_url
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def rpc_request(self, method: str, params: Dict = None) -> Dict:
        """
        Make a JSON-RPC request to Soroban
        
        Args:
            method: RPC method name
            params: Method parameters
            
        Returns:
            RPC response result
        """
        if not self.session:
            raise RuntimeError("SorobanRPCClient must be used as async context manager")
        
        payload = {
            "jsonrpc": "2.0",
            "id": f"{method}-{asyncio.get_event_loop().time()}",
            "method": method,
            "params": params or {}
        }
        
        async with self.session.post(
            self.rpc_url,
            json=payload,
            headers={"Content-Type": "application/json"}
        ) as response:
            if not response.ok:
                raise Exception(f"RPC request failed: {response.status}")
            
            data = await response.json()
            
            if "error" in data:
                raise Exception(f"RPC error: {data['error']}")
            
            return data.get("result", {})
    
    async def get_transaction(self, tx_hash: str) -> Dict:
        """Get transaction details by hash"""
        return await self.rpc_request("getTransaction", {"hash": tx_hash})
    
    async def get_ledger_entries(self, keys: List[str]) -> Dict:
        """Get ledger entries by keys"""
        return await self.rpc_request("getLedgerEntries", {"keys": keys})
    
    async def simulate_transaction(self, transaction: str) -> Dict:
        """
        Simulate a transaction to get invocation tree and footprint
        
        Args:
            transaction: Base64-encoded XDR transaction
            
        Returns:
            Simulation result with footprint and invocation data
        """
        return await self.rpc_request("simulateTransaction", {
            "transaction": transaction
        })


class SorobanContractAnalyzer:
    """High-level analyzer for Soroban contracts"""
    
    def __init__(self, rpc_url: str = "https://soroban-rpc.stellar.org"):
        self.rpc_url = rpc_url
        self.auth_analyzer = SorobanAuthAnalyzer()
    
    async def analyze_contract_by_transaction(self, tx_hash: str) -> Dict:
        """
        Analyze a Soroban contract by analyzing a transaction
        
        Args:
            tx_hash: Transaction hash to analyze
            
        Returns:
            Complete analysis including authorization risks
        """
        async with SorobanRPCClient(self.rpc_url) as client:
            # Get transaction details
            tx_data = await client.get_transaction(tx_hash)
            
            # Extract footprint and invocation data from transaction result
            transaction_trace = self._extract_trace_from_transaction(tx_data)
            
            # Analyze authorization risks
            auth_analysis = self.auth_analyzer.analyze_transaction(transaction_trace)
            
            return {
                "transaction_hash": tx_hash,
                "transaction_data": tx_data,
                "authorization_analysis": auth_analysis,
                "risk_report": self.auth_analyzer.generate_report(auth_analysis)
            }
    
    async def analyze_contract_by_simulation(self, transaction_xdr: str) -> Dict:
        """
        Analyze a Soroban contract by simulating a transaction
        
        Args:
            transaction_xdr: Base64-encoded XDR transaction to simulate
            
        Returns:
            Complete analysis including authorization risks
        """
        async with SorobanRPCClient(self.rpc_url) as client:
            # Simulate transaction
            simulation_result = await client.simulate_transaction(transaction_xdr)
            
            # Extract footprint and invocation data from simulation
            transaction_trace = self._extract_trace_from_simulation(simulation_result)
            
            # Analyze authorization risks
            auth_analysis = self.auth_analyzer.analyze_transaction(transaction_trace)
            
            return {
                "simulation_result": simulation_result,
                "authorization_analysis": auth_analysis,
                "risk_report": self.auth_analyzer.generate_report(auth_analysis)
            }
    
    def _extract_trace_from_transaction(self, tx_data: Dict) -> Dict:
        """
        Extract footprint and invocation tree from transaction data
        
        Args:
            tx_data: Raw transaction data from RPC
            
        Returns:
            Formatted trace for auth analyzer
        """
        result = tx_data.get("result", {})
        meta = tx_data.get("result", {}).get("meta", {})
        
        # Extract footprint from transaction meta
        footprint = self._parse_footprint_from_meta(meta)
        
        # Extract invocation tree from result
        invocation_tree = self._parse_invocation_from_result(result)
        
        return {
            "footprint": footprint,
            "invocation_tree": invocation_tree
        }
    
    def _extract_trace_from_simulation(self, simulation_result: Dict) -> Dict:
        """
        Extract footprint and invocation tree from simulation result
        
        Args:
            simulation_result: Simulation result from RPC
            
        Returns:
            Formatted trace for auth analyzer
        """
        # Simulation results include footprint and invocation data
        footprint = self._parse_footprint_from_simulation(simulation_result)
        invocation_tree = self._parse_invocation_from_simulation(simulation_result)
        
        return {
            "footprint": footprint,
            "invocation_tree": invocation_tree
        }
    
    def _parse_footprint_from_meta(self, meta: Dict) -> Dict:
        """Parse footprint from transaction metadata"""
        # Soroban footprint is in the transaction meta
        # This is a simplified parser - actual implementation depends on XDR structure
        return {
            "contract_id": meta.get("contract_id", "unknown"),
            "read": meta.get("read_entries", []),
            "write": meta.get("write_entries", []),
            "auth": meta.get("auth_entries", [])
        }
    
    def _parse_footprint_from_simulation(self, simulation: Dict) -> Dict:
        """Parse footprint from simulation result"""
        result = simulation.get("result", {})
        return {
            "contract_id": result.get("contract_id", "unknown"),
            "read": result.get("read_entries", []),
            "write": result.get("write_entries", []),
            "auth": result.get("auth_entries", [])
        }
    
    def _parse_invocation_from_result(self, result: Dict) -> Dict:
        """Parse invocation tree from transaction result"""
        # Extract invocation data from result
        return {
            "root": result.get("root_invocation", {}),
            "children": result.get("invocations", [])
        }
    
    def _parse_invocation_from_simulation(self, simulation: Dict) -> Dict:
        """Parse invocation tree from simulation result"""
        result = simulation.get("result", {})
        return {
            "root": result.get("root_invocation", {}),
            "children": result.get("invocations", [])
        }


class SorobanRiskEvaluator:
    """Evaluates Soroban contract risks for rug pull potential"""
    
    def __init__(self):
        self.contract_analyzer = SorobanContractAnalyzer()
    
    async def evaluate_token_pool_risk(self, contract_id: str) -> Dict:
        """
        Evaluate a Soroban token pool for rug pull risks
        
        Args:
            contract_id: Soroban contract ID (starts with C...)
            
        Returns:
            Risk evaluation with authorization analysis
        """
        # For a complete evaluation, we would:
        # 1. Get recent transactions involving the contract
        # 2. Analyze each transaction for authorization risks
        # 3. Build a comprehensive risk profile
        
        # This is a placeholder - in production, you'd fetch actual transactions
        # and analyze them
        
        return {
            "contract_id": contract_id,
            "risk_score": 0,
            "authorization_risks": [],
            "recommendation": "insufficient_data"
        }
    
    def calculate_risk_score(self, auth_analysis: Dict) -> float:
        """
        Calculate overall risk score from authorization analysis
        
        Args:
            auth_analysis: Result from SorobanAuthAnalyzer
            
        Returns:
            Risk score between 0 (safe) and 1 (critical risk)
        """
        critical_risks = auth_analysis.get("critical_risks", 0)
        high_risks = auth_analysis.get("high_risks", 0)
        total_contracts = auth_analysis.get("total_contracts", 1)
        cycles = len(auth_analysis.get("cycles_detected", []))
        
        # Weight different risk factors
        score = 0.0
        
        # Critical risks are most severe
        score += critical_risks * 0.4
        
        # High risks are significant
        score += high_risks * 0.2
        
        # Cycles indicate potential reentrancy or other issues
        score += cycles * 0.15
        
        # Normalize by number of contracts
        score = min(score / total_contracts, 1.0)
        
        return score
    
    def get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score"""
        if risk_score >= 0.7:
            return "CRITICAL"
        elif risk_score >= 0.5:
            return "HIGH"
        elif risk_score >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"


# Convenience function for quick analysis
async def quick_soroban_analysis(tx_hash: str) -> Dict:
    """
    Quick analysis of a Soroban transaction
    
    Args:
        tx_hash: Transaction hash to analyze
        
    Returns:
        Analysis results
    """
    analyzer = SorobanContractAnalyzer()
    return await analyzer.analyze_contract_by_transaction(tx_hash)


if __name__ == "__main__":
    # Example usage
    async def main():
        # Analyze a transaction (would need real transaction hash)
        # result = await quick_soroban_analysis("YOUR_TX_HASH")
        # print(result["risk_report"])
        
        # Or analyze by simulation
        # analyzer = SorobanContractAnalyzer()
        # result = await analyzer.analyze_contract_by_simulation("BASE64_XDR")
        # print(result["risk_report"])
        
        print("Soroban integration module loaded successfully")
    
    asyncio.run(main())
