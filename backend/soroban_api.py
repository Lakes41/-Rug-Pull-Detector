"""
Soroban Authorization Analysis API
FastAPI endpoint for Soroban contract authorization analysis.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
from soroban_auth_analyzer import SorobanAuthAnalyzer, AuthRiskType
from soroban_integration import SorobanContractAnalyzer, SorobanRiskEvaluator
from rate_limiter import RateLimiter, RateLimitMiddleware
import asyncio


app = FastAPI(title="Soroban Authorization Analysis API")

# Initialize rate limiter: 10 requests per second, 100 burst capacity
rate_limiter = RateLimiter(rate=10.0, capacity=100)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)


class SorobanAuthRequest(BaseModel):
    contractId: str
    transactionHash: Optional[str] = None


class SorobanAuthResponse(BaseModel):
    contractId: str
    riskScore: float
    riskLevel: str
    riskVectors: List[Dict]
    executionGraph: Optional[Dict]
    report: str


auth_analyzer = SorobanAuthAnalyzer()
contract_analyzer = SorobanContractAnalyzer()
risk_evaluator = SorobanRiskEvaluator()


@app.post("/api/soroban-auth-analyze", response_model=SorobanAuthResponse)
async def analyze_soroban_auth(request: SorobanAuthRequest):
    """
    Analyze Soroban contract authorization risks
    
    Args:
        request: SorobanAuthRequest with contractId and optional transactionHash
        
    Returns:
        SorobanAuthResponse with risk analysis results
    """
    try:
        # If transaction hash is provided, analyze actual transaction
        if request.transactionHash:
            analysis_result = await contract_analyzer.analyze_contract_by_transaction(
                request.transactionHash
            )
        else:
            # For contract-only analysis, we would need to fetch recent transactions
            # For now, return a placeholder analysis
            analysis_result = {
                "footprint": {
                    "contract_id": request.contractId,
                    "read": [],
                    "write": [],
                    "auth": []
                },
                "invocation_tree": {
                    "root": {
                        "contract_id": request.contractId,
                        "function_name": "unknown",
                        "auth_required": False,
                        "signature_verified": True,
                        "host_checks": [],
                        "sub_invocations": []
                    }
                }
            }
            
            # Run through auth analyzer
            analysis_result = auth_analyzer.analyze_transaction(analysis_result)
        
        # Calculate risk score
        risk_score = risk_evaluator.calculate_risk_score(analysis_result)
        risk_level = risk_evaluator.get_risk_level(risk_score)
        
        # Format risk vectors for response
        risk_vectors = []
        for vector in analysis_result.get("risk_vectors", []):
            risk_vectors.append({
                "contractId": vector.contract_id,
                "functionName": vector.function_name,
                "riskType": vector.risk_type.value,
                "description": vector.description,
                "severity": vector.severity,
                "affectedContracts": vector.affected_contracts
            })
        
        # Build execution graph
        execution_graph = None
        if analysis_result.get("execution_nodes"):
            nodes = [
                {"contractId": cid, "functionName": node.function_name}
                for cid, node in analysis_result["execution_nodes"].items()
            ]
            edges = [
                {
                    "from": edge.from_contract,
                    "to": edge.to_contract,
                    "type": edge.invocation_type
                }
                for edge in auth_analyzer.dag_builder.edges
            ]
            execution_graph = {"nodes": nodes, "edges": edges}
        
        # Generate report
        report = auth_analyzer.generate_report(analysis_result)
        
        return SorobanAuthResponse(
            contractId=request.contractId,
            riskScore=risk_score,
            riskLevel=risk_level,
            riskVectors=risk_vectors,
            executionGraph=execution_graph,
            report=report
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "soroban-auth-analyzer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
