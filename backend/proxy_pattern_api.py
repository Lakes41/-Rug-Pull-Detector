"""
Proxy Pattern Analysis API
FastAPI endpoint for proxy contract analysis and governance verification.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
from proxy_pattern_analyzer import (
    ProxyPatternAnalyzer,
    ProxyRiskType,
    analyze_proxy_contract
)
from rate_limiter import RateLimiter, RateLimitMiddleware
import asyncio


app = FastAPI(title="Proxy Pattern Analysis API")

# Initialize rate limiter: 10 requests per second, 100 burst capacity
rate_limiter = RateLimiter(rate=10.0, capacity=100)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)


class ProxyAnalysisRequest(BaseModel):
    contractAddress: str
    rpcUrl: Optional[str] = None


class ProxyAnalysisResponse(BaseModel):
    contract_address: str
    is_proxy: bool
    proxy_type: str
    implementation_address: Optional[str]
    admin_address: Optional[str]
    timelock_info: Dict
    risks: List[Dict]
    risk_multiplier: float
    recommendations: List[str]


# Initialize analyzer (without RPC URL - will be provided per request)
proxy_analyzer = None


@app.post("/api/proxy-pattern-analyze", response_model=ProxyAnalysisResponse)
async def analyze_proxy_pattern(request: ProxyAnalysisRequest):
    """
    Analyze a contract for proxy pattern risks and governance verification
    
    Args:
        request: ProxyAnalysisRequest with contractAddress and optional rpcUrl
        
    Returns:
        ProxyAnalysisResponse with proxy analysis results
    """
    try:
        # Create analyzer with provided RPC URL or default
        analyzer = ProxyPatternAnalyzer(rpc_url=request.rpcUrl)
        
        # Analyze contract (now async)
        analysis_result = await analyzer.analyze_proxy_contract(request.contractAddress)
        
        return ProxyAnalysisResponse(
            contract_address=analysis_result["contract_address"],
            is_proxy=analysis_result["is_proxy"],
            proxy_type=analysis_result["proxy_type"],
            implementation_address=analysis_result.get("implementation_address"),
            admin_address=analysis_result.get("admin_address"),
            timelock_info=analysis_result["timelock_info"],
            risks=analysis_result["risks"],
            risk_multiplier=analysis_result["risk_multiplier"],
            recommendations=analysis_result["recommendations"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "proxy-pattern-analyzer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)