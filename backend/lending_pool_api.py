"""
Lending Pool Risk Analysis API
FastAPI endpoint for specialized lending pool risk scoring.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
from lending_pool_risk import (
    LendingPoolRiskModifier,
    LendingPoolRiskResult,
    PoolType,
    analyze_lending_pool_risk
)
from rate_limiter import RateLimiter, RateLimitMiddleware


app = FastAPI(title="Lending Pool Risk Analysis API")

# Initialize rate limiter: 10 requests per second, 100 burst capacity
rate_limiter = RateLimiter(rate=10.0, capacity=100)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)


class LendingPoolRiskRequest(BaseModel):
    poolAddress: str
    poolType: str = "standard"
    baseRiskScore: float = 0.3


class LendingPoolRiskResponse(BaseModel):
    poolAddress: str
    poolType: str
    baseRiskScore: float
    modifiedRiskScore: float
    riskLevel: str
    riskFactors: Dict
    detectedAnomalies: List[str]
    recommendations: List[str]


risk_modifier = LendingPoolRiskModifier()


@app.post("/api/lending-pool-risk", response_model=LendingPoolRiskResponse)
async def analyze_lending_pool(request: LendingPoolRiskRequest):
    """
    Analyze lending pool risk with specialized scoring
    
    Args:
        request: LendingPoolRiskRequest with pool details
        
    Returns:
        LendingPoolRiskResponse with modified risk score and factors
    """
    try:
        # Map pool type string to enum
        pool_type_map = {
            "standard": PoolType.STANDARD_LENDING,
            "liquidity": PoolType.LIQUIDITY_POOL,
            "stable": PoolType.STABLE_POOL,
            "yield": PoolType.YIELD_POOL,
            "rwa": PoolType.RWA_TOKENIZED
        }
        
        pool_type = pool_type_map.get(request.poolType, PoolType.STANDARD_LENDING)
        
        # Analyze risk
        result = analyze_lending_pool_risk(
            pool_address=request.poolAddress,
            pool_type=pool_type,
            base_risk_score=request.baseRiskScore
        )
        
        # Format response
        return LendingPoolRiskResponse(
            poolAddress=result.pool_address,
            poolType=result.pool_type.value,
            baseRiskScore=result.base_risk_score,
            modifiedRiskScore=result.modified_risk_score,
            riskLevel=result.risk_level,
            riskFactors={
                "tvlAnomalyScore": result.risk_factors.tvl_anomaly_score,
                "infiniteMintRisk": result.risk_factors.infinite_mint_risk,
                "oracleManipulationRisk": result.risk_factors.oracle_manipulation_risk,
                "collateralWithdrawalRisk": result.risk_factors.collateral_withdrawal_risk,
                "tvlVolatility": result.risk_factors.tvl_volatility,
                "liquidityUtilization": result.risk_factors.liquidity_utilization,
                "collateralRatio": result.risk_factors.collateral_ratio,
            },
            detectedAnomalies=result.detected_anomalies,
            recommendations=result.recommendations
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "lending-pool-risk-analyzer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
