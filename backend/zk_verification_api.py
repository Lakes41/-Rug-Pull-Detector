"""
Zero-Knowledge Verification Analysis API
FastAPI endpoint for ZK verification contract analysis.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
from zk_verification_analyzer import (
    ZKVerificationAnalyzer, 
    ZKRiskType, 
    ShieldedPoolInfo,
    analyze_zk_contract
)
from rate_limiter import RateLimiter, RateLimitMiddleware


app = FastAPI(title="Zero-Knowledge Verification Analysis API")

# Initialize rate limiter: 10 requests per second, 100 burst capacity
rate_limiter = RateLimiter(rate=10.0, capacity=100)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)


class ShieldedPoolInfoRequest(BaseModel):
    contract_id: str
    total_shielded: int
    commitment_tree_depth: int
    recent_proof_count: int
    verification_enabled: bool


class ZKVerificationRequest(BaseModel):
    contractId: str
    bytecode: Optional[str] = None
    shieldedPoolInfo: Optional[ShieldedPoolInfoRequest] = None
    transactionData: Optional[Dict] = None


class ZKVerificationResponse(BaseModel):
    contractId: str
    bytecode_analysis: Dict
    risks: List[Dict]
    shielded_pool_risks: List[Dict]
    privacy_risk_level: str
    recommendations: List[str]
    disclosure: str


class ZKTransactionAuditRequest(BaseModel):
    contractId: str
    new_root: str
    proof_hash: str
    nullifiers: List[str]
    block: int
    proof_verified: bool = False


class ZKTransactionAuditResponse(BaseModel):
    contractId: str
    transaction_audited: bool
    risks_detected: int
    risks: List[Dict]
    commitment_state: Optional[Dict]


# Initialize analyzer
zk_analyzer = ZKVerificationAnalyzer()


@app.post("/api/zk-verification-analyze", response_model=ZKVerificationResponse)
async def analyze_zk_verification(request: ZKVerificationRequest):
    """
    Analyze ZK verification contract for privacy risks
    
    Args:
        request: ZKVerificationRequest with contractId, optional bytecode, shieldedPoolInfo, and transactionData
        
    Returns:
        ZKVerificationResponse with privacy risk analysis results
    """
    try:
        # Convert shielded pool info if provided
        pool_info = None
        if request.shieldedPoolInfo:
            pool_info = ShieldedPoolInfo(
                contract_id=request.shieldedPoolInfo.contract_id,
                total_shielded=request.shieldedPoolInfo.total_shielded,
                commitment_tree_depth=request.shieldedPoolInfo.commitment_tree_depth,
                recent_proof_count=request.shieldedPoolInfo.recent_proof_count,
                verification_enabled=request.shieldedPoolInfo.verification_enabled
            )
        
        # Analyze contract
        analysis_result = zk_analyzer.analyze_contract(
            request.contractId,
            request.bytecode or "0x",
            pool_info
        )
        
        # Format risks for response
        formatted_risks = []
        for risk in analysis_result["risks"]:
            formatted_risks.append({
                "contract_id": risk.contract_id,
                "risk_type": risk.risk_type.value,
                "description": risk.description,
                "severity": risk.severity,
                "affected_functions": risk.affected_functions,
                "technical_details": risk.technical_details
            })
        
        # Format shielded pool risks
        formatted_pool_risks = []
        for risk in analysis_result["shielded_pool_risks"]:
            formatted_pool_risks.append({
                "contract_id": risk.contract_id,
                "risk_type": risk.risk_type.value,
                "description": risk.description,
                "severity": risk.severity,
                "technical_details": risk.technical_details
            })
        
        # Generate disclosure
        disclosure = zk_analyzer.generate_privacy_disclosure(analysis_result)
        
        return ZKVerificationResponse(
            contractId=request.contractId,
            bytecode_analysis=analysis_result["bytecode_analysis"],
            risks=formatted_risks,
            shielded_pool_risks=formatted_pool_risks,
            privacy_risk_level=analysis_result["privacy_risk_level"],
            recommendations=analysis_result["recommendations"],
            disclosure=disclosure
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/zk-transaction-audit", response_model=ZKTransactionAuditResponse)
async def audit_zk_transaction(request: ZKTransactionAuditRequest):
    """
    Audit a ZK transaction for commitment tree state update integrity
    
    Args:
        request: ZKTransactionAuditRequest with transaction details
        
    Returns:
        ZKTransactionAuditResponse with audit results
    """
    try:
        # Prepare transaction data
        transaction_data = {
            "new_root": request.new_root,
            "proof_hash": request.proof_hash,
            "nullifiers": request.nullifiers,
            "block": request.block,
            "proof_verified": request.proof_verified
        }
        
        # Audit transaction
        audit_result = zk_analyzer.audit_transaction(
            request.contractId,
            transaction_data
        )
        
        # Format risks for response (risks are already formatted as dicts from analyzer)
        formatted_risks = audit_result["risks"]
        
        # Format commitment state (already formatted as dict from analyzer)
        commitment_state = audit_result.get("commitment_state")
        
        return ZKTransactionAuditResponse(
            contractId=request.contractId,
            transaction_audited=audit_result["transaction_audited"],
            risks_detected=audit_result["risks_detected"],
            risks=formatted_risks,
            commitment_state=commitment_state
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "zk-verification-analyzer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)