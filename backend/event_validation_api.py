"""
Event Validation API
FastAPI endpoint for transaction receipt validation and spoofing detection.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
from event_validator import (
    EventSpoofDetector,
    TransactionReceipt,
    EventLog,
    StateChange,
    EventType
)
from validated_scoring import EnhancedRiskAnalyzer
from rate_limiter import RateLimiter, RateLimitMiddleware


app = FastAPI(title="Event Validation API")

# Initialize rate limiter: 10 requests per second, 100 burst capacity
rate_limiter = RateLimiter(rate=10.0, capacity=100)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)


class EventLogRequest(BaseModel):
    address: str
    eventType: str
    topics: List[str]
    data: str
    logIndex: int
    transactionHash: str
    blockNumber: int


class StateChangeRequest(BaseModel):
    address: str
    key: str
    oldValue: Optional[str]
    newValue: Optional[str]
    changeType: str


class TransactionReceiptRequest(BaseModel):
    transactionHash: str
    fromAddress: str
    toAddress: Optional[str]
    contractAddress: Optional[str]
    status: str
    gasUsed: int
    logs: List[EventLogRequest]
    stateChanges: List[StateChangeRequest]
    blockNumber: int


class EventValidationResponse(BaseModel):
    transactionHash: str
    totalEvents: int
    validEvents: int
    spoofedEvents: int
    suspiciousEvents: int
    isLikelySpoofed: bool
    spoofedDetails: List[Dict]
    suspiciousDetails: List[Dict]
    validDetails: List[Dict]


class ValidatedScoringResponse(BaseModel):
    baseRiskScore: float
    rawScore: float
    validatedScore: float
    finalScore: float
    riskLevel: str
    isManipulated: bool
    confidence: str
    spoofedEventCount: int
    totalEventCount: int
    spoofedEventTypes: List[str]
    volumeAdjustment: Dict
    liquidityAdjustment: Dict
    recommendations: List[str]


spoof_detector = EventSpoofDetector()
risk_analyzer = EnhancedRiskAnalyzer()


def _convert_event_log(request: EventLogRequest) -> EventLog:
    """Convert API request to EventLog"""
    event_type_map = {
        "Transfer": EventType.TRANSFER,
        "Approval": EventType.APPROVAL,
        "Mint": EventType.MINT,
        "Burn": EventType.BURN,
        "Swap": EventType.SWAP,
        "AddLiquidity": EventType.ADD_LIQUIDITY,
        "RemoveLiquidity": EventType.REMOVE_LIQUIDITY
    }
    
    event_type = event_type_map.get(request.eventType, EventType.TRANSFER)
    
    return EventLog(
        address=request.address,
        event_type=event_type,
        topics=request.topics,
        data=request.data,
        log_index=request.logIndex,
        transaction_hash=request.transactionHash,
        block_number=request.blockNumber
    )


def _convert_state_change(request: StateChangeRequest) -> StateChange:
    """Convert API request to StateChange"""
    return StateChange(
        address=request.address,
        key=request.key,
        old_value=request.oldValue,
        new_value=request.newValue,
        change_type=request.changeType
    )


def _convert_receipt(request: TransactionReceiptRequest) -> TransactionReceipt:
    """Convert API request to TransactionReceipt"""
    from datetime import datetime
    
    logs = [_convert_event_log(log) for log in request.logs]
    state_changes = [_convert_state_change(sc) for sc in request.stateChanges]
    
    return TransactionReceipt(
        transaction_hash=request.transactionHash,
        from_address=request.fromAddress,
        to_address=request.toAddress,
        contract_address=request.contractAddress,
        status=request.status,
        gas_used=request.gasUsed,
        logs=logs,
        state_changes=state_changes,
        block_number=request.blockNumber,
        timestamp=datetime.now()
    )


@app.post("/api/event-validation", response_model=EventValidationResponse)
async def validate_events(request: TransactionReceiptRequest):
    """
    Validate transaction events against state changes
    
    Args:
        request: TransactionReceiptRequest with transaction data
        
    Returns:
        EventValidationResponse with validation results
    """
    try:
        receipt = _convert_receipt(request)
        detection = spoof_detector.detect_spoofing(receipt)
        
        return EventValidationResponse(
            transactionHash=request.transactionHash,
            totalEvents=detection["total_events"],
            validEvents=detection["valid_events"],
            spoofedEvents=detection["spoofed_events"],
            suspiciousEvents=detection["suspicious_events"],
            isLikelySpoofed=detection["is_likely_spoofed"],
            spoofedDetails=detection["spoofed_details"],
            suspiciousDetails=detection["suspicious_details"],
            validDetails=detection["valid_details"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/validated-scoring", response_model=ValidatedScoringResponse)
async def calculate_validated_score(request: TransactionReceiptRequest, baseRiskScore: float = 0.0):
    """
    Calculate risk score with event validation
    
    Args:
        request: TransactionReceiptRequest with transaction data
        baseRiskScore: Base risk score from other analysis
        
    Returns:
        ValidatedScoringResponse with validated risk score
    """
    try:
        receipt = _convert_receipt(request)
        result = risk_analyzer.analyze_with_validation(receipt, baseRiskScore)
        
        return ValidatedScoringResponse(
            baseRiskScore=result["base_risk_score"],
            rawScore=result["raw_score"],
            validatedScore=result["validated_score"],
            finalScore=result["final_score"],
            riskLevel=result["risk_level"],
            isManipulated=result["is_manipulated"],
            confidence=result["confidence"],
            spoofedEventCount=result["spoofed_event_count"],
            totalEventCount=result["total_event_count"],
            spoofedEventTypes=result["spoofed_event_types"],
            volumeAdjustment=result["volume_adjustment"],
            liquidityAdjustment=result["liquidity_adjustment"],
            recommendations=result["recommendations"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "event-validation-api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
