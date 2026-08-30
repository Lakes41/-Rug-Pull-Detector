"""
Validated Scoring Engine
Integrates event validation with risk scoring to ignore spoofed events.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from event_validator import (
    EventSpoofDetector,
    TransactionReceipt,
    EventLog,
    EventType,
    StateChange
)


@dataclass
class ValidatedMetrics:
    """Metrics calculated from validated events only"""
    transfer_count: int = 0
    approval_count: int = 0
    mint_count: int = 0
    burn_count: int = 0
    total_volume: float = 0.0
    unique_addresses: set = None
    
    def __post_init__(self):
        if self.unique_addresses is None:
            self.unique_addresses = set()


@dataclass
class ScoringResult:
    """Result of scoring with event validation"""
    raw_score: float
    validated_score: float
    spoofed_event_count: int
    total_event_count: int
    spoofed_event_types: List[str]
    is_manipulated: bool
    confidence: str


class ValidatedScoringEngine:
    """Scoring engine that ignores spoofed events"""
    
    def __init__(self):
        self.spoof_detector = EventSpoofDetector()
    
    def calculate_validated_score(self, receipt: TransactionReceipt,
                                  base_score: float = 0.0) -> ScoringResult:
        """
        Calculate risk score using only validated events
        
        Args:
            receipt: Transaction receipt with events and state changes
            base_score: Base score from other analysis methods
            
        Returns:
            ScoringResult with validated score and manipulation detection
        """
        # Detect spoofing
        spoof_detection = self.spoof_detector.detect_spoofing(receipt)
        
        # Get trusted events
        trusted_events = self.spoof_detector.get_trusted_events(receipt)
        
        # Calculate metrics from trusted events only
        validated_metrics = self._calculate_metrics(trusted_events)
        
        # Calculate raw metrics (all events)
        raw_metrics = self._calculate_metrics(receipt.logs)
        
        # Calculate validated score
        validated_score = self._calculate_score_from_metrics(
            validated_metrics,
            base_score
        )
        
        # Calculate raw score (for comparison)
        raw_score = self._calculate_score_from_metrics(
            raw_metrics,
            base_score
        )
        
        # Determine if manipulation occurred
        is_manipulated = spoof_detection["is_likely_spoofed"]
        
        # Calculate confidence based on event validation
        confidence = self._calculate_confidence(
            spoof_detection,
            validated_metrics,
            raw_metrics
        )
        
        # Extract spoofed event types
        spoofed_types = [
            event["event_type"]
            for event in spoof_detection["spoofed_details"]
        ]
        
        return ScoringResult(
            raw_score=raw_score,
            validated_score=validated_score,
            spoofed_event_count=spoof_detection["spoofed_events"],
            total_event_count=spoof_detection["total_events"],
            spoofed_event_types=spoofed_types,
            is_manipulated=is_manipulated,
            confidence=confidence
        )
    
    def _calculate_metrics(self, events: List[EventLog]) -> ValidatedMetrics:
        """
        Calculate metrics from events
        
        Args:
            events: List of EventLog objects
            
        Returns:
            ValidatedMetrics with calculated values
        """
        metrics = ValidatedMetrics()
        
        for event in events:
            # Count event types
            if event.event_type == EventType.TRANSFER:
                metrics.transfer_count += 1
                # Extract amount from data (simplified)
                try:
                    amount = int(event.data, 16) if event.data.startswith("0x") else int(event.data)
                    metrics.total_volume += amount
                except (ValueError, AttributeError):
                    pass
                
                # Extract addresses from topics
                if len(event.topics) >= 3:
                    metrics.unique_addresses.add(event.topics[1])  # sender
                    metrics.unique_addresses.add(event.topics[2])  # recipient
            
            elif event.event_type == EventType.APPROVAL:
                metrics.approval_count += 1
            
            elif event.event_type == EventType.MINT:
                metrics.mint_count += 1
                try:
                    amount = int(event.data, 16) if event.data.startswith("0x") else int(event.data)
                    metrics.total_volume += amount
                except (ValueError, AttributeError):
                    pass
            
            elif event.event_type == EventType.BURN:
                metrics.burn_count += 1
        
        return metrics
    
    def _calculate_score_from_metrics(self, metrics: ValidatedMetrics,
                                      base_score: float) -> float:
        """
        Calculate risk score from metrics
        
        Args:
            metrics: ValidatedMetrics
            base_score: Base score from other analysis
            
        Returns:
            Calculated risk score
        """
        score = base_score
        
        # Adjust score based on activity metrics
        if metrics.transfer_count > 0:
            # More transfers = more legitimate activity (lower risk)
            activity_factor = min(metrics.transfer_count / 100, 1.0)
            score -= activity_factor * 0.1
        
        if metrics.total_volume > 0:
            # Higher volume = more legitimate activity (lower risk)
            volume_factor = min(metrics.total_volume / 1000000, 1.0)
            score -= volume_factor * 0.1
        
        if len(metrics.unique_addresses) > 1:
            # More unique addresses = more organic activity (lower risk)
            diversity_factor = min(len(metrics.unique_addresses) / 50, 1.0)
            score -= diversity_factor * 0.1
        
        # Mint/burn ratio analysis
        if metrics.mint_count > 0 and metrics.burn_count > 0:
            # Balanced mint/burn = normal token behavior
            ratio = min(metrics.mint_count / metrics.burn_count, metrics.burn_count / metrics.mint_count)
            if ratio > 0.5:  # Reasonably balanced
                score -= 0.05
        
        # Ensure score is in valid range
        return max(0.0, min(score, 1.0))
    
    def _calculate_confidence(self, spoof_detection: Dict,
                              validated_metrics: ValidatedMetrics,
                              raw_metrics: ValidatedMetrics) -> str:
        """
        Calculate confidence level in the score
        
        Args:
            spoof_detection: Spoof detection results
            validated_metrics: Metrics from trusted events
            raw_metrics: Metrics from all events
            
        Returns:
            Confidence level: "high", "medium", "low"
        """
        total_events = spoof_detection["total_events"]
        spoofed_count = spoof_detection["spoofed_events"]
        
        if total_events == 0:
            return "low"
        
        spoof_ratio = spoofed_count / total_events
        
        if spoof_ratio > 0.5:
            return "low"
        elif spoof_ratio > 0.2:
            return "medium"
        else:
            return "high"
    
    def get_volume_adjustment(self, receipt: TransactionReceipt) -> Dict:
        """
        Calculate volume adjustment based on event validation
        
        Args:
            receipt: Transaction receipt
            
        Returns:
            Dictionary with volume adjustment details
        """
        spoof_detection = self.spoof_detector.detect_spoofing(receipt)
        trusted_events = self.spoof_detector.get_trusted_events(receipt)
        
        # Calculate volume from all events
        raw_volume = self._calculate_total_volume(receipt.logs)
        
        # Calculate volume from trusted events only
        validated_volume = self._calculate_total_volume(trusted_events)
        
        # Calculate adjustment
        if raw_volume > 0:
            adjustment_ratio = validated_volume / raw_volume
        else:
            adjustment_ratio = 1.0
        
        return {
            "raw_volume": raw_volume,
            "validated_volume": validated_volume,
            "adjustment_ratio": adjustment_ratio,
            "spoofed_volume": raw_volume - validated_volume,
            "is_volume_manipulated": adjustment_ratio < 0.8
        }
    
    def _calculate_total_volume(self, events: List[EventLog]) -> float:
        """Calculate total volume from events"""
        total = 0.0
        
        for event in events:
            if event.event_type in [EventType.TRANSFER, EventType.MINT]:
                try:
                    amount = int(event.data, 16) if event.data.startswith("0x") else int(event.data)
                    total += amount
                except (ValueError, AttributeError):
                    pass
        
        return total
    
    def get_liquidity_adjustment(self, receipt: TransactionReceipt) -> Dict:
        """
        Calculate liquidity adjustment based on event validation
        
        Args:
            receipt: Transaction receipt
            
        Returns:
            Dictionary with liquidity adjustment details
        """
        spoof_detection = self.spoof_detector.detect_spoofing(receipt)
        trusted_events = self.spoof_detector.get_trusted_events(receipt)
        
        # Count liquidity events from all events
        raw_liquidity_events = len([
            e for e in receipt.logs
            if e.event_type in [EventType.ADD_LIQUIDITY, EventType.REMOVE_LIQUIDITY]
        ])
        
        # Count liquidity events from trusted events
        validated_liquidity_events = len([
            e for e in trusted_events
            if e.event_type in [EventType.ADD_LIQUIDITY, EventType.REMOVE_LIQUIDITY]
        ])
        
        # Calculate adjustment
        if raw_liquidity_events > 0:
            adjustment_ratio = validated_liquidity_events / raw_liquidity_events
        else:
            adjustment_ratio = 1.0
        
        return {
            "raw_liquidity_events": raw_liquidity_events,
            "validated_liquidity_events": validated_liquidity_events,
            "adjustment_ratio": adjustment_ratio,
            "is_liquidity_manipulated": adjustment_ratio < 0.8
        }


class EnhancedRiskAnalyzer:
    """Enhanced risk analyzer with event validation"""
    
    def __init__(self):
        self.scoring_engine = ValidatedScoringEngine()
    
    def analyze_with_validation(self, receipt: TransactionReceipt,
                               base_risk_score: float = 0.0) -> Dict:
        """
        Analyze risk with event validation
        
        Args:
            receipt: Transaction receipt
            base_risk_score: Base risk score from other analysis
            
        Returns:
            Complete analysis with validation results
        """
        # Get validated scoring
        scoring_result = self.scoring_engine.calculate_validated_score(
            receipt,
            base_risk_score
        )
        
        # Get volume adjustment
        volume_adjustment = self.scoring_engine.get_volume_adjustment(receipt)
        
        # Get liquidity adjustment
        liquidity_adjustment = self.scoring_engine.get_liquidity_adjustment(receipt)
        
        # Determine final risk level
        if scoring_result.is_manipulated:
            # If manipulation detected, use validated score
            final_score = scoring_result.validated_score
            risk_level = "HIGH" if final_score > 0.5 else "MEDIUM"
        else:
            # No manipulation, use raw score
            final_score = scoring_result.raw_score
            risk_level = "LOW" if final_score < 0.3 else "MEDIUM" if final_score < 0.6 else "HIGH"
        
        return {
            "base_risk_score": base_risk_score,
            "raw_score": scoring_result.raw_score,
            "validated_score": scoring_result.validated_score,
            "final_score": final_score,
            "risk_level": risk_level,
            "is_manipulated": scoring_result.is_manipulated,
            "confidence": scoring_result.confidence,
            "spoofed_event_count": scoring_result.spoofed_event_count,
            "total_event_count": scoring_result.total_event_count,
            "spoofed_event_types": scoring_result.spoofed_event_types,
            "volume_adjustment": volume_adjustment,
            "liquidity_adjustment": liquidity_adjustment,
            "recommendations": self._generate_recommendations(scoring_result, volume_adjustment, liquidity_adjustment)
        }
    
    def _generate_recommendations(self, scoring_result: ScoringResult,
                                 volume_adjustment: Dict,
                                 liquidity_adjustment: Dict) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []
        
        if scoring_result.is_manipulated:
            recommendations.append("Event spoofing detected - metrics may be manipulated")
            recommendations.append(f"{scoring_result.spoofed_event_count} spoofed events found")
            
            if scoring_result.confidence == "low":
                recommendations.append("Low confidence in metrics due to high spoofing rate")
        
        if volume_adjustment["is_volume_manipulated"]:
            recommendations.append("Volume metrics may be inflated by spoofed events")
            recommendations.append(f"Volume adjustment ratio: {volume_adjustment['adjustment_ratio']:.2%}")
        
        if liquidity_adjustment["is_liquidity_manipulated"]:
            recommendations.append("Liquidity metrics may be inflated by spoofed events")
            recommendations.append(f"Liquidity adjustment ratio: {liquidity_adjustment['adjustment_ratio']:.2%}")
        
        if not scoring_result.is_manipulated and scoring_result.confidence == "high":
            recommendations.append("Event validation passed - metrics are reliable")
        
        return recommendations


def create_spoofed_receipt(transaction_hash: str) -> TransactionReceipt:
    """Create a mock receipt with spoofed events for testing"""
    return TransactionReceipt(
        transaction_hash=transaction_hash,
        from_address="0xABC123",
        to_address="0xCONTRACT",
        contract_address="0xCONTRACT",
        status="success",
        gas_used=50000,
        logs=[
            # Valid transfer event
            EventLog(
                address="0xCONTRACT",
                event_type=EventType.TRANSFER,
                topics=["0xTransfer", "0xABC123", "0xDEF456"],
                data="0x1000000000000000000",
                log_index=0,
                transaction_hash=transaction_hash,
                block_number=12345
            ),
            # Spoofed transfer event (wrong address)
            EventLog(
                address="0xFAKE123",  # Wrong address
                event_type=EventType.TRANSFER,
                topics=["0xTransfer", "0xABC123", "0xDEF456"],
                data="0x5000000000000000000",  # Fake large amount
                log_index=1,
                transaction_hash=transaction_hash,
                block_number=12345
            ),
            # Spoofed mint event (no state change)
            EventLog(
                address="0xCONTRACT",
                event_type=EventType.MINT,
                topics=["0xMint", "0xABC123"],
                data="0x10000000000000000000",  # Fake mint
                log_index=2,
                transaction_hash=transaction_hash,
                block_number=12345
            )
        ],
        state_changes=[
            # Only state change for the valid transfer
            StateChange(
                address="0xABC123",
                key="balance",
                old_value="1000000000000000000",
                new_value="0",
                change_type="balance"
            ),
            StateChange(
                address="0xDEF456",
                key="balance",
                old_value="0",
                new_value="1000000000000000000",
                change_type="balance"
            )
        ],
        block_number=12345,
        timestamp=None
    )


if __name__ == "__main__":
    # Example usage
    analyzer = EnhancedRiskAnalyzer()
    
    # Create a receipt with spoofed events
    receipt = create_spoofed_receipt("0x1234567890abcdef")
    
    # Analyze with validation
    result = analyzer.analyze_with_validation(receipt, base_risk_score=0.3)
    
    print(f"Base Risk Score: {result['base_risk_score']:.2f}")
    print(f"Raw Score: {result['raw_score']:.2f}")
    print(f"Validated Score: {result['validated_score']:.2f}")
    print(f"Final Score: {result['final_score']:.2f}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Is Manipulated: {result['is_manipulated']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Spoofed Events: {result['spoofed_event_count']}/{result['total_event_count']}")
    print(f"\nVolume Adjustment:")
    print(f"  Raw: {result['volume_adjustment']['raw_volume']}")
    print(f"  Validated: {result['volume_adjustment']['validated_volume']}")
    print(f"  Ratio: {result['volume_adjustment']['adjustment_ratio']:.2%}")
    print(f"\nRecommendations:")
    for rec in result['recommendations']:
        print(f"  - {rec}")
