"""
Event Validator and Transaction Receipt Validator
Validates transaction receipts against internal state changes to detect event spoofing.
Ensures msg.sender and contract address alignment with emitted event data.
"""

import json
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class EventType(Enum):
    """Types of blockchain events"""
    TRANSFER = "Transfer"
    APPROVAL = "Approval"
    MINT = "Mint"
    BURN = "Burn"
    SWAP = "Swap"
    ADD_LIQUIDITY = "AddLiquidity"
    REMOVE_LIQUIDITY = "RemoveLiquidity"


class ValidationResult(Enum):
    """Validation result status"""
    VALID = "valid"
    SPOOFED = "spoofed"
    MISMATCH = "mismatch"
    INCOMPLETE = "incomplete"
    ERROR = "error"


@dataclass
class StateChange:
    """Represents a state change from transaction receipt"""
    address: str
    key: str
    old_value: Optional[str]
    new_value: Optional[str]
    change_type: str  # "storage", "balance", "code", etc.


@dataclass
class EventLog:
    """Represents an event log from transaction"""
    address: str
    event_type: EventType
    topics: List[str]
    data: str
    log_index: int
    transaction_hash: str
    block_number: int


@dataclass
class EventValidation:
    """Result of event validation"""
    event: EventLog
    is_valid: bool
    result: ValidationResult
    state_changes: List[StateChange]
    discrepancies: List[str]
    msg_sender: Optional[str] = None
    contract_address: Optional[str] = None


@dataclass
class TransactionReceipt:
    """Represents a transaction receipt"""
    transaction_hash: str
    from_address: str
    to_address: Optional[str]
    contract_address: Optional[str]
    status: str
    gas_used: int
    logs: List[EventLog]
    state_changes: List[StateChange]
    block_number: int
    timestamp: datetime


class TransactionReceiptValidator:
    """Validates transaction receipts against state changes"""
    
    def __init__(self):
        self.validated_events: Dict[str, EventValidation] = {}
    
    def validate_receipt(self, receipt: TransactionReceipt) -> Dict[str, EventValidation]:
        """
        Validate a transaction receipt against state changes
        
        Args:
            receipt: TransactionReceipt to validate
            
        Returns:
            Dictionary mapping event log index to validation results
        """
        self.validated_events = {}
        
        for log in receipt.logs:
            validation = self._validate_event(log, receipt)
            self.validated_events[str(log.log_index)] = validation
        
        return self.validated_events
    
    def _validate_event(self, event: EventLog, receipt: TransactionReceipt) -> EventValidation:
        """
        Validate a single event against state changes
        
        Args:
            event: EventLog to validate
            receipt: Parent transaction receipt
            
        Returns:
            EventValidation result
        """
        # Get relevant state changes for this event
        relevant_changes = self._get_relevant_state_changes(event, receipt.state_changes)
        
        # Check for discrepancies
        discrepancies = self._check_discrepancies(event, relevant_changes, receipt)
        
        # Determine validation result
        if discrepancies:
            is_valid = False
            result = ValidationResult.SPOOFED if self._is_spoofed(discrepancies) else ValidationResult.MISMATCH
        else:
            is_valid = True
            result = ValidationResult.VALID
        
        return EventValidation(
            event=event,
            is_valid=is_valid,
            result=result,
            state_changes=relevant_changes,
            discrepancies=discrepancies,
            msg_sender=receipt.from_address,
            contract_address=receipt.contract_address or receipt.to_address
        )
    
    def _get_relevant_state_changes(self, event: EventLog, 
                                   state_changes: List[StateChange]) -> List[StateChange]:
        """
        Get state changes relevant to the event
        
        Args:
            event: Event to check
            state_changes: All state changes from transaction
            
        Returns:
            List of relevant state changes
        """
        relevant = []
        
        for change in state_changes:
            # State changes at the event's contract address are relevant
            if change.address == event.address:
                relevant.append(change)
            
            # For transfer events, check both sender and recipient addresses
            if event.event_type == EventType.TRANSFER and len(event.topics) >= 3:
                sender = event.topics[1]
                recipient = event.topics[2]
                if change.address in [sender, recipient]:
                    relevant.append(change)
        
        return relevant
    
    def _check_discrepancies(self, event: EventLog, 
                           state_changes: List[StateChange],
                           receipt: TransactionReceipt) -> List[str]:
        """
        Check for discrepancies between event and state changes
        
        Args:
            event: Event to check
            state_changes: Relevant state changes
            receipt: Transaction receipt
            
        Returns:
            List of discrepancy descriptions
        """
        discrepancies = []
        
        # Check if event address matches contract address
        if receipt.contract_address and event.address != receipt.contract_address:
            discrepancies.append(
                f"Event address {event.address} does not match contract address {receipt.contract_address}"
            )
        
        # Check for expected state changes based on event type
        expected_changes = self._get_expected_state_changes(event)
        
        if not state_changes and expected_changes:
            discrepancies.append(
                f"Event type {event.event_type.value} expects state changes but none found"
            )
        
        # Validate specific event types
        if event.event_type == EventType.TRANSFER:
            discrepancies.extend(self._validate_transfer_event(event, state_changes))
        elif event.event_type == EventType.APPROVAL:
            discrepancies.extend(self._validate_approval_event(event, state_changes))
        elif event.event_type == EventType.MINT:
            discrepancies.extend(self._validate_mint_event(event, state_changes))
        elif event.event_type == EventType.BURN:
            discrepancies.extend(self._validate_burn_event(event, state_changes))
        
        return discrepancies
    
    def _get_expected_state_changes(self, event: EventLog) -> List[str]:
        """Get expected state change types for an event"""
        change_map = {
            EventType.TRANSFER: ["balance"],
            EventType.APPROVAL: ["allowance"],
            EventType.MINT: ["balance", "total_supply"],
            EventType.BURN: ["balance", "total_supply"],
            EventType.SWAP: ["balance"],
            EventType.ADD_LIQUIDITY: ["balance", "liquidity"],
            EventType.REMOVE_LIQUIDITY: ["balance", "liquidity"]
        }
        return change_map.get(event.event_type, [])
    
    def _validate_transfer_event(self, event: EventLog, 
                                 state_changes: List[StateChange]) -> List[str]:
        """Validate transfer event against state changes"""
        discrepancies = []
        
        if len(event.topics) < 3:
            discrepancies.append("Transfer event missing sender or recipient in topics")
            return discrepancies
        
        sender = event.topics[1]
        recipient = event.topics[2]
        
        # Check for balance changes
        sender_balance_change = None
        recipient_balance_change = None
        
        for change in state_changes:
            if change.address == sender and "balance" in change.key.lower():
                sender_balance_change = change
            elif change.address == recipient and "balance" in change.key.lower():
                recipient_balance_change = change
        
        # Transfer should decrease sender balance and increase recipient balance
        if sender_balance_change and recipient_balance_change:
            # Parse balance values (simplified)
            try:
                old_sender = int(sender_balance_change.old_value or "0")
                new_sender = int(sender_balance_change.new_value or "0")
                old_recipient = int(recipient_balance_change.old_value or "0")
                new_recipient = int(recipient_balance_change.new_value or "0")
                
                if new_sender >= old_sender:
                    discrepancies.append(f"Sender balance did not decrease: {old_sender} -> {new_sender}")
                
                if new_recipient <= old_recipient:
                    discrepancies.append(f"Recipient balance did not increase: {old_recipient} -> {new_recipient}")
            except (ValueError, TypeError):
                discrepancies.append("Could not parse balance values for validation")
        elif not state_changes:
            discrepancies.append("No balance state changes found for transfer event")
        
        return discrepancies
    
    def _validate_approval_event(self, event: EventLog, 
                                state_changes: List[StateChange]) -> List[str]:
        """Validate approval event against state changes"""
        discrepancies = []
        
        if len(event.topics) < 3:
            discrepancies.append("Approval event missing owner or spender in topics")
            return discrepancies
        
        owner = event.topics[1]
        spender = event.topics[2]
        
        # Check for allowance state change
        allowance_change = None
        for change in state_changes:
            if change.address == owner and "allowance" in change.key.lower():
                allowance_change = change
                break
        
        if not allowance_change:
            discrepancies.append("No allowance state change found for approval event")
        
        return discrepancies
    
    def _validate_mint_event(self, event: EventLog, 
                             state_changes: List[StateChange]) -> List[str]:
        """Validate mint event against state changes"""
        discrepancies = []
        
        # Check for total supply increase
        supply_change = None
        for change in state_changes:
            if "total_supply" in change.key.lower() or "supply" in change.key.lower():
                supply_change = change
                break
        
        if supply_change:
            try:
                old_supply = int(supply_change.old_value or "0")
                new_supply = int(supply_change.new_value or "0")
                
                if new_supply <= old_supply:
                    discrepancies.append(f"Total supply did not increase for mint: {old_supply} -> {new_supply}")
            except (ValueError, TypeError):
                discrepancies.append("Could not parse supply values for validation")
        else:
            discrepancies.append("No total supply state change found for mint event")
        
        return discrepancies
    
    def _validate_burn_event(self, event: EventLog, 
                             state_changes: List[StateChange]) -> List[str]:
        """Validate burn event against state changes"""
        discrepancies = []
        
        # Check for total supply decrease
        supply_change = None
        for change in state_changes:
            if "total_supply" in change.key.lower() or "supply" in change.key.lower():
                supply_change = change
                break
        
        if supply_change:
            try:
                old_supply = int(supply_change.old_value or "0")
                new_supply = int(supply_change.new_value or "0")
                
                if new_supply >= old_supply:
                    discrepancies.append(f"Total supply did not decrease for burn: {old_supply} -> {new_supply}")
            except (ValueError, TypeError):
                discrepancies.append("Could not parse supply values for validation")
        else:
            discrepancies.append("No total supply state change found for burn event")
        
        return discrepancies
    
    def _is_spoofed(self, discrepancies: List[str]) -> bool:
        """
        Determine if discrepancies indicate spoofing
        
        Args:
            discrepancies: List of discrepancy descriptions
            
        Returns:
            True if likely spoofed, False otherwise
        """
        spoofing_indicators = [
            "does not match contract address",
            "expects state changes but none found",
            "did not decrease",
            "did not increase",
            "No balance state changes found",
            "No allowance state change found",
            "No total supply state change found"
        ]
        
        for discrepancy in discrepancies:
            if any(indicator in discrepancy for indicator in spoofing_indicators):
                return True
        
        return False
    
    def get_valid_events(self, receipt: TransactionReceipt) -> List[EventLog]:
        """
        Get only valid events from a receipt
        
        Args:
            receipt: Transaction receipt
            
        Returns:
            List of valid EventLog objects
        """
        validations = self.validate_receipt(receipt)
        return [
            validation.event 
            for validation in validations.values() 
            if validation.is_valid
        ]
    
    def get_spoofed_events(self, receipt: TransactionReceipt) -> List[EventLog]:
        """
        Get only spoofed events from a receipt
        
        Args:
            receipt: Transaction receipt
            
        Returns:
            List of spoofed EventLog objects
        """
        validations = self.validate_receipt(receipt)
        return [
            validation.event 
            for validation in validations.values() 
            if not validation.is_valid and validation.result == ValidationResult.SPOOFED
        ]


class EventAddressVerifier:
    """Verifies msg.sender and contract address alignment with event data"""
    
    def verify_event_addresses(self, event: EventLog, 
                              msg_sender: str,
                              contract_address: str) -> Tuple[bool, List[str]]:
        """
        Verify that event addresses align with transaction data
        
        Args:
            event: Event to verify
            msg_sender: Transaction sender
            contract_address: Contract address
            
        Returns:
            Tuple of (is_valid, list of issues)
        """
        issues = []
        
        # Check event emitter address
        if event.address != contract_address:
            issues.append(
                f"Event emitted from {event.address} but contract address is {contract_address}"
            )
        
        # Verify transfer event addresses
        if event.event_type == EventType.TRANSFER and len(event.topics) >= 3:
            sender = event.topics[1]
            recipient = event.topics[2]
            
            # For transfers, sender should match msg.sender or be approved
            if sender != msg_sender and sender != "0x0000000000000000000000000000000000000000":
                # Could be a transfer from approved spender, so not necessarily invalid
                # but worth noting
                issues.append(
                    f"Transfer sender {sender} does not match msg.sender {msg_sender} (may be approved spender)"
                )
        
        # Verify mint event addresses
        if event.event_type == EventType.MINT:
            # Mint events should originate from the contract itself
            if event.address != contract_address:
                issues.append(
                    f"Mint event emitted from {event.address} instead of contract {contract_address}"
                )
        
        # Verify approval event addresses
        if event.event_type == EventType.APPROVAL and len(event.topics) >= 3:
            owner = event.topics[1]
            spender = event.topics[2]
            
            # Owner should match msg.sender for self-approvals
            if owner == msg_sender:
                # This is expected
                pass
            elif owner != msg_sender:
                # Could be approval from different address (rare but possible)
                issues.append(
                    f"Approval owner {owner} does not match msg.sender {msg_sender}"
                )
        
        is_valid = len(issues) == 0
        return is_valid, issues
    
    def verify_batch_events(self, events: List[EventLog],
                           msg_sender: str,
                           contract_address: str) -> Dict[str, Tuple[bool, List[str]]]:
        """
        Verify multiple events
        
        Args:
            events: List of events to verify
            msg_sender: Transaction sender
            contract_address: Contract address
            
        Returns:
            Dictionary mapping log index to verification results
        """
        results = {}
        for event in events:
            is_valid, issues = self.verify_event_addresses(event, msg_sender, contract_address)
            results[str(event.log_index)] = (is_valid, issues)
        
        return results


class EventSpoofDetector:
    """Detects event spoofing attempts"""
    
    def __init__(self):
        self.receipt_validator = TransactionReceiptValidator()
        self.address_verifier = EventAddressVerifier()
    
    def detect_spoofing(self, receipt: TransactionReceipt) -> Dict:
        """
        Comprehensive spoofing detection
        
        Args:
            receipt: Transaction receipt to analyze
            
        Returns:
            Dictionary with detection results
        """
        # Validate receipt against state changes
        receipt_validations = self.receipt_validator.validate_receipt(receipt)
        
        # Verify event addresses
        address_verifications = self.address_verifier.verify_batch_events(
            receipt.logs,
            receipt.from_address,
            receipt.contract_address or receipt.to_address
        )
        
        # Combine results
        spoofed_events = []
        valid_events = []
        suspicious_events = []
        
        for log_index, validation in receipt_validations.items():
            is_valid_address, address_issues = address_verifications.get(log_index, (True, []))
            
            if not validation.is_valid:
                spoofed_events.append({
                    "log_index": log_index,
                    "event_type": validation.event.event_type.value,
                    "discrepancies": validation.discrepancies,
                    "address_issues": address_issues
                })
            elif not is_valid_address:
                suspicious_events.append({
                    "log_index": log_index,
                    "event_type": validation.event.event_type.value,
                    "address_issues": address_issues
                })
            else:
                valid_events.append({
                    "log_index": log_index,
                    "event_type": validation.event.event_type.value
                })
        
        return {
            "total_events": len(receipt.logs),
            "valid_events": len(valid_events),
            "spoofed_events": len(spoofed_events),
            "suspicious_events": len(suspicious_events),
            "spoofed_details": spoofed_events,
            "suspicious_details": suspicious_events,
            "valid_details": valid_events,
            "is_likely_spoofed": len(spoofed_events) > 0
        }
    
    def get_trusted_events(self, receipt: TransactionReceipt) -> List[EventLog]:
        """
        Get only trusted (validated) events from a receipt
        
        Args:
            receipt: Transaction receipt
            
        Returns:
            List of trusted EventLog objects
        """
        detection = self.detect_spoofing(receipt)
        
        # Get valid event indices
        valid_indices = {
            event["log_index"] 
            for event in detection["valid_details"]
        }
        
        return [
            log for log in receipt.logs 
            if str(log.log_index) in valid_indices
        ]


def create_mock_receipt(transaction_hash: str) -> TransactionReceipt:
    """Create a mock transaction receipt for testing"""
    return TransactionReceipt(
        transaction_hash=transaction_hash,
        from_address="0xABC123",
        to_address="0xCONTRACT",
        contract_address="0xCONTRACT",
        status="success",
        gas_used=50000,
        logs=[
            EventLog(
                address="0xCONTRACT",
                event_type=EventType.TRANSFER,
                topics=["0xTransfer", "0xABC123", "0xDEF456"],
                data="0x1000000000000000000",
                log_index=0,
                transaction_hash=transaction_hash,
                block_number=12345
            )
        ],
        state_changes=[
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
        timestamp=datetime.now()
    )


if __name__ == "__main__":
    # Example usage
    detector = EventSpoofDetector()
    
    # Create a mock receipt
    receipt = create_mock_receipt("0x1234567890abcdef")
    
    # Detect spoofing
    detection = detector.detect_spoofing(receipt)
    
    print(f"Total events: {detection['total_events']}")
    print(f"Valid events: {detection['valid_events']}")
    print(f"Spoofed events: {detection['spoofed_events']}")
    print(f"Suspicious events: {detection['suspicious_events']}")
    print(f"Likely spoofed: {detection['is_likely_spoofed']}")
    
    # Get trusted events
    trusted_events = detector.get_trusted_events(receipt)
    print(f"Trusted events: {len(trusted_events)}")
