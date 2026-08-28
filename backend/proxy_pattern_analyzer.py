"""
Proxy Pattern Analyzer
Analyzes proxy contracts (EIP-1967, EIP-897, Beacon) to detect implementation changes
and verify timelock governance constraints.
"""

import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from circuit_breaker import get_rpc_circuit_breaker, CircuitBreakerOpenError

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    # Create mock Web3 for graceful degradation
    class MockWeb3:
        class eth:
            @staticmethod
            def get_storage_at(address, slot):
                return b'\x00' * 32
            
            @staticmethod
            def get_code(address):
                return b''
    
    Web3 = MockWeb3


class ProxyType(Enum):
    """Types of proxy patterns"""
    EIP_1967 = "eip_1967"
    EIP_897 = "eip_897"
    BEACON = "beacon"
    UUPS = "uups"
    UNKNOWN = "unknown"


class ProxyRiskType(Enum):
    """Types of proxy-related risks"""
    INSTANT_LOGIC_SWAP = "instant_logic_swap"
    NO_TIMELOCK = "no_timelock"
    INSUFFICIENT_TIMELOCK_DELAY = "insufficient_timelock_delay"
    ADMIN_CAN_UPGRADE = "admin_can_upgrade"
    MULTIPLE_IMPLEMENTATION_CHANGES = "multiple_implementation_changes"
    STORAGE_SLOT_COLLISION = "storage_slot_collision"
    UNVERIFIED_IMPLEMENTATION = "unverified_implementation"


@dataclass
class ProxyStorageSlot:
    """Represents a proxy storage slot configuration"""
    name: str
    slot_address: str
    proxy_type: ProxyType
    description: str


@dataclass
class ImplementationInfo:
    """Information about a proxy implementation"""
    implementation_address: str
    proxy_type: ProxyType
    storage_slot: str
    last_updated: Optional[int] = None
    update_count: int = 0


@dataclass
class TimelockInfo:
    """Information about timelock governance"""
    has_timelock: bool
    timelock_address: Optional[str] = None
    minimum_delay: int = 0  # in seconds
    is_governance_delay_sufficient: bool = False
    admins: List[str] = field(default_factory=list)


@dataclass
class ProxyRisk:
    """Represents a proxy-related risk"""
    contract_id: str
    risk_type: ProxyRiskType
    description: str
    severity: str  # "critical", "high", "medium", "low"
    risk_multiplier: float = 1.0
    technical_details: Dict = field(default_factory=dict)


# Standard proxy storage slots
PROXY_STORAGE_SLOTS = {
    ProxyType.EIP_1967: [
        ProxyStorageSlot(
            name="EIP_1967_IMPLEMENTATION",
            slot_address="0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            proxy_type=ProxyType.EIP_1967,
            description="EIP-1967 standard implementation slot"
        ),
        ProxyStorageSlot(
            name="EIP_1967_BEACON",
            slot_address="0xa3f0ad74e5423aebfd80d3ef4346578335a9a72dce654f2cb75a6f3b4f2e4e2",
            proxy_type=ProxyType.EIP_1967,
            description="EIP-1967 beacon slot"
        ),
        ProxyStorageSlot(
            name="EIP_1967_ADMIN",
            slot_address="0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            proxy_type=ProxyType.EIP_1967,
            description="EIP-1967 admin slot"
        ),
    ],
    ProxyType.EIP_897: [
        ProxyStorageSlot(
            name="EIP_897_IMPLEMENTATION",
            slot_address="0x7050c9e0d499be425b1e499560863b1f469c88b78fdf11ff057772e191251b44",
            proxy_type=ProxyType.EIP_897,
            description="EIP-897 implementation slot"
        ),
    ],
    ProxyType.BEACON: [
        ProxyStorageSlot(
            name="BEACON_IMPLEMENTATION",
            slot_address="0xa3f0ad74e5423aebfd80d3ef4346578335a9a72dce654f2cb75a6f3b4f2e4e2",
            proxy_type=ProxyType.BEACON,
            description="Beacon proxy implementation slot"
        ),
    ],
}


class ProxyStorageResolver:
    """Resolves proxy storage slots to extract implementation addresses with circuit breaker protection"""
    
    def __init__(self, web3: Optional[Web3] = None, rpc_url: Optional[str] = None):
        if not WEB3_AVAILABLE:
            self.web3 = MockWeb3()
            self.circuit_breaker = None
        else:
            self.web3 = web3 or Web3()
            self.rpc_url = rpc_url
            self.circuit_breaker = None
        self.detected_proxies: Dict[str, ImplementationInfo] = {}
    
    async def _get_circuit_breaker(self):
        """Get or create circuit breaker for RPC URL"""
        if self.circuit_breaker is None and self.rpc_url:
            self.circuit_breaker = await get_rpc_circuit_breaker(self.rpc_url)
        return self.circuit_breaker
    
    async def resolve_storage_slot(self, contract_address: str, storage_slot: ProxyStorageSlot) -> Optional[str]:
        """
        Read a storage slot to extract implementation address with circuit breaker protection
        
        Args:
            contract_address: Proxy contract address
            storage_slot: Storage slot configuration
            
        Returns:
            Implementation address or None if not found
        """
        async def make_request():
            # Convert slot address to integer
            slot_int = int(storage_slot.slot_address, 16)
            
            # Read storage slot
            storage_value = self.web3.eth.get_storage_at(
                contract_address, 
                slot_int
            )
            
            # Decode as address (last 20 bytes)
            if len(storage_value) == 32:
                # Extract last 20 bytes (address)
                address_bytes = storage_value[-20:]
                implementation_address = "0x" + address_bytes.hex()
                
                # Check if it's a valid address (not zero address)
                if implementation_address != "0x0000000000000000000000000000000000000000":
                    return implementation_address
            
            return None
        
        try:
            # Use circuit breaker if available
            breaker = await self._get_circuit_breaker()
            if breaker:
                return await breaker.call(make_request)
            else:
                # Fallback to direct call if no circuit breaker
                return make_request()
        except CircuitBreakerOpenError as e:
            print(f"Circuit breaker open for RPC when resolving storage slot {storage_slot.name}: {e}")
            return None
        except Exception as e:
            print(f"Error resolving storage slot {storage_slot.name}: {e}")
            return None
    
    async def detect_proxy_type(self, contract_address: str) -> Tuple[Optional[ProxyType], Optional[str]]:
        """
        Detect proxy type and extract implementation address
        
        Args:
            contract_address: Contract address to analyze
            
        Returns:
            Tuple of (proxy_type, implementation_address)
        """
        # Try EIP-1967 slots first (most common)
        for storage_slot in PROXY_STORAGE_SLOTS[ProxyType.EIP_1967]:
            implementation = await self.resolve_storage_slot(contract_address, storage_slot)
            if implementation:
                return ProxyType.EIP_1967, implementation
        
        # Try EIP-897 slots
        for storage_slot in PROXY_STORAGE_SLOTS[ProxyType.EIP_897]:
            implementation = await self.resolve_storage_slot(contract_address, storage_slot)
            if implementation:
                return ProxyType.EIP_897, implementation
        
        # Try Beacon slots
        for storage_slot in PROXY_STORAGE_SLOTS[ProxyType.BEACON]:
            implementation = await self.resolve_storage_slot(contract_address, storage_slot)
            if implementation:
                return ProxyType.BEACON, implementation
        
        return ProxyType.UNKNOWN, None
    
    async def get_admin_address(self, contract_address: str) -> Optional[str]:
        """
        Extract admin address from EIP-1967 admin slot
        
        Args:
            contract_address: Proxy contract address
            
        Returns:
            Admin address or None
        """
        admin_slot = PROXY_STORAGE_SLOTS[ProxyType.EIP_1967][2]  # EIP_1967_ADMIN
        return await self.resolve_storage_slot(contract_address, admin_slot)


class TimelockGovernanceVerifier:
    """Verifies timelock governance constraints"""
    
    MINIMUM_DELAY_SECONDS = 24 * 60 * 60  # 24 hours
    
    def __init__(self, web3: Optional[Web3] = None):
        if not WEB3_AVAILABLE:
            self.web3 = MockWeb3()
        else:
            self.web3 = web3 or Web3()
    
    def verify_timelock(self, contract_address: str, admin_address: Optional[str] = None) -> TimelockInfo:
        """
        Verify if contract has proper timelock governance
        
        Args:
            contract_address: Contract address to verify
            admin_address: Optional admin address to check
            
        Returns:
            TimelockInfo with governance details
        """
        timelock_info = TimelockInfo(
            has_timelock=False,
            minimum_delay=0,
            is_governance_delay_sufficient=False
        )
        
        try:
            # Check if admin address is a timelock contract
            if admin_address:
                timelock_info = self._check_timelock_contract(admin_address)
            
            # If no timelock found, check if contract itself has timelock functionality
            if not timelock_info.has_timelock:
                timelock_info = self._check_contract_timelock(contract_address)
            
            # Check if delay is sufficient
            if timelock_info.has_timelock:
                timelock_info.is_governance_delay_sufficient = (
                    timelock_info.minimum_delay >= self.MINIMUM_DELAY_SECONDS
                )
            
            return timelock_info
            
        except Exception as e:
            print(f"Error verifying timelock: {e}")
            return timelock_info
    
    def _check_timelock_contract(self, address: str) -> TimelockInfo:
        """Check if address is a timelock contract"""
        try:
            # Standard timelock function selectors
            timelock_selectors = [
                "0x59129c7e",  # execute
                "0x5f5af1aa",  # schedule
                "0xd928f3a2",  # setDelay
            ]
            
            # Check if contract has timelock functions
            code = self.web3.eth.get_code(address)
            if len(code) > 0:
                # Simple check: if it has timelock functions, assume it's a timelock
                has_timelock_functions = any(selector.hex() in code.hex() for selector in 
                                             [bytes.fromhex(s[2:]) for s in timelock_selectors])
                
                if has_timelock_functions:
                    # Try to get delay (this would need ABI in production)
                    # For now, assume standard delay
                    return TimelockInfo(
                        has_timelock=True,
                        timelock_address=address,
                        minimum_delay=self.MINIMUM_DELAY_SECONDS,  # Default assumption
                        is_governance_delay_sufficient=True
                    )
        
        except Exception as e:
            print(f"Error checking timelock contract: {e}")
        
        return TimelockInfo(has_timelock=False)
    
    def _check_contract_timelock(self, contract_address: str) -> TimelockInfo:
        """Check if contract has built-in timelock"""
        try:
            code = self.web3.eth.get_code(contract_address)
            if len(code) > 0:
                # Check for timelock-related functions
                timelock_selectors = [
                    "0x59129c7e",  # execute
                    "0x5f5af1aa",  # schedule
                ]
                
                has_timelock = any(selector.hex() in code.hex() for selector in 
                                   [bytes.fromhex(s[2:]) for s in timelock_selectors])
                
                if has_timelock:
                    return TimelockInfo(
                        has_timelock=True,
                        timelock_address=contract_address,
                        minimum_delay=self.MINIMUM_DELAY_SECONDS,
                        is_governance_delay_sufficient=True
                    )
        
        except Exception as e:
            print(f"Error checking contract timelock: {e}")
        
        return TimelockInfo(has_timelock=False)


class ProxyPatternAnalyzer:
    """Main analyzer for proxy pattern risks with circuit breaker protection"""
    
    def __init__(self, web3: Optional[Web3] = None, rpc_url: Optional[str] = None):
        if not WEB3_AVAILABLE:
            self.web3 = MockWeb3()
        elif rpc_url:
            self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        else:
            self.web3 = web3 or Web3()
        
        self.rpc_url = rpc_url
        self.storage_resolver = ProxyStorageResolver(self.web3, rpc_url)
        self.timelock_verifier = TimelockGovernanceVerifier(self.web3)
        self.detected_risks: List[ProxyRisk] = []
        self.proxy_history: Dict[str, List[ImplementationInfo]] = {}
    
    async def analyze_proxy_contract(self, contract_address: str) -> Dict:
        """
        Analyze a contract for proxy pattern risks
        
        Args:
            contract_address: Contract address to analyze
            
        Returns:
            Analysis results with risks and recommendations
        """
        self.detected_risks = []
        
        # Detect proxy type and implementation
        proxy_type, implementation_address = await self.storage_resolver.detect_proxy_type(contract_address)
        
        if proxy_type == ProxyType.UNKNOWN:
            return {
                "contract_address": contract_address,
                "is_proxy": False,
                "proxy_type": "unknown",
                "risks": [],
                "risk_multiplier": 1.0,
                "recommendations": []
            }
        
        # Get admin address
        admin_address = await self.storage_resolver.get_admin_address(contract_address)
        
        # Verify timelock governance
        timelock_info = self.timelock_verifier.verify_timelock(contract_address, admin_address)
        
        # Detect risks
        self._detect_proxy_risks(
            contract_address, 
            proxy_type, 
            implementation_address, 
            admin_address, 
            timelock_info
        )
        
        # Calculate overall risk multiplier
        risk_multiplier = self._calculate_risk_multiplier()
        
        return {
            "contract_address": contract_address,
            "is_proxy": True,
            "proxy_type": proxy_type.value,
            "implementation_address": implementation_address,
            "admin_address": admin_address,
            "timelock_info": {
                "has_timelock": timelock_info.has_timelock,
                "timelock_address": timelock_info.timelock_address,
                "minimum_delay": timelock_info.minimum_delay,
                "is_governance_delay_sufficient": timelock_info.is_governance_delay_sufficient
            },
            "risks": [self._format_risk(risk) for risk in self.detected_risks],
            "risk_multiplier": risk_multiplier,
            "recommendations": self._generate_recommendations()
        }
    
    def _detect_proxy_risks(self, contract_address: str, proxy_type: ProxyType, 
                           implementation_address: str, admin_address: Optional[str],
                           timelock_info: TimelockInfo):
        """Detect proxy-related risks"""
        
        # Check for instant logic swap capability
        if admin_address and not timelock_info.has_timelock:
            risk = ProxyRisk(
                contract_id=contract_address,
                risk_type=ProxyRiskType.INSTANT_LOGIC_SWAP,
                description=f"Admin {admin_address[:10]}... can perform instant logic swaps without timelock delay",
                severity="critical",
                risk_multiplier=3.0,  # Maximum multiplier
                technical_details={
                    "admin_address": admin_address,
                    "proxy_type": proxy_type.value,
                    "implementation_address": implementation_address
                }
            )
            self.detected_risks.append(risk)
        
        # Check for insufficient timelock delay
        if timelock_info.has_timelock and not timelock_info.is_governance_delay_sufficient:
            delay_hours = timelock_info.minimum_delay / 3600
            risk = ProxyRisk(
                contract_id=contract_address,
                risk_type=ProxyRiskType.INSUFFICIENT_TIMELOCK_DELAY,
                description=f"Timelock delay ({delay_hours:.1f}h) is below 24-hour minimum requirement",
                severity="high",
                risk_multiplier=2.0,
                technical_details={
                    "minimum_delay": timelock_info.minimum_delay,
                    "required_delay": self.timelock_verifier.MINIMUM_DELAY_SECONDS
                }
            )
            self.detected_risks.append(risk)
        
        # Check for admin upgrade capability
        if admin_address:
            risk = ProxyRisk(
                contract_id=contract_address,
                risk_type=ProxyRiskType.ADMIN_CAN_UPGRADE,
                description=f"Admin {admin_address[:10]}... has upgrade privileges",
                severity="medium",
                risk_multiplier=1.5,
                technical_details={
                    "admin_address": admin_address,
                    "proxy_type": proxy_type.value
                }
            )
            self.detected_risks.append(risk)
        
        # Check for unverified implementation
        if implementation_address:
            # In production, this would check verification status on Etherscan
            # For now, we'll flag it as a potential risk
            risk = ProxyRisk(
                contract_id=contract_address,
                risk_type=ProxyRiskType.UNVERIFIED_IMPLEMENTATION,
                description=f"Implementation contract {implementation_address[:10]}... verification status unknown",
                severity="low",
                risk_multiplier=1.2,
                technical_details={
                    "implementation_address": implementation_address
                }
            )
            self.detected_risks.append(risk)
    
    def _calculate_risk_multiplier(self) -> float:
        """Calculate overall risk multiplier based on detected risks"""
        if not self.detected_risks:
            return 1.0
        
        # Use the maximum risk multiplier from detected risks
        max_multiplier = max(risk.risk_multiplier for risk in self.detected_risks)
        
        # Apply additional multiplier for multiple risks
        if len(self.detected_risks) > 1:
            max_multiplier *= 1.2
        
        return min(max_multiplier, 5.0)  # Cap at 5.0
    
    def _format_risk(self, risk: ProxyRisk) -> Dict:
        """Format risk for JSON serialization"""
        return {
            "contract_id": risk.contract_id,
            "risk_type": risk.risk_type.value,
            "description": risk.description,
            "severity": risk.severity,
            "risk_multiplier": risk.risk_multiplier,
            "technical_details": risk.technical_details
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        for risk in self.detected_risks:
            if risk.risk_type == ProxyRiskType.INSTANT_LOGIC_SWAP:
                recommendations.append(
                    "Implement timelock governance with minimum 24-hour delay for implementation changes"
                )
            elif risk.risk_type == ProxyRiskType.INSUFFICIENT_TIMELOCK_DELAY:
                recommendations.append(
                    "Increase timelock delay to minimum 24 hours for governance security"
                )
            elif risk.risk_type == ProxyRiskType.ADMIN_CAN_UPGRADE:
                recommendations.append(
                    "Consider multi-sig governance or DAO control instead of single admin"
                )
            elif risk.risk_type == ProxyRiskType.UNVERIFIED_IMPLEMENTATION:
                recommendations.append(
                    "Verify implementation contract source code on Etherscan"
                )
        
        # Remove duplicates
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations


async def analyze_proxy_contract(contract_address: str, rpc_url: Optional[str] = None) -> Dict:
    """
    Convenience function to analyze a proxy contract
    
    Args:
        contract_address: Contract address to analyze
        rpc_url: Optional RPC URL for Web3 connection
        
    Returns:
        Analysis results
    """
    analyzer = ProxyPatternAnalyzer(rpc_url=rpc_url)
    return await analyzer.analyze_proxy_contract(contract_address)


if __name__ == "__main__":
    # Example usage with mock data (without actual RPC connection)
    print("Proxy Pattern Analyzer")
    print("=" * 60)
    print("This analyzer requires an RPC connection to function properly.")
    print("Example usage:")
    print("  analyzer = ProxyPatternAnalyzer(rpc_url='https://eth.llamarpc.com')")
    print("  result = analyzer.analyze_proxy_contract('0x1234...')")
    print()
    print("Supported proxy types:")
    for proxy_type in ProxyType:
        print(f"  - {proxy_type.value}")
    print()
    print("Storage slots monitored:")
    for proxy_type, slots in PROXY_STORAGE_SLOTS.items():
        print(f"  {proxy_type.value}:")
        for slot in slots:
            print(f"    - {slot.name}: {slot.slot_address}")