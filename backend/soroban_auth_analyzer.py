"""
Soroban Authorization Analyzer
Analyzes Soroban smart contract authorization vectors to detect potential rug pulls.
Parses footprint metadata and invocation trees to build cross-contract call graphs.
"""

import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class AuthRiskType(Enum):
    """Types of authorization risks"""
    SIGNATURE_BYPASS = "signature_bypass"
    UNCHECKED_SUB_INVOCATION = "unchecked_sub_invocation"
    PRIVILEGED_AUTH_VECTOR = "privileged_auth_vector"
    ARBITRARY_CALL_FORWARDING = "arbitrary_call_forwarding"
    MISSING_HOST_CHECK = "missing_host_check"


@dataclass
class ContractNode:
    """Represents a contract in the execution graph"""
    contract_id: str
    function_name: str
    auth_required: bool = False
    signature_verified: bool = True
    host_checks: List[str] = field(default_factory=list)
    sub_invocations: List[str] = field(default_factory=list)
    risk_flags: List[AuthRiskType] = field(default_factory=list)


@dataclass
class InvocationEdge:
    """Represents an edge in the execution DAG"""
    from_contract: str
    to_contract: str
    invocation_type: str
    auth_passed: bool = True
    arbitrary_args: bool = False


@dataclass
class SorobanFootprint:
    """Parsed Soroban footprint metadata"""
    contract_id: str
    read_entries: List[Dict] = field(default_factory=list)
    write_entries: List[Dict] = field(default_factory=list)
    auth_entries: List[Dict] = field(default_factory=list)


@dataclass
class AuthorizationVector:
    """Represents a potential authorization vulnerability"""
    contract_id: str
    function_name: str
    risk_type: AuthRiskType
    description: str
    severity: str  # "critical", "high", "medium", "low"
    affected_contracts: List[str] = field(default_factory=list)


class SorobanTraceParser:
    """Parses Soroban transaction traces and footprint metadata"""
    
    def parse_footprint(self, footprint_data: Dict) -> SorobanFootprint:
        """
        Parse Soroban footprint metadata from transaction trace
        
        Args:
            footprint_data: Raw footprint data from soroban-env-host
            
        Returns:
            SorobanFootprint object with parsed entries
        """
        contract_id = footprint_data.get("contract_id", "unknown")
        
        read_entries = self._parse_storage_entries(
            footprint_data.get("read", [])
        )
        write_entries = self._parse_storage_entries(
            footprint_data.get("write", [])
        )
        auth_entries = self._parse_auth_entries(
            footprint_data.get("auth", [])
        )
        
        return SorobanFootprint(
            contract_id=contract_id,
            read_entries=read_entries,
            write_entries=write_entries,
            auth_entries=auth_entries
        )
    
    def _parse_storage_entries(self, entries: List) -> List[Dict]:
        """Parse storage ledger entries"""
        parsed = []
        for entry in entries:
            parsed.append({
                "type": entry.get("type", "unknown"),
                "contract_id": entry.get("contract_id"),
                "key": entry.get("key"),
                "delta": entry.get("delta")
            })
        return parsed
    
    def _parse_auth_entries(self, entries: List) -> List[Dict]:
        """Parse authorization entries from footprint"""
        parsed = []
        for entry in entries:
            parsed.append({
                "contract_id": entry.get("contract_id"),
                "function_name": entry.get("function_name"),
                "auth_type": entry.get("auth_type", "soroban_sdk::auth"),
                "signature_present": entry.get("signature_present", False),
                "invoked_by": entry.get("invoked_by")
            })
        return parsed
    
    def parse_invocation_tree(self, invocation_data: Dict) -> List[ContractNode]:
        """
        Parse invocation tree from soroban-env-host
        
        Args:
            invocation_data: Raw invocation tree data
            
        Returns:
            List of ContractNode objects representing execution path
        """
        nodes = []
        
        if "root" in invocation_data:
            root_node = self._parse_invocation_node(
                invocation_data["root"],
                is_root=True
            )
            nodes.append(root_node)
        
        if "children" in invocation_data:
            for child in invocation_data["children"]:
                child_node = self._parse_invocation_node(child)
                nodes.append(child_node)
        
        return nodes
    
    def _parse_invocation_node(self, node_data: Dict, is_root: bool = False) -> ContractNode:
        """Parse individual invocation node"""
        contract_id = node_data.get("contract_id", "unknown")
        function_name = node_data.get("function_name", "unknown")
        
        auth_required = node_data.get("auth_required", False)
        signature_verified = node_data.get("signature_verified", True)
        host_checks = node_data.get("host_checks", [])
        sub_invocations = node_data.get("sub_invocations", [])
        
        return ContractNode(
            contract_id=contract_id,
            function_name=function_name,
            auth_required=auth_required,
            signature_verified=signature_verified,
            host_checks=host_checks,
            sub_invocations=sub_invocations
        )


class ExecutionDAGBuilder:
    """Builds directed acyclic graph of multi-contract execution pathways"""
    
    def __init__(self):
        self.nodes: Dict[str, ContractNode] = {}
        self.edges: List[InvocationEdge] = []
    
    def build_dag(self, contract_nodes: List[ContractNode]) -> Dict[str, ContractNode]:
        """
        Build DAG from contract nodes
        
        Args:
            contract_nodes: List of ContractNode objects
            
        Returns:
            Dictionary mapping contract IDs to ContractNode objects
        """
        # Add all nodes
        for node in contract_nodes:
            self.nodes[node.contract_id] = node
        
        # Build edges from sub_invocations
        for node in contract_nodes:
            for sub_invocation in node.sub_invocations:
                edge = InvocationEdge(
                    from_contract=node.contract_id,
                    to_contract=sub_invocation,
                    invocation_type="contract_call",
                    auth_passed=node.signature_verified
                )
                self.edges.append(edge)
        
        return self.nodes
    
    def get_execution_path(self, start_contract: str) -> List[str]:
        """
        Get execution path starting from a contract
        
        Args:
            start_contract: Contract ID to start from
            
        Returns:
            List of contract IDs in execution order
        """
        visited = set()
        path = []
        self._traverse_dag(start_contract, visited, path)
        return path
    
    def _traverse_dag(self, contract_id: str, visited: Set[str], path: List[str]):
        """Recursive DAG traversal"""
        if contract_id in visited:
            return
        
        visited.add(contract_id)
        path.append(contract_id)
        
        # Find all outgoing edges
        for edge in self.edges:
            if edge.from_contract == contract_id:
                self._traverse_dag(edge.to_contract, visited, path)
    
    def detect_cycles(self) -> List[List[str]]:
        """
        Detect cycles in the execution graph (should be acyclic)
        
        Returns:
            List of cycles found (each cycle is a list of contract IDs)
        """
        cycles = []
        visited = set()
        rec_stack = set()
        path = []
        
        for contract_id in self.nodes:
            if contract_id not in visited:
                if self._detect_cycle_dfs(contract_id, visited, rec_stack, path, cycles):
                    pass
        
        return cycles
    
    def _detect_cycle_dfs(self, contract_id: str, visited: Set[str], 
                         rec_stack: Set[str], path: List[str], 
                         cycles: List[List[str]]) -> bool:
        """DFS for cycle detection"""
        visited.add(contract_id)
        rec_stack.add(contract_id)
        path.append(contract_id)
        
        for edge in self.edges:
            if edge.from_contract == contract_id:
                if edge.to_contract not in visited:
                    if self._detect_cycle_dfs(edge.to_contract, visited, rec_stack, path, cycles):
                        return True
                elif edge.to_contract in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(edge.to_contract)
                    cycle = path[cycle_start:] + [edge.to_contract]
                    cycles.append(cycle)
                    return True
        
        rec_stack.remove(contract_id)
        path.pop()
        return False


class AuthorizationVectorDetector:
    """Detects authorization vectors that could enable rug pulls"""
    
    def __init__(self, dag_builder: ExecutionDAGBuilder):
        self.dag_builder = dag_builder
        self.risk_vectors: List[AuthorizationVector] = []
    
    def detect_risks(self, nodes: Dict[str, ContractNode]) -> List[AuthorizationVector]:
        """
        Detect all authorization risks in the contract graph
        
        Args:
            nodes: Dictionary of contract nodes
            
        Returns:
            List of AuthorizationVector objects
        """
        self.risk_vectors = []
        
        for contract_id, node in nodes.items():
            self._check_signature_bypass(node)
            self._check_unchecked_sub_invocations(node)
            self._check_privileged_auth_vectors(node)
            self._check_arbitrary_call_forwarding(node)
            self._check_missing_host_checks(node)
        
        return self.risk_vectors
    
    def _check_signature_bypass(self, node: ContractNode):
        """Check if function bypasses signature verification"""
        if node.auth_required and not node.signature_verified:
            risk = AuthorizationVector(
                contract_id=node.contract_id,
                function_name=node.function_name,
                risk_type=AuthRiskType.SIGNATURE_BYPASS,
                description=f"Function {node.function_name} requires auth but signature verification is bypassed",
                severity="critical"
            )
            self.risk_vectors.append(risk)
    
    def _check_unchecked_sub_invocations(self, node: ContractNode):
        """Check if sub-invocations pass without host checks"""
        if node.sub_invocations and not node.host_checks:
            risk = AuthorizationVector(
                contract_id=node.contract_id,
                function_name=node.function_name,
                risk_type=AuthRiskType.UNCHECKED_SUB_INVOCATION,
                description=f"Function {node.function_name} performs sub-invocations without host authorization checks",
                severity="high",
                affected_contracts=node.sub_invocations
            )
            self.risk_vectors.append(risk)
    
    def _check_privileged_auth_vectors(self, node: ContractNode):
        """Check for privileged authorization vectors that allow maintainer control"""
        # Check if function can be called by admin/maintainer without user signature
        privileged_functions = ["admin", "owner", "maintainer", "upgrade", "migrate"]
        func_lower = node.function_name.lower()
        
        if any(priv in func_lower for priv in privileged_functions):
            if not node.signature_verified:
                risk = AuthorizationVector(
                    contract_id=node.contract_id,
                    function_name=node.function_name,
                    risk_type=AuthRiskType.PRIVILEGED_AUTH_VECTOR,
                    description=f"Privileged function {node.function_name} can be called without user signature verification",
                    severity="critical"
                )
                self.risk_vectors.append(risk)
    
    def _check_arbitrary_call_forwarding(self, node: ContractNode):
        """Check for arbitrary call forwarding patterns"""
        # Functions that forward calls to arbitrary addresses
        forwarding_keywords = ["call", "invoke", "delegate", "forward", "execute"]
        func_lower = node.function_name.lower()
        
        if any(keyword in func_lower for keyword in forwarding_keywords):
            if len(node.sub_invocations) > 1:
                risk = AuthorizationVector(
                    contract_id=node.contract_id,
                    function_name=node.function_name,
                    risk_type=AuthRiskType.ARBITRARY_CALL_FORWARDING,
                    description=f"Function {node.function_name} forwards calls to multiple contracts without proper validation",
                    severity="high",
                    affected_contracts=node.sub_invocations
                )
                self.risk_vectors.append(risk)
    
    def _check_missing_host_checks(self, node: ContractNode):
        """Check for missing host authorization checks"""
        critical_operations = ["transfer", "burn", "mint", "approve", "drain"]
        func_lower = node.function_name.lower()
        
        if any(op in func_lower for op in critical_operations):
            if "require_auth" not in str(node.host_checks).lower():
                risk = AuthorizationVector(
                    contract_id=node.contract_id,
                    function_name=node.function_name,
                    risk_type=AuthRiskType.MISSING_HOST_CHECK,
                    description=f"Critical function {node.function_name} missing host authorization check",
                    severity="high"
                )
                self.risk_vectors.append(risk)


class SorobanAuthAnalyzer:
    """Main analyzer for Soroban authorization risks"""
    
    def __init__(self):
        self.trace_parser = SorobanTraceParser()
        self.dag_builder = ExecutionDAGBuilder()
        self.auth_detector = None
    
    def analyze_transaction(self, transaction_trace: Dict) -> Dict:
        """
        Analyze a Soroban transaction for authorization risks
        
        Args:
            transaction_trace: Raw transaction trace from soroban-env-host
            
        Returns:
            Analysis results with risk vectors and execution graph
        """
        # Parse footprint metadata
        footprint = self.trace_parser.parse_footprint(
            transaction_trace.get("footprint", {})
        )
        
        # Parse invocation tree
        invocation_nodes = self.trace_parser.parse_invocation_tree(
            transaction_trace.get("invocation_tree", {})
        )
        
        # Build execution DAG
        nodes = self.dag_builder.build_dag(invocation_nodes)
        
        # Detect authorization risks
        self.auth_detector = AuthorizationVectorDetector(self.dag_builder)
        risk_vectors = self.auth_detector.detect_risks(nodes)
        
        # Check for cycles (should not exist in valid Soroban execution)
        cycles = self.dag_builder.detect_cycles()
        
        return {
            "footprint": footprint,
            "execution_nodes": nodes,
            "risk_vectors": risk_vectors,
            "cycles_detected": cycles,
            "total_contracts": len(nodes),
            "critical_risks": len([r for r in risk_vectors if r.severity == "critical"]),
            "high_risks": len([r for r in risk_vectors if r.severity == "high"]),
        }
    
    def generate_report(self, analysis_result: Dict) -> str:
        """
        Generate human-readable risk report
        
        Args:
            analysis_result: Result from analyze_transaction
            
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("SOROBAN AUTHORIZATION RISK ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append(f"Total Contracts Analyzed: {analysis_result['total_contracts']}")
        lines.append(f"Critical Risks Found: {analysis_result['critical_risks']}")
        lines.append(f"High Risks Found: {analysis_result['high_risks']}")
        lines.append("")
        
        if analysis_result["cycles_detected"]:
            lines.append("⚠️  CYCLES DETECTED IN EXECUTION GRAPH:")
            for cycle in analysis_result["cycles_detected"]:
                lines.append(f"  -> {' -> '.join(cycle)}")
            lines.append("")
        
        if analysis_result["risk_vectors"]:
            lines.append("RISK VECTORS DETECTED:")
            lines.append("-" * 60)
            for risk in analysis_result["risk_vectors"]:
                lines.append(f"\n[{risk.severity.upper()}] {risk.risk_type.value}")
                lines.append(f"Contract: {risk.contract_id}")
                lines.append(f"Function: {risk.function_name}")
                lines.append(f"Description: {risk.description}")
                if risk.affected_contracts:
                    lines.append(f"Affected Contracts: {', '.join(risk.affected_contracts)}")
        else:
            lines.append("✓ No authorization risks detected")
        
        lines.append("=" * 60)
        return "\n".join(lines)


def analyze_soroban_contract(transaction_trace: Dict) -> Dict:
    """
    Convenience function to analyze a Soroban contract transaction
    
    Args:
        transaction_trace: Raw transaction trace
        
    Returns:
        Analysis results
    """
    analyzer = SorobanAuthAnalyzer()
    return analyzer.analyze_transaction(transaction_trace)


if __name__ == "__main__":
    # Example usage with mock data
    mock_trace = {
        "footprint": {
            "contract_id": "CABCD1234567890",
            "read": [
                {"type": "ledger_entry", "contract_id": "CABCD1234567890", "key": "balance"}
            ],
            "write": [
                {"type": "ledger_entry", "contract_id": "CABCD1234567890", "key": "balance", "delta": "-1000"}
            ],
            "auth": [
                {"contract_id": "CABCD1234567890", "function_name": "transfer", "signature_present": False}
            ]
        },
        "invocation_tree": {
            "root": {
                "contract_id": "CABCD1234567890",
                "function_name": "transfer",
                "auth_required": True,
                "signature_verified": False,
                "host_checks": [],
                "sub_invocations": ["CDEF9876543210"]
            },
            "children": [
                {
                    "contract_id": "CDEF9876543210",
                    "function_name": "callback",
                    "auth_required": False,
                    "signature_verified": True,
                    "host_checks": [],
                    "sub_invocations": []
                }
            ]
        }
    }
    
    result = analyze_soroban_contract(mock_trace)
    analyzer = SorobanAuthAnalyzer()
    print(analyzer.generate_report(result))
