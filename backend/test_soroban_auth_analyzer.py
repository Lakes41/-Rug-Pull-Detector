"""
Test cases for Soroban Authorization Analyzer
Tests footprint parsing, DAG building, and authorization vector detection.
"""

import pytest
from soroban_auth_analyzer import (
    SorobanTraceParser,
    ExecutionDAGBuilder,
    AuthorizationVectorDetector,
    SorobanAuthAnalyzer,
    ContractNode,
    InvocationEdge,
    AuthRiskType,
    analyze_soroban_contract
)


class TestSorobanTraceParser:
    """Test footprint and invocation tree parsing"""
    
    def test_parse_footprint_basic(self):
        """Test basic footprint parsing"""
        parser = SorobanTraceParser()
        footprint_data = {
            "contract_id": "CABCD1234567890",
            "read": [
                {"type": "ledger_entry", "contract_id": "CABCD1234567890", "key": "balance"}
            ],
            "write": [
                {"type": "ledger_entry", "contract_id": "CABCD1234567890", "key": "balance", "delta": "-1000"}
            ],
            "auth": [
                {"contract_id": "CABCD1234567890", "function_name": "transfer", "signature_present": True}
            ]
        }
        
        result = parser.parse_footprint(footprint_data)
        
        assert result.contract_id == "CABCD1234567890"
        assert len(result.read_entries) == 1
        assert len(result.write_entries) == 1
        assert len(result.auth_entries) == 1
        assert result.auth_entries[0]["signature_present"] == True
    
    def test_parse_footprint_empty(self):
        """Test footprint parsing with empty data"""
        parser = SorobanTraceParser()
        result = parser.parse_footprint({})
        
        assert result.contract_id == "unknown"
        assert len(result.read_entries) == 0
        assert len(result.write_entries) == 0
        assert len(result.auth_entries) == 0
    
    def test_parse_invocation_tree(self):
        """Test invocation tree parsing"""
        parser = SorobanTraceParser()
        invocation_data = {
            "root": {
                "contract_id": "CABCD1234567890",
                "function_name": "transfer",
                "auth_required": True,
                "signature_verified": True,
                "host_checks": ["require_auth"],
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
        
        nodes = parser.parse_invocation_tree(invocation_data)
        
        assert len(nodes) == 2
        assert nodes[0].contract_id == "CABCD1234567890"
        assert nodes[0].function_name == "transfer"
        assert nodes[0].auth_required == True
        assert nodes[1].contract_id == "CDEF9876543210"
        assert nodes[1].function_name == "callback"
    
    def test_parse_invocation_node(self):
        """Test individual invocation node parsing"""
        parser = SorobanTraceParser()
        node_data = {
            "contract_id": "CABCD1234567890",
            "function_name": "mint",
            "auth_required": True,
            "signature_verified": False,
            "host_checks": ["require_auth_for_admin"],
            "sub_invocations": []
        }
        
        node = parser._parse_invocation_node(node_data)
        
        assert node.contract_id == "CABCD1234567890"
        assert node.function_name == "mint"
        assert node.auth_required == True
        assert node.signature_verified == False
        assert len(node.host_checks) == 1


class TestExecutionDAGBuilder:
    """Test DAG construction and traversal"""
    
    def test_build_dag_simple(self):
        """Test building a simple DAG"""
        builder = ExecutionDAGBuilder()
        nodes = [
            ContractNode(
                contract_id="C1",
                function_name="func1",
                sub_invocations=["C2"]
            ),
            ContractNode(
                contract_id="C2",
                function_name="func2",
                sub_invocations=[]
            )
        ]
        
        result = builder.build_dag(nodes)
        
        assert len(result) == 2
        assert "C1" in result
        assert "C2" in result
        assert len(builder.edges) == 1
        assert builder.edges[0].from_contract == "C1"
        assert builder.edges[0].to_contract == "C2"
    
    def test_build_dag_complex(self):
        """Test building a complex DAG with multiple edges"""
        builder = ExecutionDAGBuilder()
        nodes = [
            ContractNode(
                contract_id="C1",
                function_name="func1",
                sub_invocations=["C2", "C3"]
            ),
            ContractNode(
                contract_id="C2",
                function_name="func2",
                sub_invocations=["C4"]
            ),
            ContractNode(
                contract_id="C3",
                function_name="func3",
                sub_invocations=["C4"]
            ),
            ContractNode(
                contract_id="C4",
                function_name="func4",
                sub_invocations=[]
            )
        ]
        
        result = builder.build_dag(nodes)
        
        assert len(result) == 4
        assert len(builder.edges) == 3
    
    def test_get_execution_path(self):
        """Test execution path traversal"""
        builder = ExecutionDAGBuilder()
        nodes = [
            ContractNode(
                contract_id="C1",
                function_name="func1",
                sub_invocations=["C2"]
            ),
            ContractNode(
                contract_id="C2",
                function_name="func2",
                sub_invocations=["C3"]
            ),
            ContractNode(
                contract_id="C3",
                function_name="func3",
                sub_invocations=[]
            )
        ]
        
        builder.build_dag(nodes)
        path = builder.get_execution_path("C1")
        
        assert path == ["C1", "C2", "C3"]
    
    def test_detect_cycles_none(self):
        """Test cycle detection with no cycles"""
        builder = ExecutionDAGBuilder()
        nodes = [
            ContractNode(
                contract_id="C1",
                function_name="func1",
                sub_invocations=["C2"]
            ),
            ContractNode(
                contract_id="C2",
                function_name="func2",
                sub_invocations=[]
            )
        ]
        
        builder.build_dag(nodes)
        cycles = builder.detect_cycles()
        
        assert len(cycles) == 0
    
    def test_detect_cycles_present(self):
        """Test cycle detection with cycles"""
        builder = ExecutionDAGBuilder()
        nodes = [
            ContractNode(
                contract_id="C1",
                function_name="func1",
                sub_invocations=["C2"]
            ),
            ContractNode(
                contract_id="C2",
                function_name="func2",
                sub_invocations=["C1"]  # Creates cycle
            )
        ]
        
        builder.build_dag(nodes)
        cycles = builder.detect_cycles()
        
        assert len(cycles) > 0


class TestAuthorizationVectorDetector:
    """Test authorization risk detection"""
    
    def test_detect_signature_bypass(self):
        """Test signature bypass detection"""
        builder = ExecutionDAGBuilder()
        detector = AuthorizationVectorDetector(builder)
        
        node = ContractNode(
            contract_id="C1",
            function_name="transfer",
            auth_required=True,
            signature_verified=False
        )
        
        nodes = {"C1": node}
        risks = detector.detect_risks(nodes)
        
        assert len(risks) > 0
        assert any(r.risk_type == AuthRiskType.SIGNATURE_BYPASS for r in risks)
    
    def test_detect_unchecked_sub_invocations(self):
        """Test unchecked sub-invocation detection"""
        builder = ExecutionDAGBuilder()
        detector = AuthorizationVectorDetector(builder)
        
        node = ContractNode(
            contract_id="C1",
            function_name="delegate_call",
            sub_invocations=["C2", "C3"],
            host_checks=[]
        )
        
        nodes = {"C1": node}
        risks = detector.detect_risks(nodes)
        
        assert len(risks) > 0
        assert any(r.risk_type == AuthRiskType.UNCHECKED_SUB_INVOCATION for r in risks)
    
    def test_detect_privileged_auth_vectors(self):
        """Test privileged auth vector detection"""
        builder = ExecutionDAGBuilder()
        detector = AuthorizationVectorDetector(builder)
        
        node = ContractNode(
            contract_id="C1",
            function_name="admin_upgrade",
            auth_required=True,
            signature_verified=False
        )
        
        nodes = {"C1": node}
        risks = detector.detect_risks(nodes)
        
        assert len(risks) > 0
        assert any(r.risk_type == AuthRiskType.PRIVILEGED_AUTH_VECTOR for r in risks)
    
    def test_detect_arbitrary_call_forwarding(self):
        """Test arbitrary call forwarding detection"""
        builder = ExecutionDAGBuilder()
        detector = AuthorizationVectorDetector(builder)
        
        node = ContractNode(
            contract_id="C1",
            function_name="forward_calls",
            sub_invocations=["C2", "C3", "C4"]
        )
        
        nodes = {"C1": node}
        risks = detector.detect_risks(nodes)
        
        assert len(risks) > 0
        assert any(r.risk_type == AuthRiskType.ARBITRARY_CALL_FORWARDING for r in risks)
    
    def test_detect_missing_host_checks(self):
        """Test missing host check detection"""
        builder = ExecutionDAGBuilder()
        detector = AuthorizationVectorDetector(builder)
        
        node = ContractNode(
            contract_id="C1",
            function_name="drain_tokens",
            host_checks=[]
        )
        
        nodes = {"C1": node}
        risks = detector.detect_risks(nodes)
        
        assert len(risks) > 0
        assert any(r.risk_type == AuthRiskType.MISSING_HOST_CHECK for r in risks)
    
    def test_no_risks_safe_contract(self):
        """Test that safe contracts have no detected risks"""
        builder = ExecutionDAGBuilder()
        detector = AuthorizationVectorDetector(builder)
        
        node = ContractNode(
            contract_id="C1",
            function_name="safe_function",
            auth_required=True,
            signature_verified=True,
            host_checks=["require_auth"],
            sub_invocations=[]
        )
        
        nodes = {"C1": node}
        risks = detector.detect_risks(nodes)
        
        # Should have no critical/high risks
        critical_high = [r for r in risks if r.severity in ["critical", "high"]]
        assert len(critical_high) == 0


class TestSorobanAuthAnalyzer:
    """Test main analyzer integration"""
    
    def test_analyze_transaction(self):
        """Test complete transaction analysis"""
        analyzer = SorobanAuthAnalyzer()
        
        transaction_trace = {
            "footprint": {
                "contract_id": "CABCD1234567890",
                "read": [{"type": "ledger_entry", "key": "balance"}],
                "write": [{"type": "ledger_entry", "key": "balance", "delta": "-1000"}],
                "auth": [{"contract_id": "CABCD1234567890", "function_name": "transfer"}]
            },
            "invocation_tree": {
                "root": {
                    "contract_id": "CABCD1234567890",
                    "function_name": "transfer",
                    "auth_required": True,
                    "signature_verified": True,
                    "host_checks": ["require_auth"],
                    "sub_invocations": []
                }
            }
        }
        
        result = analyzer.analyze_transaction(transaction_trace)
        
        assert "footprint" in result
        assert "execution_nodes" in result
        assert "risk_vectors" in result
        assert "total_contracts" in result
        assert result["total_contracts"] == 1
    
    def test_generate_report(self):
        """Test report generation"""
        analyzer = SorobanAuthAnalyzer()
        
        analysis_result = {
            "total_contracts": 2,
            "critical_risks": 1,
            "high_risks": 2,
            "cycles_detected": [],
            "risk_vectors": []
        }
        
        report = analyzer.generate_report(analysis_result)
        
        assert "SOROBAN AUTHORIZATION RISK ANALYSIS REPORT" in report
        assert "Total Contracts Analyzed: 2" in report
        assert "Critical Risks Found: 1" in report
        assert "High Risks Found: 2" in report
    
    def test_generate_report_with_cycles(self):
        """Test report generation with cycles"""
        analyzer = SorobanAuthAnalyzer()
        
        analysis_result = {
            "total_contracts": 2,
            "critical_risks": 0,
            "high_risks": 0,
            "cycles_detected": [["C1", "C2", "C1"]],
            "risk_vectors": []
        }
        
        report = analyzer.generate_report(analysis_result)
        
        assert "CYCLES DETECTED" in report


class TestConvenienceFunction:
    """Test convenience functions"""
    
    def test_analyze_soroban_contract(self):
        """Test the convenience function"""
        mock_trace = {
            "footprint": {
                "contract_id": "CABCD1234567890",
                "read": [],
                "write": [],
                "auth": []
            },
            "invocation_tree": {
                "root": {
                    "contract_id": "CABCD1234567890",
                    "function_name": "transfer",
                    "auth_required": True,
                    "signature_verified": True,
                    "host_checks": [],
                    "sub_invocations": []
                }
            }
        }
        
        result = analyze_soroban_contract(mock_trace)
        
        assert "footprint" in result
        assert "execution_nodes" in result
        assert "risk_vectors" in result


class TestRugPullScenarios:
    """Test realistic rug pull scenarios"""
    
    def test_drain_attack_scenario(self):
        """Test detection of drain attack pattern"""
        analyzer = SorobanAuthAnalyzer()
        
        # Simulate a drain attack where admin can drain without signature
        transaction_trace = {
            "footprint": {
                "contract_id": "CPOOL1234567890",
                "read": [],
                "write": [{"type": "ledger_entry", "key": "reserves", "delta": "-1000000"}],
                "auth": [{"contract_id": "CPOOL1234567890", "function_name": "drain", "signature_present": False}]
            },
            "invocation_tree": {
                "root": {
                    "contract_id": "CPOOL1234567890",
                    "function_name": "drain",
                    "auth_required": True,
                    "signature_verified": False,
                    "host_checks": [],
                    "sub_invocations": []
                }
            }
        }
        
        result = analyzer.analyze_transaction(transaction_trace)
        
        # Should detect signature bypass
        assert result["critical_risks"] > 0
        assert any(r.risk_type == AuthRiskType.SIGNATURE_BYPASS for r in result["risk_vectors"])
    
    def test_reentrancy_scenario(self):
        """Test detection of reentrancy via cycles"""
        analyzer = SorobanAuthAnalyzer()
        
        # Simulate reentrancy with cycle
        transaction_trace = {
            "footprint": {
                "contract_id": "CPOOL1234567890",
                "read": [],
                "write": [],
                "auth": []
            },
            "invocation_tree": {
                "root": {
                    "contract_id": "C1",
                    "function_name=": "withdraw",
                    "auth_required": True,
                    "signature_verified": True,
                    "host_checks": [],
                    "sub_invocations=[": "C2"]
                },
                "children": [
                    {
                        "contract_id": "C2",
                        "function_name": "callback",
                        "auth_required": False,
                        "signature_verified": True,
                        "host_checks": [],
                        "sub_invocations=[": "C1"  # Creates cycle
                    }
                ]
            }
        }
        
        result = analyzer.analyze_transaction(transaction_trace)
        
        # Should detect cycle
        assert len(result["cycles_detected"]) > 0
    
    def test_unchecked_delegate_call_scenario(self):
        """Test detection of unchecked delegate call"""
        analyzer = SorobanAuthAnalyzer()
        
        transaction_trace = {
            "footprint": {
                "contract_id": "CPOOL1234567890",
                "read": [],
                "write": [],
                "auth": []
            },
            "invocation_tree": {
                "root": {
                    "contract_id": "CPOOL1234567890",
                    "function_name": "delegate_execute",
                    "auth_required": True,
                    "signature_verified": True,
                    "host_checks": [],
                    "sub_invocations=[": "CMALICIOUS123456"
                }
            }
        }
        
        result = analyzer.analyze_transaction(transaction_trace)
        
        # Should detect unchecked sub-invocation
        assert result["high_risks"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
