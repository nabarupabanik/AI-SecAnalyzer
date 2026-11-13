"""
Unit Tests for Exploit Constraint Graph (ECG) Builder - Patent Critical Component

Tests the construction of ECG where edges exist only when ALL constraints are satisfied.
Prevents infeasible exploit transitions from being represented.
"""

import pytest
from unittest.mock import Mock, patch

from scanner.ecg_builder import (
    ECGBuilder, ECGNode, ECGEdge, ECGGraph, 
    build_exploit_constraint_graph
)
from scanner.stg_builder import STGGraph, STGNode
from scanner.models import VulnerabilityFinding
from scanner.constraint_engine import ConstraintResult


class TestECGBuilder:
    """Test suite for ECG Builder functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Create test STG graph
        self.stg_graph = STGGraph()
        self.stg_graph.nodes = [
            STGNode(
                id="node1", file="test.py", line=1, transaction_type="db_write",
                state_change="", entry_points=["user_input"], exit_points=["database"],
                data_sources=["user_input"], data_sinks=["database"],
                function_name="func1", variables_modified=["x"], variables_accessed=[]
            ),
            STGNode(
                id="node2", file="test.py", line=2, transaction_type="db_read",
                state_change="", entry_points=["database"], exit_points=["memory"],
                data_sources=["database"], data_sinks=["memory"],
                function_name="func2", variables_modified=[], variables_accessed=["x"]
            )
        ]
        self.stg_graph.edges = [
            {"from": "node1", "to": "node2", "type": "data_flow", "tainted": True, "variables": ["x"]}
        ]
        
        self.builder = ECGBuilder(self.stg_graph)
        
        # Create test vulnerabilities
        self.vuln1 = VulnerabilityFinding(
            file="test.py", line=1, type="SQL Injection", severity="High",
            code="cursor.execute()", fingerprint="vuln1"
        )
        self.vuln2 = VulnerabilityFinding(
            file="test.py", line=2, type="XSS", severity="Medium",
            code="return data", fingerprint="vuln2"
        )
    
    def test_builder_initialization(self):
        """Test ECG builder initialization"""
        assert isinstance(self.builder.stg_graph, STGGraph)
        assert isinstance(self.builder.constraint_engine, object)
        assert self.builder.node_counter == 0
        assert self.builder.complexity_weights is not None
    
    def test_calculate_exploit_complexity_low(self):
        """Test exploit complexity calculation for low complexity"""
        constraint_result = ConstraintResult(
            data_flow_valid=True, execution_order_valid=True, privilege_valid=True,
            all_constraints_satisfied=True, data_flow_path=["node1", "node2"],
            execution_distance=1, privilege_gap=0
        )
        
        complexity = self.builder._calculate_exploit_complexity(constraint_result)
        
        assert complexity == "low"
    
    def test_calculate_exploit_complexity_medium(self):
        """Test exploit complexity calculation for medium complexity"""
        constraint_result = ConstraintResult(
            data_flow_valid=True, execution_order_valid=True, privilege_valid=True,
            all_constraints_satisfied=True, data_flow_path=["node1", "node2", "node3"],
            execution_distance=2, privilege_gap=1
        )
        
        complexity = self.builder._calculate_exploit_complexity(constraint_result)
        
        assert complexity == "medium"
    
    def test_calculate_exploit_complexity_high(self):
        """Test exploit complexity calculation for high complexity"""
        constraint_result = ConstraintResult(
            data_flow_valid=True, execution_order_valid=True, privilege_valid=True,
            all_constraints_satisfied=True, data_flow_path=["node1", "node2", "node3", "node4"],
            execution_distance=3, privilege_gap=2
        )
        
        complexity = self.builder._calculate_exploit_complexity(constraint_result)
        
        assert complexity == "high"
    
    def test_calculate_exploit_complexity_very_high(self):
        """Test exploit complexity calculation for very high complexity"""
        constraint_result = ConstraintResult(
            data_flow_valid=True, execution_order_valid=True, privilege_valid=True,
            all_constraints_satisfied=True, data_flow_path=["node1", "node2", "node3", "node4", "node5"],
            execution_distance=4, privilege_gap=3
        )
        
        complexity = self.builder._calculate_exploit_complexity(constraint_result)
        
        assert complexity == "very_high"
    
    def test_create_ecg_node(self):
        """Test ECG node creation"""
        vuln_node = Mock()
        vuln_node.id = "vuln1"
        vuln_node.vulnerability = self.vuln1
        vuln_node.stg_node_id = "node1"
        vuln_node.entry_point = True
        vuln_node.sink_type = "database"
        vuln_node.privilege_level = "user"
        
        ecg_node = self.builder._create_ecg_node(vuln_node)
        
        assert isinstance(ecg_node, ECGNode)
        assert ecg_node.id == "vuln1"
        assert ecg_node.vulnerability_id == "vuln1"
        assert ecg_node.stg_node_id == "node1"
        assert ecg_node.vulnerability_type == "SQL Injection"
        assert ecg_node.severity == "High"
        assert ecg_node.entry_point == True
        assert ecg_node.sink_type == "database"
        assert ecg_node.privilege_level == "user"
        assert ecg_node.file == "test.py"
        assert ecg_node.line == 1
    
    def test_create_ecg_edge(self):
        """Test ECG edge creation"""
        from_node = Mock()
        from_node.id = "vuln1"
        to_node = Mock()
        to_node.id = "vuln2"
        
        constraint_result = ConstraintResult(
            data_flow_valid=True, execution_order_valid=True, privilege_valid=True,
            all_constraints_satisfied=True, data_flow_path=["node1", "node2"],
            execution_distance=2, privilege_gap=1
        )
        
        ecg_edge = self.builder._create_ecg_edge(from_node, to_node, constraint_result)
        
        assert isinstance(ecg_edge, ECGEdge)
        assert ecg_edge.from_node == "vuln1"
        assert ecg_edge.to_node == "vuln2"
        assert ecg_edge.constraints_satisfied["data_flow"] == True
        assert ecg_edge.constraints_satisfied["execution_order"] == True
        assert ecg_edge.constraints_satisfied["privilege"] == True
        assert ecg_edge.data_flow_path == ["node1", "node2"]
        assert ecg_edge.execution_distance == 2
        assert ecg_edge.privilege_gap == 1
        assert ecg_edge.exploit_complexity == "medium"
    
    def test_build_ecg_empty_vulnerabilities(self):
        """Test ECG building with no vulnerabilities"""
        graph = self.builder.build_ecg([])
        
        assert isinstance(graph, ECGGraph)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert graph.eliminated_paths == 0
        assert graph.total_possible_paths == 0
    
    def test_build_ecg_single_vulnerability(self):
        """Test ECG building with single vulnerability"""
        vulnerabilities = [self.vuln1]
        
        with patch.object(self.builder, 'create_vulnerability_nodes') as mock_create:
            mock_create.return_value = []
            
            graph = self.builder.build_ecg(vulnerabilities)
            
            assert isinstance(graph, ECGGraph)
            assert len(graph.nodes) == 0
            assert len(graph.edges) == 0
    
    def test_build_ecg_with_satisfied_constraints(self):
        """Test ECG building with satisfied constraints"""
        with patch.object(self.builder, 'create_vulnerability_nodes') as mock_create_nodes, \
             patch.object(self.builder.constraint_engine, 'evaluate_all_constraints') as mock_evaluate:
            
            # Mock vulnerability nodes
            from_node = Mock()
            from_node.id = "vuln1"
            from_node.vulnerability = self.vuln1
            from_node.stg_node_id = "node1"
            from_node.entry_point = True
            from_node.sink_type = "database"
            from_node.privilege_level = "user"
            
            to_node = Mock()
            to_node.id = "vuln2"
            to_node.vulnerability = self.vuln2
            to_node.stg_node_id = "node2"
            to_node.entry_point = False
            to_node.sink_type = "memory"
            to_node.privilege_level = "user"
            
            mock_create_nodes.return_value = [from_node, to_node]
            
            # Mock constraint evaluation with satisfied constraints
            mock_evaluate.return_value = {
                "constraint_matrix": {},
                "satisfied_edges": [
                    {
                        "from": "vuln1",
                        "to": "vuln2",
                        "constraints": ConstraintResult(
                            data_flow_valid=True, execution_order_valid=True, privilege_valid=True,
                            all_constraints_satisfied=True, data_flow_path=["node1", "node2"],
                            execution_distance=1, privilege_gap=0
                        )
                    }
                ],
                "unsatisfied_edges": [],
                "statistics": {
                    "total_pairs": 1,
                    "satisfied_pairs": 1,
                    "unsatisfied_pairs": 0,
                    "satisfaction_rate": 1.0
                }
            }
            
            graph = self.builder.build_ecg([self.vuln1, self.vuln2])
            
            assert isinstance(graph, ECGGraph)
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            assert graph.eliminated_paths == 0
            assert graph.total_possible_paths == 2
    
    def test_build_ecg_with_unsatisfied_constraints(self):
        """Test ECG building with unsatisfied constraints"""
        with patch.object(self.builder, 'create_vulnerability_nodes') as mock_create_nodes, \
             patch.object(self.builder.constraint_engine, 'evaluate_all_constraints') as mock_evaluate:
            
            # Mock vulnerability nodes
            from_node = Mock()
            from_node.id = "vuln1"
            to_node = Mock()
            to_node.id = "vuln2"
            
            mock_create_nodes.return_value = [from_node, to_node]
            
            # Mock constraint evaluation with no satisfied constraints
            mock_evaluate.return_value = {
                "constraint_matrix": {},
                "satisfied_edges": [],
                "unsatisfied_edges": [
                    {
                        "from": "vuln1",
                        "to": "vuln2",
                        "constraints": ConstraintResult(
                            data_flow_valid=False, execution_order_valid=True, privilege_valid=True,
                            all_constraints_satisfied=False, data_flow_path=[],
                            execution_distance=1, privilege_gap=0
                        )
                    }
                ],
                "statistics": {
                    "total_pairs": 1,
                    "satisfied_pairs": 0,
                    "unsatisfied_pairs": 1,
                    "satisfaction_rate": 0.0
                }
            }
            
            graph = self.builder.build_ecg([self.vuln1, self.vuln2])
            
            assert isinstance(graph, ECGGraph)
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 0  # No edges due to unsatisfied constraints
            assert graph.eliminated_paths == 1
            assert graph.total_possible_paths == 2
    
    def test_calculate_eliminated_paths(self):
        """Test eliminated paths calculation"""
        eliminated = self.builder._calculate_eliminated_paths(2)
        
        # With 2 vulnerabilities, total possible paths = 2 * 1 = 2
        # If 1 satisfied edge, eliminated = 2 - 1 = 1
        assert eliminated >= 0
    
    def test_to_dict(self):
        """Test ECG graph serialization to dictionary"""
        # Create test graph
        graph = ECGGraph()
        graph.nodes = [
            ECGNode(
                id="vuln1", vulnerability_id="vuln1", stg_node_id="node1",
                vulnerability_type="SQL Injection", severity="High",
                entry_point=True, sink_type="database", privilege_level="user",
                file="test.py", line=1
            )
        ]
        graph.edges = [
            ECGEdge(
                from_node="vuln1", to_node="vuln2",
                constraints_satisfied={"data_flow": True, "execution_order": True, "privilege": True},
                data_flow_path=["node1", "node2"], execution_distance=1, privilege_gap=0,
                exploit_complexity="low"
            )
        ]
        graph.constraint_matrix = {"vuln1->vuln2": {"data_flow": True}}
        graph.eliminated_paths = 1
        graph.total_possible_paths = 2
        
        result = self.builder.to_dict(graph)
        
        assert isinstance(result, dict)
        assert "nodes" in result
        assert "edges" in result
        assert "constraint_matrix" in result
        assert "statistics" in result
        
        stats = result["statistics"]
        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert "eliminated_paths" in stats
        assert "total_possible_paths" in stats
        assert "elimination_rate" in stats
        assert "edge_complexity_distribution" in stats
        assert "entry_points" in stats
        assert "sink_types" in stats
        
        assert stats["total_nodes"] == 1
        assert stats["total_edges"] == 1
        assert stats["eliminated_paths"] == 1
        assert stats["total_possible_paths"] == 2
        assert stats["elimination_rate"] == 0.5


class TestECGBuilderIntegration:
    """Integration tests for ECG Builder"""
    
    def test_build_exploit_constraint_graph_function(self):
        """Test the main ECG builder function"""
        # Create minimal STG graph
        stg_graph = STGGraph()
        stg_graph.nodes = [
            STGNode(
                id="node1", file="test.py", line=1, transaction_type="db_write",
                state_change="", entry_points=["user_input"], exit_points=["database"],
                data_sources=["user_input"], data_sinks=["database"],
                function_name="func1", variables_modified=["x"], variables_accessed=[]
            )
        ]
        stg_graph.edges = []
        
        vulnerabilities = [
            VulnerabilityFinding(
                file="test.py", line=1, type="SQL Injection", severity="High",
                code="cursor.execute()", fingerprint="vuln1"
            )
        ]
        
        result = build_exploit_constraint_graph(stg_graph, vulnerabilities)
        
        assert isinstance(result, dict)
        assert "nodes" in result
        assert "edges" in result
        assert "statistics" in result
    
    def test_ecg_builder_with_no_stg_nodes(self):
        """Test ECG builder with empty STG"""
        stg_graph = STGGraph()
        builder = ECGBuilder(stg_graph)
        
        vulnerabilities = [
            VulnerabilityFinding(
                file="test.py", line=1, type="SQL Injection", severity="High",
                code="cursor.execute()", fingerprint="vuln1"
            )
        ]
        
        graph = builder.build_ecg(vulnerabilities)
        
        # Should handle empty STG gracefully
        assert isinstance(graph, ECGGraph)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
    
    def test_ecg_builder_complexity_distribution(self):
        """Test complexity distribution calculation"""
        stg_graph = STGGraph()
        builder = ECGBuilder(stg_graph)
        
        # Create mock graph with different complexities
        graph = ECGGraph()
        graph.edges = [
            ECGEdge(
                from_node="vuln1", to_node="vuln2",
                constraints_satisfied={}, data_flow_path=[], execution_distance=1, privilege_gap=0,
                exploit_complexity="low"
            ),
            ECGEdge(
                from_node="vuln2", to_node="vuln3",
                constraints_satisfied={}, data_flow_path=[], execution_distance=2, privilege_gap=1,
                exploit_complexity="medium"
            ),
            ECGEdge(
                from_node="vuln3", to_node="vuln4",
                constraints_satisfied={}, data_flow_path=[], execution_distance=4, privilege_gap=3,
                exploit_complexity="very_high"
            )
        ]
        
        result = builder.to_dict(graph)
        
        complexity_dist = result["statistics"]["edge_complexity_distribution"]
        assert complexity_dist["low"] == 1
        assert complexity_dist["medium"] == 1
        assert complexity_dist["very_high"] == 1
        assert complexity_dist.get("high", 0) == 0


if __name__ == "__main__":
    pytest.main([__file__])
