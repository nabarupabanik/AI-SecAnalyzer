"""
Unit Tests for Constraint Engine - Patent Critical Component

Tests the three-constraint evaluation system:
1. Data Flow Reachability (taint tracking across STG)
2. Execution Order (AST + control flow)
3. Privilege Compatibility (role hierarchy from code context)

Edges exist only when ALL constraints are satisfied simultaneously.
"""

import pytest
from unittest.mock import Mock, patch
import networkx as nx

from scanner.constraint_engine import (
    ConstraintEngine, VulnerabilityNode, ConstraintResult,
    evaluate_constraints
)
from scanner.stg_builder import STGGraph, STGNode
from scanner.models import VulnerabilityFinding


class TestConstraintEngine:
    """Test suite for Constraint Engine functionality"""
    
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
            ),
            STGNode(
                id="node3", file="test.py", line=3, transaction_type="auth_change",
                state_change="", entry_points=["credentials"], exit_points=["session"],
                data_sources=["credentials"], data_sinks=["session"],
                function_name="func3", variables_modified=[], variables_accessed=[]
            )
        ]
        self.stg_graph.edges = [
            {"from": "node1", "to": "node2", "type": "data_flow", "tainted": True, "variables": ["x"]},
            {"from": "node2", "to": "node3", "type": "data_flow", "tainted": False, "variables": []}
        ]
        
        self.engine = ConstraintEngine(self.stg_graph)
        
        # Create test vulnerabilities
        self.vuln1 = VulnerabilityFinding(
            file="test.py", line=1, type="SQL Injection", severity="High",
            code="cursor.execute(query)", fingerprint="vuln1"
        )
        self.vuln2 = VulnerabilityFinding(
            file="test.py", line=2, type="XSS", severity="Medium",
            code="return user_data", fingerprint="vuln2"
        )
    
    def test_engine_initialization(self):
        """Test constraint engine initialization"""
        assert isinstance(self.engine.stg_graph, STGGraph)
        assert isinstance(self.engine.data_flow_graph, nx.DiGraph)
        assert len(self.engine.data_flow_graph.nodes) == 3
        assert len(self.engine.data_flow_graph.edges) == 2
    
    def test_build_data_flow_graph(self):
        """Test data flow graph construction"""
        graph = self.engine._build_data_flow_graph()
        
        assert isinstance(graph, nx.DiGraph)
        assert "node1" in graph.nodes
        assert "node2" in graph.nodes
        assert "node3" in graph.nodes
        
        # Check edge data
        edge_data = graph["node1"]["node2"]
        assert edge_data["type"] == "data_flow"
        assert edge_data["tainted"] == True
    
    def test_evaluate_data_flow_constraint_valid(self):
        """Test valid data flow constraint evaluation"""
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="user",
            tainted_inputs=["user_input"]
        )
        to_node = VulnerabilityNode(
            id="vuln2", stg_node_id="node2", vulnerability=self.vuln2,
            entry_point=False, sink_type="memory", privilege_level="user",
            tainted_inputs=[]
        )
        
        result = self.engine._evaluate_data_flow_constraint(from_node, to_node)
        
        assert result[0] == True  # data_flow_valid
        assert len(result[1]) > 0  # path exists
        assert "node1" in result[1]
        assert "node2" in result[1]
    
    def test_evaluate_data_flow_constraint_invalid(self):
        """Test invalid data flow constraint evaluation"""
        # Create nodes with no path
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="user",
            tainted_inputs=[]
        )
        to_node = VulnerabilityNode(
            id="vuln3", stg_node_id="nonexistent", vulnerability=self.vuln2,
            entry_point=False, sink_type="memory", privilege_level="user",
            tainted_inputs=[]
        )
        
        result = self.engine._evaluate_data_flow_constraint(from_node, to_node)
        
        assert result[0] == False  # data_flow_invalid
        assert len(result[1]) == 0  # no path
    
    def test_evaluate_execution_order_constraint_valid(self):
        """Test valid execution order constraint"""
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="user",
            tainted_inputs=[]
        )
        to_node = VulnerabilityNode(
            id="vuln2", stg_node_id="node2", vulnerability=self.vuln2,
            entry_point=False, sink_type="memory", privilege_level="user",
            tainted_inputs=[]
        )
        
        result = self.engine._evaluate_execution_order_constraint(from_node, to_node)
        
        assert result[0] == True  # execution_order_valid
        assert result[1] > 0  # distance > 0
    
    def test_evaluate_execution_order_constraint_same_file(self):
        """Test execution order constraint in same file"""
        # Test with same file, different lines
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="user",
            tainted_inputs=[]
        )
        to_node = VulnerabilityNode(
            id="vuln2", stg_node_id="node2", vulnerability=self.vuln2,
            entry_point=False, sink_type="memory", privilege_level="user",
            tainted_inputs=[]
        )
        
        result = self.engine._evaluate_execution_order_constraint(from_node, to_node)
        
        assert result[0] == True
        assert result[1] == 1  # line 2 - line 1
    
    def test_evaluate_privilege_constraint_valid(self):
        """Test valid privilege constraint"""
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="user",
            tainted_inputs=[]
        )
        to_node = VulnerabilityNode(
            id="vuln2", stg_node_id="node2", vulnerability=self.vuln2,
            entry_point=False, sink_type="memory", privilege_level="user",
            tainted_inputs=[]
        )
        
        result = self.engine._evaluate_privilege_constraint(from_node, to_node)
        
        assert result[0] == True  # privilege_valid
        assert result[1] == 0  # no escalation needed
    
    def test_evaluate_privilege_constraint_escalation(self):
        """Test privilege constraint with escalation"""
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="user",
            tainted_inputs=[]
        )
        to_node = VulnerabilityNode(
            id="vuln2", stg_node_id="node2", vulnerability=self.vuln2,
            entry_point=False, sink_type="memory", privilege_level="admin",
            tainted_inputs=[]
        )
        
        result = self.engine._evaluate_privilege_constraint(from_node, to_node)
        
        assert result[0] == True  # escalation allowed (user -> admin)
        assert result[1] == 2  # privilege gap
    
    def test_evaluate_privilege_constraint_invalid(self):
        """Test invalid privilege constraint (too much escalation)"""
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="anonymous",
            tainted_inputs=[]
        )
        to_node = VulnerabilityNode(
            id="vuln2", stg_node_id="node2", vulnerability=self.vuln2,
            entry_point=False, sink_type="system", privilege_level="root",
            tainted_inputs=[]
        )
        
        result = self.engine._evaluate_privilege_constraint(from_node, to_node)
        
        assert result[0] == False  # too much escalation
        assert result[1] > 2  # large privilege gap
    
    def test_infer_privilege_level(self):
        """Test privilege level inference"""
        # Test admin operations
        vuln_admin = VulnerabilityFinding(
            file="test.py", line=1, type="admin_access", severity="High",
            code="admin_panel()", fingerprint="vuln_admin"
        )
        privilege = self.engine._infer_privilege_level(vuln_admin, self.stg_graph.nodes[0])
        assert privilege == "admin"
        
        # Test auth operations
        vuln_auth = VulnerabilityFinding(
            file="test.py", line=1, type="login_bypass", severity="High",
            code="check_login()", fingerprint="vuln_auth"
        )
        privilege = self.engine._infer_privilege_level(vuln_auth, self.stg_graph.nodes[0])
        assert privilege == "authenticated"
        
        # Test default
        vuln_default = VulnerabilityFinding(
            file="test.py", line=1, type="unknown", severity="Low",
            code="some_function()", fingerprint="vuln_default"
        )
        privilege = self.engine._infer_privilege_level(vuln_default, self.stg_graph.nodes[0])
        assert privilege == "anonymous"
    
    def test_infer_sink_type(self):
        """Test sink type inference"""
        # Test database operations
        vuln_db = VulnerabilityFinding(
            file="test.py", line=1, type="SQL Injection", severity="High",
            code="cursor.execute()", fingerprint="vuln_db"
        )
        sink_type = self.engine._infer_sink_type(vuln_db, self.stg_graph.nodes[0])
        assert sink_type == "database"
        
        # Test XSS
        vuln_xss = VulnerabilityFinding(
            file="test.py", line=1, type="XSS", severity="Medium",
            code="return user_data", fingerprint="vuln_xss"
        )
        sink_type = self.engine._infer_sink_type(vuln_xss, self.stg_graph.nodes[0])
        assert sink_type == "web_application"
    
    def test_is_entry_point(self):
        """Test entry point detection"""
        # Test known entry point types
        vuln_sql = VulnerabilityFinding(
            file="test.py", line=1, type="SQL Injection", severity="High",
            code="cursor.execute()", fingerprint="vuln_sql"
        )
        is_entry = self.engine._is_entry_point(vuln_sql, self.stg_graph.nodes[0])
        assert is_entry == True
        
        # Test non-entry point
        vuln_info = VulnerabilityFinding(
            file="test.py", line=1, type="information_disclosure", severity="Low",
            code="log_message()", fingerprint="vuln_info"
        )
        is_entry = self.engine._is_entry_point(vuln_info, self.stg_graph.nodes[0])
        assert is_entry == False
    
    def test_create_vulnerability_nodes(self):
        """Test vulnerability node creation"""
        vulnerabilities = [self.vuln1, self.vuln2]
        vuln_nodes = self.engine.create_vulnerability_nodes(vulnerabilities)
        
        assert len(vuln_nodes) == 2
        assert all(isinstance(node, VulnerabilityNode) for node in vuln_nodes)
        assert all(node.stg_node_id in ["node1", "node2"] for node in vuln_nodes)
    
    def test_evaluate_constraints_all_satisfied(self):
        """Test constraint evaluation when all constraints are satisfied"""
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="user",
            tainted_inputs=["user_input"]
        )
        to_node = VulnerabilityNode(
            id="vuln2", stg_node_id="node2", vulnerability=self.vuln2,
            entry_point=False, sink_type="memory", privilege_level="user",
            tainted_inputs=[]
        )
        
        result = self.engine.evaluate_constraints(from_node, to_node)
        
        assert isinstance(result, ConstraintResult)
        assert result.data_flow_valid == True
        assert result.execution_order_valid == True
        assert result.privilege_valid == True
        assert result.all_constraints_satisfied == True
        assert len(result.data_flow_path) > 0
        assert result.execution_distance > 0
        assert result.privilege_gap == 0
    
    def test_evaluate_constraints_not_all_satisfied(self):
        """Test constraint evaluation when not all constraints are satisfied"""
        from_node = VulnerabilityNode(
            id="vuln1", stg_node_id="node1", vulnerability=self.vuln1,
            entry_point=True, sink_type="database", privilege_level="anonymous",
            tainted_inputs=[]
        )
        to_node = VulnerabilityNode(
            id="vuln3", stg_node_id="node3", vulnerability=self.vuln2,
            entry_point=False, sink_type="session", privilege_level="admin",
            tainted_inputs=[]
        )
        
        result = self.engine.evaluate_constraints(from_node, to_node)
        
        assert result.data_flow_valid == False  # No tainted data flow
        assert result.execution_order_valid == True
        assert result.privilege_valid == False  # Too much escalation
        assert result.all_constraints_satisfied == False
    
    def test_evaluate_all_constraints(self):
        """Test evaluation of all constraint pairs"""
        vulnerabilities = [self.vuln1, self.vuln2]
        result = self.engine.evaluate_all_constraints(vulnerabilities)
        
        assert "constraint_matrix" in result
        assert "satisfied_edges" in result
        assert "unsatisfied_edges" in result
        assert "statistics" in result
        
        stats = result["statistics"]
        assert "total_pairs" in stats
        assert "satisfied_pairs" in stats
        assert "unsatisfied_pairs" in stats
        assert "satisfaction_rate" in stats
        
        assert stats["total_pairs"] >= 0
        assert 0 <= stats["satisfaction_rate"] <= 1


class TestConstraintEngineIntegration:
    """Integration tests for Constraint Engine"""
    
    def test_evaluate_constraints_function(self):
        """Test the main constraint evaluation function"""
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
        
        result = evaluate_constraints(stg_graph, vulnerabilities)
        
        assert isinstance(result, dict)
        assert "constraint_matrix" in result
        assert "statistics" in result
    
    def test_empty_vulnerabilities(self):
        """Test constraint evaluation with no vulnerabilities"""
        stg_graph = STGGraph()
        result = evaluate_constraints(stg_graph, [])
        
        assert result["statistics"]["total_pairs"] == 0
        assert result["statistics"]["satisfaction_rate"] == 0
    
    def test_constraint_engine_with_no_stg_nodes(self):
        """Test constraint engine with empty STG"""
        stg_graph = STGGraph()
        engine = ConstraintEngine(stg_graph)
        
        vulnerabilities = [
            VulnerabilityFinding(
                file="test.py", line=1, type="SQL Injection", severity="High",
                code="cursor.execute()", fingerprint="vuln1"
            )
        ]
        
        vuln_nodes = engine.create_vulnerability_nodes(vulnerabilities)
        
        # Should handle empty STG gracefully
        assert len(vuln_nodes) == 0


if __name__ == "__main__":
    pytest.main([__file__])
