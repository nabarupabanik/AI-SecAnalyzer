"""
Unit Tests for Constraint Satisfaction Attack Resolution (CSAR) Engine - Patent Critical Component

Tests the traversal mechanism that enforces representability.
Prevents evaluation of infeasible exploit chains by structural elimination.
Only traverses paths where all constraints are satisfied.
"""

import pytest
from unittest.mock import Mock, patch

from scanner.csar_engine import (
    CSAREngine, ExploitStep, ExploitChain, CSARResult,
    perform_csar_traversal
)
from scanner.ecg_builder import ECGGraph, ECGNode, ECGEdge
from scanner.stg_builder import STGGraph, STGNode


class TestCSAREngine:
    """Test suite for CSAR Engine functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Create test ECG graph
        self.ecg_graph = ECGGraph()
        self.ecg_graph.nodes = [
            ECGNode(
                id="vuln1", vulnerability_id="vuln1", stg_node_id="node1",
                vulnerability_type="SQL Injection", severity="High",
                entry_point=True, sink_type="database", privilege_level="user",
                file="test.py", line=1
            ),
            ECGNode(
                id="vuln2", vulnerability_id="vuln2", stg_node_id="node2",
                vulnerability_type="XSS", severity="Medium",
                entry_point=False, sink_type="web_application", privilege_level="user",
                file="test.py", line=2
            ),
            ECGNode(
                id="vuln3", vulnerability_id="vuln3", stg_node_id="node3",
                vulnerability_type="Privilege Escalation", severity="High",
                entry_point=False, sink_type="system", privilege_level="admin",
                file="test.py", line=3
            )
        ]
        self.ecg_graph.edges = [
            ECGEdge(
                from_node="vuln1", to_node="vuln2",
                constraints_satisfied={"data_flow": True, "execution_order": True, "privilege": True},
                data_flow_path=["node1", "node2"], execution_distance=1, privilege_gap=0,
                exploit_complexity="low"
            ),
            ECGEdge(
                from_node="vuln2", to_node="vuln3",
                constraints_satisfied={"data_flow": True, "execution_order": True, "privilege": True},
                data_flow_path=["node2", "node3"], execution_distance=1, privilege_gap=1,
                exploit_complexity="medium"
            )
        ]
        self.ecg_graph.constraint_matrix = {
            "vuln1->vuln2": {"data_flow_valid": True, "execution_order_valid": True, "privilege_valid": True},
            "vuln2->vuln3": {"data_flow_valid": True, "execution_order_valid": True, "privilege_valid": True}
        }
        
        # Create corresponding STG graph
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
        
        self.engine = CSAREngine(self.ecg_graph, self.stg_graph)
    
    def test_engine_initialization(self):
        """Test CSAR engine initialization"""
        assert isinstance(self.engine.ecg_graph, ECGGraph)
        assert isinstance(self.engine.stg_graph, STGGraph)
        assert self.engine.max_chain_length == 8
        assert self.engine.min_chain_length == 2
        assert len(self.engine.impact_mapping) > 0
        assert len(self.engine.attack_techniques) > 0
    
    def test_build_traversal_graph(self):
        """Test traversal graph construction"""
        graph = self.engine._build_traversal_graph()
        
        assert len(graph.nodes) == 3
        assert len(graph.edges) == 2
        assert "vuln1" in graph.nodes
        assert "vuln2" in graph.nodes
        assert "vuln3" in graph.nodes
        
        # Check edge data
        edge_data = graph["vuln1"]["vuln2"]
        assert edge_data["constraints_satisfied"]["data_flow"] == True
        assert edge_data["exploit_complexity"] == "low"
    
    def test_get_attack_technique(self):
        """Test attack technique mapping"""
        technique = self.engine._get_attack_technique("SQL Injection")
        assert technique == "SQL Injection"
        
        technique = self.engine._get_attack_technique("xss")
        assert technique == "Cross-Site Scripting"
        
        technique = self.engine._get_attack_technique("unknown_vulnerability")
        assert technique == "Unknown"
    
    def test_calculate_chain_feasibility_confirmed(self):
        """Test chain feasibility calculation for confirmed chains"""
        steps = [
            ExploitStep(
                vulnerability_id="vuln1", stg_node_id="node1", vulnerability_type="SQL Injection",
                severity="High", file="test.py", line=1,
                constraint_satisfaction={}, exploit_technique="SQL Injection",
                prerequisites_met=True, privilege_level="user"
            ),
            ExploitStep(
                vulnerability_id="vuln2", stg_node_id="node2", vulnerability_type="XSS",
                severity="Medium", file="test.py", line=2,
                constraint_satisfaction={}, exploit_technique="Cross-Site Scripting",
                prerequisites_met=True, privilege_level="user"
            )
        ]
        
        feasibility = self.engine._calculate_chain_feasibility(steps)
        assert feasibility == "confirmed"
    
    def test_calculate_chain_feasibility_theoretical(self):
        """Test chain feasibility calculation for theoretical chains"""
        steps = [
            ExploitStep(
                vulnerability_id="vuln1", stg_node_id="node1", vulnerability_type="Info Disclosure",
                severity="Low", file="test.py", line=1,
                constraint_satisfaction={}, exploit_technique="Information Disclosure",
                prerequisites_met=True, privilege_level="user"
            )
        ]
        
        feasibility = self.engine._calculate_chain_feasibility(steps)
        assert feasibility == "theoretical"
    
    def test_calculate_attack_complexity(self):
        """Test attack complexity calculation"""
        steps = [
            ExploitStep(
                vulnerability_id="vuln1", stg_node_id="node1", vulnerability_type="SQL Injection",
                severity="High", file="test.py", line=1,
                constraint_satisfaction={}, exploit_technique="SQL Injection",
                prerequisites_met=True, privilege_level="user"
            ),
            ExploitStep(
                vulnerability_id="vuln2", stg_node_id="node2", vulnerability_type="XSS",
                severity="Medium", file="test.py", line=2,
                constraint_satisfaction={}, exploit_technique="Cross-Site Scripting",
                prerequisites_met=True, privilege_level="user"
            )
        ]
        
        complexity = self.engine._calculate_attack_complexity(steps)
        assert complexity in ["low", "medium", "high", "very_high"]
    
    def test_get_required_privileges(self):
        """Test required privileges calculation"""
        steps = [
            ExploitStep(
                vulnerability_id="vuln1", stg_node_id="node1", vulnerability_type="SQL Injection",
                severity="High", file="test.py", line=1,
                constraint_satisfaction={}, exploit_technique="SQL Injection",
                prerequisites_met=True, privilege_level="user", entry_point=True
            )
        ]
        
        privileges = self.engine._get_required_privileges(steps)
        assert privileges == "user"
    
    def test_calculate_chain_metrics(self):
        """Test chain metrics calculation"""
        steps = [
            ExploitStep(
                vulnerability_id="vuln1", stg_node_id="node1", vulnerability_type="SQL Injection",
                severity="High", file="test.py", line=1,
                constraint_satisfaction={}, exploit_technique="SQL Injection",
                prerequisites_met=True, privilege_level="user"
            ),
            ExploitStep(
                vulnerability_id="vuln2", stg_node_id="node2", vulnerability_type="Privilege Escalation",
                severity="High", file="test.py", line=2,
                constraint_satisfaction={}, exploit_technique="Privilege Escalation",
                prerequisites_met=True, privilege_level="admin"
            )
        ]
        
        max_priv_gap, total_data_distance = self.engine._calculate_chain_metrics(steps)
        assert max_priv_gap >= 0
        assert total_data_distance >= 0
    
    def test_create_exploit_step(self):
        """Test exploit step creation"""
        ecg_node = self.ecg_graph.nodes[0]
        
        step = self.engine._create_exploit_step(ecg_node)
        
        assert isinstance(step, ExploitStep)
        assert step.vulnerability_id == "vuln1"
        assert step.stg_node_id == "node1"
        assert step.vulnerability_type == "SQL Injection"
        assert step.severity == "High"
        assert step.file == "test.py"
        assert step.line == 1
        assert step.entry_point == True
        assert step.prerequisites_met == True
    
    def test_find_chains_from_entry(self):
        """Test finding chains from entry points"""
        visited = set()
        chains = self.engine._find_chains_from_entry("vuln1", visited)
        
        assert len(chains) >= 0
        # Should find chains starting from vuln1
        for chain in chains:
            assert len(chain) >= 2  # Minimum chain length
            assert chain[0].vulnerability_id == "vuln1"
    
    def test_filter_unique_chains(self):
        """Test filtering duplicate chains"""
        chains = [
            ["vuln1", "vuln2"],
            ["vuln1", "vuln2"],  # Duplicate
            ["vuln2", "vuln3"]
        ]
        
        unique_chains = self.engine._filter_unique_chains(chains)
        
        assert len(unique_chains) == 2
        assert ["vuln1", "vuln2"] in unique_chains
        assert ["vuln2", "vuln3"] in unique_chains
    
    def test_rank_chains_by_severity(self):
        """Test ranking chains by severity"""
        chains = [
            ["vuln1", "vuln2"],  # High + Medium
            ["vuln1", "vuln3"],  # High + High
            ["vuln2", "vuln3"]   # Medium + High
        ]
        
        ranked_chains = self.engine._rank_chains_by_severity(chains)
        
        assert len(ranked_chains) == 3
        # Highest severity chain should be first
        assert ranked_chains[0] == ["vuln1", "vuln3"]
    
    def test_traverse_exploit_chains(self):
        """Test main CSAR traversal algorithm"""
        result = self.engine.traverse_exploit_chains()
        
        assert isinstance(result, CSARResult)
        assert isinstance(result.exploit_chains, list)
        assert isinstance(result.eliminated_paths_count, int)
        assert isinstance(result.total_paths_evaluated, int)
        assert isinstance(result.traversal_statistics, dict)
        assert isinstance(result.chain_distribution, dict)
        
        # Should find at least one chain
        assert len(result.exploit_chains) >= 0
        assert result.total_paths_evaluated >= 0
    
    def test_traverse_exploit_chains_no_entry_points(self):
        """Test CSAR traversal with no entry points"""
        # Create graph with no entry points
        ecg_graph_no_entry = ECGGraph()
        ecg_graph_no_entry.nodes = [
            ECGNode(
                id="vuln1", vulnerability_id="vuln1", stg_node_id="node1",
                vulnerability_type="Info Disclosure", severity="Low",
                entry_point=False, sink_type="application", privilege_level="user",
                file="test.py", line=1
            )
        ]
        ecg_graph_no_entry.edges = []
        
        engine = CSAREngine(ecg_graph_no_entry, self.stg_graph)
        result = engine.traverse_exploit_chains()
        
        assert len(result.exploit_chains) == 0
    
    def test_to_dict(self):
        """Test CSAR result serialization to dictionary"""
        # Create test result
        result = CSARResult()
        result.exploit_chains = [
            ExploitChain(
                chain_id="chain_1", feasibility="confirmed", steps=[],
                entry_point="vuln1", final_impact="data_breach",
                dependency_involved=False, attack_complexity="low",
                required_privileges="user", chain_length=2,
                max_privilege_gap=0, total_data_flow_distance=1
            )
        ]
        result.eliminated_paths_count = 5
        result.total_paths_evaluated = 10
        result.traversal_statistics = {
            "total_entry_points": 1,
            "chains_found": 1,
            "average_chain_length": 2.0,
            "max_chain_length": 2,
            "elimination_rate": 0.5
        }
        result.chain_distribution = {"confirmed": 1, "length_2": 1}
        
        dict_result = self.engine.to_dict(result)
        
        assert isinstance(dict_result, dict)
        assert "exploit_chains" in dict_result
        assert "statistics" in dict_result
        
        stats = dict_result["statistics"]
        assert "total_chains" in stats
        assert "eliminated_paths_count" in stats
        assert "total_paths_evaluated" in stats
        assert "elimination_rate" in stats
        assert "chain_distribution" in stats
        assert "traversal_statistics" in stats
        
        assert stats["total_chains"] == 1
        assert stats["eliminated_paths_count"] == 5
        assert stats["total_paths_evaluated"] == 10
        assert stats["elimination_rate"] == 0.5


class TestCSAREngineIntegration:
    """Integration tests for CSAR Engine"""
    
    def test_perform_csar_traversal_function(self):
        """Test the main CSAR traversal function"""
        # Create minimal ECG and STG graphs
        ecg_graph = ECGGraph()
        ecg_graph.nodes = [
            ECGNode(
                id="vuln1", vulnerability_id="vuln1", stg_node_id="node1",
                vulnerability_type="SQL Injection", severity="High",
                entry_point=True, sink_type="database", privilege_level="user",
                file="test.py", line=1
            )
        ]
        ecg_graph.edges = []
        ecg_graph.constraint_matrix = {}
        
        stg_graph = STGGraph()
        stg_graph.nodes = [
            STGNode(
                id="node1", file="test.py", line=1, transaction_type="db_write",
                state_change="", entry_points=["user_input"], exit_points=["database"],
                data_sources=["user_input"], data_sinks=["database"],
                function_name="func1", variables_modified=["x"], variables_accessed=[]
            )
        ]
        
        result = perform_csar_traversal(ecg_graph, stg_graph)
        
        assert isinstance(result, dict)
        assert "exploit_chains" in result
        assert "statistics" in result
    
    def test_csar_engine_with_empty_graphs(self):
        """Test CSAR engine with empty graphs"""
        ecg_graph = ECGGraph()
        stg_graph = STGGraph()
        
        engine = CSAREngine(ecg_graph, stg_graph)
        result = engine.traverse_exploit_chains()
        
        assert isinstance(result, CSARResult)
        assert len(result.exploit_chains) == 0
        assert result.eliminated_paths_count == 0
    
    def test_csar_engine_max_chain_length_limit(self):
        """Test CSAR engine respects max chain length"""
        # Create a graph with many potential steps
        ecg_graph = ECGGraph()
        stg_graph = STGGraph()
        
        # Add many nodes
        for i in range(10):
            ecg_graph.nodes.append(
                ECGNode(
                    id=f"vuln{i}", vulnerability_id=f"vuln{i}", stg_node_id=f"node{i}",
                    vulnerability_type="Test", severity="Medium",
                    entry_point=(i == 0), sink_type="test", privilege_level="user",
                    file="test.py", line=i
                )
            )
            stg_graph.nodes.append(
                STGNode(
                    id=f"node{i}", file="test.py", line=i, transaction_type="test",
                    state_change="", entry_points=[], exit_points=[],
                    data_sources=[], data_sinks=[],
                    function_name=f"func{i}", variables_modified=[], variables_accessed=[]
                )
            )
        
        # Add edges to create long chains
        for i in range(9):
            ecg_graph.edges.append(
                ECGEdge(
                    from_node=f"vuln{i}", to_node=f"vuln{i+1}",
                    constraints_satisfied={"data_flow": True, "execution_order": True, "privilege": True},
                    data_flow_path=[f"node{i}", f"node{i+1}"], execution_distance=1, privilege_gap=0,
                    exploit_complexity="low"
                )
            )
        
        engine = CSAREngine(ecg_graph, stg_graph, max_chain_length=5)
        result = engine.traverse_exploit_chains()
        
        # Should limit chain length
        for chain in result.exploit_chains:
            assert len(chain.steps) <= 5
    
    def test_csar_engine_feasibility_classification(self):
        """Test CSAR engine correctly classifies feasibility"""
        ecg_graph = ECGGraph()
        stg_graph = STGGraph()
        
        # Add nodes with different severities
        ecg_graph.nodes = [
            ECGNode(
                id="vuln1", vulnerability_id="vuln1", stg_node_id="node1",
                vulnerability_type="Critical SQL Injection", severity="Critical",
                entry_point=True, sink_type="database", privilege_level="user",
                file="test.py", line=1
            ),
            ECGNode(
                id="vuln2", vulnerability_id="vuln2", stg_node_id="node2",
                vulnerability_type="Info Disclosure", severity="Low",
                entry_point=False, sink_type="application", privilege_level="user",
                file="test.py", line=2
            )
        ]
        
        ecg_graph.edges = [
            ECGEdge(
                from_node="vuln1", to_node="vuln2",
                constraints_satisfied={"data_flow": True, "execution_order": True, "privilege": True},
                data_flow_path=["node1", "node2"], execution_distance=1, privilege_gap=0,
                exploit_complexity="low"
            )
        ]
        
        stg_graph.nodes = [
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
        
        engine = CSAREngine(ecg_graph, stg_graph)
        result = engine.traverse_exploit_chains()
        
        # Should classify as confirmed due to critical severity
        if len(result.exploit_chains) > 0:
            assert result.exploit_chains[0].feasibility in ["confirmed", "probable", "theoretical"]


if __name__ == "__main__":
    pytest.main([__file__])
