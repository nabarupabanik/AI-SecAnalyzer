"""
Exploit Constraint Graph (ECG) Builder - Patent Critical Component

Constructs ECG where edges exist only when ALL constraints are satisfied:
- Data flow reachability
- Execution order
- Privilege compatibility

Prevents infeasible exploit transitions from being represented.
"""

import networkx as nx
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

from .models import VulnerabilityFinding
from .stg_builder import STGGraph
from .constraint_engine import ConstraintEngine, VulnerabilityNode, ConstraintResult


@dataclass
class ECGNode:
    """Exploit Constraint Graph Node"""
    id: str
    vulnerability_id: str
    stg_node_id: str
    vulnerability_type: str
    severity: str
    entry_point: bool
    sink_type: str
    privilege_level: str
    file: str
    line: int


@dataclass
class ECGEdge:
    """Constraint-satisfied edge in ECG"""
    from_node: str
    to_node: str
    constraints_satisfied: Dict[str, bool]
    data_flow_path: List[str]
    execution_distance: int
    privilege_gap: int
    exploit_complexity: str


@dataclass
class ECGGraph:
    """Complete Exploit Constraint Graph"""
    nodes: List[ECGNode] = field(default_factory=list)
    edges: List[ECGEdge] = field(default_factory=list)
    constraint_matrix: Dict[str, Any] = field(default_factory=dict)
    eliminated_paths: int = 0
    total_possible_paths: int = 0


class ECGBuilder:
    """Builds Exploit Constraint Graph from STG and vulnerabilities"""
    
    def __init__(self, stg_graph: STGGraph):
        self.stg_graph = stg_graph
        self.constraint_engine = ConstraintEngine(stg_graph)
        self.vulnerability_nodes: List[VulnerabilityNode] = []
        
        # Complexity scoring
        self.complexity_weights = {
            "data_flow_distance": 0.3,
            "privilege_gap": 0.4,
            "execution_distance": 0.3
        }
    
    def _calculate_exploit_complexity(self, constraint_result: ConstraintResult) -> str:
        """Calculate exploit complexity from constraint results"""
        score = 0
        
        # Data flow complexity (longer path = more complex)
        if constraint_result.data_flow_path:
            score += len(constraint_result.data_flow_path) * self.complexity_weights["data_flow_distance"]
        
        # Privilege escalation complexity
        if constraint_result.privilege_gap > 0:
            score += constraint_result.privilege_gap * self.complexity_weights["privilege_gap"]
        
        # Execution distance complexity
        if constraint_result.execution_distance > 0:
            score += min(constraint_result.execution_distance / 100, 1.0) * self.complexity_weights["execution_distance"]
        
        # Classify complexity
        if score <= 0.5:
            return "low"
        elif score <= 1.5:
            return "medium"
        elif score <= 2.5:
            return "high"
        else:
            return "very_high"
    
    def _create_ecg_node(self, vuln_node: VulnerabilityNode) -> ECGNode:
        """Create ECG node from vulnerability node"""
        stg_node = self.stg_graph.nodes[
            next(i for i, node in enumerate(self.stg_graph.nodes) 
                 if node.id == vuln_node.stg_node_id)
        ]
        
        return ECGNode(
            id=vuln_node.id,
            vulnerability_id=vuln_node.vulnerability.fingerprint,
            stg_node_id=vuln_node.stg_node_id,
            vulnerability_type=vuln_node.vulnerability.type,
            severity=vuln_node.vulnerability.severity,
            entry_point=vuln_node.entry_point,
            sink_type=vuln_node.sink_type,
            privilege_level=vuln_node.privilege_level,
            file=vuln_node.vulnerability.file,
            line=vuln_node.vulnerability.line
        )
    
    def _create_ecg_edge(self, from_node: VulnerabilityNode, to_node: VulnerabilityNode,
                        constraint_result: ConstraintResult) -> ECGEdge:
        """Create ECG edge from constraint evaluation"""
        return ECGEdge(
            from_node=from_node.id,
            to_node=to_node.id,
            constraints_satisfied={
                "data_flow": constraint_result.data_flow_valid,
                "execution_order": constraint_result.execution_order_valid,
                "privilege": constraint_result.privilege_valid,
                "all_constraints_satisfied": True
            },
            data_flow_path=constraint_result.data_flow_path,
            execution_distance=constraint_result.execution_distance,
            privilege_gap=constraint_result.privilege_gap,
            exploit_complexity=self._calculate_exploit_complexity(constraint_result)
        )
    
    def _calculate_eliminated_paths(self, total_vulnerabilities: int) -> int:
        """Calculate number of eliminated infeasible paths"""
        if total_vulnerabilities <= 1:
            return 0
        
        # Total possible paths in complete graph
        total_possible = total_vulnerabilities * (total_vulnerabilities - 1)
        
        # Actual satisfied edges
        satisfied_edges = len([edge for edge in self.constraint_engine.evaluate_all_constraints(
            self.vulnerability_nodes)["satisfied_edges"]])
        
        eliminated = total_possible - satisfied_edges
        return max(0, eliminated)
    
    def build_ecg(self, vulnerabilities: List[VulnerabilityFinding]) -> ECGGraph:
        """Build complete Exploit Constraint Graph"""
        # Create vulnerability nodes
        self.vulnerability_nodes = self.constraint_engine.create_vulnerability_nodes(vulnerabilities)
        
        if len(self.vulnerability_nodes) <= 1:
            return ECGGraph()
        
        # Create ECG nodes
        ecg_nodes = [self._create_ecg_node(vuln_node) for vuln_node in self.vulnerability_nodes]
        
        # Evaluate all constraints
        constraint_results = self.constraint_engine.evaluate_all_constraints(self.vulnerability_nodes)
        
        # Create ECG edges only for satisfied constraints
        ecg_edges = []
        for satisfied_edge in constraint_results["satisfied_edges"]:
            from_node = next(v for v in self.vulnerability_nodes if v.id == satisfied_edge["from"])
            to_node = next(v for v in self.vulnerability_nodes if v.id == satisfied_edge["to"])
            
            ecg_edge = self._create_ecg_edge(from_node, to_node, satisfied_edge["constraints"])
            ecg_edges.append(ecg_edge)
        
        # Calculate eliminated paths
        total_possible = len(self.vulnerability_nodes) * (len(self.vulnerability_nodes) - 1)
        eliminated_paths = total_possible - len(ecg_edges)
        
        return ECGGraph(
            nodes=ecg_nodes,
            edges=ecg_edges,
            constraint_matrix=constraint_results["constraint_matrix"],
            eliminated_paths=eliminated_paths,
            total_possible_paths=total_possible
        )
    
    def to_dict(self, ecg_graph: ECGGraph) -> Dict[str, Any]:
        """Convert ECG to dictionary for JSON serialization"""
        return {
            "nodes": [
                {
                    "id": node.id,
                    "vulnerability_id": node.vulnerability_id,
                    "stg_node_id": node.stg_node_id,
                    "vulnerability_type": node.vulnerability_type,
                    "severity": node.severity,
                    "entry_point": node.entry_point,
                    "sink_type": node.sink_type,
                    "privilege_level": node.privilege_level,
                    "file": node.file,
                    "line": node.line
                }
                for node in ecg_graph.nodes
            ],
            "edges": [
                {
                    "from": edge.from_node,
                    "to": edge.to_node,
                    "constraints_satisfied": edge.constraints_satisfied,
                    "data_flow_path": edge.data_flow_path,
                    "execution_distance": edge.execution_distance,
                    "privilege_gap": edge.privilege_gap,
                    "exploit_complexity": edge.exploit_complexity
                }
                for edge in ecg_graph.edges
            ],
            "constraint_matrix": ecg_graph.constraint_matrix,
            "statistics": {
                "total_nodes": len(ecg_graph.nodes),
                "total_edges": len(ecg_graph.edges),
                "eliminated_paths": ecg_graph.eliminated_paths,
                "total_possible_paths": ecg_graph.total_possible_paths,
                "elimination_rate": ecg_graph.eliminated_paths / ecg_graph.total_possible_paths if ecg_graph.total_possible_paths > 0 else 0,
                "edge_complexity_distribution": {
                    complexity: len([e for e in ecg_graph.edges if e.exploit_complexity == complexity])
                    for complexity in ["low", "medium", "high", "very_high"]
                },
                "entry_points": len([n for n in ecg_graph.nodes if n.entry_point]),
                "sink_types": {
                    sink_type: len([n for n in ecg_graph.nodes if n.sink_type == sink_type])
                    for sink_type in set(n.sink_type for n in ecg_graph.nodes)
                }
            }
        }


def build_exploit_constraint_graph(stg_graph: STGGraph, 
                                  vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, Any]:
    """
    Build Exploit Constraint Graph for the given STG and vulnerabilities.
    
    Args:
        stg_graph: Semantic Transaction Graph
        vulnerabilities: List of vulnerability findings
        
    Returns:
        Dictionary representation of ECG
    """
    builder = ECGBuilder(stg_graph)
    ecg_graph = builder.build_ecg(vulnerabilities)
    return builder.to_dict(ecg_graph)
