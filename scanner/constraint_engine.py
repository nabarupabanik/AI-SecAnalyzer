"""
Constraint Engine - Patent Critical Component

Implements the three core constraints for exploit chain validation:
1. Data Flow Reachability (taint tracking across STG)
2. Execution Order (AST + control flow)
3. Privilege Compatibility (role hierarchy from code context)

Edges exist only when ALL constraints are satisfied simultaneously.
"""

import ast
import networkx as nx
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict

from .models import VulnerabilityFinding
from .stg_builder import STGNode, STGGraph


@dataclass
class ConstraintResult:
    """Result of constraint evaluation"""
    data_flow_valid: bool
    execution_order_valid: bool
    privilege_valid: bool
    all_constraints_satisfied: bool
    data_flow_path: List[str] = None
    execution_distance: int = -1
    privilege_gap: int = -1


@dataclass
class VulnerabilityNode:
    """Vulnerability mapped to STG node"""
    id: str
    stg_node_id: str
    vulnerability: VulnerabilityFinding
    entry_point: bool
    sink_type: str
    privilege_level: str
    tainted_inputs: List[str]


class ConstraintEngine:
    """Evaluates constraints for exploit chain feasibility"""
    
    def __init__(self, stg_graph):
        self.stg_graph = stg_graph
        
        # Handle both STGGraph and dictionary formats
        if hasattr(stg_graph, 'nodes') and hasattr(stg_graph.nodes, '__iter__'):
            # STGGraph format - list of node objects
            self.stg_nodes = {node.id: node for node in stg_graph.nodes}
        elif isinstance(stg_graph, dict):
            # Dictionary format
            nodes_data = stg_graph.get("nodes", [])
            if isinstance(nodes_data, list):
                # List of node dictionaries - convert to node objects
                self.stg_nodes = {}
                for node_data in nodes_data:
                    node_id = node_data.get("id", "unknown")
                    # Create a simple node-like object
                    class SimpleNode:
                        def __init__(self, data):
                            self.id = data.get("id", "unknown")
                            self.file = data.get("file", "unknown")
                            self.line = data.get("line", 0)
                            self.transaction_type = data.get("transaction_type", "unknown")
                            self.state_change = data.get("state_change", "")
                            self.entry_points = data.get("entry_points", [])
                            self.exit_points = data.get("exit_points", [])
                            self.data_sources = data.get("data_sources", [])
                            self.data_sinks = data.get("data_sinks", [])
                            self.function_name = data.get("function_name", "unknown")
                            self.variables_modified = data.get("variables_modified", [])
                            self.variables_accessed = data.get("variables_accessed", [])
                    
                    self.stg_nodes[node_id] = SimpleNode(node_data)
            else:
                # Dictionary of nodes
                self.stg_nodes = {}
                for node_id, node_data in nodes_data.items():
                    class SimpleNode:
                        def __init__(self, data, nid):
                            self.id = nid
                            self.file = data.get("file", "unknown")
                            self.line = data.get("line", 0)
                            self.transaction_type = data.get("transaction_type", "unknown")
                            self.state_change = data.get("state_change", "")
                            self.entry_points = data.get("entry_points", [])
                            self.exit_points = data.get("exit_points", [])
                            self.data_sources = data.get("data_sources", [])
                            self.data_sinks = data.get("data_sinks", [])
                            self.function_name = data.get("function_name", "unknown")
                            self.variables_modified = data.get("variables_modified", [])
                            self.variables_accessed = data.get("variables_accessed", [])
                    
                    self.stg_nodes[node_id] = SimpleNode(node_data, node_id)
        else:
            self.stg_nodes = {}
        
        self.data_flow_graph = self._build_data_flow_graph()
        
        # Privilege hierarchy (higher number = higher privilege)
        self.privilege_hierarchy = {
            "anonymous": 0,
            "user": 1,
            "authenticated": 2,
            "privileged_user": 3,
            "admin": 4,
            "system": 5,
            "root": 6
        }
    
    def _build_data_flow_graph(self) -> nx.DiGraph:
        """Build data flow graph from STG"""
        graph = nx.DiGraph()
        
        # Handle both STGGraph and dictionary formats
        if hasattr(self.stg_graph, 'nodes') and hasattr(self.stg_graph.nodes, '__iter__'):
            # STGGraph format - list of node objects
            for node in self.stg_graph.nodes:
                graph.add_node(node.id, 
                             file=node.file,
                             line=node.line,
                             transaction_type=node.transaction_type)
            
            # Add edges
            for edge in self.stg_graph.edges:
                graph.add_edge(edge['from'], edge['to'],
                             type=edge['type'],
                             tainted=edge.get('tainted', False),
                             variables=edge.get('variables', []))
        elif isinstance(self.stg_graph, dict):
            # Dictionary format
            nodes_data = self.stg_graph.get("nodes", [])
            if isinstance(nodes_data, list):
                # List of node dictionaries
                for node_data in nodes_data:
                    node_id = node_data.get("id", "unknown")
                    graph.add_node(node_id, 
                                 file=node_data.get("file", "unknown"),
                                 line=node_data.get("line", 0),
                                 transaction_type=node_data.get("transaction_type", "unknown"))
            else:
                # Dictionary of nodes
                for node_id, node_data in nodes_data.items():
                    graph.add_node(node_id, 
                                 file=node_data.get("file", "unknown"),
                                 line=node_data.get("line", 0),
                                 transaction_type=node_data.get("transaction_type", "unknown"))
            
            # Add edges
            edges = self.stg_graph.get("edges", [])
            for edge in edges:
                from_node = edge.get("from", edge.get("from_node", "unknown"))
                to_node = edge.get("to", edge.get("to_node", "unknown"))
                graph.add_edge(from_node, to_node,
                             type=edge.get("type", "data_flow"),
                             tainted=edge.get("tainted", False),
                             variables=edge.get("variables", []))
        
        return graph
    
    def _evaluate_data_flow_constraint(self, from_node: VulnerabilityNode, 
                                      to_node: VulnerabilityNode) -> Tuple[bool, List[str]]:
        """
        Evaluate data flow reachability constraint.
        Checks if tainted data can flow from source vulnerability to target.
        """
        try:
            # Find path in data flow graph
            if not nx.has_path(self.data_flow_graph, from_node.stg_node_id, to_node.stg_node_id):
                return False, []
            
            # Get shortest path
            path = nx.shortest_path(self.data_flow_graph, from_node.stg_node_id, to_node.stg_node_id)
            
            # Check if path carries tainted data
            from_stg = self.stg_nodes[from_node.stg_node_id]
            to_stg = self.stg_nodes[to_node.stg_node_id]
            
            # Variable-based taint tracking
            tainted_vars = set(from_stg.variables_modified)
            
            for i in range(len(path) - 1):
                current_node = self.stg_nodes[path[i]]
                next_node = self.stg_nodes[path[i + 1]]
                
                # Check if tainted variables propagate
                edge_data = self.data_flow_graph[path[i]][path[i + 1]]
                if edge_data.get("tainted", False):
                    # Variables flowing through edge
                    edge_vars = set(edge_data.get("variables", []))
                    if edge_vars & tainted_vars:
                        # Taint propagates
                        tainted_vars.update(next_node.variables_modified)
                    else:
                        # Taint lost
                        return False, []
                else:
                    # Check if current node accesses tainted variables
                    if not (tainted_vars & set(next_node.variables_accessed)):
                        return False, []
            
            return True, path
            
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return False, []
    
    def _evaluate_execution_order_constraint(self, from_node: VulnerabilityNode,
                                          to_node: VulnerabilityNode) -> Tuple[bool, int]:
        """
        Evaluate execution order constraint.
        Checks if source vulnerability can execute before target vulnerability.
        """
        from_stg = self.stg_nodes[from_node.stg_node_id]
        to_stg = self.stg_nodes[to_node.stg_node_id]
        
        # Simple line-based ordering for same file
        if from_stg.file == to_stg.file:
            if from_stg.line < to_stg.line:
                return True, to_stg.line - from_stg.line
            else:
                return False, -1
        
        # Cross-file execution order based on function calls
        # For now, assume any order is possible across files
        # This could be enhanced with call graph analysis
        return True, 1
    
    def _evaluate_privilege_constraint(self, from_node: VulnerabilityNode,
                                     to_node: VulnerabilityNode) -> Tuple[bool, int]:
        """
        Evaluate privilege compatibility constraint.
        Checks if privilege escalation is possible between vulnerabilities.
        """
        from_priv = from_node.privilege_level
        to_priv = to_node.privilege_level
        
        # Get privilege levels
        from_level = self.privilege_hierarchy.get(from_priv, 1)
        to_level = self.privilege_hierarchy.get(to_priv, 1)
        
        # Check if privilege escalation is possible
        if from_level >= to_level:
            return True, 0  # No escalation needed
        else:
            # Check if escalation is reasonable (max 2 levels)
            escalation_gap = to_level - from_level
            if escalation_gap <= 2:
                return True, escalation_gap
            else:
                return False, escalation_gap
    
    def _infer_privilege_level(self, vulnerability: VulnerabilityFinding, 
                             stg_node: STGNode) -> str:
        """Infer privilege level from vulnerability and STG context"""
        vuln_type = vulnerability.type.lower()
        code = vulnerability.code.lower()
        
        # Check for admin-only operations
        if any(keyword in vuln_type or keyword in code for keyword in 
               ["admin", "root", "system", "privilege", "escalation"]):
            return "admin"
        
        # Check for authenticated operations
        if any(keyword in vuln_type or keyword in code for keyword in
               ["auth", "login", "session", "token", "authenticated"]):
            return "authenticated"
        
        # Check for privileged operations
        if any(keyword in vuln_type or keyword in code for keyword in
               ["privileged", "sudo", "elevated"]):
            return "privileged_user"
        
        # Check for user operations
        if any(keyword in vuln_type or keyword in code for keyword in
               ["user", "profile", "account"]):
            return "user"
        
        # Default to anonymous
        return "anonymous"
    
    def _infer_sink_type(self, vulnerability: VulnerabilityFinding, stg_node) -> str:
        """Infer sink type from vulnerability and STG node"""
        # Handle None stg_node
        if stg_node is None:
            transaction_type = 'unknown'
        else:
            transaction_type = getattr(stg_node, 'transaction_type', 'unknown')
        
        # Map transaction types to sink types
        if transaction_type.startswith('db'):
            return 'database'
        elif transaction_type.startswith('auth'):
            return 'authentication'
        elif transaction_type.startswith('file'):
            return 'file_system'
        elif transaction_type.startswith('network'):
            return 'network'
        elif transaction_type.startswith('memory'):
            return 'memory'
        else:
            # Infer from vulnerability type
            vuln_type = vulnerability.type.lower()
            if "sql" in vuln_type or "injection" in vuln_type:
                return "database"
            elif "xss" in vuln_type or "csrf" in vuln_type:
                return "web_application"
            elif "rce" in vuln_type or "command" in vuln_type:
                return "system"
            else:
                return "application"
    
    def _is_entry_point(self, vulnerability: VulnerabilityFinding,
                        stg_node: STGNode) -> bool:
        """Determine if vulnerability is an entry point"""
        vuln_type = vulnerability.type.lower()
        
        # Common entry point types
        entry_types = [
            "sql_injection", "xss", "csrf", "command_injection",
            "path_traversal", "file_upload", "buffer_overflow"
        ]
        
        return any(entry_type in vuln_type for entry_type in entry_types)
    
    def _find_closest_stg_node(self, file: str, line: int) -> str:
        """
        Find the STG node whose location is closest to the given vulnerability.
        Matches first by file (normalized basename), then by smallest line distance.
        Falls back to any node if no file match, or to a synthetic ID if STG is empty.
        """
        # Normalize for comparison: use the basename to tolerate absolute vs. relative paths
        def _basename(p: str) -> str:
            return p.replace("\\", "/").rsplit("/", 1)[-1] if p else ""

        vuln_base = _basename(file)

        best_id: str | None = None
        best_dist = float("inf")
        fallback_id: str | None = None

        for node_id, node in self.stg_nodes.items():
            node_base = _basename(getattr(node, "file", ""))

            # Keep a global fallback (any node) in case no file matches
            if fallback_id is None:
                fallback_id = node_id

            # File match (exact basename or substring)
            if vuln_base and node_base and (vuln_base == node_base
                                             or vuln_base in node_base
                                             or node_base in vuln_base):
                dist = abs(getattr(node, "line", 0) - line)
                if dist < best_dist:
                    best_dist = dist
                    best_id = node_id

        if best_id is not None:
            return best_id
        if fallback_id is not None:
            return fallback_id
        # STG is completely empty — return a synthetic id (safe, no path will exist)
        return f"stg_empty_{abs(hash(file + str(line))) % 100000}"

    def create_vulnerability_nodes(self, vulnerabilities: List[VulnerabilityFinding]) -> List[VulnerabilityNode]:
        """Map vulnerabilities to the nearest real STG nodes by file+line proximity."""
        vuln_nodes = []

        for i, vuln in enumerate(vulnerabilities):
            # Resolve to a real STG node (not a synthetic placeholder)
            stg_node_id = self._find_closest_stg_node(
                getattr(vuln, "file", ""), getattr(vuln, "line", 0)
            )

            node = VulnerabilityNode(
                id=f"vuln_{i}",
                stg_node_id=stg_node_id,
                vulnerability=vuln,
                entry_point=self._is_entry_point(vuln, None),
                sink_type=self._infer_sink_type(vuln, None),
                privilege_level=self._infer_privilege_level(vuln, None),
                tainted_inputs=["user_input"] if self._is_entry_point(vuln, None) else []
            )
            vuln_nodes.append(node)

        return vuln_nodes
    
    def evaluate_constraints(self, from_node: VulnerabilityNode,
                           to_node: VulnerabilityNode) -> ConstraintResult:
        """
        Evaluate all three constraints between two vulnerability nodes.
        Returns constraint satisfaction result.
        """
        # Evaluate data flow constraint
        data_flow_valid, data_flow_path = self._evaluate_data_flow_constraint(from_node, to_node)
        
        # Evaluate execution order constraint
        execution_order_valid, execution_distance = self._evaluate_execution_order_constraint(from_node, to_node)
        
        # Evaluate privilege constraint
        privilege_valid, privilege_gap = self._evaluate_privilege_constraint(from_node, to_node)
        
        # All constraints must be satisfied
        all_satisfied = data_flow_valid and execution_order_valid and privilege_valid
        
        return ConstraintResult(
            data_flow_valid=data_flow_valid,
            execution_order_valid=execution_order_valid,
            privilege_valid=privilege_valid,
            all_constraints_satisfied=all_satisfied,
            data_flow_path=data_flow_path if data_flow_valid else [],
            execution_distance=execution_distance,
            privilege_gap=privilege_gap
        )
    
    def evaluate_all_constraints(self, vulnerability_nodes: List[VulnerabilityNode]) -> Dict[str, Any]:
        """
        Evaluate constraints for all pairs of vulnerability nodes.
        Returns constraint satisfaction matrix.
        """
        constraint_matrix = {}
        satisfied_edges = []
        unsatisfied_edges = []
        
        for i, from_node in enumerate(vulnerability_nodes):
            for j, to_node in enumerate(vulnerability_nodes):
                if i == j:
                    continue
                
                edge_key = f"{from_node.id}->{to_node.id}"
                result = self.evaluate_constraints(from_node, to_node)
                
                constraint_matrix[edge_key] = {
                    "data_flow_valid": result.data_flow_valid,
                    "execution_order_valid": result.execution_order_valid,
                    "privilege_valid": result.privilege_valid,
                    "all_satisfied": result.all_constraints_satisfied,
                    "data_flow_path": result.data_flow_path,
                    "execution_distance": result.execution_distance,
                    "privilege_gap": result.privilege_gap
                }
                
                if result.all_constraints_satisfied:
                    satisfied_edges.append({
                        "from": from_node.id,
                        "to": to_node.id,
                        "constraints": result
                    })
                else:
                    unsatisfied_edges.append({
                        "from": from_node.id,
                        "to": to_node.id,
                        "constraints": result,
                        "failed_constraints": [
                            "data_flow" if not result.data_flow_valid else None,
                            "execution_order" if not result.execution_order_valid else None,
                            "privilege" if not result.privilege_valid else None
                        ]
                    })
        
        return {
            "constraint_matrix": constraint_matrix,
            "satisfied_edges": satisfied_edges,
            "unsatisfied_edges": unsatisfied_edges,
            "statistics": {
                "total_pairs": len(constraint_matrix),
                "satisfied_pairs": len(satisfied_edges),
                "unsatisfied_pairs": len(unsatisfied_edges),
                "satisfaction_rate": len(satisfied_edges) / len(constraint_matrix) if constraint_matrix else 0
            }
        }


def evaluate_constraints(stg_graph: STGGraph, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, Any]:
    """
    Evaluate constraints for exploit chain construction.
    
    Args:
        stg_graph: Semantic Transaction Graph
        vulnerabilities: List of vulnerability findings
        
    Returns:
        Constraint evaluation results
    """
    engine = ConstraintEngine(stg_graph)
    vuln_nodes = engine.create_vulnerability_nodes(vulnerabilities)
    return engine.evaluate_all_constraints(vuln_nodes)
