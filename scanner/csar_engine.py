"""
Constraint Satisfaction Attack Resolution (CSAR) Engine - Patent Critical Component

Traversal mechanism that enforces representability.
Prevents evaluation of infeasible exploit chains by structural elimination.
Only traverses paths where all constraints are satisfied.
"""

import networkx as nx
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

from .models import VulnerabilityFinding
from .stg_builder import STGGraph
from .ecg_builder import ECGGraph, ECGNode, ECGEdge


@dataclass
class ExploitStep:
    """Single step in exploit chain"""
    vulnerability_id: str
    stg_node_id: str
    vulnerability_type: str
    severity: str
    file: str
    line: int
    constraint_satisfaction: Dict[str, bool]
    exploit_technique: str
    prerequisites_met: bool
    privilege_level: str


@dataclass
class ExploitChain:
    """Feasible exploit chain"""
    chain_id: str
    feasibility: str  # "confirmed", "probable", "theoretical"
    steps: List[ExploitStep]
    entry_point: str
    final_impact: str
    dependency_involved: bool
    attack_complexity: str
    required_privileges: str
    chain_length: int
    max_privilege_gap: int
    total_data_flow_distance: int


@dataclass
class CSARResult:
    """Result of CSAR traversal"""
    exploit_chains: List[ExploitChain] = field(default_factory=list)
    eliminated_paths_count: int = 0
    total_paths_evaluated: int = 0
    traversal_statistics: Dict[str, Any] = field(default_factory=dict)
    chain_distribution: Dict[str, int] = field(default_factory=dict)


class CSAREngine:
    """Constraint Satisfaction Attack Resolution Engine"""
    
    def __init__(self, ecg_graph: ECGGraph, stg_graph: STGGraph):
        self.ecg_graph = ecg_graph
        self.stg_graph = stg_graph
        self.traversal_graph = self._build_traversal_graph()
        
        # Chain analysis parameters
        self.max_chain_length = 8  # Prevent infinite chains
        self.min_chain_length = 2  # Single vulns aren't chains
        
        # Impact classification
        self.impact_mapping = {
            "database": "data_breach",
            "authentication": "account_takeover",
            "file_system": "file_compromise",
            "network": "network_compromise",
            "system": "system_compromise",
            "web_application": "application_compromise"
        }
        
        # Attack techniques mapping
        self.attack_techniques = {
            "sql_injection": "SQL Injection",
            "xss": "Cross-Site Scripting",
            "csrf": "Cross-Site Request Forgery",
            "command_injection": "Command Injection",
            "path_traversal": "Path Traversal",
            "buffer_overflow": "Buffer Overflow",
            "rce": "Remote Code Execution",
            "privilege_escalation": "Privilege Escalation"
        }
    
    def _build_traversal_graph(self) -> nx.DiGraph:
        """Build NetworkX graph from ECG for traversal"""
        graph = nx.DiGraph()
        
        # Add nodes
        for node in self.ecg_graph.nodes:
            graph.add_node(node.id, **{
                "entry_point": node.entry_point,
                "sink_type": node.sink_type,
                "privilege_level": node.privilege_level,
                "severity": node.severity,
                "vulnerability_type": node.vulnerability_type,
                "file": node.file,
                "line": node.line
            })
        
        # Add edges (only constraint-satisfied edges exist in ECG)
        for edge in self.ecg_graph.edges:
            graph.add_edge(edge.from_node, edge.to_node, **{
                "constraints_satisfied": edge.constraints_satisfied,
                "data_flow_path": edge.data_flow_path,
                "execution_distance": edge.execution_distance,
                "privilege_gap": edge.privilege_gap,
                "exploit_complexity": edge.exploit_complexity
            })
        
        return graph
    
    def _get_attack_technique(self, vulnerability_type: str) -> str:
        """Get attack technique from vulnerability type"""
        for vuln_type, technique in self.attack_techniques.items():
            if vuln_type.lower() in vulnerability_type.lower():
                return technique
        return "Unknown"
    
    def _calculate_chain_feasibility(self, steps: List[ExploitStep]) -> str:
        """Calculate overall chain feasibility"""
        if not steps:
            return "theoretical"
        
        # Check for high-severity vulnerabilities
        has_high_severity = any(step.severity in ["High", "Critical"] for step in steps)
        
        # Check for complex constraints
        max_complexity = max(
            len(self.traversal_graph[steps[i].vulnerability_id][steps[i+1].vulnerability_id]["data_flow_path"])
            for i in range(len(steps) - 1)
        )
        
        # Check privilege escalation
        max_priv_gap = max(
            self.traversal_graph[steps[i].vulnerability_id][steps[i+1].vulnerability_id]["privilege_gap"]
            for i in range(len(steps) - 1)
        )
        
        if has_high_severity and max_complexity <= 3 and max_priv_gap <= 2:
            return "confirmed"
        elif max_complexity <= 5 and max_priv_gap <= 3:
            return "probable"
        else:
            return "theoretical"
    
    def _calculate_attack_complexity(self, steps: List[ExploitStep]) -> str:
        """Calculate overall attack complexity"""
        if not steps:
            return "low"
        
        complexities = []
        for i in range(len(steps) - 1):
            edge_data = self.traversal_graph[steps[i].vulnerability_id][steps[i+1].vulnerability_id]
            complexities.append(edge_data["exploit_complexity"])
        
        # Use worst complexity
        if "very_high" in complexities:
            return "very_high"
        elif "high" in complexities:
            return "high"
        elif "medium" in complexities:
            return "medium"
        else:
            return "low"
    
    def _get_required_privileges(self, steps: List[ExploitStep]) -> str:
        """Get required privileges for chain"""
        if not steps:
            return "none"
        
        # Get minimum privilege level to start chain
        entry_privileges = [step.privilege_level for step in steps if step.entry_point]
        if entry_privileges:
            return min(entry_privileges, key=lambda p: ["anonymous", "user", "authenticated", "privileged_user", "admin", "system"].index(p))
        
        return "user"
    
    def _calculate_chain_metrics(self, steps: List[ExploitStep]) -> Tuple[int, int]:
        """Calculate chain metrics"""
        max_priv_gap = 0
        total_data_distance = 0
        
        for i in range(len(steps) - 1):
            edge_data = self.traversal_graph[steps[i].vulnerability_id][steps[i+1].vulnerability_id]
            max_priv_gap = max(max_priv_gap, edge_data["privilege_gap"])
            total_data_distance += len(edge_data["data_flow_path"])
        
        return max_priv_gap, total_data_distance
    
    def _create_exploit_step(self, ecg_node: ECGNode) -> ExploitStep:
        """Create exploit step from ECG node"""
        return ExploitStep(
            vulnerability_id=ecg_node.vulnerability_id,
            stg_node_id=ecg_node.stg_node_id,
            vulnerability_type=ecg_node.vulnerability_type,
            severity=ecg_node.severity,
            file=ecg_node.file,
            line=ecg_node.line,
            constraint_satisfaction={},  # Will be populated during traversal
            exploit_technique=self._get_attack_technique(ecg_node.vulnerability_type),
            prerequisites_met=True,
            privilege_level=ecg_node.privilege_level
        )
    
    def _find_chains_from_entry(self, entry_node: str, visited: Set[str]) -> List[List[ExploitStep]]:
        """Find all chains starting from entry node"""
        chains = []
        
        def dfs(current_node: str, current_path: List[ExploitStep], visited_nodes: Set[str]):
            # Prevent infinite recursion
            if len(current_path) >= self.max_chain_length:
                return
            
            # Mark as visited
            visited_nodes.add(current_node)
            
            # Explore neighbors
            for neighbor in self.traversal_graph.successors(current_node):
                if neighbor in visited_nodes:
                    continue
                
                # Get edge data
                edge_data = self.traversal_graph[current_node][neighbor]
                
                # Create step for neighbor node
                neighbor_ecg_node = next(n for n in self.ecg_graph.nodes if n.id == neighbor)
                step = self._create_exploit_step(neighbor_ecg_node)
                step.constraint_satisfaction = edge_data["constraints_satisfied"]
                
                # Add to path
                new_path = current_path + [step]
                
                # Check if we have a valid chain
                if len(new_path) >= self.min_chain_length:
                    chains.append(new_path)
                
                # Continue recursion
                dfs(neighbor, new_path, visited_nodes.copy())
        
        # Start DFS from entry node
        entry_ecg_node = next(n for n in self.ecg_graph.nodes if n.id == entry_node)
        entry_step = self._create_exploit_step(entry_ecg_node)
        
        dfs(entry_node, [entry_step], visited.copy())
        
        return chains
    
    def _filter_unique_chains(self, chains: List[List[ExploitStep]]) -> List[List[ExploitStep]]:
        """Filter duplicate chains based on vulnerability sequence"""
        seen = set()
        unique_chains = []
        
        for chain in chains:
            vuln_sequence = tuple(step.vulnerability_id for step in chain)
            if vuln_sequence not in seen:
                seen.add(vuln_sequence)
                unique_chains.append(chain)
        
        return unique_chains
    
    def _rank_chains_by_severity(self, chains: List[List[ExploitStep]]) -> List[List[ExploitStep]]:
        """Rank chains by severity and complexity"""
        def chain_score(chain: List[ExploitStep]) -> float:
            severity_score = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            max_severity = max(severity_score.get(step.severity, 1) for step in chain)
            
            # Prefer shorter chains with higher severity
            length_penalty = len(chain) * 0.1
            return max_severity - length_penalty
        
        return sorted(chains, key=chain_score, reverse=True)
    
    def traverse_exploit_chains(self) -> CSARResult:
        """
        Main CSAR traversal algorithm.
        Only traverses paths where all constraints are satisfied.
        """
        chains = []
        total_paths_evaluated = 0
        
        # Find all entry points
        entry_nodes = [node.id for node in self.ecg_graph.nodes if node.entry_point]
        
        if not entry_nodes:
            elim_paths = getattr(self.ecg_graph, "eliminated_paths", 0) if hasattr(self.ecg_graph, "eliminated_paths") else (self.ecg_graph.get("eliminated_paths", 0) if isinstance(self.ecg_graph, dict) else 0)
            return CSARResult(
                eliminated_paths_count=elim_paths,
                traversal_statistics={"elimination_rate": 1.0 if elim_paths > 0 else 0}
            )
        
        # Find chains from each entry point
        for entry_node in entry_nodes:
            visited = set()
            entry_chains = self._find_chains_from_entry(entry_node, visited)
            chains.extend(entry_chains)
            total_paths_evaluated += len(entry_chains)
        
        # Filter and rank chains
        unique_chains = self._filter_unique_chains(chains)
        ranked_chains = self._rank_chains_by_severity(unique_chains)
        
        # Convert to ExploitChain objects
        exploit_chains = []
        for i, chain_steps in enumerate(ranked_chains[:20]):  # Limit to top 20 chains
            feasibility = self._calculate_chain_feasibility(chain_steps)
            attack_complexity = self._calculate_attack_complexity(chain_steps)
            required_privileges = self._get_required_privileges(chain_steps)
            max_priv_gap, total_data_distance = self._calculate_chain_metrics(chain_steps)
            
            # Determine final impact
            final_impact = "unknown"
            if chain_steps:
                final_sink = chain_steps[-1].sink_type
                final_impact = self.impact_mapping.get(final_sink, "unknown")
            
            exploit_chain = ExploitChain(
                chain_id=f"chain_{i+1}",
                feasibility=feasibility,
                steps=chain_steps,
                entry_point=chain_steps[0].vulnerability_id if chain_steps else "",
                final_impact=final_impact,
                dependency_involved=False,  # Will be updated later
                attack_complexity=attack_complexity,
                required_privileges=required_privileges,
                chain_length=len(chain_steps),
                max_privilege_gap=max_priv_gap,
                total_data_flow_distance=total_data_distance
            )
            
            exploit_chains.append(exploit_chain)
        
        # Calculate statistics
        chain_distribution = defaultdict(int)
        for chain in exploit_chains:
            chain_distribution[chain.feasibility] += 1
            chain_distribution[f"length_{chain.chain_length}"] += 1
        
        eliminated_paths = self.ecg_graph.eliminated_paths
        
        return CSARResult(
            exploit_chains=exploit_chains,
            eliminated_paths_count=eliminated_paths,
            total_paths_evaluated=total_paths_evaluated,
            traversal_statistics={
                "total_entry_points": len(entry_nodes),
                "chains_found": len(exploit_chains),
                "average_chain_length": sum(len(chain.steps) for chain in exploit_chains) / len(exploit_chains) if exploit_chains else 0,
                "max_chain_length": max(len(chain.steps) for chain in exploit_chains) if exploit_chains else 0,
                "elimination_rate": eliminated_paths / (eliminated_paths + total_paths_evaluated) if (eliminated_paths + total_paths_evaluated) > 0 else 0
            },
            chain_distribution=dict(chain_distribution)
        )
    
    def to_dict(self, result: CSARResult) -> Dict[str, Any]:
        """Convert CSAR result to dictionary for JSON serialization"""
        return {
            "exploit_chains": [
                {
                    "chain_id": chain.chain_id,
                    "feasibility": chain.feasibility,
                    "steps": [
                        {
                            "vulnerability_id": step.vulnerability_id,
                            "stg_node_id": step.stg_node_id,
                            "vulnerability_type": step.vulnerability_type,
                            "severity": step.severity,
                            "file": step.file,
                            "line": step.line,
                            "constraint_satisfaction": step.constraint_satisfaction,
                            "exploit_technique": step.exploit_technique,
                            "prerequisites_met": step.prerequisites_met,
                            "privilege_level": step.privilege_level
                        }
                        for step in chain.steps
                    ],
                    "entry_point": chain.entry_point,
                    "final_impact": chain.final_impact,
                    "dependency_involved": chain.dependency_involved,
                    "attack_complexity": chain.attack_complexity,
                    "required_privileges": chain.required_privileges,
                    "chain_length": chain.chain_length,
                    "max_privilege_gap": chain.max_privilege_gap,
                    "total_data_flow_distance": chain.total_data_flow_distance
                }
                for chain in result.exploit_chains
            ],
            "statistics": {
                "total_chains": len(result.exploit_chains),
                "eliminated_paths_count": result.eliminated_paths_count,
                "total_paths_evaluated": result.total_paths_evaluated,
                "elimination_rate": result.traversal_statistics.get("elimination_rate", 0),
                "chain_distribution": result.chain_distribution,
                "traversal_statistics": result.traversal_statistics
            }
        }


def perform_csar_traversal(ecg_graph: ECGGraph, stg_graph: STGGraph) -> Dict[str, Any]:
    """
    Perform Constraint Satisfaction Attack Resolution traversal.
    
    Args:
        ecg_graph: Exploit Constraint Graph
        stg_graph: Semantic Transaction Graph
        
    Returns:
        CSAR traversal results
    """
    engine = CSAREngine(ecg_graph, stg_graph)
    result = engine.traverse_exploit_chains()
    return engine.to_dict(result)
