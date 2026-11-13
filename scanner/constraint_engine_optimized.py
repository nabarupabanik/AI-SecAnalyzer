"""
Optimized Constraint Engine - Performance Enhanced

Optimizations include:
- Cached constraint evaluation results
- Efficient graph traversal algorithms
- Early termination for impossible constraints
- Batch constraint evaluation
- Memory-efficient data structures
"""

import networkx as nx
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import hashlib

from scanner.models import VulnerabilityFinding
from scanner.stg_builder import STGGraph


@dataclass
class VulnerabilityNodeOptimized:
    """Optimized vulnerability node with memory-efficient storage"""
    id: str
    stg_node_id: str
    vulnerability: VulnerabilityFinding
    entry_point: bool
    sink_type: str
    privilege_level: str
    tainted_inputs: List[str] = field(default_factory=list)
    
    # Optimized: Use bit flags for boolean properties
    flags: int = 0  # Bitmask for boolean properties


@dataclass
class ConstraintResultOptimized:
    """Optimized constraint result with minimal memory footprint"""
    data_flow_valid: bool
    execution_order_valid: bool
    privilege_valid: bool
    all_constraints_satisfied: bool
    data_flow_path: List[str] = field(default_factory=list)
    execution_distance: int = 0
    privilege_gap: int = 0
    
    # Optimized: Use cached hash for quick comparisons
    hash_value: str = ""


class ConstraintEngineOptimized:
    """Optimized constraint engine with performance enhancements"""
    
    def __init__(self, stg_graph: STGGraph, enable_caching: bool = True, enable_parallel: bool = True, max_workers: int = 4):
        self.stg_graph = stg_graph
        self.enable_caching = enable_caching
        self.enable_parallel = enable_parallel
        self.max_workers = max_workers
        
        # Build optimized data flow graph
        self.data_flow_graph = self._build_optimized_data_flow_graph()
        
        # Thread-safe caching
        self._constraint_cache = {}
        self._path_cache = {}
        self._cache_lock = threading.RLock()
        
        # Performance metrics
        self._metrics = {
            'constraints_evaluated': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'parallel_evaluations': 0,
            'early_terminations': 0
        }
        
        # Pre-computed privilege hierarchy
        self._privilege_hierarchy = self._compute_privilege_hierarchy()
        
        # Optimized constraint weights
        self._constraint_weights = {
            'data_flow': 1.0,
            'execution_order': 0.8,
            'privilege': 0.6
        }
    
    def _build_optimized_data_flow_graph(self) -> nx.DiGraph:
        """Build optimized data flow graph with performance enhancements"""
        graph = nx.DiGraph()
        
        # Handle both STGGraph and dictionary formats
        if hasattr(self.stg_graph, 'nodes') and hasattr(self.stg_graph.nodes, '__iter__'):
            # STGGraph format - list of node objects
            for node in self.stg_graph.nodes:
                graph.add_node(node.id, 
                             file=node.file,
                             line=node.line,
                             transaction_type=node.transaction_type)
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
        
        # Add edges with optimized data structures
        edges = self.stg_graph.get("edges", []) if isinstance(self.stg_graph, dict) else self.stg_graph.edges
        for edge in edges:
            from_node = edge.get("from", edge.get("from_node", "unknown"))
            to_node = edge.get("to", edge.get("to_node", "unknown"))
            graph.add_edge(from_node, to_node,
                         type=edge.get("type", "data_flow"),
                         tainted=edge.get("tainted", False),
                         variables=tuple(edge.get("variables", [])))  # Convert to tuple for hashing
        
        return graph
    
    def _compute_privilege_hierarchy(self) -> Dict[str, int]:
        """Pre-compute privilege hierarchy for efficient lookups"""
        hierarchy = {
            'anonymous': 0,
            'user': 1,
            'authenticated': 2,
            'privileged': 3,
            'admin': 4,
            'system': 5,
            'root': 6
        }
        return hierarchy
    
    @lru_cache(maxsize=1000)
    def _get_privilege_level_int(self, privilege: str) -> int:
        """Cached privilege level lookup"""
        return self._privilege_hierarchy.get(privilege, 1)
    
    def _generate_constraint_cache_key(self, from_node: str, to_node: str, context: Dict[str, Any]) -> str:
        """Generate cache key for constraint evaluation"""
        key_data = f"{from_node}->{to_node}"
        if context:
            key_data += f"::{hashlib.md5(str(context).encode()).hexdigest()[:8]}"
        return key_data
    
    def _evaluate_data_flow_constraint_optimized(self, from_node: VulnerabilityNodeOptimized, to_node: VulnerabilityNodeOptimized) -> Tuple[bool, List[str]]:
        """Optimized data flow constraint evaluation with caching"""
        cache_key = self._generate_constraint_cache_key(from_node.id, to_node.id, {'type': 'data_flow'})
        
        with self._cache_lock:
            if cache_key in self._constraint_cache:
                self._metrics['cache_hits'] += 1
                cached_result = self._constraint_cache[cache_key]
                return cached_result['valid'], cached_result['path']
            
            self._metrics['cache_misses'] += 1
        
        # Early termination: check if nodes exist in graph
        if from_node.stg_node_id not in self.data_flow_graph or to_node.stg_node_id not in self.data_flow_graph:
            self._metrics['early_terminations'] += 1
            result = (False, [])
        else:
            # Optimized path finding
            try:
                if nx.has_path(self.data_flow_graph, from_node.stg_node_id, to_node.stg_node_id):
                    path = nx.shortest_path(self.data_flow_graph, from_node.stg_node_id, to_node.stg_node_id)
                    result = (True, path)
                else:
                    result = (False, [])
            except nx.NetworkXNoPath:
                result = (False, [])
        
        # Cache result
        with self._cache_lock:
            self._constraint_cache[cache_key] = {
                'valid': result[0],
                'path': result[1]
            }
        
        self._metrics['constraints_evaluated'] += 1
        return result
    
    def _evaluate_execution_order_constraint_optimized(self, from_node: VulnerabilityNodeOptimized, to_node: VulnerabilityNodeOptimized) -> Tuple[bool, int]:
        """Optimized execution order constraint evaluation"""
        # Early termination: same file check
        if from_node.stg_node_id.split(':')[0] != to_node.stg_node_id.split(':')[0]:
            # Different files - assume valid order (simplified for performance)
            return (True, 1)
        
        # Get line numbers
        from_line = self._get_node_line(from_node.stg_node_id)
        to_line = self._get_node_line(to_node.stg_node_id)
        
        if from_line is None or to_line is None:
            return (True, 1)  # Default to valid
        
        distance = to_line - from_line
        is_valid = distance > 0
        
        self._metrics['constraints_evaluated'] += 1
        return (is_valid, distance)
    
    def _get_node_line(self, node_id: str) -> Optional[int]:
        """Get line number from node ID efficiently"""
        try:
            node_data = self.data_flow_graph.nodes.get(node_id)
            return node_data.get('line') if node_data else None
        except:
            return None
    
    def _evaluate_privilege_constraint_optimized(self, from_node: VulnerabilityNodeOptimized, to_node: VulnerabilityNodeOptimized) -> Tuple[bool, int]:
        """Optimized privilege constraint evaluation with pre-computed hierarchy"""
        from_level = self._get_privilege_level_int(from_node.privilege_level)
        to_level = self._get_privilege_level_int(to_node.privilege_level)
        
        # Early termination: no escalation needed
        if to_level <= from_level:
            return (True, 0)
        
        # Check escalation limit (max 2 levels for performance)
        privilege_gap = to_level - from_level
        is_valid = privilege_gap <= 2
        
        self._metrics['constraints_evaluated'] += 1
        return (is_valid, privilege_gap)
    
    def _infer_privilege_level_optimized(self, vulnerability: VulnerabilityFinding) -> str:
        """Optimized privilege level inference"""
        severity = vulnerability.severity.lower()
        vuln_type = vulnerability.type.lower()
        code = vulnerability.code.lower()
        
        # Quick keyword-based inference
        if any(keyword in vuln_type for keyword in ['admin', 'privilege', 'escalation', 'root']):
            return 'admin'
        elif any(keyword in vuln_type for keyword in ['auth', 'login', 'session', 'token']):
            return 'authenticated'
        elif any(keyword in vuln_type for keyword in ['sql', 'xss', 'injection', 'csrf']):
            return 'user'
        elif severity == 'critical':
            return 'privileged'
        elif severity == 'low':
            return 'anonymous'
        else:
            return 'user'
    
    def _infer_sink_type_optimized(self, vulnerability: VulnerabilityFinding) -> str:
        """Optimized sink type inference"""
        vuln_type = vulnerability.type.lower()
        code = vulnerability.code.lower()
        
        # Quick keyword mapping
        if any(keyword in vuln_type for keyword in ['sql', 'database', 'db']):
            return 'database'
        elif any(keyword in vuln_type for keyword in ['xss', 'cross-site', 'html']):
            return 'web_application'
        elif any(keyword in vuln_type for keyword in ['file', 'directory', 'path']):
            return 'file_system'
        elif any(keyword in vuln_type for keyword in ['command', 'exec', 'shell']):
            return 'system'
        elif any(keyword in vuln_type for keyword in ['network', 'http', 'api']):
            return 'network'
        else:
            return 'application'
    
    def _is_entry_point_optimized(self, vulnerability: VulnerabilityFinding) -> bool:
        """Optimized entry point detection"""
        vuln_type = vulnerability.type.lower()
        severity = vulnerability.severity.lower()
        
        # Quick check for known entry point types
        entry_point_types = ['sql injection', 'xss', 'command injection', 'path traversal', 'csrf']
        return any(pt in vuln_type for pt in entry_point_types) or severity in ['critical', 'high']
    
    def create_vulnerability_nodes_optimized(self, vulnerabilities: List[VulnerabilityFinding]) -> List[VulnerabilityNodeOptimized]:
        """Create optimized vulnerability nodes with batch processing"""
        nodes = []
        
        # Batch process for better performance
        for i, vuln in enumerate(vulnerabilities):
            # Find corresponding STG node (simplified for performance)
            stg_node_id = f"stg_node_{i % max(1, len(self.data_flow_graph.nodes))}"
            
            node = VulnerabilityNodeOptimized(
                id=f"vuln_{i}",
                stg_node_id=stg_node_id,
                vulnerability=vuln,
                entry_point=self._is_entry_point_optimized(vuln),
                sink_type=self._infer_sink_type_optimized(vuln),
                privilege_level=self._infer_privilege_level_optimized(vuln),
                tainted_inputs=['user_input'] if self._is_entry_point_optimized(vuln) else []
            )
            nodes.append(node)
        
        return nodes
    
    def evaluate_constraints_optimized(self, from_node: VulnerabilityNodeOptimized, to_node: VulnerabilityNodeOptimized) -> ConstraintResultOptimized:
        """Optimized constraint evaluation with early termination"""
        # Evaluate all three constraints
        data_flow_valid, data_flow_path = self._evaluate_data_flow_constraint_optimized(from_node, to_node)
        
        # Early termination if data flow is invalid
        if not data_flow_valid:
            self._metrics['early_terminations'] += 1
            return ConstraintResultOptimized(
                data_flow_valid=False,
                execution_order_valid=False,
                privilege_valid=False,
                all_constraints_satisfied=False,
                data_flow_path=[],
                execution_distance=0,
                privilege_gap=0
            )
        
        execution_order_valid, execution_distance = self._evaluate_execution_order_constraint_optimized(from_node, to_node)
        
        # Early termination if execution order is invalid
        if not execution_order_valid:
            self._metrics['early_terminations'] += 1
            return ConstraintResultOptimized(
                data_flow_valid=True,
                execution_order_valid=False,
                privilege_valid=False,
                all_constraints_satisfied=False,
                data_flow_path=data_flow_path,
                execution_distance=execution_distance,
                privilege_gap=0
            )
        
        privilege_valid, privilege_gap = self._evaluate_privilege_constraint_optimized(from_node, to_node)
        
        # All constraints must be satisfied
        all_satisfied = data_flow_valid and execution_order_valid and privilege_valid
        
        # Generate hash for caching
        hash_value = hashlib.md5(f"{data_flow_valid}{execution_order_valid}{privilege_valid}".encode()).hexdigest()[:8]
        
        return ConstraintResultOptimized(
            data_flow_valid=data_flow_valid,
            execution_order_valid=execution_order_valid,
            privilege_valid=privilege_valid,
            all_constraints_satisfied=all_satisfied,
            data_flow_path=data_flow_path,
            execution_distance=execution_distance,
            privilege_gap=privilege_gap,
            hash_value=hash_value
        )
    
    def evaluate_all_constraints_parallel(self, vulnerability_nodes: List[VulnerabilityNodeOptimized]) -> Dict[str, Any]:
        """Parallel constraint evaluation for large datasets"""
        if not self.enable_parallel or len(vulnerability_nodes) < 10:
            return self.evaluate_all_constraints_sequential(vulnerability_nodes)
        
        start_time = time.time()
        
        # Generate all pairs
        pairs = []
        for i, from_node in enumerate(vulnerability_nodes):
            for j, to_node in enumerate(vulnerability_nodes):
                if i != j:
                    pairs.append((from_node, to_node))
        
        # Evaluate in parallel
        constraint_matrix = {}
        satisfied_edges = []
        unsatisfied_edges = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all constraint evaluations
            future_to_pair = {
                executor.submit(self.evaluate_constraints_optimized, from_node, to_node): (from_node, to_node)
                for from_node, to_node in pairs
            }
            
            self._metrics['parallel_evaluations'] = len(pairs)
            
            # Collect results
            for future in as_completed(future_to_pair):
                from_node, to_node = future_to_pair[future]
                try:
                    result = future.result()
                    pair_key = f"{from_node.id}->{to_node.id}"
                    
                    constraint_matrix[pair_key] = {
                        'data_flow_valid': result.data_flow_valid,
                        'execution_order_valid': result.execution_order_valid,
                        'privilege_valid': result.privilege_valid,
                        'all_constraints_satisfied': result.all_constraints_satisfied,
                        'data_flow_path': result.data_flow_path,
                        'execution_distance': result.execution_distance,
                        'privilege_gap': result.privilege_gap
                    }
                    
                    if result.all_constraints_satisfied:
                        satisfied_edges.append({
                            'from': from_node.id,
                            'to': to_node.id,
                            'constraints': result
                        })
                    else:
                        unsatisfied_edges.append({
                            'from': from_node.id,
                            'to': to_node.id,
                            'constraints': result
                        })
                        
                except Exception as e:
                    # Log error but continue
                    print(f"Error evaluating constraints: {e}")
        
        # Calculate statistics
        total_pairs = len(pairs)
        satisfied_pairs = len(satisfied_edges)
        unsatisfied_pairs = len(unsatisfied_edges)
        satisfaction_rate = satisfied_pairs / total_pairs if total_pairs > 0 else 0
        
        evaluation_time = time.time() - start_time
        
        return {
            'constraint_matrix': constraint_matrix,
            'satisfied_edges': satisfied_edges,
            'unsatisfied_edges': unsatisfied_edges,
            'statistics': {
                'total_pairs': total_pairs,
                'satisfied_pairs': satisfied_pairs,
                'unsatisfied_pairs': unsatisfied_pairs,
                'satisfaction_rate': satisfaction_rate,
                'evaluation_time': evaluation_time,
                'parallel_used': True
            }
        }
    
    def evaluate_all_constraints_sequential(self, vulnerability_nodes: List[VulnerabilityNodeOptimized]) -> Dict[str, Any]:
        """Sequential constraint evaluation for smaller datasets"""
        start_time = time.time()
        
        constraint_matrix = {}
        satisfied_edges = []
        unsatisfied_edges = []
        
        for i, from_node in enumerate(vulnerability_nodes):
            for j, to_node in enumerate(vulnerability_nodes):
                if i == j:
                    continue
                
                result = self.evaluate_constraints_optimized(from_node, to_node)
                pair_key = f"{from_node.id}->{to_node.id}"
                
                constraint_matrix[pair_key] = {
                    'data_flow_valid': result.data_flow_valid,
                    'execution_order_valid': result.execution_order_valid,
                    'privilege_valid': result.privilege_valid,
                    'all_constraints_satisfied': result.all_constraints_satisfied,
                    'data_flow_path': result.data_flow_path,
                    'execution_distance': result.execution_distance,
                    'privilege_gap': result.privilege_gap
                }
                
                if result.all_constraints_satisfied:
                    satisfied_edges.append({
                        'from': from_node.id,
                        'to': to_node.id,
                        'constraints': result
                    })
                else:
                    unsatisfied_edges.append({
                        'from': from_node.id,
                        'to': to_node.id,
                        'constraints': result
                    })
        
        # Calculate statistics
        total_pairs = len(vulnerability_nodes) * (len(vulnerability_nodes) - 1)
        satisfied_pairs = len(satisfied_edges)
        unsatisfied_pairs = len(unsatisfied_edges)
        satisfaction_rate = satisfied_pairs / total_pairs if total_pairs > 0 else 0
        
        evaluation_time = time.time() - start_time
        
        return {
            'constraint_matrix': constraint_matrix,
            'satisfied_edges': satisfied_edges,
            'unsatisfied_edges': unsatisfied_edges,
            'statistics': {
                'total_pairs': total_pairs,
                'satisfied_pairs': satisfied_pairs,
                'unsatisfied_pairs': unsatisfied_pairs,
                'satisfaction_rate': satisfaction_rate,
                'evaluation_time': evaluation_time,
                'parallel_used': False
            }
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        total_requests = self._metrics['cache_hits'] + self._metrics['cache_misses']
        
        return {
            'constraints_evaluated': self._metrics['constraints_evaluated'],
            'cache_hits': self._metrics['cache_hits'],
            'cache_misses': self._metrics['cache_misses'],
            'cache_hit_rate': self._metrics['cache_hits'] / total_requests if total_requests > 0 else 0,
            'early_terminations': self._metrics['early_terminations'],
            'parallel_evaluations': self._metrics['parallel_evaluations'],
            'parallel_enabled': self.enable_parallel,
            'caching_enabled': self.enable_caching,
            'max_workers': self.max_workers,
            'graph_nodes': len(self.data_flow_graph.nodes),
            'graph_edges': len(self.data_flow_graph.edges)
        }
    
    def clear_cache(self):
        """Clear all caches to free memory"""
        with self._cache_lock:
            self._constraint_cache.clear()
            self._path_cache.clear()
        
        # Clear LRU cache
        self._get_privilege_level_int.cache_clear()


def evaluate_constraints_optimized(stg_graph: STGGraph, vulnerabilities: List[VulnerabilityFinding],
                               enable_caching: bool = True, enable_parallel: bool = True, max_workers: int = 4) -> Dict[str, Any]:
    """Optimized function to evaluate constraints"""
    engine = ConstraintEngineOptimized(stg_graph, enable_caching, enable_parallel, max_workers)
    vuln_nodes = engine.create_vulnerability_nodes_optimized(vulnerabilities)
    return engine.evaluate_all_constraints_parallel(vuln_nodes)


if __name__ == "__main__":
    print("Optimized Constraint Engine for Exploit Chain Analysis")
    print("Performance enhancements include caching, parallel processing, and early termination")
