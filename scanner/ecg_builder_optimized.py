"""
Optimized Exploit Constraint Graph (ECG) Builder - Performance Enhanced

Optimizations include:
- Batch edge creation and validation
- Memory-efficient graph storage
- Early termination for unsatisfied constraints
- Parallel constraint evaluation
- Optimized complexity calculations
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import hashlib

from scanner.models import VulnerabilityFinding
from scanner.stg_builder import STGGraph
from scanner.constraint_engine_optimized import ConstraintEngineOptimized, ConstraintResultOptimized


@dataclass
class ECGNodeOptimized:
    """Optimized ECG node with memory-efficient storage"""
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
    
    # Optimized: Use bit flags for boolean properties
    flags: int = 0  # Bitmask for boolean properties


@dataclass
class ECGEdgeOptimized:
    """Optimized ECG edge with minimal memory footprint"""
    from_node: str
    to_node: str
    constraints_satisfied: Dict[str, bool]
    data_flow_path: List[str] = field(default_factory=list)
    execution_distance: int = 0
    privilege_gap: int = 0
    exploit_complexity: str = "medium"
    
    # Optimized: Pre-computed hash for quick comparisons
    hash_value: str = ""


@dataclass
class ECGGraphOptimized:
    """Optimized ECG graph with performance enhancements"""
    nodes: Dict[str, ECGNodeOptimized] = field(default_factory=dict)
    edges: List[ECGEdgeOptimized] = field(default_factory=list)
    constraint_matrix: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    eliminated_paths: int = 0
    total_possible_paths: int = 0
    
    # Performance tracking
    build_time: float = 0.0
    memory_usage: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


class ECGBuilderOptimized:
    """Optimized ECG Builder with performance enhancements"""
    
    def __init__(self, stg_graph: STGGraph, enable_caching: bool = True, enable_parallel: bool = True, max_workers: int = 4):
        self.stg_graph = stg_graph
        self.enable_caching = enable_caching
        self.enable_parallel = enable_parallel
        self.max_workers = max_workers
        
        # Use optimized constraint engine
        self.constraint_engine = ConstraintEngineOptimized(stg_graph, enable_caching, enable_parallel, max_workers)
        
        # Performance metrics
        self._metrics = {
            'nodes_created': 0,
            'edges_created': 0,
            'edges_evaluated': 0,
            'edges_filtered': 0,
            'parallel_batches': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Pre-computed complexity weights
        self._complexity_weights = {
            'path_length': 0.3,
            'privilege_gap': 0.4,
            'constraint_satisfaction': 0.3
        }
        
        # Optimized complexity thresholds
        self._complexity_thresholds = {
            'low': 2,
            'medium': 4,
            'high': 6,
            'very_high': 8
        }
        
        # Thread-safe caching
        self._edge_cache = {}
        self._cache_lock = threading.RLock()
    
    def _calculate_exploit_complexity_optimized(self, constraint_result: ConstraintResultOptimized) -> str:
        """Optimized exploit complexity calculation"""
        # Quick calculation using pre-defined thresholds
        path_length = len(constraint_result.data_flow_path)
        privilege_gap = constraint_result.privilege_gap
        
        # Calculate weighted score
        score = (
            path_length * self._complexity_weights['path_length'] +
            privilege_gap * self._complexity_weights['privilege_gap'] +
            (3 if constraint_result.all_constraints_satisfied else 0) * self._complexity_weights['constraint_satisfaction']
        )
        
        # Determine complexity based on thresholds
        if score <= self._complexity_thresholds['low']:
            return "low"
        elif score <= self._complexity_thresholds['medium']:
            return "medium"
        elif score <= self._complexity_thresholds['high']:
            return "high"
        else:
            return "very_high"
    
    def _generate_edge_cache_key(self, from_node: str, to_node: str, constraints: ConstraintResultOptimized) -> str:
        """Generate cache key for edge creation"""
        key_data = f"{from_node}->{to_node}"
        if constraints:
            key_data += f"::{constraints.hash_value}"
        return hashlib.md5(key_data.encode()).hexdigest()[:12]
    
    def _create_ecg_node_optimized(self, vuln_node) -> ECGNodeOptimized:
        """Create optimized ECG node with minimal overhead"""
        return ECGNodeOptimized(
            id=vuln_node.id,
            vulnerability_id=vuln_node.id,
            stg_node_id=vuln_node.stg_node_id,
            vulnerability_type=vuln_node.vulnerability.type,
            severity=vuln_node.vulnerability.severity,
            entry_point=vuln_node.entry_point,
            sink_type=vuln_node.sink_type,
            privilege_level=vuln_node.privilege_level,
            file=vuln_node.vulnerability.file,
            line=vuln_node.vulnerability.line
        )
    
    def _create_ecg_edge_optimized(self, from_node: str, to_node: str, constraint_result: ConstraintResultOptimized) -> ECGEdgeOptimized:
        """Create optimized ECG edge with pre-computed values"""
        exploit_complexity = self._calculate_exploit_complexity_optimized(constraint_result)
        
        edge = ECGEdgeOptimized(
            from_node=from_node,
            to_node=to_node,
            constraints_satisfied={
                'data_flow': constraint_result.data_flow_valid,
                'execution_order': constraint_result.execution_order_valid,
                'privilege': constraint_result.privilege_valid
            },
            data_flow_path=constraint_result.data_flow_path,
            execution_distance=constraint_result.execution_distance,
            privilege_gap=constraint_result.privilege_gap,
            exploit_complexity=exploit_complexity
        )
        
        # Generate hash for caching
        edge.hash_value = self._generate_edge_cache_key(from_node, to_node, constraint_result)
        
        return edge
    
    def _batch_create_edges(self, vulnerability_nodes: List, constraint_results: Any) -> List[ECGEdgeOptimized]:
        """Batch create edges for better performance"""
        edges = []
        
        # Handle both list and dict formats
        if isinstance(constraint_results, dict):
            # Dictionary format
            for pair_key, constraint_data in constraint_results.items():
                if constraint_data.get('all_constraints_satisfied', False):
                    # Parse pair key
                    from_id, to_id = pair_key.split('->')
                    
                    # Find constraint result
                    constraint_result = constraint_data.get('constraints')
                    if constraint_result:
                        edge = self._create_ecg_edge_optimized(from_id, to_id, constraint_result)
                        edges.append(edge)
                        self._metrics['edges_created'] += 1
        elif isinstance(constraint_results, list):
            # List format - handle satisfied_edges list
            for edge_data in constraint_results:
                if isinstance(edge_data, dict) and edge_data.get('from') and edge_data.get('to'):
                    # Create edge from satisfied edge data
                    from_id = edge_data['from']
                    to_id = edge_data['to']
                    
                    # Create a simple constraint result
                    constraint_result = ConstraintResultOptimized(
                        data_flow_valid=True,
                        execution_order_valid=True,
                        privilege_valid=True,
                        all_constraints_satisfied=True,
                        data_flow_path=[],
                        execution_distance=1,
                        privilege_gap=0
                    )
                    
                    edge = self._create_ecg_edge_optimized(from_id, to_id, constraint_result)
                    edges.append(edge)
                    self._metrics['edges_created'] += 1
        
        return edges
    
    def _calculate_eliminated_paths_optimized(self, total_vulnerabilities: int) -> int:
        """Optimized eliminated paths calculation"""
        if total_vulnerabilities <= 1:
            return 0
        
        total_possible = total_vulnerabilities * (total_vulnerabilities - 1)
        satisfied_edges = self._metrics['edges_created']
        
        return total_possible - satisfied_edges
    
    def build_ecg_optimized(self, vulnerabilities: List[VulnerabilityFinding]) -> ECGGraphOptimized:
        """Build optimized ECG with performance enhancements"""
        start_time = time.time()
        
        graph = ECGGraphOptimized()
        
        if not vulnerabilities:
            return graph
        
        # Create vulnerability nodes
        vuln_nodes = self.constraint_engine.create_vulnerability_nodes_optimized(vulnerabilities)
        
        # Create ECG nodes
        ecg_nodes = {}
        for vuln_node in vuln_nodes:
            ecg_node = self._create_ecg_node_optimized(vuln_node)
            ecg_nodes[ecg_node.id] = ecg_node
            self._metrics['nodes_created'] += 1
        
        # Evaluate constraints (parallel or sequential)
        if self.enable_parallel and len(vuln_nodes) > 10:
            constraint_results = self._evaluate_constraints_parallel(vuln_nodes)
        else:
            constraint_results = self._evaluate_constraints_sequential(vuln_nodes)
        
        # Batch create edges from satisfied constraints
        edges = self._batch_create_edges(vuln_nodes, constraint_results['satisfied_edges'])
        
        # Update graph
        graph.nodes = ecg_nodes
        graph.edges = edges
        graph.constraint_matrix = constraint_results['constraint_matrix']
        
        # Calculate statistics
        graph.total_possible_paths = len(vulnerabilities) * (len(vulnerabilities) - 1) if len(vulnerabilities) > 1 else 0
        graph.eliminated_paths = graph.total_possible_paths - len(edges)
        
        # Performance metrics
        graph.build_time = time.time() - start_time
        graph.cache_hits = self.constraint_engine._metrics.get('cache_hits', 0)
        graph.cache_misses = self.constraint_engine._metrics.get('cache_misses', 0)
        
        # Estimate memory usage
        graph.memory_usage = len(ecg_nodes) * 150 + len(edges) * 80  # Bytes per node/edge
        
        return graph
    
    def _evaluate_constraints_parallel(self, vulnerability_nodes: List) -> Dict[str, Any]:
        """Parallel constraint evaluation for large datasets"""
        self._metrics['parallel_batches'] += 1
        return self.constraint_engine.evaluate_all_constraints_parallel(vulnerability_nodes)
    
    def _evaluate_constraints_sequential(self, vulnerability_nodes: List) -> Dict[str, Any]:
        """Sequential constraint evaluation for smaller datasets"""
        return self.constraint_engine.evaluate_all_constraints_sequential(vulnerability_nodes)
    
    def to_dict_optimized(self, graph: ECGGraphOptimized) -> Dict[str, Any]:
        """Convert optimized graph to dictionary format"""
        # Convert edges to dictionaries
        edge_dicts = []
        for edge in graph.edges:
            edge_dict = {
                'from': edge.from_node,
                'to': edge.to_node,
                'constraints_satisfied': edge.constraints_satisfied,
                'data_flow_path': edge.data_flow_path,
                'execution_distance': edge.execution_distance,
                'privilege_gap': edge.privilege_gap,
                'exploit_complexity': edge.exploit_complexity
            }
            edge_dicts.append(edge_dict)
        
        # Calculate complexity distribution
        complexity_dist = {'low': 0, 'medium': 0, 'high': 0, 'very_high': 0}
        for edge in graph.edges:
            complexity_dist[edge.exploit_complexity] += 1
        
        # Calculate entry points and sink types
        entry_points = sum(1 for node in graph.nodes.values() if node.entry_point)
        sink_types = {}
        for node in graph.nodes.values():
            sink_types[node.sink_type] = sink_types.get(node.sink_type, 0) + 1
        
        return {
            'nodes': [
                {
                    'id': node.id,
                    'vulnerability_id': node.vulnerability_id,
                    'stg_node_id': node.stg_node_id,
                    'vulnerability_type': node.vulnerability_type,
                    'severity': node.severity,
                    'entry_point': node.entry_point,
                    'sink_type': node.sink_type,
                    'privilege_level': node.privilege_level,
                    'file': node.file,
                    'line': node.line
                }
                for node in graph.nodes.values()
            ],
            'edges': edge_dicts,
            'constraint_matrix': graph.constraint_matrix,
            'statistics': {
                'total_nodes': len(graph.nodes),
                'total_edges': len(graph.edges),
                'eliminated_paths': graph.eliminated_paths,
                'total_possible_paths': graph.total_possible_paths,
                'elimination_rate': graph.eliminated_paths / graph.total_possible_paths if graph.total_possible_paths > 0 else 0,
                'edge_complexity_distribution': complexity_dist,
                'entry_points': entry_points,
                'sink_types': sink_types
            },
            'performance_metrics': {
                'build_time': graph.build_time,
                'cache_hits': graph.cache_hits,
                'cache_misses': graph.cache_misses,
                'cache_hit_rate': graph.cache_hits / (graph.cache_hits + graph.cache_misses) if (graph.cache_hits + graph.cache_misses) > 0 else 0,
                'memory_usage_estimate': graph.memory_usage
            }
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        return {
            'nodes_created': self._metrics['nodes_created'],
            'edges_created': self._metrics['edges_created'],
            'edges_evaluated': self._metrics['edges_evaluated'],
            'edges_filtered': self._metrics['edges_filtered'],
            'parallel_batches': self._metrics['parallel_batches'],
            'parallel_enabled': self.enable_parallel,
            'caching_enabled': self.enable_caching,
            'max_workers': self.max_workers
        }
    
    def clear_cache(self):
        """Clear all caches to free memory"""
        with self._cache_lock:
            self._edge_cache.clear()
        
        # Clear constraint engine cache
        self.constraint_engine.clear_cache()


def build_exploit_constraint_graph_optimized(stg_graph: STGGraph, vulnerabilities: List[VulnerabilityFinding],
                                           enable_caching: bool = True, enable_parallel: bool = True, max_workers: int = 4) -> Dict[str, Any]:
    """Optimized function to build exploit constraint graph"""
    builder = ECGBuilderOptimized(stg_graph, enable_caching, enable_parallel, max_workers)
    graph = builder.build_ecg_optimized(vulnerabilities)
    return builder.to_dict_optimized(graph)


if __name__ == "__main__":
    print("Optimized ECG Builder for Exploit Chain Analysis")
    print("Performance enhancements include batch processing, parallel evaluation, and memory optimization")
