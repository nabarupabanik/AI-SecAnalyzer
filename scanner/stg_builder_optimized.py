"""
Optimized Semantic Transaction Graph (STG) Builder - Performance Enhanced

Optimizations include:
- AST caching for repeated analysis
- Parallel file processing
- Memory-efficient node storage
- Early termination for simple cases
- Incremental graph building
"""

import ast
import hashlib
import pickle
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import threading
import time

from scanner.models import ApplicationModel, FileModel, VulnerabilityFinding


@dataclass
class STGNodeOptimized:
    """Optimized STG node with memory-efficient storage"""
    id: str
    file: str
    line: int
    transaction_type: str
    function_name: str
    state_change: str
    entry_points: List[str] = field(default_factory=list)
    exit_points: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    data_sinks: List[str] = field(default_factory=list)
    variables_modified: List[str] = field(default_factory=list)
    variables_accessed: List[str] = field(default_factory=list)
    
    # Optimized: Use bit flags for boolean properties
    flags: int = 0  # Bitmask for boolean properties


@dataclass
class STGGraphOptimized:
    """Optimized STG graph with performance enhancements"""
    nodes: Dict[str, STGNodeOptimized] = field(default_factory=dict)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    file_nodes: Dict[str, List[str]] = field(default_factory=dict)
    
    # Performance tracking
    build_time: float = 0.0
    memory_usage: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


class STGBuilderOptimized:
    """Optimized STG Builder with performance enhancements"""
    
    def __init__(self, enable_caching: bool = True, enable_parallel: bool = True, max_workers: int = 4):
        self.enable_caching = enable_caching
        self.enable_parallel = enable_parallel
        self.max_workers = max_workers
        
        # Thread-safe caching
        self._ast_cache = {}
        self._cache_lock = threading.RLock()
        
        # Performance metrics
        self._metrics = {
            'files_processed': 0,
            'nodes_created': 0,
            'edges_created': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'parallel_tasks': 0
        }
        
        # Pre-compiled patterns for performance
        self._transaction_patterns = self._compile_transaction_patterns()
    
    def _compile_transaction_patterns(self) -> Dict[str, Any]:
        """Pre-compile regex patterns for transaction detection"""
        import re
        
        return {
            'database': [
                re.compile(r'\b(execute|query|select|insert|update|delete)\b', re.IGNORECASE),
                re.compile(r'\b(cursor\.|db\.|conn\.)', re.IGNORECASE),
                re.compile(r'\b(sql|database|db)\b', re.IGNORECASE)
            ],
            'auth': [
                re.compile(r'\b(session|login|auth|password|credential)\b', re.IGNORECASE),
                re.compile(r'\b(set|get|clear).*session', re.IGNORECASE),
                re.compile(r'\b(authenticate|authorize)\b', re.IGNORECASE)
            ],
            'file': [
                re.compile(r'\b(open|read|write|delete|file)\b', re.IGNORECASE),
                re.compile(r'\b(with\s+open\(|open\s*\()', re.IGNORECASE),
                re.compile(r'\b(\.read|\.write|\.close)\b', re.IGNORECASE)
            ],
            'network': [
                re.compile(r'\b(requests|urllib|http|https|socket)\b', re.IGNORECASE),
                re.compile(r'\b(get|post|put|delete|patch)\s*\(', re.IGNORECASE),
                re.compile(r'\b(url|uri|endpoint)\b', re.IGNORECASE)
            ],
            'memory': [
                re.compile(r'\b(eval|exec|compile)\b', re.IGNORECASE),
                re.compile(r'\b(pickle|marshal|subprocess)\b', re.IGNORECASE),
                re.compile(r'\b(__import__|getattr|setattr)\b', re.IGNORECASE)
            ]
        }
    
    @lru_cache(maxsize=1000)
    def _generate_node_id(self, file_path: str, line: int) -> str:
        """Cached node ID generation"""
        content = f"{file_path}:{line}"
        hash_obj = hashlib.md5(content.encode())
        return f"stg_{hash_obj.hexdigest()[:12]}"
    
    def _get_file_hash(self, file_content: str) -> str:
        """Get hash of file content for caching"""
        return hashlib.sha256(file_content.encode()).hexdigest()
    
    def _parse_ast_cached(self, file_path: str, file_content: str) -> Optional[ast.AST]:
        """Parse AST with caching support"""
        if not self.enable_caching:
            try:
                return ast.parse(file_content)
            except SyntaxError:
                return None
        
        file_hash = self._get_file_hash(file_content)
        
        with self._cache_lock:
            if file_hash in self._ast_cache:
                self._metrics['cache_hits'] += 1
                return self._ast_cache[file_hash]
            
            self._metrics['cache_misses'] += 1
            
            try:
                tree = ast.parse(file_content)
                self._ast_cache[file_hash] = tree
                return tree
            except SyntaxError:
                return None
    
    def _detect_transaction_type_optimized(self, node: ast.AST, code_lines: List[str]) -> str:
        """Optimized transaction type detection using pre-compiled patterns"""
        # Fast path: check node type first
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node)
            if func_name:
                func_name_lower = func_name.lower()
                
                # Quick keyword matching
                if any(keyword in func_name_lower for keyword in ['execute', 'query', 'select', 'insert', 'update', 'delete']):
                    return 'db_write' if any(keyword in func_name_lower for keyword in ['insert', 'update', 'delete']) else 'db_read'
                elif any(keyword in func_name_lower for keyword in ['open', 'read', 'write']):
                    return 'file_op'
                elif any(keyword in func_name_lower for keyword in ['get', 'post', 'request']):
                    return 'network_op'
                elif any(keyword in func_name_lower for keyword in ['eval', 'exec']):
                    return 'memory_mutation'
        
        # Fallback to pattern matching for complex cases
        line_text = code_lines[node.lineno - 1] if hasattr(node, 'lineno') and node.lineno <= len(code_lines) else ""
        
        for transaction_type, patterns in self._transaction_patterns.items():
            for pattern in patterns:
                if pattern.search(line_text):
                    return f"{transaction_type}_write" if transaction_type == 'database' and any(kw in line_text.lower() for kw in ['insert', 'update', 'delete']) else f"{transaction_type}_read" if transaction_type == 'database' else f"{transaction_type}_op"
        
        return "unknown"
    
    def _get_function_name(self, node: ast.AST) -> Optional[str]:
        """Extract function name from call node efficiently"""
        if not isinstance(node, ast.Call):
            return None
            
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return None
    
    def _extract_variables_optimized(self, node: ast.AST) -> Tuple[List[str], List[str]]:
        """Optimized variable extraction with early termination"""
        accessed = []
        modified = []
        
        # Fast path for common node types
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    modified.append(target.id)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                modified.append(node.target.id)
        elif isinstance(node, ast.Name):
            accessed.append(node.id)
        elif isinstance(node, ast.Call):
            # Extract from arguments
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    accessed.append(arg.id)
        
        return accessed, modified
    
    def _create_transaction_node_optimized(self, node_id: str, file_path: str, line: int, 
                                         transaction_type: str, function_name: str) -> STGNodeOptimized:
        """Create optimized STG node with minimal memory footprint"""
        return STGNodeOptimized(
            id=node_id,
            file=file_path,
            line=line,
            transaction_type=transaction_type,
            function_name=function_name,
            state_change=f"{transaction_type}_in_{function_name}",
            flags=0  # Will be set later if needed
        )
    
    def _process_file_optimized(self, file_model: FileModel) -> Tuple[List[STGNodeOptimized], List[Dict[str, Any]]]:
        """Process a single file with optimizations"""
        start_time = time.time()
        
        # Parse AST with caching
        tree = self._parse_ast_cached(file_model.file_path, file_model.content or "")
        if not tree:
            return [], []
        
        code_lines = (file_model.content or "").splitlines()
        nodes = []
        edges = []
        last_node = None
        
        # Walk AST efficiently
        for node in ast.walk(tree):
            # Skip non-relevant node types early
            if not isinstance(node, (ast.Call, ast.Assign, ast.AugAssign, ast.Return)):
                continue
            
            line_num = getattr(node, 'lineno', 0)
            if line_num == 0:
                continue
            
            # Detect transaction type
            transaction_type = self._detect_transaction_type_optimized(node, code_lines)
            if transaction_type == "unknown":
                continue
            
            # Create node
            node_id = self._generate_node_id(file_model.file_path, line_num)
            function_name = self._get_function_name(node) or f"line_{line_num}"
            
            stg_node = self._create_transaction_node_optimized(
                node_id, file_model.file_path, line_num, transaction_type, function_name
            )
            
            # Extract variables efficiently
            accessed, modified = self._extract_variables_optimized(node)
            stg_node.variables_accessed.extend(accessed)
            stg_node.variables_modified.extend(modified)
            
            # Add data sources and sinks
            sources, sinks = self._identify_data_sources_sinks_optimized(node, transaction_type)
            stg_node.data_sources.extend(sources)
            stg_node.data_sinks.extend(sinks)
            
            nodes.append(stg_node)
            self._metrics['nodes_created'] += 1
            
            # Create edge to previous node if data flow exists
            if last_node and self._has_data_flow(last_node, stg_node):
                edge = {
                    "from": last_node.id,
                    "to": stg_node.id,
                    "type": "data_flow",
                    "tainted": any(var in last_node.variables_modified for var in stg_node.variables_accessed),
                    "variables": list(set(last_node.variables_modified) & set(stg_node.variables_accessed))
                }
                edges.append(edge)
                self._metrics['edges_created'] += 1
            
            last_node = stg_node
        
        self._metrics['files_processed'] += 1
        processing_time = time.time() - start_time
        
        return nodes, edges
    
    def _identify_data_sources_sinks_optimized(self, node: ast.AST, transaction_type: str) -> Tuple[List[str], List[str]]:
        """Optimized data source and sink identification"""
        sources = []
        sinks = []
        
        # Use pre-defined mappings for common transaction types
        if transaction_type.startswith('db'):
            sources = ["user_input", "application_data", "session_data"]
            sinks = ["database", "query_result"]
        elif transaction_type.startswith('auth'):
            sources = ["credentials", "tokens", "cookies"]
            sinks = ["session", "auth_token", "user_context"]
        elif transaction_type.startswith('file'):
            sources = ["user_input", "application_data"]
            sinks = ["file_system", "disk_storage"]
        elif transaction_type.startswith('network'):
            sources = ["user_input", "application_data"]
            sinks = ["network", "external_api", "remote_service"]
        elif transaction_type.startswith('memory'):
            sources = ["user_input", "external_data"]
            sinks = ["memory", "process_state"]
        
        return sources, sinks
    
    def _has_data_flow(self, from_node: STGNodeOptimized, to_node: STGNodeOptimized) -> bool:
        """Optimized data flow detection"""
        # Quick check: same file and line ordering
        if from_node.file != to_node.file or from_node.line >= to_node.line:
            return False
        
        # Check variable overlap
        return bool(set(from_node.variables_modified) & set(to_node.variables_accessed))
    
    def _build_data_flow_edges_optimized(self, nodes: List[STGNodeOptimized]) -> List[Dict[str, Any]]:
        """Optimized data flow edge construction"""
        edges = []
        
        # Group nodes by file for efficient processing
        file_nodes = {}
        for node in nodes:
            file_nodes.setdefault(node.file, []).append(node)
        
        # Process each file
        for file_nodes_list in file_nodes.values():
            # Sort by line number for deterministic processing
            file_nodes_list.sort(key=lambda x: x.line)
            
            # Build edges within file
            for i in range(len(file_nodes_list)):
                for j in range(i + 1, len(file_nodes_list)):
                    from_node = file_nodes_list[i]
                    to_node = file_nodes_list[j]
                    
                    if self._has_data_flow(from_node, to_node):
                        edge = {
                            "from": from_node.id,
                            "to": to_node.id,
                            "type": "data_flow",
                            "tainted": any(var in from_node.variables_modified for var in to_node.variables_accessed),
                            "variables": list(set(from_node.variables_modified) & set(to_node.variables_accessed))
                        }
                        edges.append(edge)
        
        return edges
    
    def build_stg_optimized(self, model: ApplicationModel) -> STGGraphOptimized:
        """Build optimized STG with performance enhancements"""
        start_time = time.time()
        
        graph = STGGraphOptimized()
        
        if not model.files:
            return graph
        
        # Process files in parallel if enabled
        if self.enable_parallel and len(model.files) > 1:
            nodes, edges = self._process_files_parallel(model.files)
        else:
            nodes, edges = self._process_files_sequential(model.files)
        
        # Build graph structure
        graph.nodes = {node.id: node for node in nodes}
        graph.edges = edges
        
        # Build file nodes mapping
        for node in nodes:
            graph.file_nodes.setdefault(node.file, []).append(node.id)
        
        # Calculate metrics
        graph.build_time = time.time() - start_time
        graph.cache_hits = self._metrics['cache_hits']
        graph.cache_misses = self._metrics['cache_misses']
        
        # Estimate memory usage (rough approximation)
        graph.memory_usage = len(nodes) * 200 + len(edges) * 100  # Bytes per node/edge
        
        return graph
    
    def _process_files_parallel(self, files: List[FileModel]) -> Tuple[List[STGNodeOptimized], List[Dict[str, Any]]]:
        """Process files in parallel"""
        all_nodes = []
        all_edges = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self._process_file_optimized, file): file
                for file in files
            }
            
            self._metrics['parallel_tasks'] = len(files)
            
            # Collect results
            for future in as_completed(future_to_file):
                try:
                    nodes, edges = future.result()
                    all_nodes.extend(nodes)
                    all_edges.extend(edges)
                except Exception as e:
                    # Log error but continue processing
                    print(f"Error processing file: {e}")
        
        return all_nodes, all_edges
    
    def _process_files_sequential(self, files: List[FileModel]) -> Tuple[List[STGNodeOptimized], List[Dict[str, Any]]]:
        """Process files sequentially"""
        all_nodes = []
        all_edges = []
        
        for file in files:
            nodes, edges = self._process_file_optimized(file)
            all_nodes.extend(nodes)
            all_edges.extend(edges)
        
        return all_nodes, all_edges
    
    def to_dict_optimized(self, graph: STGGraphOptimized) -> Dict[str, Any]:
        """Convert optimized graph to dictionary format"""
        return {
            "nodes": [
                {
                    "id": node.id,
                    "file": node.file,
                    "line": node.line,
                    "transaction_type": node.transaction_type,
                    "function_name": node.function_name,
                    "state_change": node.state_change,
                    "entry_points": node.entry_points,
                    "exit_points": node.exit_points,
                    "data_sources": node.data_sources,
                    "data_sinks": node.data_sinks,
                    "variables_modified": node.variables_modified,
                    "variables_accessed": node.variables_accessed
                }
                for node in graph.nodes.values()
            ],
            "edges": graph.edges,
            "file_nodes": graph.file_nodes,
            "summary": {
                "total_nodes": len(graph.nodes),
                "total_edges": len(graph.edges),
                "files_processed": len(graph.file_nodes),
                "build_time": graph.build_time,
                "cache_hits": graph.cache_hits,
                "cache_misses": graph.cache_misses,
                "cache_hit_rate": graph.cache_hits / (graph.cache_hits + graph.cache_misses) if (graph.cache_hits + graph.cache_misses) > 0 else 0,
                "memory_usage_estimate": graph.memory_usage
            },
            "performance_metrics": self._metrics
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        total_requests = self._metrics['cache_hits'] + self._metrics['cache_misses']
        
        return {
            "files_processed": self._metrics['files_processed'],
            "nodes_created": self._metrics['nodes_created'],
            "edges_created": self._metrics['edges_created'],
            "cache_hits": self._metrics['cache_hits'],
            "cache_misses": self._metrics['cache_misses'],
            "cache_hit_rate": self._metrics['cache_hits'] / total_requests if total_requests > 0 else 0,
            "parallel_tasks": self._metrics['parallel_tasks'],
            "parallel_enabled": self.enable_parallel,
            "caching_enabled": self.enable_caching,
            "max_workers": self.max_workers
        }
    
    def clear_cache(self):
        """Clear AST cache to free memory"""
        with self._cache_lock:
            self._ast_cache.clear()
        
        # Clear LRU cache
        self._generate_node_id.cache_clear()


def build_semantic_transaction_graph_optimized(model: ApplicationModel, 
                                            enable_caching: bool = True,
                                            enable_parallel: bool = True,
                                            max_workers: int = 4) -> Dict[str, Any]:
    """Optimized function to build semantic transaction graph"""
    builder = STGBuilderOptimized(enable_caching, enable_parallel, max_workers)
    graph = builder.build_stg_optimized(model)
    return builder.to_dict_optimized(graph)


if __name__ == "__main__":
    print("Optimized STG Builder for Exploit Chain Analysis")
    print("Performance enhancements include caching, parallel processing, and memory optimization")
