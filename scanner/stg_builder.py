"""
Semantic Transaction Graph (STG) Builder - Patent Critical Component

Transforms AST into transaction-level nodes based on state change boundaries.
Identifies transaction boundaries by detecting state-altering operations.
"""

import ast
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from .models import FileModel, ApplicationModel


@dataclass
class STGNode:
    """Semantic Transaction Graph Node"""
    id: str
    file: str
    line: int
    transaction_type: str  # "db_write", "db_read", "auth_change", "file_op", "network_op", "memory_mutation"
    state_change: str
    entry_points: List[str] = field(default_factory=list)
    exit_points: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    data_sinks: List[str] = field(default_factory=list)
    function_name: str = ""
    variables_modified: List[str] = field(default_factory=list)
    variables_accessed: List[str] = field(default_factory=list)


@dataclass
class STGGraph:
    """Complete Semantic Transaction Graph"""
    nodes: List[STGNode] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    file_nodes: Dict[str, List[str]] = field(default_factory=dict)  # file -> node_ids


class STGBuilder:
    """Builds Semantic Transaction Graph from AST"""
    
    def __init__(self):
        self.node_counter = 0
        self.nodes: List[STGNode] = []
        self.edges: List[Dict[str, Any]] = []
        self.file_nodes: Dict[str, List[str]] = {}
        
        # State change detection patterns
        self.db_patterns = [
            r'\.execute\(', r'\.commit\(', r'\.cursor\(',
            r'insert\s+into', r'update\s+', r'delete\s+from',
            r'create\s+table', r'drop\s+table'
        ]
        self.auth_patterns = [
            r'login\(', r'authenticate\(', r'check_password\(',
            r'set_password\(', r'change_role\(', r'grant\s+',
            r'revoke\s+', r'create_user\(', r'delete_user\('
        ]
        self.file_patterns = [
            r'open\(', r'\.write\(', r'\.read\(',
            r'\.remove\(', r'\.mkdir\(', r'\.rmdir\(',
            r'shutil\.', r'os\.path\.'
        ]
        self.network_patterns = [
            r'requests\.', r'urllib\.', r'http\.',
            r'socket\.', r'connect\(', r'\.send\(',
            r'\.recv\(', r'ftp\.', r'smtp\.'
        ]
    
    def _generate_node_id(self, file_path: str, line: int) -> str:
        """Generate unique node ID"""
        self.node_counter += 1
        file_hash = hash(file_path) % 10000
        return f"stg_{file_hash}_{line}_{self.node_counter}"
    
    def _detect_transaction_type(self, node: ast.AST, code_lines: List[str]) -> str:
        """Detect transaction type from AST node and source code"""
        line_code = ""
        if hasattr(node, 'lineno') and node.lineno <= len(code_lines):
            line_code = code_lines[node.lineno - 1].lower()
        
        # Check for database operations
        for pattern in self.db_patterns:
            if re.search(pattern, line_code, re.IGNORECASE):
                if 'read' in line_code or 'select' in line_code:
                    return "db_read"
                return "db_write"
        
        # Check for authentication operations
        for pattern in self.auth_patterns:
            if re.search(pattern, line_code, re.IGNORECASE):
                return "auth_change"
        
        # Check for file operations
        for pattern in self.file_patterns:
            if re.search(pattern, line_code, re.IGNORECASE):
                return "file_op"
        
        # Check for network operations
        for pattern in self.network_patterns:
            if re.search(pattern, line_code, re.IGNORECASE):
                return "network_op"
        
        # Default to memory mutation for other operations
        return "memory_mutation"
    
    def _extract_variables(self, node: ast.AST) -> Tuple[List[str], List[str]]:
        """Extract accessed and modified variables from AST node"""
        accessed = set()
        modified = set()
        
        class VariableVisitor(ast.NodeVisitor):
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Load):
                    accessed.add(node.id)
                elif isinstance(node.ctx, ast.Store):
                    modified.add(node.id)
                self.generic_visit(node)
            
            def visit_Attribute(self, node):
                if isinstance(node.ctx, ast.Load):
                    accessed.add(ast.unparse(node))
                elif isinstance(node.ctx, ast.Store):
                    modified.add(ast.unparse(node))
                self.generic_visit(node)
        
        visitor = VariableVisitor()
        visitor.visit(node)
        
        return list(accessed), list(modified)
    
    def _identify_data_sources_sinks(self, node: ast.AST, transaction_type: str) -> Tuple[List[str], List[str]]:
        """Identify data sources and sinks based on transaction type"""
        sources = []
        sinks = []
        
        if transaction_type == "db_read":
            sources = ["database", "user_input"]
            sinks = ["memory", "response"]
        elif transaction_type == "db_write":
            sources = ["user_input", "memory", "form_data"]
            sinks = ["database"]
        elif transaction_type == "auth_change":
            sources = ["user_input", "credentials"]
            sinks = ["session", "database", "auth_token"]
        elif transaction_type == "file_op":
            sources = ["file_system", "user_input"]
            sinks = ["file_system", "memory"]
        elif transaction_type == "network_op":
            sources = ["user_input", "memory", "network"]
            sinks = ["network", "memory", "response"]
        else:  # memory_mutation
            sources = ["memory", "user_input"]
            sinks = ["memory", "response"]
        
        return sources, sinks
    
    def _analyze_function(self, func_node: ast.FunctionDef, file_path: str, code_lines: List[str]) -> List[STGNode]:
        """Analyze a function and create transaction nodes"""
        nodes = []
        
        # Group statements into transactions based on state changes
        current_statements = []
        current_transaction_type = None
        
        for stmt in func_node.body:
            transaction_type = self._detect_transaction_type(stmt, code_lines)
            
            # Start new transaction if type changes or we hit a state change
            if (transaction_type != current_transaction_type and 
                transaction_type != "memory_mutation" and 
                current_statements):
                
                # Create node for completed transaction
                if current_statements:
                    node = self._create_transaction_node(
                        current_statements[0], file_path, code_lines,
                        current_transaction_type or "memory_mutation",
                        func_node.name
                    )
                    nodes.append(node)
                
                current_statements = [stmt]
                current_transaction_type = transaction_type
            else:
                current_statements.append(stmt)
                if transaction_type != "memory_mutation":
                    current_transaction_type = transaction_type
        
        # Handle final transaction
        if current_statements and current_transaction_type != "memory_mutation":
            node = self._create_transaction_node(
                current_statements[0], file_path, code_lines,
                current_transaction_type or "memory_mutation",
                func_node.name
            )
            nodes.append(node)
        
        return nodes
    
    def _create_transaction_node(self, node: ast.AST, file_path: str, 
                                code_lines: List[str], transaction_type: str,
                                function_name: str) -> STGNode:
        """Create a single STG node"""
        line = getattr(node, 'lineno', 1)
        node_id = self._generate_node_id(file_path, line)
        
        # Extract variables
        accessed_vars, modified_vars = self._extract_variables(node)
        
        # Identify data sources and sinks
        sources, sinks = self._identify_data_sources_sinks(node, transaction_type)
        
        # Determine state change description
        state_change = f"{transaction_type}_in_{function_name}"
        
        return STGNode(
            id=node_id,
            file=file_path,
            line=line,
            transaction_type=transaction_type,
            state_change=state_change,
            entry_points=sources,
            exit_points=sinks,
            data_sources=sources,
            data_sinks=sinks,
            function_name=function_name,
            variables_modified=modified_vars,
            variables_accessed=accessed_vars
        )
    
    def _build_data_flow_edges(self, nodes: List[STGNode]) -> List[Dict[str, Any]]:
        """Build data flow edges between STG nodes"""
        edges = []
        GENERIC_CATEGORIES = {"memory", "response"}
        
        for i, node1 in enumerate(nodes):
            for j, node2 in enumerate(nodes):
                if i >= j:  # Avoid duplicates and self-edges
                    continue
                
                # Check for data flow dependency
                data_flow = False
                tainted = False
                shared_vars = set(node1.variables_modified) & set(node2.variables_accessed)
                
                # 1. Variable flow: node1 modifies variables that node2 accesses
                if shared_vars:
                    data_flow = True
                    if "user_input" in node1.data_sources or "user_input" in node1.entry_points:
                        tainted = True
                else:
                    # 2. Specific source-sink channel matching (must NOT be generic memory/response)
                    # For cross-file matching, require specific security-relevant channels (e.g., user_input -> network/db/file_system)
                    for sink in node1.exit_points:
                        if sink in GENERIC_CATEGORIES:
                            continue
                        for src in node2.data_sources:
                            if src in GENERIC_CATEGORIES:
                                continue
                            # Same file OR specific channel transfer (user_input -> sink)
                            if node1.file == node2.file or (sink == src and sink in {"file_system", "network", "database"}):
                                data_flow = True
                                if "user_input" in node1.data_sources or src == "user_input":
                                    tainted = True
                                break
                        if data_flow:
                            break
                
                if data_flow:
                    edges.append({
                        "from": node1.id,
                        "to": node2.id,
                        "type": "data_flow",
                        "tainted": tainted,
                        "variables": list(shared_vars)
                    })
        
        return edges
    
    def build_stg(self, model: ApplicationModel) -> STGGraph:
        """Build complete Semantic Transaction Graph"""
        self.nodes = []
        self.edges = []
        self.file_nodes = {}
        self.node_counter = 0
        
        for file_model in model.files:
            if not file_model.content or file_model.extension != ".py":
                continue
            
            file_path = str(file_model.file_path)
            code_lines = file_model.content.splitlines()
            file_nodes = []
            
            try:
                # Parse AST
                tree = ast.parse(file_model.content)
                
                # Analyze each function
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        func_nodes = self._analyze_function(node, file_path, code_lines)
                        self.nodes.extend(func_nodes)
                        file_nodes.extend([n.id for n in func_nodes])
                
                self.file_nodes[file_path] = file_nodes
                
            except SyntaxError as e:
                # Skip files with syntax errors
                continue
        
        # Build data flow edges
        self.edges = self._build_data_flow_edges(self.nodes)
        
        return STGGraph(
            nodes=self.nodes,
            edges=self.edges,
            file_nodes=self.file_nodes
        )
    
    def to_dict(self, graph: STGGraph) -> Dict[str, Any]:
        """Convert STG to dictionary for JSON serialization"""
        return {
            "nodes": [
                {
                    "id": node.id,
                    "file": node.file,
                    "line": node.line,
                    "transaction_type": node.transaction_type,
                    "state_change": node.state_change,
                    "entry_points": node.entry_points,
                    "exit_points": node.exit_points,
                    "data_sources": node.data_sources,
                    "data_sinks": node.data_sinks,
                    "function_name": node.function_name,
                    "variables_modified": node.variables_modified,
                    "variables_accessed": node.variables_accessed
                }
                for node in graph.nodes
            ],
            "edges": graph.edges,
            "file_nodes": graph.file_nodes,
            "summary": {
                "total_nodes": len(graph.nodes),
                "total_edges": len(graph.edges),
                "transaction_types": {
                    t: len([n for n in graph.nodes if n.transaction_type == t])
                    for t in set(n.transaction_type for n in graph.nodes)
                }
            }
        }


def build_semantic_transaction_graph(model: ApplicationModel) -> Dict[str, Any]:
    """
    Build Semantic Transaction Graph for the given application model.
    
    Args:
        model: ApplicationModel with parsed files
        
    Returns:
        Dictionary representation of STG
    """
    builder = STGBuilder()
    graph = builder.build_stg(model)
    return builder.to_dict(graph)
