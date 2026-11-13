"""
Unit Tests for Semantic Transaction Graph (STG) Builder - Patent Critical Component

Tests the core functionality of building semantic transaction graphs from AST.
"""

import pytest
import ast
from unittest.mock import Mock, patch
from pathlib import Path

from scanner.stg_builder import STGBuilder, STGNode, STGGraph, build_semantic_transaction_graph
from scanner.models import ApplicationModel, FileModel


class TestSTGBuilder:
    """Test suite for STG Builder functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.builder = STGBuilder()
        
        # Sample Python code with various transaction types
        self.sample_code_db = """
def process_user_data(user_id):
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    
    cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return user_data
"""
        
        self.sample_code_auth = """
def authenticate_user(username, password):
    user = find_user_by_username(username)
    if user and check_password(user.password, password):
        session['user_id'] = user.id
        session['role'] = user.role
        return True
    return False
"""
        
        self.sample_code_file = """
def save_uploaded_file(filename, content):
    with open(f'/uploads/{filename}', 'w') as f:
        f.write(content)
    return True
"""
        
        self.sample_code_network = """
def fetch_api_data(url):
    import requests
    response = requests.get(url)
    return response.json()
"""
    
    def test_generate_node_id(self):
        """Test unique node ID generation"""
        file_path = "/test/app.py"
        line = 10
        
        id1 = self.builder._generate_node_id(file_path, line)
        id2 = self.builder._generate_node_id(file_path, line + 1)
        
        assert id1 != id2
        assert id1.startswith("stg_")
        assert id2.startswith("stg_")
    
    def test_detect_transaction_type_database(self):
        """Test database transaction type detection"""
        tree = ast.parse(self.sample_code_db)
        code_lines = self.sample_code_db.splitlines()
        
        # Find execute call
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                transaction_type = self.builder._detect_transaction_type(node, code_lines)
                assert transaction_type in ["db_write", "db_read"]
                break
    
    def test_detect_transaction_type_auth(self):
        """Test authentication transaction type detection"""
        tree = ast.parse(self.sample_code_auth)
        code_lines = self.sample_code_auth.splitlines()
        
        # Find session assignment
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                transaction_type = self.builder._detect_transaction_type(node, code_lines)
                assert transaction_type == "auth_change"
                break
    
    def test_detect_transaction_type_file(self):
        """Test file operation transaction type detection"""
        tree = ast.parse(self.sample_code_file)
        code_lines = self.sample_code_file.splitlines()
        
        # Find open call
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                transaction_type = self.builder._detect_transaction_type(node, code_lines)
                assert transaction_type == "file_op"
                break
    
    def test_detect_transaction_type_network(self):
        """Test network operation transaction type detection"""
        tree = ast.parse(self.sample_code_network)
        code_lines = self.sample_code_network.splitlines()
        
        # Find requests call
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                transaction_type = self.builder._detect_transaction_type(node, code_lines)
                assert transaction_type == "network_op"
                break
    
    def test_extract_variables(self):
        """Test variable extraction from AST nodes"""
        code = """
def test():
    x = user_input
    y = x + 1
    return y
"""
        tree = ast.parse(code)
        
        # Find assignment node
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                accessed, modified = self.builder._extract_variables(node)
                assert "x" in modified
                break
        
        # Find return node
        for node in ast.walk(tree):
            if isinstance(node, ast.Return):
                accessed, modified = self.builder._extract_variables(node)
                assert "y" in accessed
                break
    
    def test_identify_data_sources_sinks(self):
        """Test data source and sink identification"""
        sources, sinks = self.builder._identify_data_sources_sinks(None, "db_write")
        assert "user_input" in sources
        assert "database" in sinks
        
        sources, sinks = self.builder._identify_data_sources_sinks(None, "auth_change")
        assert "credentials" in sources
        assert "session" in sinks
    
    def test_create_transaction_node(self):
        """Test STG node creation"""
        file_path = "/test/app.py"
        line = 10
        transaction_type = "db_write"
        function_name = "process_user"
        
        node = self.builder._create_transaction_node(
            Mock(), file_path, Mock(), transaction_type, function_name
        )
        
        assert isinstance(node, STGNode)
        assert node.file == file_path
        assert node.line == line
        assert node.transaction_type == transaction_type
        assert node.function_name == function_name
        assert node.state_change == f"{transaction_type}_in_{function_name}"
    
    def test_build_data_flow_edges(self):
        """Test data flow edge construction"""
        # Create test nodes
        node1 = STGNode(
            id="node1", file="test.py", line=1, transaction_type="db_write",
            state_change="", entry_points=[], exit_points=[], data_sources=[],
            data_sinks=[], function_name="func1", variables_modified=["x"],
            variables_accessed=[]
        )
        node2 = STGNode(
            id="node2", file="test.py", line=2, transaction_type="db_read",
            state_change="", entry_points=[], exit_points=[], data_sources=[],
            data_sinks=[], function_name="func2", variables_modified=[],
            variables_accessed=["x"]
        )
        
        edges = self.builder._build_data_flow_edges([node1, node2])
        
        assert len(edges) == 1
        assert edges[0]["from"] == "node1"
        assert edges[0]["to"] == "node2"
        assert edges[0]["tainted"] == False  # No user_input in sources
        assert "x" in edges[0]["variables"]
    
    def test_build_stg_empty_model(self):
        """Test STG building with empty model"""
        model = ApplicationModel(project_path="/test")
        graph = self.builder.build_stg(model)
        
        assert isinstance(graph, STGGraph)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
    
    def test_build_stg_with_files(self):
        """Test STG building with files containing vulnerabilities"""
        # Create test model with files
        model = ApplicationModel(project_path="/test")
        model.files = [
            FileModel(
                file_name="app.py",
                file_path="/test/app.py",
                file_type="Python",
                extension=".py",
                file_size=1000,
                content=self.sample_code_db
            )
        ]
        
        graph = self.builder.build_stg(model)
        
        assert isinstance(graph, STGGraph)
        assert len(graph.nodes) > 0
        assert "app.py" in graph.file_nodes
        assert len(graph.file_nodes["app.py"]) > 0
    
    def test_to_dict(self):
        """Test STG graph serialization to dictionary"""
        # Create test graph
        graph = STGGraph()
        graph.nodes = [
            STGNode(
                id="node1", file="test.py", line=1, transaction_type="db_write",
                state_change="", entry_points=[], exit_points=[], data_sources=[],
                data_sinks=[], function_name="func", variables_modified=[],
                variables_accessed=[]
            )
        ]
        graph.edges = [{"from": "node1", "to": "node2", "type": "data_flow"}]
        graph.file_nodes = {"test.py": ["node1"]}
        
        result = self.builder.to_dict(graph)
        
        assert "nodes" in result
        assert "edges" in result
        assert "file_nodes" in result
        assert "summary" in result
        assert result["summary"]["total_nodes"] == 1
        assert result["summary"]["total_edges"] == 1


class TestSTGBuilderIntegration:
    """Integration tests for STG Builder"""
    
    def test_build_semantic_transaction_graph_function(self):
        """Test the main STG builder function"""
        model = ApplicationModel(project_path="/test")
        model.files = [
            FileModel(
                file_name="app.py",
                file_path="/test/app.py",
                file_type="Python",
                extension=".py",
                file_size=1000,
                content="""
def process_data(data):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs VALUES (%s)", (data,))
    conn.commit()
    return True
"""
            )
        ]
        
        result = build_semantic_transaction_graph(model)
        
        assert isinstance(result, dict)
        assert "nodes" in result
        assert "edges" in result
        assert "summary" in result
        assert result["summary"]["total_nodes"] > 0
    
    def test_stg_builder_with_syntax_error(self):
        """Test STG builder handles syntax errors gracefully"""
        model = ApplicationModel(project_path="/test")
        model.files = [
            FileModel(
                file_name="broken.py",
                file_path="/test/broken.py",
                file_type="Python",
                extension=".py",
                file_size=100,
                content="def broken_syntax(\n    # Missing closing parenthesis"
            )
        ]
        
        graph = STGBuilder().build_stg(model)
        
        # Should handle syntax error gracefully
        assert isinstance(graph, STGGraph)
        assert len(graph.nodes) == 0


if __name__ == "__main__":
    pytest.main([__file__])
