"""
Basic Test for Optimized Implementation

Tests that the optimized implementations work correctly without complex compatibility issues.
"""

import time
import tempfile
import os
from pathlib import Path

from scanner.models import ApplicationModel, FileModel, VulnerabilityFinding
from scanner.stg_builder_optimized import build_semantic_transaction_graph_optimized
from scanner.constraint_engine_optimized import evaluate_constraints_optimized
from scanner.ecg_builder_optimized import build_exploit_constraint_graph_optimized
from scanner.csar_engine_optimized import perform_csar_traversal_optimized


def test_optimized_pipeline():
    """Test the complete optimized pipeline"""
    print("Testing Optimized Exploit Chain Analysis Pipeline...")
    
    # Create temporary test project
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create test code
        test_code = """
def login(username, password):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = execute_query(query)
    user = cursor.fetchone()
    
    if user:
        # XSS vulnerability
        session['welcome_message'] = f"Welcome {user['name']}!"
        return True
    return False

def execute_query(query):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor

def get_user_data(user_id):
    # Another SQL injection
    query = f"SELECT * FROM user_data WHERE id = {user_id}"
    return execute_query(query)
"""
        
        # Write test file
        test_file_path = os.path.join(temp_dir, "app.py")
        with open(test_file_path, 'w') as f:
            f.write(test_code)
        
        # Create test model
        model = ApplicationModel(project_path=temp_dir)
        model.files = [
            FileModel(
                file_name="app.py",
                file_path=test_file_path,
                file_type="Python",
                extension=".py",
                file_size=len(test_code),
                content=test_code
            )
        ]
        
        # Add vulnerabilities
        model.vulnerabilities = [
            VulnerabilityFinding(
                file="app.py", line=3, type="SQL Injection", severity="High",
                code="query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
                fingerprint="sql_injection_1"
            ),
            VulnerabilityFinding(
                file="app.py", line=8, type="XSS", severity="Medium",
                code="session['welcome_message'] = f\"Welcome {user['name']}!\"",
                fingerprint="xss_1"
            ),
            VulnerabilityFinding(
                file="app.py", line=15, type="SQL Injection", severity="High",
                code="query = f\"SELECT * FROM user_data WHERE id = {user_id}\"",
                fingerprint="sql_injection_2"
            )
        ]
        
        print(f"  Created test model with {len(model.files)} files and {len(model.vulnerabilities)} vulnerabilities")
        
        # Test STG Builder
        print("  Testing STG Builder...")
        start_time = time.time()
        stg_result = build_semantic_transaction_graph_optimized(
            model, enable_caching=True, enable_parallel=True
        )
        stg_time = time.time() - start_time
        
        assert "nodes" in stg_result
        assert "edges" in stg_result
        assert "summary" in stg_result
        assert len(stg_result["nodes"]) > 0
        
        print(f"    STG: {len(stg_result['nodes'])} nodes, {len(stg_result['edges'])} edges, {stg_time:.3f}s")
        
        # Test Constraint Engine
        print("  Testing Constraint Engine...")
        start_time = time.time()
        constraint_result = evaluate_constraints_optimized(
            stg_result, model.vulnerabilities, enable_caching=True, enable_parallel=True
        )
        constraint_time = time.time() - start_time
        
        assert "constraint_matrix" in constraint_result
        assert "satisfied_edges" in constraint_result
        assert "unsatisfied_edges" in constraint_result
        assert "statistics" in constraint_result
        
        print(f"    Constraints: {constraint_result['statistics']['satisfaction_rate']:.2f} satisfaction rate, {constraint_time:.3f}s")
        
        # Test ECG Builder
        print("  Testing ECG Builder...")
        start_time = time.time()
        ecg_result = build_exploit_constraint_graph_optimized(
            stg_result, model.vulnerabilities, enable_caching=True, enable_parallel=True
        )
        ecg_time = time.time() - start_time
        
        assert "nodes" in ecg_result
        assert "edges" in ecg_result
        assert "statistics" in ecg_result
        
        print(f"    ECG: {len(ecg_result['nodes'])} nodes, {len(ecg_result['edges'])} edges, {ecg_time['statistics']['elimination_rate']:.2f} elimination rate, {ecg_time:.3f}s")
        
        # Test CSAR Engine
        print("  Testing CSAR Engine...")
        start_time = time.time()
        csar_result = perform_csar_traversal_optimized(
            ecg_result, stg_result, enable_caching=True, enable_parallel=True
        )
        csar_time = time.time() - start_time
        
        assert "exploit_chains" in csar_result
        assert "statistics" in csar_result
        
        print(f"    CSAR: {len(csar_result['exploit_chains'])} chains found, {csar_time:.3f}s")
        
        # Print chain details
        for i, chain in enumerate(csar_result['exploit_chains']):
            print(f"      Chain {i+1}: {chain['feasibility']} feasibility, {len(chain['steps'])} steps")
        
        # Test performance
        total_time = stg_time + constraint_time + ecg_time + csar_time
        print(f"  Total processing time: {total_time:.3f}s")
        
        # Test caching effectiveness
        print("  Testing caching effectiveness...")
        
        # Run STG again (should use cache)
        start_time = time.time()
        stg_result2 = build_semantic_transaction_graph_optimized(
            model, enable_caching=True, enable_parallel=True
        )
        cached_time = time.time() - start_time
        
        print(f"    Cache test: First run {stg_time:.3f}s, Second run {cached_time:.3f}s")
        
        # Results should be equivalent
        assert len(stg_result["nodes"]) == len(stg_result2["nodes"])
        
        print("  Optimized pipeline test: PASSED")
        return True
        
    finally:
        # Clean up
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_performance_comparison():
    """Test performance with different project sizes"""
    print("\nTesting Performance Comparison...")
    
    sizes = [1, 5, 10, 20]
    
    for size in sizes:
        print(f"  Testing with {size} files...")
        
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Create test model
            model = ApplicationModel(project_path=temp_dir)
            
            # Add files
            for i in range(size):
                file_content = f"""
def function_{i}(data):
    query = f"SELECT * FROM table_{i} WHERE id = {{data}}"
    return execute_query(query)

def process_{i}(input_data):
    result = function_{i}(input_data)
    session['result_{i}'] = f"Processed: {{result}}"
    return result
"""
                
                model.files.append(
                    FileModel(
                        file_name=f"module_{i}.py",
                        file_path=os.path.join(temp_dir, f"module_{i}.py"),
                        file_type="Python",
                        extension=".py",
                        file_size=len(file_content),
                        content=file_content
                    )
                )
                
                # Add vulnerabilities
                model.vulnerabilities.extend([
                    VulnerabilityFinding(
                        file=f"module_{i}.py", line=2, type="SQL Injection", severity="High",
                        code=f"query = f\"SELECT * FROM table_{i} WHERE id = {{data}}\"",
                        fingerprint=f"sql_injection_{i}"
                    ),
                    VulnerabilityFinding(
                        file=f"module_{i}.py", line=6, type="XSS", severity="Medium",
                        code=f"session['result_{i}'] = f\"Processed: {{result}}\"",
                        fingerprint=f"xss_{i}"
                    )
                ])
            
            # Test with caching enabled
            start_time = time.time()
            stg_result = build_semantic_transaction_graph_optimized(
                model, enable_caching=True, enable_parallel=True
            )
            constraint_result = evaluate_constraints_optimized(
                stg_result, model.vulnerabilities, enable_caching=True, enable_parallel=True
            )
            ecg_result = build_exploit_constraint_graph_optimized(
                stg_result, model.vulnerabilities, enable_caching=True, enable_parallel=True
            )
            csar_result = perform_csar_traversal_optimized(
                ecg_result, stg_result, enable_caching=True, enable_parallel=True
            )
            total_time = time.time() - start_time
            
            print(f"    {size} files: {total_time:.3f}s, {len(stg_result['nodes'])} nodes, {len(csar_result['exploit_chains'])} chains")
            
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    print("  Performance comparison test: PASSED")


def test_parallel_vs_sequential():
    """Test parallel vs sequential processing"""
    print("\nTesting Parallel vs Sequential Processing...")
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create larger test model
        model = ApplicationModel(project_path=temp_dir)
        
        for i in range(15):
            file_content = f"""
def parallel_function_{i}(data):
    query = f"SELECT * FROM table_{i} WHERE id = {{data}}"
    return execute_query(query)
"""
            
            model.files.append(
                FileModel(
                    file_name=f"parallel_module_{i}.py",
                    file_path=os.path.join(temp_dir, f"parallel_module_{i}.py"),
                    file_type="Python",
                    extension=".py",
                    file_size=len(file_content),
                    content=file_content
                )
            )
            
            model.vulnerabilities.append(
                VulnerabilityFinding(
                    file=f"parallel_module_{i}.py", line=2, type="SQL Injection", severity="High",
                    code=f"query = f\"SELECT * FROM table_{i} WHERE id = {{data}}\"",
                    fingerprint=f"sql_injection_{i}"
                )
            )
        
        # Test sequential
        start_time = time.time()
        stg_sequential = build_semantic_transaction_graph_optimized(
            model, enable_caching=False, enable_parallel=False
        )
        sequential_time = time.time() - start_time
        
        # Test parallel
        start_time = time.time()
        stg_parallel = build_semantic_transaction_graph_optimized(
            model, enable_caching=False, enable_parallel=True, max_workers=4
        )
        parallel_time = time.time() - start_time
        
        print(f"  Sequential: {sequential_time:.3f}s")
        print(f"  Parallel: {parallel_time:.3f}s")
        print(f"  Speedup: {sequential_time/parallel_time:.2f}x")
        
        # Results should be equivalent
        assert len(stg_sequential["nodes"]) == len(stg_parallel["nodes"])
        
        print("  Parallel vs sequential test: PASSED")
        
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_basic_tests():
    """Run all basic tests"""
    print("=" * 60)
    print("BASIC OPTIMIZED IMPLEMENTATION TESTS")
    print("=" * 60)
    
    try:
        test_optimized_pipeline()
        test_performance_comparison()
        test_parallel_vs_sequential()
        
        print("\n" + "=" * 60)
        print("ALL BASIC TESTS PASSED!")
        print("Optimized implementation is working correctly")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    run_basic_tests()
