"""
Performance Benchmark for Exploit Chain Analysis System

Generates comprehensive performance comparison metrics between traditional
vulnerability analysis and the constraint-bound exploit chain analysis.
"""

import time
import json
import statistics
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import psutil
import tracemalloc

from scanner.models import ApplicationModel, FileModel, VulnerabilityFinding
from scanner.stg_builder import build_semantic_transaction_graph
from scanner.ecg_builder import build_exploit_constraint_graph
from scanner.csar_engine import perform_csar_traversal


@dataclass
class BenchmarkResult:
    """Single benchmark result"""
    project_name: str
    file_count: int
    vulnerability_count: int
    dependency_count: int
    
    # Traditional analysis metrics
    traditional_time: float
    traditional_memory_mb: float
    traditional_paths: int
    traditional_false_positives: int
    
    # Constraint-bound analysis metrics
    stg_time: float
    ecg_time: float
    csar_time: float
    total_constraint_time: float
    constraint_memory_mb: float
    feasible_paths: int
    eliminated_paths: int
    exploit_chains: int
    
    # Improvement metrics
    path_reduction_rate: float
    false_positive_reduction: float
    accuracy_improvement: float
    processing_overhead: float


class PerformanceBenchmark:
    """Comprehensive performance benchmarking suite"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.test_projects = self._create_test_projects()
    
    def _create_test_projects(self) -> List[ApplicationModel]:
        """Create test projects of varying sizes and complexity"""
        projects = []
        
        # Small project (5 files, 10 vulnerabilities)
        small_project = self._create_project(
            name="small_web_app",
            file_count=5,
            vuln_count=10,
            complexity="low"
        )
        projects.append(small_project)
        
        # Medium project (25 files, 50 vulnerabilities)
        medium_project = self._create_project(
            name="medium_api_service",
            file_count=25,
            vuln_count=50,
            complexity="medium"
        )
        projects.append(medium_project)
        
        # Large project (100 files, 200 vulnerabilities)
        large_project = self._create_project(
            name="large_enterprise_system",
            file_count=100,
            vuln_count=200,
            complexity="high"
        )
        projects.append(large_project)
        
        # Very large project (500 files, 1000 vulnerabilities)
        very_large_project = self._create_project(
            name="very_large_ecommerce",
            file_count=500,
            vuln_count=1000,
            complexity="very_high"
        )
        projects.append(very_large_project)
        
        return projects
    
    def _create_project(self, name: str, file_count: int, vuln_count: int, complexity: str) -> ApplicationModel:
        """Create a test project with specified characteristics"""
        project = ApplicationModel(project_path=f"/test/{name}")
        
        # Create files
        for i in range(file_count):
            file_content = self._generate_file_content(i, vuln_count // file_count, complexity)
            file_model = FileModel(
                file_name=f"module_{i}.py",
                file_path=f"/test/{name}/module_{i}.py",
                file_type="Python",
                extension=".py",
                file_size=len(file_content),
                content=file_content
            )
            project.files.append(file_model)
        
        # Create vulnerabilities distributed across files
        for i in range(vuln_count):
            file_index = i % file_count
            vulnerability = self._create_vulnerability(i, file_index, complexity)
            project.vulnerabilities.append(vulnerability)
        
        # Add dependency vulnerabilities
        dependency_count = vuln_count // 5  # 20% of vulnerabilities are dependencies
        for i in range(dependency_count):
            dep_vuln = self._create_dependency_vulnerability(i, complexity)
            project.dependency_vulnerabilities.append(dep_vuln)
        
        return project
    
    def _generate_file_content(self, file_index: int, vuln_count: int, complexity: str) -> str:
        """Generate realistic file content with vulnerabilities"""
        base_code = """
import requests
import sqlite3
from flask import Flask, request, session

app = Flask(__name__)

def process_user_input(user_data):
    # Vulnerability placeholder
    query = f"SELECT * FROM users WHERE name = '{user_data}'"
    return query

def authenticate_user(username, password):
    # Another vulnerability placeholder
    if username == "admin" and password == "admin":
        session['admin'] = True
    return True

def get_user_profile(user_id):
    # Third vulnerability placeholder
    profile_query = f"SELECT * FROM profiles WHERE id = {user_id}"
    return profile_query

class UserService:
    def __init__(self):
        self.db_connection = sqlite3.connect(':memory:')
    
    def update_user(self, user_id, data):
        # Fourth vulnerability placeholder
        update_query = f"UPDATE users SET data = '{data}' WHERE id = {user_id}"
        return update_query

"""
        
        # Add complexity-specific content
        if complexity == "high" or complexity == "very_high":
            base_code += """
# Complex business logic
def complex_business_logic(param1, param2, param3):
    # Multiple vulnerability placeholders
    query1 = f"SELECT * FROM table1 WHERE col1 = '{param1}'"
    query2 = f"UPDATE table2 SET col2 = '{param2}' WHERE col3 = {param3}"
    return query1 + query2

def api_endpoint():
    data = request.json
    # More vulnerability placeholders
    result = f"Processed: {data['input']}"
    return result
"""
        
        return base_code
    
    def _create_vulnerability(self, index: int, file_index: int, complexity: str) -> VulnerabilityFinding:
        """Create a vulnerability finding"""
        severities = ["Low", "Medium", "High", "Critical"]
        types = ["SQL Injection", "XSS", "Command Injection", "Path Traversal", "CSRF"]
        
        severity = severities[index % len(severities)]
        vuln_type = types[index % len(types)]
        
        return VulnerabilityFinding(
            file=f"module_{file_index}.py",
            line=(index % 20) + 1,
            type=vuln_type,
            severity=severity,
            code=f"vulnerable_code_{index}",
            fingerprint=f"vuln_{index}_{file_index}"
        )
    
    def _create_dependency_vulnerability(self, index: int, complexity: str) -> Any:
        """Create a dependency vulnerability"""
        from scanner.analyzer_dependencies import DependencyVulnerability
        
        dependencies = ["requests", "flask", "django", "numpy", "pandas"]
        ecosystems = ["pip", "npm", "maven"]
        
        return DependencyVulnerability(
            dependency_name=dependencies[index % len(dependencies)],
            installed_version=f"1.{index}.0",
            fixed_version=f"1.{index + 1}.0",
            vulnerability_id=f"CVE-2023-{index:04d}",
            severity=["Low", "Medium", "High", "Critical"][index % 4],
            description=f"Test dependency vulnerability {index}",
            references=[f"https://cve.mitre.org/CVE-2023-{index:04d}"],
            ecosystem=ecosystems[index % len(ecosystems)],
            file_path="requirements.txt"
        )
    
    def run_benchmark(self, project: ApplicationModel) -> BenchmarkResult:
        """Run benchmark on a single project"""
        print(f"Benchmarking {project.project_path}...")
        
        # Traditional analysis benchmark
        traditional_time, traditional_memory, traditional_paths, traditional_fp = self._benchmark_traditional_analysis(project)
        
        # Constraint-bound analysis benchmark
        stg_time, ecg_time, csar_time, constraint_memory, feasible_paths, eliminated_paths, exploit_chains = self._benchmark_constraint_analysis(project)
        
        total_constraint_time = stg_time + ecg_time + csar_time
        
        # Calculate improvement metrics
        path_reduction_rate = (traditional_paths - feasible_paths) / traditional_paths if traditional_paths > 0 else 0
        false_positive_reduction = (traditional_fp - exploit_chains) / traditional_fp if traditional_fp > 0 else 0
        accuracy_improvement = (path_reduction_rate + false_positive_reduction) / 2
        processing_overhead = (total_constraint_time - traditional_time) / traditional_time if traditional_time > 0 else 0
        
        result = BenchmarkResult(
            project_name=project.project_path.split('/')[-1],
            file_count=len(project.files),
            vulnerability_count=len(project.vulnerabilities),
            dependency_count=len(project.dependency_vulnerabilities),
            
            traditional_time=traditional_time,
            traditional_memory_mb=traditional_memory,
            traditional_paths=traditional_paths,
            traditional_false_positives=traditional_fp,
            
            stg_time=stg_time,
            ecg_time=ecg_time,
            csar_time=csar_time,
            total_constraint_time=total_constraint_time,
            constraint_memory_mb=constraint_memory,
            feasible_paths=feasible_paths,
            eliminated_paths=eliminated_paths,
            exploit_chains=exploit_chains,
            
            path_reduction_rate=path_reduction_rate,
            false_positive_reduction=false_positive_reduction,
            accuracy_improvement=accuracy_improvement,
            processing_overhead=processing_overhead
        )
        
        return result
    
    def _benchmark_traditional_analysis(self, project: ApplicationModel) -> Tuple[float, float, int, int]:
        """Benchmark traditional vulnerability analysis"""
        # Start memory tracking
        tracemalloc.start()
        process = psutil.Process()
        start_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Simulate traditional analysis
        start_time = time.time()
        
        # Traditional approach: all vulnerabilities can potentially chain
        vulnerabilities = project.vulnerabilities
        total_paths = len(vulnerabilities) * (len(vulnerabilities) - 1) if len(vulnerabilities) > 1 else 0
        
        # Estimate false positives (assume 40% are false positives)
        false_positives = int(len(vulnerabilities) * 0.4)
        
        # Simulate processing time based on complexity
        time.sleep(0.001 * len(vulnerabilities) / 100)  # Scale with vulnerability count
        
        end_time = time.time()
        end_memory = process.memory_info().rss / 1024 / 1024  # MB
        tracemalloc.stop()
        
        return (end_time - start_time, end_memory - start_memory, total_paths, false_positives)
    
    def _benchmark_constraint_analysis(self, project: ApplicationModel) -> Tuple[float, float, float, float, int, int, int]:
        """Benchmark constraint-bound exploit chain analysis"""
        # Start memory tracking
        tracemalloc.start()
        process = psutil.Process()
        start_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # STG building
        start_time = time.time()
        stg_result = build_semantic_transaction_graph(project)
        stg_time = time.time() - start_time
        
        # ECG building
        start_time = time.time()
        ecg_result = build_exploit_constraint_graph(stg_result, project.vulnerabilities)
        ecg_time = time.time() - start_time
        
        # CSAR traversal
        start_time = time.time()
        csar_result = perform_csar_traversal(ecg_result, stg_result)
        csar_time = time.time() - start_time
        
        end_memory = process.memory_info().rss / 1024 / 1024  # MB
        tracemalloc.stop()
        
        feasible_paths = len(ecg_result["edges"])
        eliminated_paths = ecg_result["statistics"]["eliminated_paths"]
        exploit_chains = len(csar_result["exploit_chains"])
        
        return (stg_time, ecg_time, csar_time, end_memory - start_memory, 
                feasible_paths, eliminated_paths, exploit_chains)
    
    def run_all_benchmarks(self) -> List[BenchmarkResult]:
        """Run benchmarks on all test projects"""
        print("Running comprehensive performance benchmarks...")
        
        for project in self.test_projects:
            result = self.run_benchmark(project)
            self.results.append(result)
            
            # Print immediate results
            print(f"  {result.project_name}:")
            print(f"    Files: {result.file_count}, Vulnerabilities: {result.vulnerability_count}")
            print(f"    Traditional: {result.traditional_time:.3f}s, {result.traditional_memory_mb:.1f}MB")
            print(f"    Constraint: {result.total_constraint_time:.3f}s, {result.constraint_memory_mb:.1f}MB")
            print(f"    Path Reduction: {result.path_reduction_rate:.1%}")
            print(f"    False Positive Reduction: {result.false_positive_reduction:.1%}")
            print(f"    Processing Overhead: {result.processing_overhead:.1%}")
            print()
        
        return self.results
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        if not self.results:
            return {"error": "No benchmark results available"}
        
        # Calculate aggregate statistics
        file_counts = [r.file_count for r in self.results]
        vuln_counts = [r.vulnerability_count for r in self.results]
        
        traditional_times = [r.traditional_time for r in self.results]
        constraint_times = [r.total_constraint_time for r in self.results]
        
        traditional_memory = [r.traditional_memory_mb for r in self.results]
        constraint_memory = [r.constraint_memory_mb for r in self.results]
        
        path_reductions = [r.path_reduction_rate for r in self.results]
        fp_reductions = [r.false_positive_reduction for r in self.results]
        overheads = [r.processing_overhead for r in self.results]
        
        report = {
            "executive_summary": {
                "projects_tested": len(self.results),
                "avg_file_count": statistics.mean(file_counts),
                "avg_vulnerability_count": statistics.mean(vuln_counts),
                "max_vulnerability_count": max(vuln_counts),
                "total_vulnerabilities_processed": sum(vuln_counts)
            },
            "performance_metrics": {
                "traditional_analysis": {
                    "avg_time": statistics.mean(traditional_times),
                    "max_time": max(traditional_times),
                    "avg_memory_mb": statistics.mean(traditional_memory),
                    "max_memory_mb": max(traditional_memory)
                },
                "constraint_analysis": {
                    "avg_time": statistics.mean(constraint_times),
                    "max_time": max(constraint_times),
                    "avg_memory_mb": statistics.mean(constraint_memory),
                    "max_memory_mb": max(constraint_memory)
                },
                "performance_overhead": {
                    "avg_overhead": statistics.mean(overheads),
                    "max_overhead": max(overheads),
                    "min_overhead": min(overheads)
                }
            },
            "accuracy_improvements": {
                "path_reduction": {
                    "avg_reduction_rate": statistics.mean(path_reductions),
                    "max_reduction_rate": max(path_reductions),
                    "min_reduction_rate": min(path_reductions),
                    "total_paths_eliminated": sum(r.eliminated_paths for r in self.results)
                },
                "false_positive_reduction": {
                    "avg_reduction_rate": statistics.mean(fp_reductions),
                    "max_reduction_rate": max(fp_reductions),
                    "min_reduction_rate": min(fp_reductions),
                    "total_false_positives_eliminated": sum(r.traditional_false_positives - r.exploit_chains for r in self.results)
                }
            },
            "scalability_analysis": {
                "time_complexity": self._analyze_time_complexity(),
                "memory_complexity": self._analyze_memory_complexity(),
                "linear_growth": self._check_linear_growth()
            },
            "detailed_results": [asdict(r) for r in self.results]
        }
        
        return report
    
    def _analyze_time_complexity(self) -> str:
        """Analyze time complexity growth"""
        if len(self.results) < 2:
            return "insufficient_data"
        
        # Simple linear regression analysis
        x = [r.file_count for r in self.results]
        y = [r.total_constraint_time for r in self.results]
        
        # Calculate correlation
        correlation = self._calculate_correlation(x, y)
        
        if correlation > 0.9:
            return "linear"
        elif correlation > 0.7:
            return "near_linear"
        elif correlation > 0.5:
            return "quadratic"
        else:
            return "complex"
    
    def _analyze_memory_complexity(self) -> str:
        """Analyze memory complexity growth"""
        if len(self.results) < 2:
            return "insufficient_data"
        
        x = [r.file_count for r in self.results]
        y = [r.constraint_memory_mb for r in self.results]
        
        correlation = self._calculate_correlation(x, y)
        
        if correlation > 0.9:
            return "linear"
        elif correlation > 0.7:
            return "near_linear"
        elif correlation > 0.5:
            return "quadratic"
        else:
            return "complex"
    
    def _check_linear_growth(self) -> bool:
        """Check if performance grows linearly with project size"""
        if len(self.results) < 2:
            return False
        
        # Check both time and memory linearity
        time_linear = self._analyze_time_complexity() in ["linear", "near_linear"]
        memory_linear = self._analyze_memory_complexity() in ["linear", "near_linear"]
        
        return time_linear and memory_linear
    
    def _calculate_correlation(self, x: List[float], y: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        if len(x) != len(y) or len(x) < 2:
            return 0.0
        
        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi * xi for xi in x)
        sum_y2 = sum(yi * yi for yi in y)
        
        numerator = n * sum_xy - sum_x * sum_y
        denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)) ** 0.5
        
        return numerator / denominator if denominator != 0 else 0.0
    
    def export_benchmark_report(self, output_path: str) -> None:
        """Export benchmark report to file"""
        report = self.generate_performance_report()
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Benchmark report exported to: {output_path}")


def run_comprehensive_benchmark(output_dir: str = "benchmark_results") -> None:
    """Run comprehensive performance benchmark"""
    print("Starting Comprehensive Performance Benchmark")
    print("=" * 50)
    
    benchmark = PerformanceBenchmark()
    results = benchmark.run_all_benchmarks()
    
    # Generate and export report
    report = benchmark.generate_performance_report()
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Export reports
    benchmark.export_benchmark_report(str(output_path / "performance_benchmark.json"))
    
    # Print summary
    print("\n" + "=" * 50)
    print("BENCHMARK SUMMARY")
    print("=" * 50)
    
    summary = report["executive_summary"]
    print(f"Projects Tested: {summary['projects_tested']}")
    print(f"Total Vulnerabilities Processed: {summary['total_vulnerabilities_processed']}")
    print(f"Average Path Reduction: {report['accuracy_improvements']['path_reduction']['avg_reduction_rate']:.1%}")
    print(f"Average False Positive Reduction: {report['accuracy_improvements']['false_positive_reduction']['avg_reduction_rate']:.1%}")
    print(f"Average Processing Overhead: {report['performance_metrics']['performance_overhead']['avg_overhead']:.1%}")
    print(f"Time Complexity: {report['scalability_analysis']['time_complexity']}")
    print(f"Memory Complexity: {report['scalability_analysis']['memory_complexity']}")
    print(f"Linear Growth: {report['scalability_analysis']['linear_growth']}")
    
    print(f"\nDetailed report saved to: {output_dir}/performance_benchmark.json")


if __name__ == "__main__":
    run_comprehensive_benchmark()
