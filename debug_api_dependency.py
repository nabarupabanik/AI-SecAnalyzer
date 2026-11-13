import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.analyzer_dependencies import scan_all_dependencies, convert_to_vulnerability_findings
from scanner.risk_scoring import compute_dependency_score
from scanner.models import ApplicationModel

project_path = "c:\\Users\\vcvan\\Desktop\\Minor_project\\test_dependency_project"

print(f"Testing dependency scanning for: {project_path}")
print(f"Path exists: {os.path.exists(project_path)}")

# Check if requirements.txt exists
req_file = os.path.join(project_path, "requirements.txt")
print(f"requirements.txt exists: {os.path.exists(req_file)}")

if os.path.exists(req_file):
    with open(req_file, 'r') as f:
        print(f"requirements.txt content:\n{f.read()}")

# Test dependency scanning
try:
    dependency_vulns = scan_all_dependencies(project_path)
    print(f"\nFound {len(dependency_vulns)} dependency vulnerabilities")
    
    for i, vuln in enumerate(dependency_vulns[:5]):
        print(f"  {i+1}. {vuln.dependency_name}@{vuln.installed_version}: {vuln.vulnerability_id} ({vuln.severity})")
    
    # Test conversion to findings
    dependency_findings = convert_to_vulnerability_findings(dependency_vulns)
    print(f"\nConverted to {len(dependency_findings)} findings")
    
    # Test dependency scoring
    temp_model = ApplicationModel(project_path=project_path)
    temp_model.dependency_vulnerabilities = dependency_vulns
    dependency_score = compute_dependency_score(temp_model)
    print(f"Dependency score: {dependency_score}")
    
except Exception as e:
    print(f"Error during dependency scanning: {e}")
    import traceback
    traceback.print_exc()
