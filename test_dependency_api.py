import requests
import json

# Test the dependency scanning API
url = "http://localhost:5001/api/scan-dependencies"
data = {"path": "c:\\Users\\vcvan\\Desktop\\Minor_project\\test_dependency_project"}

try:
    response = requests.post(url, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        result = response.json()
        summary = result.get("summary", {})
        print(f"\nSummary:")
        print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"Dependency Score: {summary.get('dependency_score', 0)}")
        print(f"Severity Breakdown: {summary.get('severity_breakdown', {})}")
        
        vulns = result.get("dependency_vulnerabilities", [])
        print(f"\nFound {len(vulns)} dependency vulnerabilities")
        for i, vuln in enumerate(vulns[:5]):  # Show first 5
            print(f"  {i+1}. {vuln.get('dependency_name', 'Unknown')}@{vuln.get('installed_version', 'Unknown')}: {vuln.get('vulnerability_id', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
        if len(vulns) > 5:
            print(f"  ... and {len(vulns) - 5} more")
    else:
        print(f"Error: {response.text}")
        
except Exception as e:
    print(f"Request failed: {e}")
