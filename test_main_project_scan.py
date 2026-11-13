import requests
import json
import time

# Test the full scan with the main project
url = "http://localhost:5001/api/scan"
data = {"path": "c:\\Users\\vcvan\\Desktop\\Minor_project"}

print("Testing full scan with main project (includes dependency scanning)...")
print(f"Scanning: {data['path']}")

try:
    start_time = time.time()
    response = requests.post(url, json=data)
    end_time = time.time()
    
    print(f"Status Code: {response.status_code}")
    print(f"Scan Time: {end_time - start_time:.2f} seconds")
    
    if response.status_code == 200:
        result = response.json()
        
        print(f"\nScan Results:")
        print(f"Scan ID: {result.get('scan_id')}")
        print(f"File Count: {result.get('file_count', 0)}")
        print(f"Total Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
        print(f"Risk Score: {result.get('risk_score', 0)}")
        print(f"Risk Level: {result.get('risk_level', 'Unknown')}")
        
        # Check for dependency-specific information
        runtime_extras = result.get('runtime_extras', {})
        print(f"\nDependency Information:")
        print(f"Dependency Vulnerability Count: {runtime_extras.get('dependency_vulnerability_count', 0)}")
        print(f"Dependency Ecosystems: {runtime_extras.get('dependency_ecosystems', [])}")
        
        # Show some dependency vulnerabilities if found
        vulnerabilities = result.get('vulnerabilities', [])
        dependency_vulns = [v for v in vulnerabilities if 'Dependency:' in v.get('type', '')]
        print(f"\nFound {len(dependency_vulns)} dependency vulnerabilities in full scan")
        
        for i, vuln in enumerate(dependency_vulns[:5]):
            print(f"  {i+1}. {vuln.get('type', 'Unknown')} at {vuln.get('file', 'Unknown')}: {vuln.get('severity', 'Unknown')}")
        
        if len(dependency_vulns) > 5:
            print(f"  ... and {len(dependency_vulns) - 5} more")
            
    else:
        print(f"Error: {response.text}")
        
except Exception as e:
    print(f"Request failed: {e}")
    import traceback
    traceback.print_exc()
