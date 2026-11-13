#!/usr/bin/env python3
"""
Test a complete scan with AI suggestions to verify integration
"""

import asyncio
from scanner.streaming_scan import stream_project_scan
from scanner.models import VulnerabilityFinding

def test_scan_with_ai():
    print("=== Testing Complete Scan with AI Suggestions ===")
    print()
    
    # Test with a simple Python file that has vulnerabilities
    project_path = "c:\\Users\\vcvan\\Desktop\\Minor_project"
    
    print(f"Scanning project: {project_path}")
    print("Looking for AI suggestions in vulnerability findings...")
    print()
    
    vulnerabilities_with_ai = []
    total_vulnerabilities = 0
    
    try:
        for event in stream_project_scan(
            project_path=project_path,
            include_ai_suggestions=True,
            progress_callback=None
        ):
            if event.get("type") == "vulnerability":
                vuln = event.get("vulnerability")
                if vuln:
                    total_vulnerabilities += 1
                    
                    # Check if it has AI suggestions
                    if hasattr(vuln, 'fix_suggestion') and vuln.fix_suggestion:
                        vulnerabilities_with_ai.append(vuln)
                        print(f"Found vulnerability with AI suggestion:")
                        print(f"  Type: {vuln.type}")
                        print(f"  File: {vuln.file}:{vuln.line}")
                        print(f"  Fix Suggestion: {vuln.fix_suggestion[:100]}...")
                        print(f"  Confidence: {getattr(vuln, 'fix_confidence', 0.0)}")
                        print()
            
            elif event.get("type") == "complete":
                print("Scan completed!")
                break
    
    except Exception as e:
        print(f"Error during scan: {e}")
        return
    
    print(f"Results:")
    print(f"  Total vulnerabilities found: {total_vulnerabilities}")
    print(f"  Vulnerabilities with AI suggestions: {len(vulnerabilities_with_ai)}")
    
    if vulnerabilities_with_ai:
        print("\nAI suggestions are working! The frontend should show them.")
    else:
        print("\nNo AI suggestions found. Need to debug further.")

if __name__ == "__main__":
    test_scan_with_ai()
