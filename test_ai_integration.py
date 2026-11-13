#!/usr/bin/env python3
"""
Test AI integration in the scanning pipeline
"""

from scanner.enhanced_static_analyzer import analyze_single_python_file_enhanced
from scanner.models import FileModel, VulnerabilityFinding

def test_ai_integration():
    print("=== Testing AI Integration in Enhanced Static Analyzer ===")
    print()
    
    # Create a test file with vulnerabilities
    test_file = FileModel(
        file_name="test_vuln.py",
        file_path="test_vuln.py",
        file_type="Python",
        extension=".py",
        file_size=200,
        content='''
import os

def get_user(user_id):
    # SQL Injection vulnerability
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def check_password():
    # Hardcoded password vulnerability
    password = "admin123"
    return password

def run_command(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    return True
'''
    )
    
    print("Analyzing test file with AI suggestions enabled...")
    
    # Test with AI enabled
    findings = analyze_single_python_file_enhanced(
        test_file, 
        enable_ai=True, 
        max_ai_suggestions=5
    )
    
    print(f"Found {len(findings)} vulnerabilities")
    print()
    
    for i, finding in enumerate(findings, 1):
        print(f"Vulnerability {i}:")
        print(f"  Type: {finding.type}")
        print(f"  Severity: {finding.severity}")
        print(f"  Line: {finding.line}")
        print(f"  Code: {finding.code}")
        print(f"  Fix Suggestion: {finding.fix_suggestion}")
        print(f"  Auto-fixable: {finding.auto_fixable}")
        print(f"  Fix Confidence: {finding.fix_confidence}")
        print()
    
    # Check if AI suggestions are present
    ai_suggestions = [f for f in findings if f.fix_suggestion]
    print(f"Vulnerabilities with AI suggestions: {len(ai_suggestions)}")
    
    if ai_suggestions:
        print("SUCCESS: AI suggestions are being generated!")
    else:
        print("ISSUE: No AI suggestions found")

if __name__ == "__main__":
    test_ai_integration()
