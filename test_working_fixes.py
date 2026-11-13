#!/usr/bin/env python3
"""
Test the working rule-based fix suggestions (FREE and working now!)
"""

from scanner.ai_fix_suggestions import get_ai_suggester
from scanner.models import VulnerabilityFinding

def test_working_fixes():
    print("=== FREE FIX SUGGESTIONS (Working Right Now!) ===")
    print()
    
    # Test vulnerabilities with smart rule-based fixes
    test_cases = [
        {
            "name": "SQL Injection",
            "vuln": VulnerabilityFinding(
                file='app.py',
                line=42,
                type='SQL Injection',
                severity='High',
                code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                analyzer='python_ast',
                confidence='High'
            )
        },
        {
            "name": "Hardcoded Password",
            "vuln": VulnerabilityFinding(
                file='config.py',
                line=15,
                type='Hardcoded Secret',
                severity='Medium',
                code='password = "admin123"',
                analyzer='python_ast',
                confidence='High'
            )
        },
        {
            "name": "Command Injection",
            "vuln": VulnerabilityFinding(
                file='process.py',
                line=28,
                type='Command Injection',
                severity='High',
                code='os.system(f"ls {user_input}")',
                analyzer='python_ast',
                confidence='High'
            )
        }
    ]
    
    suggester = get_ai_suggester()
    
    for test_case in test_cases:
        print(f"Vulnerability: {test_case['name']}")
        print(f"Code: {test_case['vuln'].code}")
        print()
        
        # Get the fix suggestion
        suggestion = suggester._generate_rule_based_fallback(test_case['vuln'])
        
        print("Fix Suggestion:")
        print(suggestion.fix_code)
        print()
        print("Explanation:", suggestion.explanation)
        print("Confidence:", suggestion.confidence)
        print("References:", ", ".join(suggestion.references))
        print("=" * 60)
        print()

if __name__ == "__main__":
    test_working_fixes()
