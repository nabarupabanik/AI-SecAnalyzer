#!/usr/bin/env python3
"""
Test rule-based fix suggestions (no AI required)
"""

from scanner.ai_fix_suggestions import get_ai_suggester
from scanner.models import VulnerabilityFinding

def test_rule_based_fix():
    # Create test vulnerabilities
    vulnerabilities = [
        VulnerabilityFinding(
            file='test.py',
            line=10,
            type='SQL Injection',
            severity='High',
            code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            analyzer='python_ast',
            confidence='High'
        ),
        VulnerabilityFinding(
            file='config.py',
            line=5,
            type='Hardcoded Secret',
            severity='Medium',
            code='password = "admin123"',
            analyzer='python_ast',
            confidence='High'
        ),
        VulnerabilityFinding(
            file='process.py',
            line=15,
            type='Command Injection',
            severity='High',
            code='os.system(f"ls {user_input}")',
            analyzer='python_ast',
            confidence='High'
        )
    ]
    
    print("Testing Rule-Based Fix Suggestions (No AI Required)")
    print("=" * 60)
    
    suggester = get_ai_suggester()
    print(f"AI Suggester Enabled: {suggester.enabled}")
    
    for vuln in vulnerabilities:
        print(f"\nVulnerability: {vuln.type}")
        print(f"Code: {vuln.code}")
        
        # Get rule-based fallback
        suggestion = suggester._generate_rule_based_fallback(vuln)
        
        print(f"Fix Suggestion: {suggestion.fix_code}")
        print(f"Auto-fixable: {suggestion.auto_fixable}")
        print(f"Confidence: {suggestion.confidence}")
        print(f"References: {', '.join(suggestion.references)}")
        print("-" * 40)

if __name__ == "__main__":
    test_rule_based_fix()
