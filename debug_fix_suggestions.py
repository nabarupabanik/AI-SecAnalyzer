#!/usr/bin/env python3
"""
Debug and fix the rule-based suggestions
"""

from scanner.ai_fix_suggestions import get_ai_suggester
from scanner.models import VulnerabilityFinding

def debug_fix_suggestions():
    print("=== Debugging Fix Suggestions ===")
    print()
    
    # Test SQL injection specifically
    vuln = VulnerabilityFinding(
        file='app.py',
        line=42,
        type='SQL Injection',
        severity='High',
        code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        analyzer='python_ast',
        confidence='High'
    )
    
    print(f"Vulnerability type: '{vuln.type}'")
    print(f"Lowercase: '{vuln.type.lower()}'")
    print()
    
    suggester = get_ai_suggester()
    
    # Check the matching logic
    vuln_type_lower = vuln.type.lower()
    print("Checking for matches:")
    print(f"  'sql_injection' in '{vuln_type_lower}': {'sql_injection' in vuln_type_lower}")
    print(f"  'sql' in '{vuln_type_lower}': {'sql' in vuln_type_lower}")
    print()
    
    # Manually call the fallback function
    suggestion = suggester._generate_rule_based_fallback(vuln)
    
    print("Generated suggestion:")
    print(f"  Description: {suggestion.description}")
    print(f"  Fix code: {suggestion.fix_code}")
    print(f"  Confidence: {suggestion.confidence}")
    print()

if __name__ == "__main__":
    debug_fix_suggestions()
