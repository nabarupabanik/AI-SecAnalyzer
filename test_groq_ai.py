#!/usr/bin/env python3
"""
Test Groq AI fix suggestions
"""

import asyncio
from scanner.ai_fix_suggestions import generate_fix_suggestion
from scanner.models import VulnerabilityFinding

async def test_groq_ai():
    print("=== Testing Groq AI Fix Suggestions ===")
    print()
    
    # Test vulnerabilities
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
        }
    ]
    
    for test_case in test_cases:
        print(f"Testing: {test_case['name']}")
        print(f"Code: {test_case['vuln'].code}")
        print("Generating AI fix suggestion...")
        
        try:
            suggestion = await generate_fix_suggestion(test_case['vuln'])
            
            if suggestion:
                print("\nAI Fix Suggestion:")
                print(f"Description: {suggestion.description}")
                print(f"Fix Code: {suggestion.fix_code}")
                print(f"Explanation: {suggestion.explanation}")
                print(f"Confidence: {suggestion.confidence}")
                print(f"Auto-fixable: {suggestion.auto_fixable}")
                print(f"References: {suggestion.references}")
            else:
                print("No suggestion generated")
                
        except Exception as e:
            print(f"Error: {e}")
        
        print("=" * 60)
        print()

if __name__ == "__main__":
    asyncio.run(test_groq_ai())
