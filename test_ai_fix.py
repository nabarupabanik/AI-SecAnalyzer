#!/usr/bin/env python3
"""
Test script for AI fix suggestions
"""

import asyncio
from scanner.ai_fix_suggestions import generate_fix_suggestion
from scanner.models import VulnerabilityFinding

async def test_ai_fix():
    # Create test vulnerability
    vuln = VulnerabilityFinding(
        file='test.py',
        line=10,
        type='SQL Injection',
        severity='High',
        code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        analyzer='python_ast',
        confidence='High'
    )
    
    print("Testing AI fix suggestion...")
    print("Vulnerability:", vuln.type)
    print("Code:", vuln.code)
    print("Generating fix suggestion...")
    
    # Generate AI fix suggestion
    suggestion = await generate_fix_suggestion(vuln)
    
    if suggestion:
        print("\nAI Fix Suggestion:")
        print("Description:", suggestion.description)
        print("Fix Code:", suggestion.fix_code)
        print("Confidence:", suggestion.confidence)
        print("Auto-fixable:", suggestion.auto_fixable)
        print("References:", suggestion.references)
    else:
        print("No suggestion generated")

if __name__ == "__main__":
    asyncio.run(test_ai_fix())
