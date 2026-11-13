"""
AI-Powered Fix Suggestions for Security Vulnerabilities

This module provides intelligent fix suggestions using OpenAI's language models
to help developers understand and remediate security vulnerabilities.
"""

import os
import json
import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import logging
from pathlib import Path

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    logging.warning("Groq library not installed. AI fix suggestions will be disabled.")

from .models import VulnerabilityFinding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FixSuggestion:
    """Structured fix suggestion for a vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    fix_code: str
    explanation: str
    confidence: float
    auto_fixable: bool
    references: List[str]
    security_context: str

class AIFixSuggester:
    """AI-powered fix suggestion engine using Groq"""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "llama-3.1-8b-instant"):
        """
        Initialize AI fix suggester
        
        Args:
            api_key: Groq API key (defaults to GROQ_API_KEY env var)
            model: Groq model to use (llama3-8b-8192, mixtral-8x7b-32768, etc.)
        """
        self.model = model
        self.enabled = GROQ_AVAILABLE
        
        if self.enabled:
            # Try environment variable first, then .env file
            api_key_from_env = api_key or os.getenv('GROQ_API_KEY')
            
            # Load from .env file if not found
            if not api_key_from_env:
                try:
                    from dotenv import load_dotenv
                    load_dotenv()
                    api_key_from_env = os.getenv('GROQ_API_KEY')
                except ImportError:
                    pass
            
            self.client = Groq(api_key=api_key_from_env)
            if not self.client.api_key:
                logger.warning("Groq API key not found. AI fix suggestions disabled.")
                self.enabled = False
        else:
            self.client = None
            logger.warning("Groq not available. Install with: pip install groq")
    
    async def generate_fix_suggestion(
        self, 
        vulnerability: VulnerabilityFinding, 
        code_context: Optional[str] = None,
        max_retries: int = 3
    ) -> Optional[FixSuggestion]:
        """
        Generate AI-powered fix suggestion for a vulnerability
        
        Args:
            vulnerability: The vulnerability finding
            code_context: Surrounding code for context
            max_retries: Maximum number of API retries
            
        Returns:
            FixSuggestion or None if generation fails
        """
        if not self.enabled:
            return self._generate_rule_based_fallback(vulnerability)
        
        try:
            prompt = self._build_prompt(vulnerability, code_context)
            
            for attempt in range(max_retries):
                try:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system", 
                                "content": self._get_system_prompt()
                            },
                            {
                                "role": "user", 
                                "content": prompt
                            }
                        ],
                        max_tokens=800,
                        temperature=0.3,
                        response_format={"type": "json_object"}
                    )
                    
                    result = json.loads(response.choices[0].message.content)
                    return self._parse_ai_response(result, vulnerability)
                    
                except Exception as e:
                    logger.warning(f"AI suggestion attempt {attempt + 1} failed: {e}")
                    if attempt == max_retries - 1:
                        return self._generate_rule_based_fallback(vulnerability)
                    await asyncio.sleep(1)  # Rate limiting
                    
        except Exception as e:
            logger.error(f"Failed to generate AI fix suggestion: {e}")
            return self._generate_rule_based_fallback(vulnerability)
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the AI model"""
        return """You are a cybersecurity expert and senior software developer specializing in secure coding practices.

Your task is to provide specific, actionable fix suggestions for security vulnerabilities.

Requirements:
1. Provide clear, concise explanations
2. Include corrected code examples
3. Explain why the fix works
4. Assign confidence scores (0.0-1.0)
5. Indicate if auto-fix is safe
6. Provide security references

Response Format (JSON):
{
    "description": "Brief description of the vulnerability",
    "fix_code": "Corrected code snippet",
    "explanation": "Why this fix resolves the vulnerability",
    "confidence": 0.9,
    "auto_fixable": true,
    "references": ["OWASP", "CWE-89"],
    "security_context": "Broader security implications"
}

Focus on practical, production-ready fixes that maintain code functionality while improving security."""
    
    def _build_prompt(self, vulnerability: VulnerabilityFinding, code_context: Optional[str]) -> str:
        """Build the prompt for the AI model"""
        prompt = f"""Security Vulnerability Analysis:

Vulnerability Details:
- Type: {vulnerability.type}
- Severity: {vulnerability.severity}
- File: {vulnerability.file}
- Line: {vulnerability.line}
- Analyzer: {vulnerability.analyzer}
- Confidence: {vulnerability.confidence}

Vulnerable Code:
```
{vulnerability.code}
```
"""
        
        if code_context:
            prompt += f"""
Code Context:
```
{code_context}
```
"""
        
        prompt += """
Please provide a specific fix suggestion with:
1. Description of the vulnerability
2. Corrected code that maintains functionality
3. Explanation of why the fix works
4. Confidence level in the fix
5. Whether it's safe to auto-fix
6. Security references
7. Broader security context

Focus on practical, secure coding practices."""
        
        return prompt
    
    def _parse_ai_response(self, response: Dict[str, Any], vulnerability: VulnerabilityFinding) -> FixSuggestion:
        """Parse AI response into FixSuggestion object"""
        return FixSuggestion(
            vulnerability_type=vulnerability.type,
            severity=vulnerability.severity,
            description=response.get('description', ''),
            fix_code=response.get('fix_code', ''),
            explanation=response.get('explanation', ''),
            confidence=float(response.get('confidence', 0.5)),
            auto_fixable=bool(response.get('auto_fixable', False)),
            references=response.get('references', []),
            security_context=response.get('security_context', '')
        )
    
    def _generate_rule_based_fallback(self, vulnerability: VulnerabilityFinding) -> FixSuggestion:
        """Generate rule-based fallback when AI is unavailable"""
        fallback_rules = {
            "sql_injection": FixSuggestion(
                vulnerability_type=vulnerability.type,
                severity=vulnerability.severity,
                description="SQL Injection detected. Use parameterized queries.",
                fix_code="cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
                explanation="Parameterized queries prevent SQL injection by separating SQL logic from data.",
                confidence=0.8,
                auto_fixable=False,
                references=["OWASP A03:2021 - Injection", "CWE-89"],
                security_context="SQL injection can lead to data breach, authentication bypass, and data manipulation."
            ),
            "hardcoded_password": FixSuggestion(
                vulnerability_type=vulnerability.type,
                severity=vulnerability.severity,
                description="Hardcoded credentials detected. Use environment variables.",
                fix_code="password = os.getenv('DB_PASSWORD')",
                explanation="Environment variables keep credentials out of source code and allow proper secret management.",
                confidence=0.9,
                auto_fixable=False,
                references=["OWASP A02:2021 - Cryptographic Failures", "CWE-798"],
                security_context="Hardcoded credentials expose sensitive data and can be extracted from version control."
            ),
            "command_injection": FixSuggestion(
                vulnerability_type=vulnerability.type,
                severity=vulnerability.severity,
                description="Command injection detected. Use subprocess with argument list.",
                fix_code="subprocess.run(['ls', '-la'], check=True)",
                explanation="Using argument lists prevents shell injection by avoiding shell interpretation.",
                confidence=0.85,
                auto_fixable=False,
                references=["OWASP A03:2021 - Injection", "CWE-78"],
                security_context="Command injection can lead to arbitrary code execution and system compromise."
            )
        }
        
        # Find matching rule by vulnerability type
        vuln_type_lower = vulnerability.type.lower()
        for key, rule in fallback_rules.items():
            if key in vuln_type_lower or vuln_type_lower in key:
                return rule
        
        # Generic fallback
        return FixSuggestion(
            vulnerability_type=vulnerability.type,
            severity=vulnerability.severity,
            description="Security vulnerability detected. Review and secure the code.",
            fix_code="# Review this code for security issues and implement appropriate controls",
            explanation="This code pattern may introduce security risks. Apply secure coding practices.",
            confidence=0.5,
            auto_fixable=False,
            references=["OWASP Top 10", "Secure Coding Guidelines"],
            security_context="Address security vulnerabilities to prevent potential attacks."
        )
    
    async def batch_generate_suggestions(
        self, 
        vulnerabilities: List[VulnerabilityFinding], 
        max_concurrent: int = 3
    ) -> List[FixSuggestion]:
        """
        Generate fix suggestions for multiple vulnerabilities concurrently
        
        Args:
            vulnerabilities: List of vulnerability findings
            max_concurrent: Maximum concurrent API calls
            
        Returns:
            List of fix suggestions
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def generate_with_semaphore(vuln: VulnerabilityFinding) -> FixSuggestion:
            async with semaphore:
                suggestion = await self.generate_fix_suggestion(vuln)
                return suggestion or self._generate_rule_based_fallback(vuln)
        
        tasks = [generate_with_semaphore(vuln) for vuln in vulnerabilities]
        return await asyncio.gather(*tasks, return_exceptions=True)

# Global instance
_ai_suggester: Optional[AIFixSuggester] = None

def get_ai_suggester() -> AIFixSuggester:
    """Get or create global AI suggester instance"""
    global _ai_suggester
    if _ai_suggester is None:
        _ai_suggester = AIFixSuggester()
    return _ai_suggester

async def generate_fix_suggestion(vulnerability: VulnerabilityFinding, code_context: Optional[str] = None) -> Optional[FixSuggestion]:
    """
    Convenience function to generate fix suggestion for a vulnerability
    
    Args:
        vulnerability: The vulnerability finding
        code_context: Surrounding code for context
        
    Returns:
        FixSuggestion or None
    """
    suggester = get_ai_suggester()
    return await suggester.generate_fix_suggestion(vulnerability, code_context)
