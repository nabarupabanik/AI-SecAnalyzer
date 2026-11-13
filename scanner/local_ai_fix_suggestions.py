"""
Local AI Fix Suggestions using Ollama (Free Alternative to OpenAI)

This module provides AI-powered fix suggestions using locally running models
through Ollama - completely free and private.
"""

import os
import json
import asyncio
import subprocess
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import logging
from pathlib import Path

from .models import VulnerabilityFinding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class LocalFixSuggestion:
    """Structured fix suggestion from local AI"""
    vulnerability_type: str
    severity: str
    description: str
    fix_code: str
    explanation: str
    confidence: float
    auto_fixable: bool
    references: List[str]
    security_context: str

class LocalAIFixSuggester:
    """Local AI-powered fix suggestion engine using Ollama"""
    
    def __init__(self, model: str = "llama3.2"):
        """
        Initialize local AI suggester
        
        Args:
            model: Ollama model to use (llama3.2, codellama, mistral, etc.)
        """
        self.model = model
        self.enabled = self._check_ollama_available()
        
        if not self.enabled:
            logger.warning("Ollama not available. Install from https://ollama.ai")
    
    def _check_ollama_available(self) -> bool:
        """Check if Ollama is installed and running"""
        try:
            # Check if ollama command exists
            result = subprocess.run(['ollama', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return False
            
            # Check if model is available
            result = subprocess.run(['ollama', 'list'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    async def generate_fix_suggestion(
        self, 
        vulnerability: VulnerabilityFinding, 
        code_context: Optional[str] = None
    ) -> Optional[LocalFixSuggestion]:
        """
        Generate AI-powered fix suggestion using local Ollama model
        
        Args:
            vulnerability: The vulnerability finding
            code_context: Surrounding code for context
            
        Returns:
            LocalFixSuggestion or None if generation fails
        """
        if not self.enabled:
            return self._generate_rule_based_fallback(vulnerability)
        
        try:
            prompt = self._build_prompt(vulnerability, code_context)
            
            # Run Ollama command
            cmd = ['ollama', 'run', self.model, prompt]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.warning(f"Ollama command failed: {result.stderr}")
                return self._generate_rule_based_fallback(vulnerability)
            
            # Parse the response
            response_text = result.stdout.strip()
            return self._parse_local_response(response_text, vulnerability)
            
        except subprocess.TimeoutExpired:
            logger.warning("Ollama request timed out")
            return self._generate_rule_based_fallback(vulnerability)
        except Exception as e:
            logger.error(f"Failed to generate local AI fix suggestion: {e}")
            return self._generate_rule_based_fallback(vulnerability)
    
    def _build_prompt(self, vulnerability: VulnerabilityFinding, code_context: Optional[str]) -> str:
        """Build the prompt for the local AI model"""
        prompt = f"""You are a cybersecurity expert and senior software developer specializing in secure coding practices.

Analyze this security vulnerability and provide a specific fix suggestion:

Vulnerability Details:
- Type: {vulnerability.type}
- Severity: {vulnerability.severity}
- File: {vulnerability.file}
- Line: {vulnerability.line}
- Code: {vulnerability.code}

Please provide a fix suggestion in this JSON format:
{{
    "description": "Brief description of the vulnerability",
    "fix_code": "Corrected code snippet",
    "explanation": "Why this fix resolves the vulnerability",
    "confidence": 0.9,
    "auto_fixable": true,
    "references": ["OWASP", "CWE-89"],
    "security_context": "Broader security implications"
}}

Focus on practical, secure coding practices."""
        
        if code_context:
            prompt += f"\n\nContext:\n{code_context}"
        
        return prompt
    
    def _parse_local_response(self, response: str, vulnerability: VulnerabilityFinding) -> LocalFixSuggestion:
        """Parse local AI response into LocalFixSuggestion object"""
        try:
            # Try to parse as JSON
            if response.startswith('{') and response.endswith('}'):
                result = json.loads(response)
                return LocalFixSuggestion(
                    vulnerability_type=vulnerability.type,
                    severity=vulnerability.severity,
                    description=result.get('description', ''),
                    fix_code=result.get('fix_code', ''),
                    explanation=result.get('explanation', ''),
                    confidence=float(result.get('confidence', 0.5)),
                    auto_fixable=bool(result.get('auto_fixable', False)),
                    references=result.get('references', []),
                    security_context=result.get('security_context', '')
                )
        except json.JSONDecodeError:
            pass
        
        # Fallback: extract information from text response
        return LocalFixSuggestion(
            vulnerability_type=vulnerability.type,
            severity=vulnerability.severity,
            description="Security vulnerability detected",
            fix_code=self._extract_fix_code(response),
            explanation=response[:200] + "..." if len(response) > 200 else response,
            confidence=0.7,
            auto_fixable=False,
            references=["OWASP Top 10"],
            security_context="Address security vulnerabilities to prevent potential attacks."
        )
    
    def _extract_fix_code(self, response: str) -> str:
        """Extract fix code from text response"""
        # Look for code blocks or code-like patterns
        lines = response.split('\n')
        fix_code_lines = []
        
        for line in lines:
            line = line.strip()
            # Look for code patterns
            if any(keyword in line.lower() for keyword in ['cursor.execute', 'os.getenv', 'subprocess.run', 'parameterized']):
                fix_code_lines.append(line)
            elif line.startswith('```') and 'python' in line.lower():
                continue
            elif line.startswith('```'):
                break
            elif fix_code_lines and not line.startswith('```'):
                fix_code_lines.append(line)
        
        return '\n'.join(fix_code_lines) if fix_code_lines else "# Review and fix this code"
    
    def _generate_rule_based_fallback(self, vulnerability: VulnerabilityFinding) -> LocalFixSuggestion:
        """Generate rule-based fallback when local AI is unavailable"""
        fallback_rules = {
            "sql_injection": LocalFixSuggestion(
                vulnerability_type=vulnerability.type,
                severity=vulnerability.severity,
                description="SQL Injection detected. Use parameterized queries.",
                fix_code="# Replace string concatenation with parameterized queries\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
                explanation="Parameterized queries prevent SQL injection by separating SQL logic from data.",
                confidence=0.8,
                auto_fixable=False,
                references=["OWASP A03:2021 - Injection", "CWE-89"],
                security_context="SQL injection can lead to data breach, authentication bypass, and data manipulation."
            ),
            "hardcoded_password": LocalFixSuggestion(
                vulnerability_type=vulnerability.type,
                severity=vulnerability.severity,
                description="Hardcoded credentials detected. Use environment variables.",
                fix_code="# Replace hardcoded password with environment variable\npassword = os.getenv('DB_PASSWORD')",
                explanation="Environment variables keep credentials out of source code and allow proper secret management.",
                confidence=0.9,
                auto_fixable=False,
                references=["OWASP A02:2021 - Cryptographic Failures", "CWE-798"],
                security_context="Hardcoded credentials expose sensitive data and can be extracted from version control."
            ),
            "command_injection": LocalFixSuggestion(
                vulnerability_type=vulnerability.type,
                severity=vulnerability.severity,
                description="Command injection detected. Use subprocess with argument list.",
                fix_code="# Replace shell commands with argument lists\nsubprocess.run(['ls', '-la'], check=True)",
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
            if key in vuln_type_lower:
                return rule
        
        # Generic fallback
        return LocalFixSuggestion(
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

# Global instance
_local_ai_suggester: Optional[LocalAIFixSuggester] = None

def get_local_ai_suggester() -> LocalAIFixSuggester:
    """Get or create global local AI suggester instance"""
    global _local_ai_suggester
    if _local_ai_suggester is None:
        _local_ai_suggester = LocalAIFixSuggester()
    return _local_ai_suggester

async def generate_local_fix_suggestion(vulnerability: VulnerabilityFinding, code_context: Optional[str] = None) -> Optional[LocalFixSuggestion]:
    """
    Convenience function to generate fix suggestion using local AI
    
    Args:
        vulnerability: The vulnerability finding
        code_context: Surrounding code for context
        
    Returns:
        LocalFixSuggestion or None
    """
    suggester = get_local_ai_suggester()
    return await suggester.generate_fix_suggestion(vulnerability, code_context)
