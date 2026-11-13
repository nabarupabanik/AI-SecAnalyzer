"""
Enhanced Static Vulnerability Scanner with AI Fix Suggestions

This module extends the static analyzer with AI-powered fix suggestions,
providing developers with actionable remediation guidance.
"""

from __future__ import annotations

import ast
import asyncio
import re
from dataclasses import asdict
from typing import Iterable, Optional, List
import logging

from .models import ApplicationModel, FileModel, VulnerabilityFinding
from .static_analyzer import (
    _get_line, _is_python_analyzable, attach_python_ast,
    _SECRET_RE, _SECRET_PLACEHOLDER_RE, _SENSITIVE_FILE_PATH_RE, _PythonVulnVisitor
)

# Import AI fix suggestions
try:
    from .ai_fix_suggestions import get_ai_suggester, generate_fix_suggestion
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    logging.warning("AI fix suggestions not available")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedPythonVulnVisitor(_PythonVulnVisitor):
    """Enhanced vulnerability visitor with AI fix suggestion support"""
    
    def __init__(self, file_model: FileModel, enable_ai: bool = True):
        super().__init__(file_model)
        self.file_model = file_model  # Ensure file_model is accessible
        self.enable_ai = enable_ai and AI_AVAILABLE
        self.ai_suggester = get_ai_suggester() if self.enable_ai else None
    
    def visit_Call(self, node: ast.Call) -> None:
        """Override to add AI fix suggestions to SQL injection findings"""
        super().visit_Call(node)
        
        # Add AI suggestions to existing SQL injection findings
        for finding in self.findings:
            if "SQL Injection" in finding.type and not finding.fix_suggestion:
                self._add_ai_suggestion_async(finding)
    
    def _add_ai_suggestion_async(self, finding: VulnerabilityFinding) -> None:
        """Add AI fix suggestion to a vulnerability finding"""
        if not self.enable_ai:
            # Add rule-based fallback
            finding.fix_suggestion = "Use parameterized queries to prevent SQL injection:\n# cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
            finding.auto_fixable = False
            finding.fix_confidence = 0.8
            return
        
        try:
            # Get code context
            code_context = self._get_code_context(finding.line)
            
            # Generate AI suggestion (synchronously for now)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                suggestion = loop.run_until_complete(
                    generate_fix_suggestion(finding, code_context)
                )
                if suggestion:
                    finding.fix_suggestion = suggestion.fix_code
                    finding.auto_fixable = suggestion.auto_fixable
                    finding.fix_confidence = suggestion.confidence
                else:
                    self._add_fallback_suggestion(finding)
            finally:
                loop.close()
        except Exception as e:
            logger.warning(f"Failed to generate AI suggestion: {e}")
            self._add_fallback_suggestion(finding)
    
    def _get_code_context(self, line_number: int, context_lines: int = 5) -> str:
        """Get code context around a specific line"""
        if not self.file_model.content:
            return ""
        
        lines = self.file_model.content.splitlines()
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context_lines_list = lines[start:end]
        return "\n".join(f"{i+1}: {line}" for i, line in enumerate(context_lines_list, start=start+1))
    
    def _add_fallback_suggestion(self, finding: VulnerabilityFinding) -> None:
        """Add rule-based fallback suggestion"""
        fallback_suggestions = {
            "SQL Injection": "Use parameterized queries to prevent SQL injection:\n# cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
            "Hardcoded Secret": "Move secrets to environment variables:\n# password = os.getenv('DB_PASSWORD')",
            "Command Injection": "Use subprocess with argument lists:\n# subprocess.run(['ls', '-la'], check=True)",
            "Unsafe Deserialization": "Use safe deserialization methods:\n# json.loads(data) instead of pickle.loads(data)"
        }
        
        for vuln_type, suggestion in fallback_suggestions.items():
            if vuln_type in finding.type:
                finding.fix_suggestion = suggestion
                finding.auto_fixable = False
                finding.fix_confidence = 0.7
                break
        else:
            finding.fix_suggestion = "Review this code for security issues and implement appropriate controls."
            finding.auto_fixable = False
            finding.fix_confidence = 0.5

def analyze_single_python_file_enhanced(
    f: FileModel, 
    enable_ai: bool = True,
    max_ai_suggestions: int = 10
) -> List[VulnerabilityFinding]:
    """
    Analyze a single Python file with enhanced AI fix suggestions.
    
    Args:
        f: FileModel to analyze
        enable_ai: Whether to enable AI fix suggestions
        max_ai_suggestions: Maximum number of AI suggestions to generate
        
    Returns:
        List of VulnerabilityFinding objects with fix suggestions
    """
    findings: List[VulnerabilityFinding] = []

    if not _is_python_analyzable(f):
        return findings

    parse_error = attach_python_ast(f)
    if parse_error:
        return findings

    tree = getattr(f, "ast_tree", None)
    if tree is None:
        return findings

    # Use enhanced visitor
    visitor = EnhancedPythonVulnVisitor(f, enable_ai=enable_ai)
    visitor.visit(tree)

    # Process hardcoded secrets with AI suggestions
    for m in _SECRET_RE.finditer(f.content or ""):
        line = (f.content or "")[: m.start()].count("\n") + 1
        code_line = _get_line(f.content or "", line)
        value_match = re.search(r"=\s*(['\"])(.+?)\1", code_line)
        secret_val = (value_match.group(2).strip() if value_match else "")
        
        if len(secret_val) < 8 or _SECRET_PLACEHOLDER_RE.match(secret_val):
            continue
        
        finding = VulnerabilityFinding(
            file=f.file_path,
            line=line,
            type="Hardcoded Secret",
            severity="Medium",
            code=code_line,
            confidence="High",
            rule_id="pyast.secret.hardcoded",
        )
        
        # Add fix suggestion
        if enable_ai and AI_AVAILABLE and len(findings) < max_ai_suggestions:
            try:
                code_context = visitor._get_code_context(line)
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    suggestion = loop.run_until_complete(
                        generate_fix_suggestion(finding, code_context)
                    )
                    if suggestion:
                        finding.fix_suggestion = suggestion.fix_code
                        finding.auto_fixable = suggestion.auto_fixable
                        finding.fix_confidence = suggestion.confidence
                    else:
                        finding.fix_suggestion = "Move secrets to environment variables:\n# password = os.getenv('DB_PASSWORD')"
                        finding.auto_fixable = False
                        finding.fix_confidence = 0.8
                finally:
                    loop.close()
            except Exception as e:
                logger.warning(f"AI suggestion failed for secret: {e}")
                finding.fix_suggestion = "Move secrets to environment variables:\n# password = os.getenv('DB_PASSWORD')"
                finding.auto_fixable = False
                finding.fix_confidence = 0.8
        else:
            finding.fix_suggestion = "Move secrets to environment variables:\n# password = os.getenv('DB_PASSWORD')"
            finding.auto_fixable = False
            finding.fix_confidence = 0.8
        
        findings.append(finding)

    findings.extend(visitor.findings)
    
    # Limit AI suggestions to prevent API overuse
    if len(findings) > max_ai_suggestions:
        # Keep AI suggestions for the most severe findings
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 4), f.line))
        
        # Remove AI suggestions from less severe findings
        for finding in findings[max_ai_suggestions:]:
            finding.fix_suggestion = None
            finding.auto_fixable = False
            finding.fix_confidence = 0.0

    return findings

def analyze_python_files_enhanced(
    model: ApplicationModel, 
    enable_ai: bool = True,
    max_ai_suggestions_per_file: int = 5
) -> None:
    """
    Enhanced analysis of Python files with AI fix suggestions.
    
    Args:
        model: ApplicationModel to mutate
        enable_ai: Whether to enable AI fix suggestions
        max_ai_suggestions_per_file: Max AI suggestions per file
    """
    findings: List[VulnerabilityFinding] = []
    total_ai_suggestions = 0
    max_total_suggestions = 20  # Global limit to prevent API overuse

    logger.info(f"Starting enhanced static analysis with AI suggestions: {enable_ai}")
    
    for f in model.files:
        if total_ai_suggestions >= max_total_suggestions:
            logger.info("Reached AI suggestion limit, disabling for remaining files")
            file_findings = analyze_single_python_file_enhanced(f, enable_ai=False)
        else:
            remaining_suggestions = max_total_suggestions - total_ai_suggestions
            file_findings = analyze_single_python_file_enhanced(
                f, 
                enable_ai=enable_ai,
                max_ai_suggestions=min(max_ai_suggestions_per_file, remaining_suggestions)
            )
            
            # Count AI suggestions
            ai_count = sum(1 for finding in file_findings if finding.fix_suggestion)
            total_ai_suggestions += ai_count
            logger.info(f"Generated {ai_count} AI suggestions for {f.file_name}")
        
        findings.extend(file_findings)

    model.vulnerabilities = findings
    logger.info(f"Enhanced static analysis complete: {len(findings)} total findings, {total_ai_suggestions} AI suggestions")

def add_ai_suggestions_to_existing_findings(
    findings: List[VulnerabilityFinding],
    code_contexts: Optional[dict[str, str]] = None
) -> List[VulnerabilityFinding]:
    """
    Add AI fix suggestions to existing vulnerability findings.
    
    Args:
        findings: List of existing vulnerability findings
        code_contexts: Optional mapping of file paths to code context
        
    Returns:
        Updated findings with AI suggestions
    """
    if not AI_AVAILABLE:
        logger.warning("AI not available, skipping fix suggestions")
        return findings
    
    logger.info(f"Adding AI suggestions to {len(findings)} existing findings")
    
    for finding in findings:
        if finding.fix_suggestion:  # Skip if already has suggestion
            continue
        
        try:
            code_context = None
            if code_contexts and finding.file in code_contexts:
                code_context = code_contexts[finding.file]
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                suggestion = loop.run_until_complete(
                    generate_fix_suggestion(finding, code_context)
                )
                if suggestion:
                    finding.fix_suggestion = suggestion.fix_code
                    finding.auto_fixable = suggestion.auto_fixable
                    finding.fix_confidence = suggestion.confidence
            finally:
                loop.close()
                
        except Exception as e:
            logger.warning(f"Failed to add AI suggestion to {finding.type}: {e}")
            # Add fallback
            finding.fix_suggestion = "Review this code for security issues and implement appropriate controls."
            finding.auto_fixable = False
            finding.fix_confidence = 0.5
    
    return findings
