"""
Business Logic Security Analyzer - UNIQUE SAST FEATURE

This analyzer identifies business logic vulnerabilities that traditional SAST tools miss.
Finds issues like privilege escalation, authorization bypass, race conditions, etc.
"""

import ast
import re
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from pathlib import Path

from .models import VulnerabilityFinding

@dataclass
class BusinessLogicVulnerability:
    """Business logic vulnerability with context"""
    vulnerability_type: str
    business_impact: str
    affected_workflows: List[str]
    attack_scenario: str
    financial_impact: str
    compliance_impact: List[str]

class BusinessLogicAnalyzer:
    """Analyzes business logic security flaws"""
    
    def __init__(self):
        self.business_patterns = {
            "privilege_escalation": {
                "patterns": [
                    r"role.*=.*admin",
                    r"is_admin.*=.*True",
                    r"user\.role.*=.*['\"]admin['\"]"
                ],
                "workflows": ["user_management", "authentication", "authorization"],
                "impact": "Unauthorized admin access"
            },
            "price_manipulation": {
                "patterns": [
                    r"price.*=.*request\.",
                    r"total.*=.*float\(.*request",
                    r"amount.*=.*request\.form\.get"
                ],
                "workflows": ["payment", "checkout", "billing"],
                "impact": "Financial loss through price tampering"
            },
            "authorization_bypass": {
                "patterns": [
                    r"if.*user.*:.*return.*True",
                    r"if.*authenticated.*:.*pass",
                    r"@login_required.*def.*admin"
                ],
                "workflows": ["authentication", "authorization", "access_control"],
                "impact": "Unauthorized resource access"
            },
            "race_condition": {
                "patterns": [
                    r"balance.*-=.*amount",
                    r"stock.*-=.*quantity",
                    r"points.*-=.*reward"
                ],
                "workflows": ["transactions", "inventory", "rewards"],
                "impact": "Data inconsistency, financial loss"
            }
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        """Analyze file for business logic vulnerabilities"""
        findings = []
        
        try:
            tree = ast.parse(content)
            analyzer = BusinessLogicVisitor(file_path, content, self.business_patterns)
            analyzer.visit(tree)
            findings.extend(analyzer.findings)
        except SyntaxError:
            # Handle syntax errors gracefully
            pass
        
        return findings

class BusinessLogicVisitor(ast.NodeVisitor):
    """AST visitor for business logic analysis"""
    
    def __init__(self, file_path: str, content: str, patterns: Dict[str, Any]):
        self.file_path = file_path
        self.content = content
        self.patterns = patterns
        self.findings: List[VulnerabilityFinding] = []
        self.current_function = None
        self.current_class = None
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition"""
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = None
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definition"""
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = None
    
    def visit_Assign(self, node: ast.Assign):
        """Visit assignment statements for business logic patterns"""
        code_snippet = ast.get_source_segment(self.content, node)
        if code_snippet:
            self._check_business_patterns(code_snippet, node.lineno)
        self.generic_visit(node)
    
    def visit_If(self, node: ast.If):
        """Visit if statements for authorization issues"""
        code_snippet = ast.get_source_segment(self.content, node)
        if code_snippet:
            self._check_business_patterns(code_snippet, node.lineno)
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Visit function calls for dangerous operations"""
        code_snippet = ast.get_source_segment(self.content, node)
        if code_snippet:
            self._check_business_patterns(code_snippet, node.lineno)
        self.generic_visit(node)
    
    def _check_business_patterns(self, code: str, line: int):
        """Check code against business vulnerability patterns"""
        for vuln_type, config in self.patterns.items():
            for pattern in config["patterns"]:
                if re.search(pattern, code, re.IGNORECASE):
                    self._create_business_finding(vuln_type, config, code, line)
    
    def _create_business_finding(self, vuln_type: str, config: Dict[str, Any], code: str, line: int):
        """Create business logic vulnerability finding"""
        business_vuln = BusinessLogicVulnerability(
            vulnerability_type=vuln_type.replace("_", " ").title(),
            business_impact=config["impact"],
            affected_workflows=config["workflows"],
            attack_scenario=self._generate_attack_scenario(vuln_type, code),
            financial_impact=self._estimate_financial_impact(vuln_type),
            compliance_impact=self._get_compliance_impact(vuln_type)
        )
        
        finding = VulnerabilityFinding(
            file=self.file_path,
            line=line,
            type=f"Business Logic: {business_vuln.vulnerability_type}",
            severity=self._calculate_business_severity(vuln_type),
            code=code,
            fingerprint=f"business_logic_{vuln_type}_{line}",
            analyzer="business-logic-analyzer",
            rule_id=f"BL-{vuln_type.upper()}",
            confidence="High"
        )
        
        # Add business context as metadata
        finding.business_context = business_vuln
        self.findings.append(finding)
    
    def _generate_attack_scenario(self, vuln_type: str, code: str) -> str:
        """Generate realistic attack scenario"""
        scenarios = {
            "privilege_escalation": "Attacker manipulates role assignment to gain admin privileges",
            "price_manipulation": "Attacker modifies price parameters in checkout process",
            "authorization_bypass": "Attacker bypasses authentication checks to access protected resources",
            "race_condition": "Attacker exploits timing window to manipulate transactions"
        }
        return scenarios.get(vuln_type, "Business logic vulnerability exploitation")
    
    def _estimate_financial_impact(self, vuln_type: str) -> str:
        """Estimate potential financial impact"""
        impacts = {
            "privilege_escalation": "$50,000 - $500,000 (data breach, system compromise)",
            "price_manipulation": "$10,000 - $1M+ (revenue loss, fraud)",
            "authorization_bypass": "$25,000 - $250,000 (data theft, unauthorized access)",
            "race_condition": "$5,000 - $100,000 (financial inconsistency, inventory loss)"
        }
        return impacts.get(vuln_type, "Financial impact depends on business context")
    
    def _get_compliance_impact(self, vuln_type: str) -> List[str]:
        """Get affected compliance frameworks"""
        compliance = {
            "privilege_escalation": ["SOX", "GDPR", "PCI-DSS", "HIPAA"],
            "price_manipulation": ["SOX", "PCI-DSS", "SEC regulations"],
            "authorization_bypass": ["GDPR", "HIPAA", "PCI-DSS"],
            "race_condition": ["SOX", "PCI-DSS", "banking regulations"]
        }
        return compliance.get(vuln_type, ["General compliance impact"])
    
    def _calculate_business_severity(self, vuln_type: str) -> str:
        """Calculate severity based on business impact"""
        severity_map = {
            "privilege_escalation": "Critical",
            "price_manipulation": "Critical", 
            "authorization_bypass": "High",
            "race_condition": "High"
        }
        return severity_map.get(vuln_type, "Medium")

def analyze_business_logic(project_path: str) -> List[VulnerabilityFinding]:
    """Analyze entire project for business logic vulnerabilities"""
    findings = []
    analyzer = BusinessLogicAnalyzer()
    
    project_dir = Path(project_path)
    python_files = project_dir.rglob("*.py")
    
    for py_file in python_files:
        try:
            content = py_file.read_text(encoding='utf-8')
            file_findings = analyzer.analyze_file(str(py_file), content)
            findings.extend(file_findings)
        except Exception:
            continue
    
    return findings
