"""
Attack Path Analyzer - UNIQUE SAST FEATURE

Maps vulnerability chains and calculates realistic attack paths.
Shows how multiple vulnerabilities can be combined for system compromise.
"""

import networkx as nx
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path
import json

from .models import VulnerabilityFinding

@dataclass
class AttackPath:
    """Represents a complete attack path from entry to critical asset"""
    path_id: str
    entry_point: str
    vulnerabilities: List[VulnerabilityFinding]
    attack_complexity: str
    required_privileges: str
    target_asset: str
    breach_likelihood: float
    estimated_cost: str
    time_to_compromise: str

@dataclass
class AttackStep:
    """Single step in attack chain"""
    vulnerability: VulnerabilityFinding
    prerequisites: List[str]
    outcomes: List[str]
    skill_level: str
    tools_required: List[str]
    detection_difficulty: str

class AttackPathAnalyzer:
    """Analyzes and maps attack paths across vulnerabilities"""
    
    def __init__(self):
        self.attack_graph = nx.DiGraph()
        self.vulnerability_chains = []
        self.critical_assets = [
            "database", "admin_panel", "api_keys", "user_data", 
            "payment_system", "source_code", "config_files"
        ]
        
        # Attack technique mapping
        self.technique_mapping = {
            "SQL Injection": "T1190 - Exploit Public-Facing Application",
            "Command Injection": "T1059 - Command and Scripting Interpreter",
            "Hardcoded Secret": "T1552 - Unsecured Credentials",
            "Path Traversal": "T1006 - Directory/File Discovery",
            "XSS": "T1059 - Command and Scripting Interpreter",
            "CSRF": "T1566 - Phishing",
            "Privilege Escalation": "T1068 - Exploitation for Privilege Escalation"
        }
    
    def build_attack_graph(self, vulnerabilities: List[VulnerabilityFinding]) -> nx.DiGraph:
        """Build attack graph from vulnerabilities"""
        self.attack_graph.clear()
        
        # Add nodes for each vulnerability
        for vuln in vulnerabilities:
            node_id = f"{vuln.file}:{vuln.line}:{vuln.type}"
            self.attack_graph.add_node(
                node_id,
                vulnerability=vuln,
                cvss_score=self._calculate_cvss(vuln),
                exploitability=self._calculate_exploitability(vuln),
                asset_type=self._identify_asset_type(vuln)
            )
        
        # Add edges based on vulnerability relationships
        self._add_attack_edges()
        
        return self.attack_graph
    
    def _add_attack_edges(self):
        """Add edges representing possible attack transitions"""
        nodes = list(self.attack_graph.nodes())
        
        for i, node1 in enumerate(nodes):
            for node2 in nodes[i+1:]:
                if self._can_chain_vulnerabilities(node1, node2):
                    self.attack_graph.add_edge(node1, node2, 
                                              weight=self._calculate_edge_weight(node1, node2))
    
    def _can_chain_vulnerabilities(self, node1: str, node2: str) -> bool:
        """Determine if two vulnerabilities can be chained"""
        vuln1 = self.attack_graph.nodes[node1]['vulnerability']
        vuln2 = self.attack_graph.nodes[node2]['vulnerability']
        
        # Same file vulnerabilities are more likely to be chainable
        if vuln1.file == vuln2.file and abs(vuln1.line - vuln2.line) < 50:
            return True
        
        # Web-related vulnerabilities can often be chained
        web_vulns = ["SQL Injection", "XSS", "CSRF", "Command Injection"]
        if vuln1.type in web_vulns and vuln2.type in web_vulns:
            return True
        
        # Auth bypass can lead to privilege escalation
        if "Authorization" in vuln1.type and "Privilege" in vuln2.type:
            return True
        
        return False
    
    def find_attack_paths(self, max_paths: int = 10) -> List[AttackPath]:
        """Find most critical attack paths"""
        paths = []
        
        # Find paths to critical assets
        for asset in self.critical_assets:
            asset_nodes = [n for n, attr in self.attack_graph.nodes(data=True) 
                          if attr.get('asset_type') == asset]
            
            for target_node in asset_nodes:
                # Find all paths to this critical asset
                for source_node in self.attack_graph.nodes():
                    if source_node != target_node:
                        try:
                            path = nx.shortest_path(self.attack_graph, source_node, target_node)
                            if len(path) >= 2:  # At least one edge
                                attack_path = self._create_attack_path(path)
                                if attack_path:
                                    paths.append(attack_path)
                        except nx.NetworkXNoPath:
                            continue
        
        # Sort by breach likelihood
        paths.sort(key=lambda p: p.breach_likelihood, reverse=True)
        return paths[:max_paths]
    
    def _create_attack_path(self, node_path: List[str]) -> Optional[AttackPath]:
        """Create attack path from node path"""
        vulnerabilities = [self.attack_graph.nodes[node]['vulnerability'] for node in node_path]
        
        return AttackPath(
            path_id=f"path_{'_'.join(node_path[:3])}",
            entry_point=f"{vulnerabilities[0].file}:{vulnerabilities[0].line}",
            vulnerabilities=vulnerabilities,
            attack_complexity=self._calculate_attack_complexity(vulnerabilities),
            required_privileges=self._calculate_required_privileges(vulnerabilities),
            target_asset=self._identify_target_asset(vulnerabilities[-1]),
            breach_likelihood=self._calculate_breach_likelihood(vulnerabilities),
            estimated_cost=self._estimate_breach_cost(vulnerabilities),
            time_to_compromise=self._estimate_time_to_compromise(vulnerabilities)
        )
    
    def generate_attack_report(self, paths: List[AttackPath]) -> Dict[str, Any]:
        """Generate comprehensive attack path report"""
        report = {
            "summary": {
                "total_paths": len(paths),
                "critical_paths": len([p for p in paths if p.breach_likelihood > 0.7]),
                "high_risk_assets": self._identify_high_risk_assets(paths)
            },
            "attack_paths": [],
            "recommendations": self._generate_path_recommendations(paths)
        }
        
        for path in paths:
            path_report = {
                "path_id": path.path_id,
                "entry_point": path.entry_point,
                "target_asset": path.target_asset,
                "breach_likelihood": f"{path.breach_likelihood:.1%}",
                "estimated_cost": path.estimated_cost,
                "time_to_compromise": path.time_to_compromise,
                "attack_complexity": path.attack_complexity,
                "required_privileges": path.required_privileges,
                "steps": []
            }
            
            for i, vuln in enumerate(path.vulnerabilities):
                step = {
                    "step_number": i + 1,
                    "vulnerability": vuln.type,
                    "location": f"{vuln.file}:{vuln.line}",
                    "code": vuln.code,
                    "mitigation": self._get_step_mitigation(vuln),
                    "mitigation_effort": self._estimate_mitigation_effort(vuln)
                }
                path_report["steps"].append(step)
            
            report["attack_paths"].append(path_report)
        
        return report
    
    def _calculate_cvss(self, vuln: VulnerabilityFinding) -> float:
        """Calculate CVSS score for vulnerability"""
        severity_scores = {"Critical": 9.5, "High": 8.5, "Medium": 6.5, "Low": 3.5}
        base_score = severity_scores.get(vuln.severity, 5.0)
        
        # Adjust based on vulnerability type
        type_multipliers = {
            "SQL Injection": 1.2,
            "Command Injection": 1.3,
            "Hardcoded Secret": 1.1,
            "Privilege Escalation": 1.4
        }
        
        multiplier = type_multipliers.get(vuln.type, 1.0)
        return min(10.0, base_score * multiplier)
    
    def _calculate_exploitability(self, vuln: VulnerabilityFinding) -> float:
        """Calculate exploitability score (0-1)"""
        base_exploitability = {
            "Critical": 0.9,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.3
        }.get(vuln.severity, 0.5)
        
        # Adjust based on vulnerability type
        if "SQL Injection" in vuln.type:
            return min(1.0, base_exploitability + 0.1)
        elif "Hardcoded" in vuln.type:
            return min(1.0, base_exploitability + 0.2)
        
        return base_exploitability
    
    def _identify_asset_type(self, vuln: VulnerabilityFinding) -> str:
        """Identify the type of asset this vulnerability affects"""
        file_name = vuln.file.lower()
        code_content = vuln.code.lower()
        
        if "database" in code_content or "sql" in code_content:
            return "database"
        elif "admin" in code_content or "auth" in file_name:
            return "admin_panel"
        elif "key" in code_content or "secret" in code_content:
            return "api_keys"
        elif "password" in code_content or "user" in file_name:
            return "user_data"
        elif "payment" in code_content or "billing" in file_name:
            return "payment_system"
        
        return "general_application"
    
    def _calculate_edge_weight(self, node1: str, node2: str) -> float:
        """Calculate weight for attack graph edge"""
        vuln1 = self.attack_graph.nodes[node1]['vulnerability']
        vuln2 = self.attack_graph.nodes[node2]['vulnerability']
        
        # Higher weight = easier to exploit
        base_weight = (self.attack_graph.nodes[node1]['exploitability'] + 
                     self.attack_graph.nodes[node2]['exploitability']) / 2
        
        # Same file bonus
        if vuln1.file == vuln2.file:
            base_weight += 0.2
        
        return min(1.0, base_weight)
    
    def _calculate_attack_complexity(self, vulnerabilities: List[VulnerabilityFinding]) -> str:
        """Calculate overall attack complexity"""
        complexity_scores = {"Low": 0, "Medium": 1, "High": 2}
        total_complexity = 0
        
        for vuln in vulnerabilities:
            if vuln.severity in complexity_scores:
                total_complexity += complexity_scores[vuln.severity]
        
        avg_complexity = total_complexity / len(vulnerabilities)
        
        if avg_complexity <= 0.5:
            return "Low"
        elif avg_complexity <= 1.5:
            return "Medium"
        else:
            return "High"
    
    def _calculate_required_privileges(self, vulnerabilities: List[VulnerabilityFinding]) -> str:
        """Calculate required privileges for attack"""
        # Check if any vulnerability provides initial access
        for vuln in vulnerabilities:
            if "SQL Injection" in vuln.type or "Command Injection" in vuln.type:
                return "None (Remote)"
            elif "Authorization" in vuln.type:
                return "Low (User)"
        
        return "Medium (Authenticated)"
    
    def _identify_target_asset(self, vuln: VulnerabilityFinding) -> str:
        """Identify the target asset based on vulnerability"""
        asset_type = self._identify_asset_type(vuln)
        return asset_type.replace("_", " ").title()
    
    def _calculate_breach_likelihood(self, vulnerabilities: List[VulnerabilityFinding]) -> float:
        """Calculate likelihood of successful breach"""
        if not vulnerabilities:
            return 0.0
        
        # Product of exploitability scores
        likelihood = 1.0
        for vuln in vulnerabilities:
            exploitability = self._calculate_exploitability(vuln)
            likelihood *= (1.0 - exploitability)
        
        return 1.0 - likelihood
    
    def _estimate_breach_cost(self, vulnerabilities: List[VulnerabilityFinding]) -> str:
        """Estimate potential breach cost"""
        base_cost = 50000  # Base breach cost
        
        # Multiply by severity and number of vulnerabilities
        severity_multiplier = {
            "Critical": 5.0,
            "High": 3.0,
            "Medium": 1.5,
            "Low": 1.0
        }
        
        total_multiplier = sum(severity_multiplier.get(v.severity, 1.0) for v in vulnerabilities)
        estimated_cost = base_cost * total_multiplier
        
        if estimated_cost > 1000000:
            return f"${estimated_cost/1000000:.1f}M+"
        elif estimated_cost > 1000:
            return f"${estimated_cost/1000:.0f}K"
        else:
            return f"${estimated_cost:.0f}"
    
    def _estimate_time_to_compromise(self, vulnerabilities: List[VulnerabilityFinding]) -> str:
        """Estimate time to compromise"""
        complexity_times = {
            "Low": "Hours to Days",
            "Medium": "Days to Weeks", 
            "High": "Weeks to Months"
        }
        
        complexity = self._calculate_attack_complexity(vulnerabilities)
        return complexity_times.get(complexity, "Unknown")
    
    def _identify_high_risk_assets(self, paths: List[AttackPath]) -> List[str]:
        """Identify assets at highest risk"""
        asset_counts = {}
        for path in paths:
            asset = path.target_asset
            asset_counts[asset] = asset_counts.get(asset, 0) + path.breach_likelihood
        
        return sorted(asset_counts.keys(), key=lambda x: asset_counts[x], reverse=True)
    
    def _generate_path_recommendations(self, paths: List[AttackPath]) -> List[str]:
        """Generate recommendations based on attack paths"""
        recommendations = []
        
        # Find most common vulnerability types in paths
        vuln_counts = {}
        for path in paths:
            for vuln in path.vulnerabilities:
                vuln_counts[vuln.type] = vuln_counts.get(vuln.type, 0) + 1
        
        # Generate recommendations for top vulnerability types
        top_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        
        for vuln_type, count in top_vulns:
            recommendations.append(f"Priority: Fix {count} {vuln_type} vulnerabilities to break {count} attack paths")
        
        # Add general recommendations
        recommendations.append("Implement defense-in-depth to prevent vulnerability chaining")
        recommendations.append("Add monitoring and alerting for critical asset access")
        
        return recommendations
    
    def _get_step_mitigation(self, vuln: VulnerabilityFinding) -> str:
        """Get mitigation for specific vulnerability step"""
        mitigations = {
            "SQL Injection": "Use parameterized queries and input validation",
            "Command Injection": "Use subprocess with argument lists, avoid shell=True",
            "Hardcoded Secret": "Move secrets to environment variables or key vault",
            "Privilege Escalation": "Implement proper authorization checks",
            "XSS": "Implement output encoding and CSP headers",
            "CSRF": "Implement anti-CSRF tokens"
        }
        
        return mitigations.get(vuln.type, "Apply secure coding practices")
    
    def _estimate_mitigation_effort(self, vuln: VulnerabilityFinding) -> str:
        """Estimate effort to mitigate vulnerability"""
        effort_map = {
            "SQL Injection": "Medium (2-4 hours)",
            "Command Injection": "Medium (2-4 hours)",
            "Hardcoded Secret": "Low (1-2 hours)",
            "Privilege Escalation": "High (4-8 hours)",
            "XSS": "Medium (2-6 hours)",
            "CSRF": "Low (1-3 hours)"
        }
        
        return effort_map.get(vuln.type, "Medium (2-4 hours)")

def analyze_attack_paths(vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, Any]:
    """Analyze attack paths for given vulnerabilities"""
    analyzer = AttackPathAnalyzer()
    
    # Build attack graph
    attack_graph = analyzer.build_attack_graph(vulnerabilities)
    
    # Find attack paths
    paths = analyzer.find_attack_paths()
    
    # Generate report
    return analyzer.generate_attack_report(paths)
