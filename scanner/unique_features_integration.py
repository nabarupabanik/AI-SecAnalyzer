"""
Unique Features Integration - Making Your SAST Tool Revolutionary

Integrates business logic analysis, attack path mapping, and security debt tracking
into the main scanning pipeline.
"""

from typing import List, Dict, Any, Optional
from pathlib import Path

from .models import VulnerabilityFinding, ApplicationModel
from .business_logic_analyzer import analyze_business_logic
from .attack_path_analyzer import analyze_attack_paths
from .security_debt_analyzer import analyze_security_debt

class UniqueFeaturesEngine:
    """Integrates unique SAST features into scanning pipeline"""
    
    def __init__(self, industry: str = "general", compliance_frameworks: List[str] = None):
        self.industry = industry
        self.compliance_frameworks = compliance_frameworks or []
    
    def analyze_with_unique_features(self, 
                                    vulnerabilities: List[VulnerabilityFinding],
                                    project_path: str) -> Dict[str, Any]:
        """Run all unique features analysis"""
        
        results = {
            "business_logic_analysis": self._run_business_logic_analysis(project_path),
            "attack_path_analysis": self._run_attack_path_analysis(vulnerabilities),
            "security_debt_analysis": self._run_security_debt_analysis(vulnerabilities)
        }
        
        return results
    
    def _run_business_logic_analysis(self, project_path: str) -> Dict[str, Any]:
        """Run business logic vulnerability analysis"""
        business_vulns = analyze_business_logic(project_path)
        
        return {
            "business_logic_vulnerabilities": len(business_vulns),
            "business_impact_summary": self._summarize_business_impact(business_vulns),
            "affected_workflows": self._identify_affected_workflows(business_vulns),
            "recommendations": self._generate_business_recommendations(business_vulns)
        }
    
    def _run_attack_path_analysis(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Run attack path analysis"""
        attack_report = analyze_attack_paths(vulnerabilities)
        
        return {
            "total_attack_paths": attack_report["summary"]["total_paths"],
            "critical_paths": attack_report["summary"]["critical_paths"],
            "high_risk_assets": attack_report["summary"]["high_risk_assets"],
            "breach_likelihood": self._calculate_overall_breach_likelihood(attack_report),
            "top_paths": attack_report["attack_paths"][:3]  # Top 3 most critical paths
        }
    
    def _run_security_debt_analysis(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Run security debt analysis"""
        debt_report = analyze_security_debt(
            vulnerabilities, 
            self.industry, 
            self.compliance_frameworks
        )
        
        return {
            "executive_summary": debt_report["executive_summary"],
            "top_priority_fixes": debt_report["action_items"][:3],
            "financial_projections": debt_report["financial_projections"],
            "security_health_score": debt_report["executive_summary"]["security_health_score"]
        }
    
    def _summarize_business_impact(self, business_vulns: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Summarize business impact of logic vulnerabilities"""
        if not business_vulns:
            return {"total_financial_impact": "$0", "compliance_risk": "Low"}
        
        # Calculate financial impact ranges
        financial_impacts = []
        compliance_risks = []
        
        for vuln in business_vulns:
            if hasattr(vuln, 'business_context'):
                financial_impacts.append(vuln.business_context.financial_impact)
                compliance_risks.extend(vuln.business_context.compliance_impact)
        
        return {
            "total_financial_impact": financial_impacts,
            "compliance_frameworks_affected": list(set(compliance_risks)),
            "high_impact_vulnerabilities": len([v for v in business_vulns if v.severity in ["Critical", "High"]])
        }
    
    def _identify_affected_workflows(self, business_vulns: List[VulnerabilityFinding]) -> List[str]:
        """Identify business workflows affected by logic vulnerabilities"""
        workflows = set()
        
        for vuln in business_vulns:
            if hasattr(vuln, 'business_context'):
                workflows.update(vuln.business_context.affected_workflows)
        
        return list(workflows)
    
    def _generate_business_recommendations(self, business_vulns: List[VulnerabilityFinding]) -> List[str]:
        """Generate business logic security recommendations"""
        recommendations = []
        
        if not business_vulns:
            return ["No business logic vulnerabilities found"]
        
        # Count by type
        vuln_types = {}
        for vuln in business_vulns:
            vuln_types[vuln.type] = vuln_types.get(vuln.type, 0) + 1
        
        # Generate recommendations for most common types
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            if "privilege" in vuln_type.lower():
                recommendations.append(f"Implement proper role-based access control - {count} privilege escalation risks found")
            elif "price" in vuln_type.lower() or "payment" in vuln_type.lower():
                recommendations.append(f"Add server-side validation for all financial operations - {count} price manipulation risks found")
            elif "authorization" in vuln_type.lower():
                recommendations.append(f"Review and strengthen authorization checks - {count} bypass vulnerabilities found")
            elif "race" in vuln_type.lower():
                recommendations.append(f"Implement proper locking mechanisms - {count} race condition risks found")
        
        return recommendations
    
    def _calculate_overall_breach_likelihood(self, attack_report: Dict[str, Any]) -> str:
        """Calculate overall breach likelihood from attack paths"""
        if not attack_report["attack_paths"]:
            return "Low (0%)"
        
        # Calculate weighted average breach likelihood
        total_likelihood = 0
        total_weight = 0
        
        for path in attack_report["attack_paths"]:
            likelihood_str = path["breach_likelihood"].rstrip('%')
            likelihood = float(likelihood_str) / 100
            
            # Weight by number of steps (fewer steps = higher weight)
            weight = 1.0 / len(path["steps"])
            
            total_likelihood += likelihood * weight
            total_weight += weight
        
        if total_weight == 0:
            return "Low (0%)"
        
        avg_likelihood = (total_likelihood / total_weight) * 100
        
        if avg_likelihood >= 70:
            return f"High ({avg_likelihood:.0f}%)"
        elif avg_likelihood >= 40:
            return f"Medium ({avg_likelihood:.0f}%)"
        else:
            return f"Low ({avg_likelihood:.0f}%)"

# Integration function for main scanner
def run_unique_features_analysis(vulnerabilities: List[VulnerabilityFinding],
                                project_path: str,
                                industry: str = "general",
                                compliance_frameworks: List[str] = None) -> Dict[str, Any]:
    """Run all unique features analysis"""
    engine = UniqueFeaturesEngine(industry, compliance_frameworks)
    return engine.analyze_with_unique_features(vulnerabilities, project_path)
