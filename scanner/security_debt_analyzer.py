"""
Security Debt Analyzer - UNIQUE SAST FEATURE

Tracks security debt like financial debt with ROI calculations.
Helps justify security spending and prioritize fixes based on business impact.
"""

import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .models import VulnerabilityFinding

@dataclass
class SecurityDebtItem:
    """Individual security debt item"""
    vulnerability: VulnerabilityFinding
    principal_amount: float  # Cost to fix
    interest_rate: float  # Daily risk accumulation
    age_days: int  # How long it's been unfixed
    risk_multiplier: float  # Industry-specific risk factor
    compliance_fine_risk: float  # Potential regulatory fines

@dataclass
class SecurityPortfolio:
    """Complete security debt portfolio"""
    total_debt: float
    daily_interest: float
    risk_score: float
    compliance_risk: float
    top_risk_items: List[SecurityDebtItem]
    industry_benchmark: str
    security_health_score: float

class SecurityDebtAnalyzer:
    """Analyzes security debt and calculates ROI"""
    
    def __init__(self):
        self.industry_multipliers = {
            "finance": 2.5,      # Higher risk due to financial data
            "healthcare": 3.0,   # HIPAA, patient data
            "retail": 1.8,       # Payment processing
            "technology": 1.5,   # IP protection
            "government": 2.0,   # National security
            "education": 1.2,    # Student data
            "general": 1.0       # Baseline
        }
        
        self.severity_costs = {
            "Critical": {"fix_cost": 5000, "daily_risk": 500, "fine_risk": 50000},
            "High": {"fix_cost": 2000, "daily_risk": 200, "fine_risk": 10000},
            "Medium": {"fix_cost": 800, "daily_risk": 50, "fine_risk": 2000},
            "Low": {"fix_cost": 300, "daily_risk": 10, "fine_risk": 500}
        }
        
        self.compliance_frameworks = {
            "DPDP Act (India)": {"fine_multiplier": 5.0, "trigger_severity": "Medium"},
            "RBI Guidelines": {"fine_multiplier": 3.5, "trigger_severity": "High"},
            "CERT-In": {"fine_multiplier": 2.5, "trigger_severity": "Medium"},
            "GDPR": {"fine_multiplier": 4.0, "trigger_severity": "Medium"},
            "HIPAA": {"fine_multiplier": 3.5, "trigger_severity": "Medium"},
            "PCI-DSS": {"fine_multiplier": 2.5, "trigger_severity": "High"},
            "SOX": {"fine_multiplier": 2.0, "trigger_severity": "High"},
            "CCPA": {"fine_multiplier": 3.0, "trigger_severity": "Medium"}
        }
    
    def calculate_security_debt(self, 
                              vulnerabilities: List[VulnerabilityFinding],
                              industry: str = "general",
                              compliance_frameworks: List[str] = None) -> SecurityPortfolio:
        """Calculate complete security debt portfolio"""
        
        debt_items = []
        total_debt = 0
        total_daily_interest = 0
        total_risk_score = 0
        total_compliance_risk = 0
        
        industry_multiplier = self.industry_multipliers.get(industry.lower(), 1.0)
        
        for vuln in vulnerabilities:
            debt_item = self._create_debt_item(vuln, industry_multiplier, compliance_frameworks)
            debt_items.append(debt_item)
            
            total_debt += debt_item.principal_amount
            total_daily_interest += debt_item.principal_amount * debt_item.interest_rate
            total_risk_score += self._calculate_item_risk_score(debt_item)
            total_compliance_risk += debt_item.compliance_fine_risk
        
        # Sort by risk (highest first)
        debt_items.sort(key=lambda x: x.principal_amount * x.risk_multiplier, reverse=True)
        
        # Calculate security health score
        max_possible_debt = len(vulnerabilities) * self.severity_costs["Critical"]["fix_cost"]
        security_health_score = max(0, 100 - (total_debt / max_possible_debt * 100)) if max_possible_debt > 0 else 100
        
        return SecurityPortfolio(
            total_debt=total_debt,
            daily_interest=total_daily_interest,
            risk_score=total_risk_score,
            compliance_risk=total_compliance_risk,
            top_risk_items=debt_items[:10],  # Top 10 risk items
            industry_benchmark=industry,
            security_health_score=security_health_score
        )
    
    def _create_debt_item(self, 
                         vuln: VulnerabilityFinding, 
                         industry_multiplier: float,
                         compliance_frameworks: List[str]) -> SecurityDebtItem:
        """Create individual security debt item"""
        
        severity_config = self.severity_costs.get(vuln.severity, self.severity_costs["Medium"])
        
        # Calculate principal (cost to fix)
        principal = severity_config["fix_cost"] * industry_multiplier
        
        # Calculate interest rate based on severity and type
        base_interest = severity_config["daily_risk"] / principal
        type_multiplier = self._get_type_multiplier(vuln.type)
        interest_rate = base_interest * type_multiplier
        
        # Estimate age (would use actual timestamp in real implementation)
        age_days = 30  # Default 30 days
        
        # Calculate risk multiplier
        risk_multiplier = self._calculate_risk_multiplier(vuln, industry_multiplier)
        
        # Calculate compliance fine risk
        compliance_fine_risk = self._calculate_compliance_risk(vuln, compliance_frameworks)
        
        return SecurityDebtItem(
            vulnerability=vuln,
            principal_amount=principal,
            interest_rate=interest_rate,
            age_days=age_days,
            risk_multiplier=risk_multiplier,
            compliance_fine_risk=compliance_fine_risk
        )
    
    def _get_type_multiplier(self, vuln_type: str) -> float:
        """Get risk multiplier based on vulnerability type"""
        type_multipliers = {
            "SQL Injection": 2.0,
            "Command Injection": 1.8,
            "Hardcoded Secret": 1.5,
            "Privilege Escalation": 1.6,
            "XSS": 1.2,
            "CSRF": 1.1,
            "Path Traversal": 1.3
        }
        
        for key, multiplier in type_multipliers.items():
            if key.lower() in vuln_type.lower():
                return multiplier
        
        return 1.0
    
    def _calculate_risk_multiplier(self, vuln: VulnerabilityFinding, industry_multiplier: float) -> float:
        """Calculate overall risk multiplier"""
        base_risk = {"Critical": 2.0, "High": 1.5, "Medium": 1.0, "Low": 0.5}.get(vuln.severity, 1.0)
        type_risk = self._get_type_multiplier(vuln.type)
        
        return base_risk * type_risk * industry_multiplier
    
    def _calculate_compliance_risk(self, vuln: VulnerabilityFinding, compliance_frameworks: List[str]) -> float:
        """Calculate compliance fine risk"""
        if not compliance_frameworks:
            return 0
        
        total_fine_risk = 0
        base_fine = self.severity_costs.get(vuln.severity, self.severity_costs["Medium"])["fine_risk"]
        
        for framework in compliance_frameworks:
            if framework in self.compliance_frameworks:
                config = self.compliance_frameworks[framework]
                trigger_severity = config["trigger_severity"]
                
                # Check if vulnerability triggers compliance fine
                if self._severity_meets_threshold(vuln.severity, trigger_severity):
                    total_fine_risk += base_fine * config["fine_multiplier"]
        
        return total_fine_risk
    
    def _severity_meets_threshold(self, vuln_severity: str, threshold_severity: str) -> bool:
        """Check if vulnerability severity meets compliance threshold"""
        severity_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        
        vuln_level = severity_order.get(vuln_severity, 2)
        threshold_level = severity_order.get(threshold_severity, 2)
        
        return vuln_level >= threshold_level
    
    def _calculate_item_risk_score(self, debt_item: SecurityDebtItem) -> float:
        """Calculate risk score for individual debt item"""
        return debt_item.principal_amount * debt_item.interest_rate * debt_item.risk_multiplier
    
    def calculate_fix_roi(self, 
                         debt_item: SecurityDebtItem, 
                         fix_time_days: int = 7) -> Dict[str, Any]:
        """Calculate ROI for fixing a specific vulnerability"""
        
        # Cost to fix (principal + time cost)
        developer_cost_per_hour = 100  # $100/hour
        fix_hours = self._estimate_fix_hours(debt_item.vulnerability)
        fix_cost = debt_item.principal_amount + (fix_hours * developer_cost_per_hour)
        
        # Risk reduction (interest saved over time)
        daily_interest_saved = debt_item.principal_amount * debt_item.interest_rate
        annual_risk_reduction = daily_interest_saved * 365
        
        # Compliance risk reduction
        compliance_reduction = debt_item.compliance_fine_risk * 0.8  # 80% reduction assumption
        
        # Total annual benefit
        annual_benefit = annual_risk_reduction + compliance_reduction
        
        # ROI calculations
        annual_roi = (annual_benefit - fix_cost) / fix_cost * 100
        payback_period_days = fix_cost / daily_interest_saved if daily_interest_saved > 0 else float('inf')
        
        return {
            "fix_cost": fix_cost,
            "annual_benefit": annual_benefit,
            "annual_roi_percentage": annual_roi,
            "payback_period_days": payback_period_days,
            "fix_hours": fix_hours,
            "daily_interest_saved": daily_interest_saved,
            "compliance_risk_reduction": compliance_reduction,
            "recommendation": self._get_roi_recommendation(annual_roi, payback_period_days)
        }
    
    def _estimate_fix_hours(self, vuln: VulnerabilityFinding) -> int:
        """Estimate hours to fix vulnerability"""
        complexity_hours = {
            "SQL Injection": 8,
            "Command Injection": 6,
            "Hardcoded Secret": 2,
            "Privilege Escalation": 12,
            "XSS": 4,
            "CSRF": 3,
            "Path Traversal": 5
        }
        
        for vuln_type, hours in complexity_hours.items():
            if vuln_type.lower() in vuln.type.lower():
                return hours
        
        return 4  # Default 4 hours
    
    def _get_roi_recommendation(self, roi: float, payback_days: float) -> str:
        """Get recommendation based on ROI"""
        if roi > 200 and payback_days < 30:
            return "Immediate Fix - High ROI"
        elif roi > 100 and payback_days < 90:
            return "Priority Fix - Good ROI"
        elif roi > 50 and payback_days < 180:
            return "Consider Fix - Moderate ROI"
        else:
            return "Defer - Low ROI"
    
    def generate_security_debt_report(self, 
                                     portfolio: SecurityPortfolio,
                                     timeframe_days: int = 365) -> Dict[str, Any]:
        """Generate comprehensive security debt report"""
        
        # Project debt growth (linear daily accumulation over timeframe)
        projected_debt = portfolio.total_debt + (portfolio.daily_interest * timeframe_days)
        debt_growth = projected_debt - portfolio.total_debt
        
        # Calculate industry comparison
        industry_avg_debt = self._get_industry_benchmark(portfolio.industry_benchmark)
        debt_vs_industry = (portfolio.total_debt / industry_avg_debt - 1) * 100 if industry_avg_debt > 0 else 0
        
        # Generate recommendations
        recommendations = self._generate_debt_recommendations(portfolio)
        
        return {
            "executive_summary": {
                "current_security_debt": f"${portfolio.total_debt:,.0f}",
                "daily_risk_accumulation": f"${portfolio.daily_interest:,.0f}",
                "annual_debt_growth": f"${debt_growth:,.0f}",
                "security_health_score": portfolio.security_health_score,
                "industry_comparison": f"{debt_vs_industry:+.1f}% vs industry average",
                "compliance_exposure": f"${portfolio.compliance_risk:,.0f}"
            },
            "risk_breakdown": {
                "by_severity": self._analyze_by_severity(portfolio.top_risk_items),
                "by_type": self._analyze_by_type(portfolio.top_risk_items),
                "top_risk_items": [
                    {
                        "location": f"{item.vulnerability.file}:{item.vulnerability.line}",
                        "type": item.vulnerability.type,
                        "severity": item.vulnerability.severity,
                        "debt_amount": f"${item.principal_amount:,.0f}",
                        "daily_interest": f"${item.principal_amount * item.interest_rate:,.0f}",
                        "compliance_risk": f"${item.compliance_fine_risk:,.0f}",
                        "roi_analysis": self.calculate_fix_roi(item)
                    }
                    for item in portfolio.top_risk_items[:5]
                ]
            },
            "financial_projections": {
                "30_day_projection": f"${portfolio.total_debt + (portfolio.daily_interest * 30):,.0f}",
                "90_day_projection": f"${portfolio.total_debt + (portfolio.daily_interest * 90):,.0f}",
                "1_year_projection": f"${projected_debt:,.0f}",
                "total_annual_risk": f"${portfolio.daily_interest * 365:,.0f}"
            },
            "recommendations": recommendations,
            "action_items": self._generate_action_items(portfolio)
        }
    
    def _get_industry_benchmark(self, industry: str) -> float:
        """Get industry average security debt for comparison"""
        benchmarks = {
            "finance": 250000,
            "healthcare": 300000,
            "retail": 150000,
            "technology": 100000,
            "government": 200000,
            "education": 75000,
            "general": 100000
        }
        return benchmarks.get(industry, 100000)
    
    def _analyze_by_severity(self, debt_items: List[SecurityDebtItem]) -> Dict[str, float]:
        """Analyze debt by severity"""
        severity_debt = {}
        for item in debt_items:
            severity = item.vulnerability.severity
            severity_debt[severity] = severity_debt.get(severity, 0) + item.principal_amount
        
        return {k: f"${v:,.0f}" for k, v in severity_debt.items()}
    
    def _analyze_by_type(self, debt_items: List[SecurityDebtItem]) -> Dict[str, float]:
        """Analyze debt by vulnerability type"""
        type_debt = {}
        for item in debt_items:
            vuln_type = item.vulnerability.type
            type_debt[vuln_type] = type_debt.get(vuln_type, 0) + item.principal_amount
        
        # Return top 5 types
        sorted_types = sorted(type_debt.items(), key=lambda x: x[1], reverse=True)[:5]
        return {k: f"${v:,.0f}" for k, v in sorted_types}
    
    def _generate_debt_recommendations(self, portfolio: SecurityPortfolio) -> List[str]:
        """Generate recommendations based on security debt analysis"""
        recommendations = []
        
        if portfolio.security_health_score < 50:
            recommendations.append("Critical: Security health score below 50% - immediate action required")
        
        if portfolio.daily_interest > 1000:
            recommendations.append("High daily risk accumulation - prioritize high-severity vulnerabilities")
        
        if portfolio.compliance_risk > 50000:
            recommendations.append("Significant compliance exposure - address compliance-related vulnerabilities")
        
        # Check for high ROI items
        high_roi_items = [item for item in portfolio.top_risk_items[:5] 
                         if self.calculate_fix_roi(item)["annual_roi_percentage"] > 100]
        
        if high_roi_items:
            recommendations.append(f"Found {len(high_roi_items)} high-ROI fixes - prioritize for immediate impact")
        
        return recommendations
    
    def _generate_action_items(self, portfolio: SecurityPortfolio) -> List[Dict[str, Any]]:
        """Generate specific action items"""
        actions = []
        
        # Top 3 priority fixes
        for i, item in enumerate(portfolio.top_risk_items[:3]):
            roi = self.calculate_fix_roi(item)
            actions.append({
                "priority": i + 1,
                "action": f"Fix {item.vulnerability.type} in {item.vulnerability.file}",
                "location": f"{item.vulnerability.file}:{item.vulnerability.line}",
                "estimated_cost": f"${roi['fix_cost']:,.0f}",
                "annual_roi": f"{roi['annual_roi_percentage']:.0f}%",
                "payback_period": f"{roi['payback_period_days']:.0f} days",
                "impact": roi['recommendation']
            })
        
        return actions

def analyze_security_debt(vulnerabilities: List[VulnerabilityFinding],
                          industry: str = "general",
                          compliance_frameworks: List[str] = None) -> Dict[str, Any]:
    """Analyze security debt for given vulnerabilities"""
    analyzer = SecurityDebtAnalyzer()
    
    portfolio = analyzer.calculate_security_debt(vulnerabilities, industry, compliance_frameworks)
    return analyzer.generate_security_debt_report(portfolio)
