"""
Dependency Vulnerability Analyzer
Scans third-party dependencies for known vulnerabilities using multiple tools.
Supports Python (pip), Node.js (npm), Java (Maven), and generic SBOM analysis.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import tempfile
import os
import re
from dataclasses import dataclass

from .models import VulnerabilityFinding


@dataclass
class DependencyVulnerability:
    """Represents a vulnerability found in a third-party dependency."""
    dependency_name: str
    installed_version: str
    fixed_version: Optional[str]
    vulnerability_id: str  # CVE, GHSA, etc.
    severity: str  # Critical, High, Medium, Low
    description: str
    references: List[str]
    ecosystem: str  # pip, npm, maven, etc.
    file_path: str  # requirements.txt, package.json, pom.xml


def scan_python_dependencies(project_path: str) -> List[DependencyVulnerability]:
    """
    Scan Python dependencies using pip-audit and safety.
    """
    vulnerabilities = []
    project_dir = Path(project_path)
    
    # Check for requirements files
    req_files = [
        project_dir / "requirements.txt",
        project_dir / "requirements-dev.txt",
        project_dir / "Pipfile",
        project_dir / "pyproject.toml"
    ]
    
    req_files = [f for f in req_files if f.exists()]
    if not req_files:
        return vulnerabilities
    
    # Use pip-audit for comprehensive scanning
    try:
        # Run pip-audit in the project directory
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "--format", "json"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.stdout:
            audit_data = json.loads(result.stdout)
            dependencies = audit_data.get("dependencies", [])
            
            for dep in dependencies:
                dep_name = dep.get("name", "")
                dep_version = dep.get("version", "")
                vulns = dep.get("vulns", [])
                
                for vuln in vulns:
                    vulnerabilities.append(DependencyVulnerability(
                        dependency_name=dep_name,
                        installed_version=dep_version,
                        fixed_version=vuln.get("fix_versions", [None])[0] if vuln.get("fix_versions") else None,
                        vulnerability_id=vuln.get("id", ""),
                        severity="High",  # pip-audit doesn't provide severity, default to High
                        description=vuln.get("description", ""),
                        references=vuln.get("aliases", []),
                        ecosystem="pip",
                        file_path=str(req_files[0])
                    ))
    
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        # Fallback to safety if pip-audit fails
        try:
            result = subprocess.run(
                [sys.executable, "-m", "safety", "check", "--json", "--short-report"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.stdout:
                safety_data = json.loads(result.stdout)
                for vuln in safety_data:
                    vulnerabilities.append(DependencyVulnerability(
                        dependency_name=vuln.get("package", ""),
                        installed_version=vuln.get("installed_version", ""),
                        fixed_version=vuln.get("analyzed_version"),
                        vulnerability_id=vuln.get("advisory", ""),
                        severity=vuln.get("vulnerability", "Medium"),
                        description=vuln.get("advisory", ""),
                        references=[],
                        ecosystem="pip",
                        file_path=str(req_files[0])
                    ))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
    
    return vulnerabilities


def scan_nodejs_dependencies(project_path: str) -> List[DependencyVulnerability]:
    """
    Scan Node.js dependencies using npm audit.
    """
    vulnerabilities = []
    project_dir = Path(project_path)
    
    package_json = project_dir / "package.json"
    package_lock = project_dir / "package-lock.json"
    
    if not package_json.exists():
        return vulnerabilities
    
    try:
        # Run npm audit
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=180
        )
        
        if result.stdout:
            audit_data = json.loads(result.stdout)
            vulns = audit_data.get("vulnerabilities", {})
            
            for package_name, vuln_data in vulns.items():
                for vuln in vuln_data.get("via", []):
                    if isinstance(vuln, dict):
                        vulnerabilities.append(DependencyVulnerability(
                            dependency_name=package_name,
                            installed_version=vuln_data.get("version", ""),
                            fixed_version=vuln.get("fixAvailable", {}).get("version"),
                            vulnerability_id=vuln.get("source", ""),
                            severity=vuln.get("severity", "Medium"),
                            description=vuln.get("title", ""),
                            references=[vuln.get("url", "")] if vuln.get("url") else [],
                            ecosystem="npm",
                            file_path=str(package_json)
                        ))
    
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    
    return vulnerabilities


def scan_java_dependencies(project_path: str) -> List[DependencyVulnerability]:
    """
    Scan Java Maven dependencies using OWASP Dependency-Check.
    """
    vulnerabilities = []
    project_dir = Path(project_path)
    
    pom_xml = project_dir / "pom.xml"
    build_gradle = project_dir / "build.gradle"
    
    if not (pom_xml.exists() or build_gradle.exists()):
        return vulnerabilities
    
    # Try OWASP Dependency-Check if available
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                ["dependency-check", "--project", project_path, "--format", "JSON", "--out", temp_dir],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )
            
            # Parse the JSON report
            report_file = Path(temp_dir) / "dependency-check-report.json"
            if report_file.exists():
                with open(report_file) as f:
                    report_data = json.load(f)
                
                for dependency in report_data.get("dependencies", []):
                    for vuln in dependency.get("vulnerabilities", []):
                        vulnerabilities.append(DependencyVulnerability(
                            dependency_name=dependency.get("fileName", ""),
                            installed_version=dependency.get("version", ""),
                            fixed_version=None,
                            vulnerability_id=vuln.get("name", ""),
                            severity=vuln.get("severity", "Medium"),
                            description=vuln.get("description", ""),
                            references=vuln.get("references", []),
                            ecosystem="maven",
                            file_path=str(pom_xml if pom_xml.exists() else build_gradle)
                        ))
    
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        # Fallback: basic parsing of pom.xml for known vulnerable libraries
        if pom_xml.exists():
            vulnerabilities.extend(_scan_pom_xml_basic(pom_xml))
    
    return vulnerabilities


def _scan_pom_xml_basic(pom_xml: Path) -> List[DependencyVulnerability]:
    """
    Basic scanning of pom.xml for known vulnerable libraries without OWASP Dependency-Check.
    This is a simplified fallback.
    """
    vulnerabilities = []
    
    try:
        content = pom_xml.read_text()
        
        # Simple regex-based dependency extraction
        dependency_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
        matches = re.findall(dependency_pattern, content, re.DOTALL)
        
        # Known vulnerable versions (simplified database)
        known_vulns = {
            ("org.springframework", "spring-core"): [("5.3.18", "CVE-2022-22965")],
            ("org.apache.logging.log4j", "log4j-core"): [("2.17.0", "CVE-2021-44228")],
            ("com.fasterxml.jackson.core", "jackson-databind"): [("2.12.7", "CVE-2022-23807")]
        }
        
        for group_id, artifact_id, version in matches:
            key = (group_id, artifact_id)
            if key in known_vulns:
                for vuln_version, cve in known_vulns[key]:
                    if version and version < vuln_version:
                        vulnerabilities.append(DependencyVulnerability(
                            dependency_name=f"{group_id}:{artifact_id}",
                            installed_version=version,
                            fixed_version=vuln_version,
                            vulnerability_id=cve,
                            severity="High",
                            description=f"Known vulnerability in {artifact_id}",
                            references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"],
                            ecosystem="maven",
                            file_path=str(pom_xml)
                        ))
    
    except Exception:
        pass
    
    return vulnerabilities


def scan_all_dependencies(project_path: str) -> List[DependencyVulnerability]:
    """
    Scan dependencies for all supported ecosystems.
    """
    all_vulnerabilities = []
    
    # Scan each ecosystem
    all_vulnerabilities.extend(scan_python_dependencies(project_path))
    all_vulnerabilities.extend(scan_nodejs_dependencies(project_path))
    all_vulnerabilities.extend(scan_java_dependencies(project_path))
    
    return all_vulnerabilities


def convert_to_vulnerability_findings(dependency_vulns: List[DependencyVulnerability]) -> List[VulnerabilityFinding]:
    """
    Convert DependencyVulnerability objects to VulnerabilityFinding objects
    for compatibility with existing models.
    """
    findings = []
    
    for dep_vuln in dependency_vulns:
        finding = VulnerabilityFinding(
            file=dep_vuln.file_path,
            line=1,  # Dependencies are typically at project level
            type="Dependency Vulnerability",
            severity=dep_vuln.severity,
            code=f"{dep_vuln.dependency_name}=={dep_vuln.installed_version}",
            fingerprint=f"dep_{dep_vuln.ecosystem}_{dep_vuln.dependency_name}_{dep_vuln.vulnerability_id}",
            analyzer="dependency-scanner",
            rule_id=dep_vuln.vulnerability_id,
            confidence=dep_vuln.severity if dep_vuln.severity in ["High", "Critical"] else "Medium"
        )
        findings.append(finding)
    
    return findings


if __name__ == "__main__":
    # Test the dependency scanner
    import sys
    if len(sys.argv) > 1:
        project_path = sys.argv[1]
        vulns = scan_all_dependencies(project_path)
        print(f"Found {len(vulns)} dependency vulnerabilities:")
        for vuln in vulns:
            print(f"  - {vuln.dependency_name}@{vuln.installed_version}: {vuln.vulnerability_id} ({vuln.severity})")
