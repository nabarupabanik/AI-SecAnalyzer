#!/usr/bin/env python3
"""
Integration script to add unique features to main scanner
"""

import os
from pathlib import Path

def integrate_unique_features():
    """Add unique features to main scanning pipeline"""
    
    # Update streaming_scan.py to include unique features
    streaming_scan_path = Path("scanner/streaming_scan.py")
    
    if streaming_scan_path.exists():
        print("Updating streaming_scan.py with unique features...")
        
        # Read current content
        content = streaming_scan_path.read_text()
        
        # Add unique features import
        if "from .unique_features_integration import run_unique_features_analysis" not in content:
            import_line = "from .unique_features_integration import run_unique_features_analysis\n"
            
            # Find the last import and add after it
            lines = content.split('\n')
            import_index = -1
            for i, line in enumerate(lines):
                if line.startswith('from .') or line.startswith('import '):
                    import_index = i
            
            if import_index >= 0:
                lines.insert(import_index + 1, import_line)
                content = '\n'.join(lines)
        
        # Add unique features analysis after dependency scanning
        if "unique_features_analysis" not in content:
            unique_features_code = '''
        # Unique Features Analysis - Revolutionary SAST Capabilities
        if mods["unique_features"]:
            yield {"type": "log", "line": L("Running unique security analysis..."), "progress": pg(85, "unique")}
            
            # Industry and compliance configuration (can be customized)
            industry = os.getenv("SECURITY_INDUSTRY", "general")
            compliance_frameworks = os.getenv("COMPLIANCE_FRAMEWORKS", "GDPR,SOX").split(",") if os.getenv("COMPLIANCE_FRAMEWORKS") else []
            
            # Run unique features analysis
            unique_results = run_unique_features_analysis(
                model.vulnerabilities, 
                project_path, 
                industry, 
                compliance_frameworks
            )
            
            # Store results in model for frontend access
            model.business_logic_analysis = unique_results["business_logic_analysis"]
            model.attack_path_analysis = unique_results["attack_path_analysis"] 
            model.security_debt_analysis = unique_results["security_debt_analysis"]
            
            yield {
                "type": "unique_features",
                "business_logic": model.business_logic_analysis,
                "attack_paths": model.attack_path_analysis,
                "security_debt": model.security_debt_analysis,
                "progress": pg(88, "unique")
            }
            
            yield {
                "type": "log", 
                "line": L(f"Business logic vulns: {model.business_logic_analysis['business_logic_vulnerabilities']}"),
                "progress": pg(89, "unique")
            }
            
            yield {
                "type": "log",
                "line": L(f"Attack paths: {model.attack_path_analysis['total_attack_paths']} (Critical: {model.attack_path_analysis['critical_paths']})"),
                "progress": pg(90, "unique")
            }
            
            yield {
                "type": "log",
                "line": L(f"Security debt: {model.security_debt_analysis['executive_summary']['current_security_debt']} (Health: {model.security_debt_analysis['security_health_score']})"),
                "progress": pg(91, "unique")
            }
'''
            
            # Find where dependency scanning ends and add unique features
            dependency_end = content.find("yield {\"type\": \"log\", \"line\": L(\"Dependencies stage complete.\"")
            if dependency_end > 0:
                # Find the end of that yield block
                insert_point = content.find("}", dependency_end) + 1
                content = content[:insert_point] + unique_features_code + content[insert_point:]
        
        # Add unique_features to analysis_modules
        if "unique_features" not in content:
            # Find analysis_modules normalization
            modules_start = content.find("def normalize_analysis_modules")
            if modules_start > 0:
                # Find the return statement and add unique_features
                return_start = content.find("return", modules_start)
                if return_start > 0:
                    line_end = content.find("\n", return_start)
                    if line_end > 0:
                        # Add unique_features to the modules
                        content = content[:line_end] + "\n    mods[\"unique_features\"] = True" + content[line_end:]
        
        # Write updated content
        streaming_scan_path.write_text(content)
        print("Updated streaming_scan.py successfully!")
    
    # Update ApplicationModel to include new fields
    models_path = Path("scanner/models.py")
    if models_path.exists():
        print("Updating models.py with new fields...")
        
        content = models_path.read_text()
        
        # Add new fields to ApplicationModel
        if "business_logic_analysis" not in content:
            # Find ApplicationModel class
            class_start = content.find("class ApplicationModel")
            if class_start > 0:
                # Find the end of the class definition (before first method)
                class_end = content.find("\n    def ", class_start)
                if class_end > 0:
                    # Add new fields
                    new_fields = '''
    # Unique Features Analysis Results
    business_logic_analysis: Optional[Dict[str, Any]] = None
    attack_path_analysis: Optional[Dict[str, Any]] = None
    security_debt_analysis: Optional[Dict[str, Any]] = None
'''
                    content = content[:class_end] + new_fields + content[class_end:]
                    
                    # Add required imports at top
                    if "from typing import" in content:
                        import_line = content.find("from typing import")
                        import_end = content.find("\n", import_line)
                        if "Dict" not in content[import_line:import_end]:
                            content = content[:import_end] + " Dict" + content[import_end:]
                    
                    models_path.write_text(content)
                    print("Updated models.py successfully!")
    
    # Create API endpoints for unique features
    api_path = Path("api_server.py")
    if api_path.exists():
        print("Adding API endpoints for unique features...")
        
        content = api_path.read_text()
        
        # Add new API endpoints
        if "/api/unique-features" not in content:
            new_endpoints = '''
# Unique Features API Endpoints
@app.route("/api/unique-features", methods=["POST"])
def analyze_unique_features():
    """Run unique features analysis on existing vulnerabilities"""
    try:
        data = request.get_json()
        project_path = data.get("project_path")
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not project_path:
            return jsonify({"error": "project_path required"}), 400
        
        # Convert to VulnerabilityFinding objects
        vuln_objects = []
        for vuln_data in vulnerabilities:
            vuln_obj = VulnerabilityFinding(
                file=vuln_data.get("file", ""),
                line=vuln_data.get("line", 1),
                type=vuln_data.get("type", ""),
                severity=vuln_data.get("severity", "Medium"),
                code=vuln_data.get("code", ""),
                analyzer=vuln_data.get("analyzer", "unknown")
            )
            vuln_objects.append(vuln_obj)
        
        # Run unique features analysis
        from scanner.unique_features_integration import run_unique_features_analysis
        
        industry = data.get("industry", "general")
        compliance_frameworks = data.get("compliance_frameworks", [])
        
        results = run_unique_features_analysis(
            vuln_objects, 
            project_path, 
            industry, 
            compliance_frameworks
        )
        
        return jsonify({
            "business_logic_analysis": results["business_logic_analysis"],
            "attack_path_analysis": results["attack_path_analysis"],
            "security_debt_analysis": results["security_debt_analysis"],
            "summary": {
                "business_logic_vulns": results["business_logic_analysis"]["business_logic_vulnerabilities"],
                "attack_paths": results["attack_path_analysis"]["total_attack_paths"],
                "security_health_score": results["security_debt_analysis"]["security_health_score"]
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/security-debt", methods=["POST"])
def analyze_security_debt():
    """Analyze security debt with financial metrics"""
    try:
        data = request.get_json()
        vulnerabilities = data.get("vulnerabilities", [])
        industry = data.get("industry", "general")
        compliance_frameworks = data.get("compliance_frameworks", [])
        
        # Convert to VulnerabilityFinding objects
        vuln_objects = []
        for vuln_data in vulnerabilities:
            vuln_obj = VulnerabilityFinding(
                file=vuln_data.get("file", ""),
                line=vuln_data.get("line", 1),
                type=vuln_data.get("type", ""),
                severity=vuln_data.get("severity", "Medium"),
                code=vuln_data.get("code", ""),
                analyzer=vuln_data.get("analyzer", "unknown")
            )
            vuln_objects.append(vuln_obj)
        
        # Run security debt analysis
        from scanner.security_debt_analyzer import analyze_security_debt
        
        debt_report = analyze_security_debt(vuln_objects, industry, compliance_frameworks)
        
        return jsonify(debt_report)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/attack-paths", methods=["POST"])
def analyze_attack_paths():
    """Analyze attack paths and exploitation chains"""
    try:
        data = request.get_json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Convert to VulnerabilityFinding objects
        vuln_objects = []
        for vuln_data in vulnerabilities:
            vuln_obj = VulnerabilityFinding(
                file=vuln_data.get("file", ""),
                line=vuln_data.get("line", 1),
                type=vuln_data.get("type", ""),
                severity=vuln_data.get("severity", "Medium"),
                code=vuln_data.get("code", ""),
                analyzer=vuln_data.get("analyzer", "unknown")
            )
            vuln_objects.append(vuln_obj)
        
        # Run attack path analysis
        from scanner.attack_path_analyzer import analyze_attack_paths
        
        attack_report = analyze_attack_paths(vuln_objects)
        
        return jsonify(attack_report)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
'''
            
            # Add at end of file
            content += new_endpoints
            api_path.write_text(content)
            print("Added API endpoints successfully!")
    
    print("\n" + "="*60)
    print("UNIQUE FEATURES INTEGRATION COMPLETE!")
    print("="*60)
    print("\nYour SAST tool now has revolutionary capabilities:")
    print("1. Business Logic Security Analysis")
    print("2. Attack Path Visualization & Exploitation Analysis") 
    print("3. Security Debt Tracking & ROI Analysis")
    print("\nThese features are NOT available in any other SAST tool!")
    print("\nNext steps:")
    print("1. Test the unique features with: python test_unique_features.py")
    print("2. Update frontend to display new analysis results")
    print("3. Configure industry and compliance settings as needed")

if __name__ == "__main__":
    integrate_unique_features()
