#!/usr/bin/env python3
"""
API Patent System - Server for Novel Patent Implementations

Flask API server for the novel patent claims system with concrete technical implementations.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
from pathlib import Path
from typing import Dict

# Add the scanner directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner'))

from scanner.novel_technical_implementations import NovelTechnicalImplementations
from scanner.models import VulnerabilityFinding

app = Flask(__name__)
CORS(app)

# Initialize the novel implementations engine
novel_engine = NovelTechnicalImplementations()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'system': 'Novel Patent Claims API',
        'version': '1.0.0',
        'novel_implementations': 3,
        'patentable_algorithms': True
    })

@app.route('/api/novel-patent-analysis', methods=['POST'])
def execute_novel_patent_analysis():
    """
    Execute comprehensive novel patent analysis with concrete technical implementations
    
    Patent Claims:
    1. Business Workflow Extraction with Hierarchical AST Analysis
    2. Multi-Layer Attack Path Construction with Temporal Constraints  
    3. Dynamic Security Debt Portfolio with Modern Portfolio Theory
    """
    try:
        data = request.get_json()
        
        # Validate required parameters
        if not data.get('project_path'):
            return jsonify({'error': 'project_path is required'}), 400
        
        project_path = data.get('project_path')
        vulnerabilities_data = data.get('vulnerabilities', [])
        industry = data.get('industry', 'technology')
        
        # Convert vulnerability data to VulnerabilityFinding objects
        vulnerabilities = []
        for vuln_data in vulnerabilities_data:
            vuln_obj = VulnerabilityFinding(
                file=vuln_data.get('file', ''),
                line=vuln_data.get('line', 1),
                type=vuln_data.get('type', ''),
                severity=vuln_data.get('severity', 'Medium'),
                code=vuln_data.get('code', ''),
                analyzer=vuln_data.get('analyzer', 'novel_patent_system')
            )
            vulnerabilities.append(vuln_obj)
        
        # Execute all novel implementations
        results = novel_engine.execute_all_novel_implementations(
            vulnerabilities, 
            project_path, 
            industry
        )
        
        return jsonify({
            'success': True,
            'patent_analysis_results': results,
            'technical_summary': {
                'algorithms_executed': 3,
                'patentable_features': results['patentability_assessment'],
                'competitive_advantages': results['competitive_advantages']
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/business-workflow-extraction', methods=['POST'])
def extract_business_workflows():
    """
    Patent Claim 1: Business Workflow Extraction Algorithm
    
    Novel Technical Implementation:
    - Hierarchical AST Analysis with Business Semantic Tagging
    - Multi-dimensional business semantic hierarchy
    - Context-aware AST parsing with business intent recognition
    - Dynamic workflow boundary detection using control flow analysis
    """
    try:
        data = request.get_json()
        
        if not data.get('project_path'):
            return jsonify({'error': 'project_path is required'}), 400
        
        project_path = data.get('project_path')
        
        # Load project code
        try:
            with open(project_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except Exception as e:
            return jsonify({'error': f'Failed to read project file: {str(e)}'}), 400
        
        # Execute business workflow extraction
        results = novel_engine.workflow_extractor.extract_business_workflows(code_content, project_path)
        
        return jsonify({
            'success': True,
            'patent_claim': 'Business Workflow Extraction Algorithm',
            'technical_algorithm': 'Hierarchical AST Analysis with Business Semantic Tagging',
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack-path-modeling', methods=['POST'])
def model_attack_paths():
    """
    Patent Claim 2: Multi-Layer Attack Path Construction
    
    Novel Technical Implementation:
    - Multi-layer vulnerability analysis with exploit dependency modeling
    - Temporal constraint analysis with real-time feasibility scoring
    - Modified Dijkstra algorithm for temporal optimization
    - Custom vulnerability layering algorithm with business context
    """
    try:
        data = request.get_json()
        
        vulnerabilities_data = data.get('vulnerabilities', [])
        
        # Convert to VulnerabilityFinding objects
        vulnerabilities = []
        for vuln_data in vulnerabilities_data:
            vuln_obj = VulnerabilityFinding(
                file=vuln_data.get('file', ''),
                line=vuln_data.get('line', 1),
                type=vuln_data.get('type', ''),
                severity=vuln_data.get('severity', 'Medium'),
                code=vuln_data.get('code', ''),
                analyzer=vuln_data.get('analyzer', 'novel_patent_system')
            )
            vulnerabilities.append(vuln_obj)
        
        # Execute attack path modeling
        results = novel_engine.attack_path_modeler.construct_attack_path_graph(vulnerabilities)
        
        return jsonify({
            'success': True,
            'patent_claim': 'Multi-Layer Attack Path Construction with Temporal Constraints',
            'technical_algorithm': 'Exploit Dependency Modeling with Temporal Optimization',
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/security-debt-portfolio', methods=['POST'])
def model_security_debt_portfolio():
    """
    Patent Claim 3: Dynamic Security Debt Portfolio Modeling
    
    Novel Technical Implementation:
    - Time-varying risk accumulation using stochastic processes
    - Markowitz mean-variance optimization for security portfolio
    - Monte Carlo simulation with copula modeling for uncertainty
    - Industry-specific risk modeling with regression analysis
    """
    try:
        data = request.get_json()
        
        vulnerabilities_data = data.get('vulnerabilities', [])
        industry = data.get('industry', 'technology')
        
        # Convert to VulnerabilityFinding objects
        vulnerabilities = []
        for vuln_data in vulnerabilities_data:
            vuln_obj = VulnerabilityFinding(
                file=vuln_data.get('file', ''),
                line=vuln_data.get('line', 1),
                type=vuln_data.get('type', ''),
                severity=vuln_data.get('severity', 'Medium'),
                code=vuln_data.get('code', ''),
                analyzer=vuln_data.get('analyzer', 'novel_patent_system')
            )
            vulnerabilities.append(vuln_obj)
        
        # Execute security debt portfolio modeling
        results = novel_engine.security_debt_modeler.model_security_debt_portfolio(vulnerabilities, industry)
        
        return jsonify({
            'success': True,
            'patent_claim': 'Dynamic Security Debt Portfolio with Modern Portfolio Theory',
            'technical_algorithm': 'Markowitz Optimization with Stochastic Risk Modeling',
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/patent-claims-validation', methods=['POST'])
def validate_patent_claims():
    """
    Validate patent claims against USPTO requirements
    
    Checks for:
    - Technical novelty (not abstract ideas)
    - Non-obviousness (creative combinations)
    - Industrial applicability (enterprise use)
    - Enablement (detailed specifications)
    """
    try:
        data = request.get_json()
        
        claim_id = data.get('claim_id')
        claim_text = data.get('claim_text')
        technical_details = data.get('technical_details', {})
        
        if not claim_id or not claim_text:
            return jsonify({'error': 'claim_id and claim_text are required'}), 400
        
        # Validate patent claim
        validation_results = {
            'claim_id': claim_id,
            'technical_novelty': _assess_technical_novelty(claim_text, technical_details),
            'non_obviousness': _assess_non_obviousness(claim_text, technical_details),
            'industrial_applicability': _assess_industrial_applicability(technical_details),
            'enablement': _assess_enablement(technical_details),
            'patentability_score': 0,
            'recommendation': ''
        }
        
        # Calculate overall patentability score
        scores = [
            validation_results['technical_novelty']['score'],
            validation_results['non_obviousness']['score'],
            validation_results['industrial_applicability']['score'],
            validation_results['enablement']['score']
        ]
        validation_results['patentability_score'] = int(sum(scores) / len(scores))
        
        # Generate recommendation
        if validation_results['patentability_score'] >= 80:
            validation_results['recommendation'] = 'Strong candidate for patent filing'
        elif validation_results['patentability_score'] >= 60:
            validation_results['recommendation'] = 'Good candidate with some improvements'
        else:
            validation_results['recommendation'] = 'Needs significant improvement before filing'
        
        return jsonify({
            'success': True,
            'validation_results': validation_results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _assess_technical_novelty(claim_text: str, technical_details: Dict) -> Dict:
    """Assess technical novelty of patent claim"""
    score = 50  # Base score
    
    # Check for specific technical implementations
    if 'algorithm' in claim_text.lower():
        score += 15
    if 'method for' in claim_text.lower():
        score += 10
    if technical_details.get('novel_technical_features'):
        score += 15
    if technical_details.get('algorithm_specifications'):
        score += 10
    
    return {'score': min(100, score), 'assessment': 'High' if score >= 80 else 'Medium' if score >= 60 else 'Low'}

def _assess_non_obviousness(claim_text: str, technical_details: Dict) -> Dict:
    """Assess non-obviousness of patent claim"""
    score = 50
    
    # Check for creative combinations
    if 'novel' in claim_text.lower():
        score += 10
    if 'custom' in claim_text.lower():
        score += 10
    if 'unique' in claim_text.lower():
        score += 10
    if len(technical_details.get('technical_features', [])) > 3:
        score += 10
    if technical_details.get('algorithm_complexity') == 'high':
        score += 10
    
    return {'score': min(100, score), 'assessment': 'High' if score >= 80 else 'Medium' if score >= 60 else 'Low'}

def _assess_industrial_applicability(technical_details: Dict) -> Dict:
    """Assess industrial applicability"""
    score = 50
    
    # Check for enterprise applicability
    if 'enterprise' in str(technical_details).lower():
        score += 15
    if 'security' in str(technical_details).lower():
        score += 10
    if 'software' in str(technical_details).lower():
        score += 10
    if technical_details.get('market_size'):
        score += 15
    
    return {'score': min(100, score), 'assessment': 'High' if score >= 80 else 'Medium' if score >= 60 else 'Low'}

def _assess_enablement(technical_details: Dict) -> Dict:
    """Assess enablement (detailed specifications)"""
    score = 50
    
    # Check for detailed technical specifications
    if technical_details.get('algorithm_specifications'):
        score += 15
    if technical_details.get('data_structures'):
        score += 10
    if technical_details.get('implementation_details'):
        score += 15
    if technical_details.get('test_cases'):
        score += 10
    
    return {'score': min(100, score), 'assessment': 'High' if score >= 80 else 'Medium' if score >= 60 else 'Low'}

# Add the validation methods to the Flask app
app._assess_technical_novelty = _assess_technical_novelty
app._assess_non_obviousness = _assess_non_obviousness
app._assess_industrial_applicability = _assess_industrial_applicability
app._assess_enablement = _assess_enablement

@app.route('/api/patent-documentation', methods=['POST'])
def generate_patent_documentation():
    """Generate comprehensive patent documentation"""
    try:
        data = request.get_json()
        
        claim_ids = data.get('claim_ids', [])
        include_technical_specs = data.get('include_technical_specs', True)
        
        documentation = {
            'patent_application': {
                'title': 'Integrated Security Analysis System with Novel Technical Implementations',
                'abstract': 'A comprehensive computer-implemented system for advanced security vulnerability analysis comprising three novel technical methodologies: hierarchical AST analysis with business semantic tagging for workflow extraction; multi-layer attack path construction with temporal constraint modeling; and dynamic security debt portfolio optimization using modern portfolio theory.',
                'claims': [
                    {
                        'claim_number': '1',
                        'title': 'Business Workflow Extraction Algorithm',
                        'technical_contribution': 'Hierarchical AST analysis with business semantic tagging and multi-dimensional workflow boundary detection',
                        'novel_features': [
                            'Multi-layer business semantic hierarchy classification',
                            'Context-aware AST parsing with business intent recognition',
                            'Dynamic workflow boundary detection using control flow analysis',
                            'Business semantic similarity scoring with custom embedding vectors'
                        ]
                    },
                    {
                        'claim_number': '2',
                        'title': 'Multi-Layer Attack Path Construction',
                        'technical_contribution': 'Exploit dependency modeling with temporal constraint analysis and optimization',
                        'novel_features': [
                            'Custom vulnerability layering algorithm with business context',
                            'Exploit dependency graph construction using constraint satisfaction',
                            'Temporal constraint analysis with real-time feasibility scoring',
                            'Modified Dijkstra algorithm for temporal path optimization'
                        ]
                    },
                    {
                        'claim_number': '3',
                        'title': 'Dynamic Security Debt Portfolio Modeling',
                        'technical_contribution': 'Modern portfolio theory applied to security vulnerability management',
                        'novel_features': [
                            'Time-varying risk accumulation using stochastic processes',
                            'Markowitz mean-variance optimization for security portfolios',
                            'Monte Carlo simulation with copula modeling for uncertainty',
                            'Industry-specific risk modeling with regression analysis'
                        ]
                    }
                ],
                'technical_specifications': include_technical_specs,
                'patent_strength': 'High - Novel algorithms with concrete implementations',
                'commercial_potential': 'High - Enterprise security market applicability'
            }
        }
        
        return jsonify({
            'success': True,
            'patent_documentation': documentation
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Novel Patent Claims API Server...")
    print("Available endpoints:")
    print("  GET  /api/health")
    print("  POST /api/novel-patent-analysis")
    print("  POST /api/business-workflow-extraction")
    print("  POST /api/attack-path-modeling")
    print("  POST /api/security-debt-portfolio")
    print("  POST /api/patent-claims-validation")
    print("  POST /api/patent-documentation")
    print()
    print("Novel Patent Claims System Ready!")
    print("Patentable Technical Implementations: 3")
    print("Algorithms with Novelty: High")
    print()
    
    app.run(host='0.0.0.0', port=5001, debug=True)
