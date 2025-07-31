"""
Advanced Report Generator Module
AI-enhanced reporting for penetration testing results
"""

import asyncio
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import jinja2
from dataclasses import asdict

from ..utils.logger import get_logger


class ReportGenerator:
    """AI-enhanced penetration testing report generator"""
    
    def __init__(self, config):
        """Initialize the report generator"""
        self.config = config
        self.logger = get_logger(__name__)
        
        # Report settings
        self.report_dir = Path(config.get('reports', {}).get('output_dir', 'reports'))
        self.template_dir = Path(config.get('reports', {}).get('template_dir', 'templates'))
        
        # Ensure directories exist
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        self.logger.info("📊 Report Generator initialized")
    
    async def generate_pentest_report(self, results: Dict) -> Dict:
        """Generate comprehensive penetration test report"""
        self.logger.info("📋 Generating penetration test report")
        
        try:
            # Prepare report data
            report_data = await self._prepare_report_data(results)
            
            # Generate different report formats
            report_files = {}
            
            # HTML Report
            html_report = await self._generate_html_report(report_data)
            html_file = self._save_report(html_report, 'html', report_data['metadata']['timestamp'])
            report_files['html'] = html_file
            
            # JSON Report
            json_report = await self._generate_json_report(report_data)
            json_file = self._save_report(json_report, 'json', report_data['metadata']['timestamp'])
            report_files['json'] = json_file
            
            # PDF Report (if available)
            try:
                pdf_report = await self._generate_pdf_report(report_data)
                pdf_file = self._save_report(pdf_report, 'pdf', report_data['metadata']['timestamp'])
                report_files['pdf'] = pdf_file
            except Exception as e:
                self.logger.warning(f"PDF generation failed: {e}")
            
            # Executive Summary
            executive_summary = await self._generate_executive_summary(report_data)
            
            report_info = {
                'files': report_files,
                'summary': executive_summary,
                'metadata': report_data['metadata'],
                'statistics': report_data['statistics']
            }
            
            self.logger.info(f"✅ Report generated successfully: {len(report_files)} formats")
            return report_info
            
        except Exception as e:
            self.logger.error(f"❌ Report generation failed: {e}")
            raise
    
    async def _prepare_report_data(self, results: Dict) -> Dict:
        """Prepare and structure data for reporting"""
        scan_results = results.get('scan_results', [])
        exploit_results = results.get('exploit_results', [])
        
        # Calculate statistics
        total_targets = len(scan_results)
        total_vulnerabilities = sum(len(scan.vulnerabilities) for scan in scan_results)
        successful_exploits = sum(1 for exploit in exploit_results if exploit.success)
        high_risk_targets = sum(1 for scan in scan_results if scan.risk_score >= 7.0)
        
        # Categorize vulnerabilities by severity
        vulnerability_breakdown = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for scan in scan_results:
            for vuln in scan.vulnerabilities:
                severity = self._get_vulnerability_severity(vuln.get('cvss_score', 0))
                vulnerability_breakdown[severity] += 1
        
        # Generate findings
        key_findings = await self._analyze_key_findings(scan_results, exploit_results)
        
        report_data = {
            'metadata': {
                'title': 'Metasploit-AI Penetration Test Report',
                'timestamp': datetime.now().isoformat(),
                'generated_by': 'Metasploit-AI Framework',
                'version': '1.0.0'
            },
            'executive_summary': {
                'total_targets': total_targets,
                'total_vulnerabilities': total_vulnerabilities,
                'successful_exploits': successful_exploits,
                'high_risk_targets': high_risk_targets,
                'overall_risk_level': self._calculate_overall_risk(scan_results)
            },
            'statistics': {
                'vulnerability_breakdown': vulnerability_breakdown,
                'exploit_success_rate': (successful_exploits / max(len(exploit_results), 1)) * 100,
                'average_risk_score': sum(scan.risk_score for scan in scan_results) / max(total_targets, 1)
            },
            'detailed_findings': {
                'scan_results': [self._serialize_scan_result(scan) for scan in scan_results],
                'exploit_results': [self._serialize_exploit_result(exploit) for exploit in exploit_results],
                'key_findings': key_findings
            },
            'recommendations': await self._generate_recommendations(scan_results, exploit_results),
            'technical_details': {
                'scan_methodology': self._get_scan_methodology(),
                'exploit_techniques': self._get_exploit_techniques(exploit_results),
                'tools_used': self._get_tools_used()
            }
        }
        
        return report_data
    
    async def _generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML report"""
        try:
            template = self.jinja_env.get_template('pentest_report.html')
            html_content = template.render(**report_data)
            return html_content
        except jinja2.TemplateNotFound:
            # Fallback to basic HTML template
            return self._generate_basic_html_report(report_data)
    
    def _generate_basic_html_report(self, report_data: Dict) -> str:
        """Generate basic HTML report when template is not available"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{report_data['metadata']['title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
        .vulnerability {{ background-color: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #27ae60; }}
        .stats {{ display: flex; gap: 20px; }}
        .stat-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report_data['metadata']['title']}</h1>
        <p>Generated: {report_data['metadata']['timestamp']}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <h3>{report_data['executive_summary']['total_targets']}</h3>
                <p>Targets Scanned</p>
            </div>
            <div class="stat-box">
                <h3>{report_data['executive_summary']['total_vulnerabilities']}</h3>
                <p>Vulnerabilities Found</p>
            </div>
            <div class="stat-box">
                <h3>{report_data['executive_summary']['successful_exploits']}</h3>
                <p>Successful Exploits</p>
            </div>
            <div class="stat-box">
                <h3>{report_data['executive_summary']['high_risk_targets']}</h3>
                <p>High Risk Targets</p>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Vulnerability Breakdown</h2>
        <ul>
            <li>Critical: {report_data['statistics']['vulnerability_breakdown']['critical']}</li>
            <li>High: {report_data['statistics']['vulnerability_breakdown']['high']}</li>
            <li>Medium: {report_data['statistics']['vulnerability_breakdown']['medium']}</li>
            <li>Low: {report_data['statistics']['vulnerability_breakdown']['low']}</li>
            <li>Info: {report_data['statistics']['vulnerability_breakdown']['info']}</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
"""
        
        for recommendation in report_data['recommendations']:
            html += f"<li><strong>{recommendation['title']}</strong>: {recommendation['description']}</li>"
        
        html += """
        </ul>
    </div>
</body>
</html>
"""
        return html
    
    async def _generate_json_report(self, report_data: Dict) -> str:
        """Generate JSON report"""
        return json.dumps(report_data, indent=2, default=str)
    
    async def _generate_pdf_report(self, report_data: Dict) -> bytes:
        """Generate PDF report (requires additional dependencies)"""
        try:
            # Try to use weasyprint for PDF generation
            import weasyprint
            html_content = await self._generate_html_report(report_data)
            pdf_content = weasyprint.HTML(string=html_content).write_pdf()
            return pdf_content
        except ImportError:
            self.logger.warning("weasyprint not available for PDF generation")
            raise Exception("PDF generation not available - install weasyprint")
    
    async def _generate_executive_summary(self, report_data: Dict) -> str:
        """Generate executive summary"""
        summary = f"""
EXECUTIVE SUMMARY

Assessment Overview:
- {report_data['executive_summary']['total_targets']} targets were assessed
- {report_data['executive_summary']['total_vulnerabilities']} vulnerabilities identified
- {report_data['executive_summary']['successful_exploits']} successful exploits executed
- Overall risk level: {report_data['executive_summary']['overall_risk_level']}

Key Findings:
- {report_data['statistics']['vulnerability_breakdown']['critical']} critical vulnerabilities
- {report_data['statistics']['vulnerability_breakdown']['high']} high severity vulnerabilities
- {report_data['statistics']['exploit_success_rate']:.1f}% exploit success rate

Immediate Actions Required:
1. Address all critical vulnerabilities immediately
2. Implement network segmentation
3. Update vulnerable systems and services
4. Enhance monitoring and detection capabilities
"""
        return summary
    
    def _save_report(self, content: Any, format_type: str, timestamp: str) -> str:
        """Save report to file"""
        timestamp_clean = timestamp.replace(':', '-').replace('.', '-')
        filename = f"pentest_report_{timestamp_clean}.{format_type}"
        filepath = self.report_dir / filename
        
        if format_type == 'pdf':
            with open(filepath, 'wb') as f:
                f.write(content)
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        
        self.logger.info(f"📄 Report saved: {filepath}")
        return str(filepath)
    
    def _serialize_scan_result(self, scan_result) -> Dict:
        """Serialize scan result for JSON compatibility"""
        if hasattr(scan_result, '__dict__'):
            return asdict(scan_result)
        return scan_result
    
    def _serialize_exploit_result(self, exploit_result) -> Dict:
        """Serialize exploit result for JSON compatibility"""
        if hasattr(exploit_result, '__dict__'):
            return asdict(exploit_result)
        return exploit_result
    
    def _get_vulnerability_severity(self, cvss_score: float) -> str:
        """Get vulnerability severity based on CVSS score"""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0.0:
            return 'low'
        else:
            return 'info'
    
    def _calculate_overall_risk(self, scan_results: List) -> str:
        """Calculate overall risk level"""
        if not scan_results:
            return 'Unknown'
        
        avg_risk = sum(scan.risk_score for scan in scan_results) / len(scan_results)
        
        if avg_risk >= 8.0:
            return 'Critical'
        elif avg_risk >= 6.0:
            return 'High'
        elif avg_risk >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    async def _analyze_key_findings(self, scan_results: List, exploit_results: List) -> List[Dict]:
        """Analyze and extract key findings"""
        findings = []
        
        # Critical vulnerabilities
        for scan in scan_results:
            for vuln in scan.vulnerabilities:
                if vuln.get('cvss_score', 0) >= 9.0:
                    findings.append({
                        'type': 'critical_vulnerability',
                        'target': scan.target,
                        'title': vuln.get('name', 'Unknown Vulnerability'),
                        'description': vuln.get('description', 'No description available'),
                        'cvss_score': vuln.get('cvss_score', 0),
                        'impact': 'Critical system compromise possible'
                    })
        
        # Successful exploits
        for exploit in exploit_results:
            if exploit.success:
                findings.append({
                    'type': 'successful_exploit',
                    'target': exploit.target,
                    'title': f'Successful Exploitation: {exploit.exploit_name}',
                    'description': f'Successfully exploited {exploit.target} using {exploit.exploit_name}',
                    'impact': 'System compromised'
                })
        
        return findings[:10]  # Top 10 findings
    
    async def _generate_recommendations(self, scan_results: List, exploit_results: List) -> List[Dict]:
        """Generate security recommendations"""
        recommendations = [
            {
                'priority': 'Critical',
                'title': 'Patch Critical Vulnerabilities',
                'description': 'Immediately apply security patches for all critical vulnerabilities identified during the assessment.'
            },
            {
                'priority': 'High',
                'title': 'Implement Network Segmentation',
                'description': 'Segment the network to limit lateral movement and contain potential breaches.'
            },
            {
                'priority': 'High',
                'title': 'Enable Security Monitoring',
                'description': 'Deploy comprehensive security monitoring and incident detection systems.'
            },
            {
                'priority': 'Medium',
                'title': 'Regular Security Assessments',
                'description': 'Conduct regular penetration testing and vulnerability assessments.'
            },
            {
                'priority': 'Medium',
                'title': 'Security Awareness Training',
                'description': 'Implement regular security awareness training for all personnel.'
            }
        ]
        
        return recommendations
    
    def _get_scan_methodology(self) -> List[str]:
        """Get scan methodology used"""
        return [
            'Network Discovery and Port Scanning',
            'Service Enumeration and Fingerprinting', 
            'Vulnerability Assessment',
            'AI-Enhanced Risk Analysis',
            'Exploit Verification'
        ]
    
    def _get_exploit_techniques(self, exploit_results: List) -> List[str]:
        """Get exploit techniques used"""
        techniques = set()
        for exploit in exploit_results:
            if exploit.success:
                techniques.add(exploit.exploit_name)
        return list(techniques)
    
    def _get_tools_used(self) -> List[str]:
        """Get tools used in assessment"""
        return [
            'Metasploit Framework',
            'Nmap Network Scanner',
            'AI Vulnerability Analyzer',
            'Custom Exploit Scripts',
            'Metasploit-AI Framework'
        ]
