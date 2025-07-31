"""
Core Framework Module
Main framework class that orchestrates all components
"""

import asyncio
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from .config import Config
from .metasploit_client import MetasploitClient
from .database import DatabaseManager
from ..ai.vulnerability_analyzer import VulnerabilityAnalyzer
from ..ai.exploit_recommender import ExploitRecommender
from ..ai.payload_generator import PayloadGenerator
from ..modules.scanner import NetworkScanner
from ..modules.exploit_manager import ExploitManager
from ..modules.report_generator import ReportGenerator
from ..utils.logger import get_logger

@dataclass
class ScanResult:
    """Represents a scan result"""
    target: str
    timestamp: datetime
    vulnerabilities: List[Dict]
    services: List[Dict]
    os_info: Dict
    risk_score: float

@dataclass
class ExploitResult:
    """Represents an exploit result"""
    target: str
    exploit_name: str
    success: bool
    payload: str
    timestamp: datetime
    details: Dict

class MetasploitAIFramework:
    """Main framework class for Metasploit-AI"""
    
    def __init__(self, config: Config):
        """Initialize the framework"""
        self.config = config
        self.logger = get_logger(__name__)
        
        # Core components
        self.db_manager = DatabaseManager(config.database)
        self.msf_client = MetasploitClient(config.metasploit)
        
        # AI components
        self.vuln_analyzer = VulnerabilityAnalyzer(config.ai)
        self.exploit_recommender = ExploitRecommender(config.ai)
        self.payload_generator = PayloadGenerator(config.ai)
        
        # Functional modules
        self.scanner = NetworkScanner(config)
        self.exploit_manager = ExploitManager(self.msf_client, config)
        self.report_generator = ReportGenerator(config)
        
        # State management
        self.active_scans: Dict[str, Any] = {}
        self.active_exploits: Dict[str, Any] = {}
        self.session_data: Dict[str, Any] = {}
        
        self.logger.info("🤖 Metasploit-AI Framework initialized")
    
    async def initialize(self) -> bool:
        """Initialize all components"""
        try:
            # Initialize database
            await self.db_manager.initialize()
            
            # Connect to Metasploit
            if not await self.msf_client.connect():
                self.logger.error("Failed to connect to Metasploit")
                return False
            
            # Initialize AI models
            await self.vuln_analyzer.initialize()
            await self.exploit_recommender.initialize()
            await self.payload_generator.initialize()
            
            self.logger.info("✅ Framework initialization completed")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Framework initialization failed: {e}")
            return False
    
    async def scan_target(self, target: str, scan_type: str = "comprehensive") -> ScanResult:
        """Perform intelligent target scanning"""
        self.logger.info(f"🔍 Starting {scan_type} scan on {target}")
        
        scan_id = f"scan_{target}_{datetime.now().timestamp()}"
        self.active_scans[scan_id] = {
            'target': target,
            'type': scan_type,
            'status': 'running',
            'start_time': datetime.now()
        }
        
        try:
            # Network scanning
            scan_data = await self.scanner.scan(target, scan_type)
            
            # AI-powered vulnerability analysis
            vulnerabilities = await self.vuln_analyzer.analyze(scan_data)
            
            # Calculate AI-based risk score
            risk_score = await self._calculate_risk_score(scan_data, vulnerabilities)
            
            result = ScanResult(
                target=target,
                timestamp=datetime.now(),
                vulnerabilities=vulnerabilities,
                services=scan_data.get('services', []),
                os_info=scan_data.get('os_info', {}),
                risk_score=risk_score
            )
            
            # Store in database
            await self.db_manager.store_scan_result(result)
            
            self.active_scans[scan_id]['status'] = 'completed'
            self.logger.info(f"✅ Scan completed for {target} - Risk Score: {risk_score:.2f}")
            
            return result
            
        except Exception as e:
            self.active_scans[scan_id]['status'] = 'failed'
            self.logger.error(f"❌ Scan failed for {target}: {e}")
            raise
    
    async def recommend_exploits(self, target: str, vulnerabilities: List[Dict]) -> List[Dict]:
        """Get AI-powered exploit recommendations"""
        self.logger.info(f"🧠 Generating exploit recommendations for {target}")
        
        try:
            recommendations = await self.exploit_recommender.recommend(
                target, vulnerabilities
            )
            
            # Enhance with Metasploit module information
            enhanced_recommendations = []
            for rec in recommendations:
                msf_module = await self.msf_client.get_module_info(rec['exploit_name'])
                if msf_module:
                    rec.update({
                        'msf_module': msf_module,
                        'available': True
                    })
                enhanced_recommendations.append(rec)
            
            self.logger.info(f"🎯 Generated {len(enhanced_recommendations)} exploit recommendations")
            return enhanced_recommendations
            
        except Exception as e:
            self.logger.error(f"❌ Failed to generate recommendations: {e}")
            return []
    
    async def execute_exploit(self, target: str, exploit_name: str, 
                            options: Dict = None) -> ExploitResult:
        """Execute exploit with AI-generated payload"""
        self.logger.info(f"💥 Executing exploit {exploit_name} against {target}")
        
        exploit_id = f"exploit_{target}_{exploit_name}_{datetime.now().timestamp()}"
        self.active_exploits[exploit_id] = {
            'target': target,
            'exploit': exploit_name,
            'status': 'preparing',
            'start_time': datetime.now()
        }
        
        try:
            # Generate AI-optimized payload
            payload = await self.payload_generator.generate(target, exploit_name, options)
            
            self.active_exploits[exploit_id]['status'] = 'executing'
            
            # Execute through Metasploit
            result = await self.exploit_manager.execute(
                target, exploit_name, payload, options
            )
            
            exploit_result = ExploitResult(
                target=target,
                exploit_name=exploit_name,
                success=result['success'],
                payload=payload,
                timestamp=datetime.now(),
                details=result
            )
            
            # Store result
            await self.db_manager.store_exploit_result(exploit_result)
            
            self.active_exploits[exploit_id]['status'] = 'completed'
            self.logger.info(f"🎯 Exploit {'succeeded' if result['success'] else 'failed'}")
            
            return exploit_result
            
        except Exception as e:
            self.active_exploits[exploit_id]['status'] = 'failed'
            self.logger.error(f"❌ Exploit execution failed: {e}")
            raise
    
    async def automated_penetration_test(self, targets: List[str]) -> Dict:
        """Perform fully automated penetration test"""
        self.logger.info(f"🤖 Starting automated penetration test on {len(targets)} targets")
        
        results = {
            'scan_results': [],
            'exploit_results': [],
            'summary': {},
            'recommendations': []
        }
        
        for target in targets:
            try:
                # 1. Scan target
                scan_result = await self.scan_target(target, "comprehensive")
                results['scan_results'].append(scan_result)
                
                # 2. Get exploit recommendations
                if scan_result.vulnerabilities:
                    recommendations = await self.recommend_exploits(
                        target, scan_result.vulnerabilities
                    )
                    
                    # 3. Auto-execute high-confidence exploits
                    for rec in recommendations[:3]:  # Top 3 recommendations
                        if rec.get('confidence', 0) > 0.8:
                            exploit_result = await self.execute_exploit(
                                target, rec['exploit_name'], rec.get('options', {})
                            )
                            results['exploit_results'].append(exploit_result)
                
            except Exception as e:
                self.logger.error(f"❌ Automated test failed for {target}: {e}")
        
        # Generate comprehensive report
        report = await self.report_generator.generate_pentest_report(results)
        results['report'] = report
        
        self.logger.info("🎉 Automated penetration test completed")
        return results
    
    async def _calculate_risk_score(self, scan_data: Dict, vulnerabilities: List[Dict]) -> float:
        """Calculate AI-based risk score"""
        try:
            # Base score from vulnerabilities
            vuln_score = sum(vuln.get('cvss_score', 0) for vuln in vulnerabilities) / 10
            
            # Service exposure factor
            service_count = len(scan_data.get('services', []))
            service_factor = min(service_count / 10, 1.0)
            
            # AI confidence factor
            ai_confidence = await self.vuln_analyzer.get_confidence_score(scan_data)
            
            # Combined risk score (0-10 scale)
            risk_score = (vuln_score * 0.6 + service_factor * 2 + ai_confidence * 3)
            return min(risk_score, 10.0)
            
        except Exception as e:
            self.logger.error(f"Risk calculation error: {e}")
            return 5.0  # Default medium risk
    
    def get_status(self) -> Dict:
        """Get framework status"""
        return {
            'active_scans': len(self.active_scans),
            'active_exploits': len(self.active_exploits),
            'metasploit_connected': self.msf_client.is_connected(),
            'ai_models_loaded': all([
                self.vuln_analyzer.is_ready(),
                self.exploit_recommender.is_ready(),
                self.payload_generator.is_ready()
            ])
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        self.logger.info("🧹 Cleaning up framework resources")
        
        # Stop active operations
        for scan_id in self.active_scans:
            self.active_scans[scan_id]['status'] = 'cancelled'
        
        # Disconnect from Metasploit
        await self.msf_client.disconnect()
        
        # Close database connections
        await self.db_manager.close()
        
        self.logger.info("✅ Framework cleanup completed")
