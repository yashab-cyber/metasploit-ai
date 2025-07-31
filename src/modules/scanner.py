"""
Advanced Network Scanner Module
AI-enhanced network scanning and reconnaissance
"""

import asyncio
import socket
import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Network scanning imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..utils.logger import get_logger

class NetworkScanner:
    """Advanced AI-enhanced network scanner"""
    
    def __init__(self, config):
        """Initialize the network scanner"""
        self.config = config
        self.logger = get_logger(__name__)
        
        # Scanner configuration
        self.max_threads = config.scan.max_threads
        self.default_timeout = config.scan.default_timeout
        self.timing_template = config.scan.timing_template
        self.stealth_mode = config.scan.stealth_mode
        
        # Nmap scanner
        self.nm = None
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        
        # Scan results cache
        self.scan_cache = {}
        
        # Service detection patterns
        self.service_patterns = {}
        self._load_service_patterns()
        
    async def scan(self, target: str, scan_type: str = "comprehensive") -> Dict:
        """Perform network scan on target"""
        try:
            self.logger.info(f"🔍 Starting {scan_type} scan on {target}")
            
            # Validate target
            targets = await self._parse_targets(target)
            if not targets:
                raise ValueError(f"Invalid target: {target}")
            
            # Choose scan method based on type
            if scan_type == "quick":
                return await self._quick_scan(targets)
            elif scan_type == "comprehensive":
                return await self._comprehensive_scan(targets)
            elif scan_type == "stealth":
                return await self._stealth_scan(targets)
            elif scan_type == "aggressive":
                return await self._aggressive_scan(targets)
            else:
                return await self._custom_scan(targets, scan_type)
                
        except Exception as e:
            self.logger.error(f"❌ Scan failed: {e}")
            raise
    
    async def _parse_targets(self, target: str) -> List[str]:
        """Parse and validate target specification"""
        targets = []
        
        try:
            # Single IP
            if self._is_valid_ip(target):
                targets.append(target)
            
            # IP range (CIDR)
            elif '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                targets.extend([str(ip) for ip in network.hosts()][:254])  # Limit for safety
            
            # IP range (hyphen notation)
            elif '-' in target:
                start_ip, end_ip = target.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                current = start
                while current <= end and len(targets) < 254:
                    targets.append(str(current))
                    current += 1
            
            # Hostname
            else:
                try:
                    ip = socket.gethostbyname(target)
                    targets.append(ip)
                except socket.gaierror:
                    raise ValueError(f"Cannot resolve hostname: {target}")
            
            return targets
            
        except Exception as e:
            self.logger.error(f"Target parsing error: {e}")
            return []
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    async def _quick_scan(self, targets: List[str]) -> Dict:
        """Perform quick scan (top 100 ports)"""
        self.logger.info("⚡ Performing quick scan...")
        
        results = {
            'scan_type': 'quick',
            'targets': targets,
            'hosts': {},
            'summary': {}
        }
        
        # Quick port scan on top ports
        top_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080"
        
        for target in targets:
            try:
                host_result = await self._scan_host_ports(target, top_ports, timeout=5)
                if host_result['open_ports']:
                    results['hosts'][target] = host_result
                    
            except Exception as e:
                self.logger.error(f"Quick scan error for {target}: {e}")
        
        results['summary'] = await self._generate_scan_summary(results['hosts'])
        return results
    
    async def _comprehensive_scan(self, targets: List[str]) -> Dict:
        """Perform comprehensive scan with service detection"""
        self.logger.info("🔍 Performing comprehensive scan...")
        
        results = {
            'scan_type': 'comprehensive',
            'targets': targets,
            'hosts': {},
            'summary': {}
        }
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=min(len(targets), self.max_threads)) as executor:
            future_to_target = {
                executor.submit(self._comprehensive_host_scan, target): target 
                for target in targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    host_result = future.result(timeout=self.default_timeout)
                    if host_result and host_result.get('state') == 'up':
                        results['hosts'][target] = host_result
                except Exception as e:
                    self.logger.error(f"Comprehensive scan error for {target}: {e}")
        
        results['summary'] = await self._generate_scan_summary(results['hosts'])
        return results
    
    async def _stealth_scan(self, targets: List[str]) -> Dict:
        """Perform stealth scan to avoid detection"""
        self.logger.info("🥷 Performing stealth scan...")
        
        results = {
            'scan_type': 'stealth',
            'targets': targets,
            'hosts': {},
            'summary': {}
        }
        
        # Stealth scanning with randomization and delays
        for target in targets:
            try:
                # Add random delay between scans
                await asyncio.sleep(random.uniform(1, 3))
                
                host_result = await self._stealth_host_scan(target)
                if host_result and host_result.get('open_ports'):
                    results['hosts'][target] = host_result
                    
            except Exception as e:
                self.logger.error(f"Stealth scan error for {target}: {e}")
        
        results['summary'] = await self._generate_scan_summary(results['hosts'])
        return results
    
    async def _aggressive_scan(self, targets: List[str]) -> Dict:
        """Perform aggressive scan with OS detection and scripts"""
        self.logger.info("⚔️ Performing aggressive scan...")
        
        results = {
            'scan_type': 'aggressive',
            'targets': targets,
            'hosts': {},
            'summary': {}
        }
        
        # Aggressive scanning with all features
        for target in targets:
            try:
                host_result = await self._aggressive_host_scan(target)
                if host_result:
                    results['hosts'][target] = host_result
                    
            except Exception as e:
                self.logger.error(f"Aggressive scan error for {target}: {e}")
        
        results['summary'] = await self._generate_scan_summary(results['hosts'])
        return results
    
    def _comprehensive_host_scan(self, target: str) -> Dict:
        """Comprehensive scan of a single host"""
        try:
            if not NMAP_AVAILABLE:
                return self._basic_host_scan(target)
            
            # Nmap comprehensive scan
            arguments = f"-sS -sV -O -A -T{self.timing_template} --version-intensity 9"
            self.nm.scan(target, arguments=arguments)
            
            if target not in self.nm.all_hosts():
                return {'state': 'down', 'reason': 'no-response'}
            
            host_info = self.nm[target]
            
            result = {
                'state': host_info.state(),
                'reason': host_info.get('reason', ''),
                'hostnames': host_info.get('hostnames', []),
                'addresses': host_info.get('addresses', {}),
                'vendor': host_info.get('vendor', {}),
                'os_info': self._extract_os_info(host_info),
                'ports': [],
                'services': [],
                'open_ports': [],
                'vulnerabilities': []
            }
            
            # Process ports and services
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    port_data = {
                        'port': port,
                        'protocol': 'tcp',
                        'state': port_info['state'],
                        'reason': port_info.get('reason', ''),
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'conf': port_info.get('conf', ''),
                        'cpe': port_info.get('cpe', '')
                    }
                    
                    result['ports'].append(port_data)
                    
                    if port_info['state'] == 'open':
                        result['open_ports'].append(port)
                        result['services'].append({
                            'port': port,
                            'name': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Comprehensive host scan error for {target}: {e}")
            return self._basic_host_scan(target)
    
    def _basic_host_scan(self, target: str) -> Dict:
        """Basic host scan without nmap"""
        result = {
            'state': 'unknown',
            'ports': [],
            'services': [],
            'open_ports': [],
            'os_info': {}
        }
        
        try:
            # Check if host is up with ping
            if self._ping_host(target):
                result['state'] = 'up'
                
                # Scan common ports
                common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5900]
                
                for port in common_ports:
                    if self._check_port(target, port):
                        result['open_ports'].append(port)
                        
                        # Try to identify service
                        service_info = self._identify_service(target, port)
                        result['services'].append(service_info)
                        
                        result['ports'].append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': service_info.get('name', ''),
                            'version': service_info.get('version', '')
                        })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Basic host scan error for {target}: {e}")
            return result
    
    def _ping_host(self, target: str) -> bool:
        """Check if host is reachable"""
        try:
            # Use ping command
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', target],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False
    
    def _check_port(self, target: str, port: int, timeout: int = 3) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
            
        except Exception:
            return False
    
    def _identify_service(self, target: str, port: int) -> Dict:
        """Try to identify service on port"""
        service_info = {
            'port': port,
            'name': 'unknown',
            'version': '',
            'banner': ''
        }
        
        try:
            # Common service mappings
            common_services = {
                21: 'ftp',
                22: 'ssh',
                23: 'telnet',
                25: 'smtp',
                53: 'dns',
                80: 'http',
                110: 'pop3',
                135: 'msrpc',
                139: 'netbios-ssn',
                143: 'imap',
                443: 'https',
                993: 'imaps',
                995: 'pop3s',
                3389: 'ms-wbt-server',
                5900: 'vnc'
            }
            
            if port in common_services:
                service_info['name'] = common_services[port]
            
            # Try to grab banner
            banner = self._grab_banner(target, port)
            if banner:
                service_info['banner'] = banner
                
                # Extract version info from banner
                version = self._extract_version_from_banner(banner)
                if version:
                    service_info['version'] = version
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"Service identification error for {target}:{port}: {e}")
            return service_info
    
    def _grab_banner(self, target: str, port: int, timeout: int = 3) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send HTTP request for web servers
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else:
                # For other services, just try to receive
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
            
        except Exception:
            return ""
    
    def _extract_version_from_banner(self, banner: str) -> str:
        """Extract version information from service banner"""
        try:
            # Common version patterns
            patterns = [
                r'(\d+\.\d+\.\d+)',  # x.y.z
                r'(\d+\.\d+)',       # x.y
                r'v(\d+\.\d+\.\d+)', # vx.y.z
                r'version (\d+\.\d+\.\d+)',  # version x.y.z
            ]
            
            for pattern in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    return match.group(1)
            
            return ""
            
        except Exception:
            return ""
    
    async def _stealth_host_scan(self, target: str) -> Dict:
        """Stealth scan of a single host"""
        try:
            if not NMAP_AVAILABLE:
                return self._basic_host_scan(target)
            
            # Stealth SYN scan with timing
            arguments = f"-sS -T1 -f --scan-delay 5s --max-retries 1"
            self.nm.scan(target, arguments=arguments)
            
            if target not in self.nm.all_hosts():
                return None
            
            host_info = self.nm[target]
            
            result = {
                'state': host_info.state(),
                'open_ports': [],
                'services': []
            }
            
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    if port_info['state'] == 'open':
                        result['open_ports'].append(port)
                        result['services'].append({
                            'port': port,
                            'name': port_info.get('name', ''),
                            'state': port_info['state']
                        })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Stealth scan error for {target}: {e}")
            return None
    
    async def _aggressive_host_scan(self, target: str) -> Dict:
        """Aggressive scan with all features"""
        try:
            if not NMAP_AVAILABLE:
                return self._basic_host_scan(target)
            
            # Aggressive scan with scripts and OS detection
            arguments = f"-A -T5 -sS -sV -O --script=vuln,exploit,auth,discovery"
            self.nm.scan(target, arguments=arguments)
            
            if target not in self.nm.all_hosts():
                return None
            
            host_info = self.nm[target]
            
            result = {
                'state': host_info.state(),
                'os_info': self._extract_os_info(host_info),
                'ports': [],
                'services': [],
                'open_ports': [],
                'scripts': {}
            }
            
            # Process TCP ports
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    port_data = {
                        'port': port,
                        'protocol': 'tcp',
                        'state': port_info['state'],
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'scripts': port_info.get('script', {})
                    }
                    
                    result['ports'].append(port_data)
                    
                    if port_info['state'] == 'open':
                        result['open_ports'].append(port)
                        result['services'].append({
                            'port': port,
                            'name': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'scripts': port_info.get('script', {})
                        })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Aggressive scan error for {target}: {e}")
            return None
    
    def _extract_os_info(self, host_info) -> Dict:
        """Extract OS information from nmap results"""
        os_info = {
            'name': 'Unknown',
            'version': '',
            'accuracy': 0,
            'family': '',
            'generation': '',
            'vendor': ''
        }
        
        try:
            if 'osmatch' in host_info:
                os_matches = host_info['osmatch']
                if os_matches:
                    best_match = os_matches[0]
                    os_info.update({
                        'name': best_match.get('name', 'Unknown'),
                        'accuracy': int(best_match.get('accuracy', 0)),
                    })
                    
                    # Parse OS details
                    if 'osclass' in best_match:
                        os_classes = best_match['osclass']
                        if os_classes:
                            best_class = os_classes[0]
                            os_info.update({
                                'family': best_class.get('osfamily', ''),
                                'generation': best_class.get('osgen', ''),
                                'vendor': best_class.get('vendor', '')
                            })
            
            return os_info
            
        except Exception as e:
            self.logger.error(f"OS info extraction error: {e}")
            return os_info
    
    async def _scan_host_ports(self, target: str, ports: str, timeout: int = 10) -> Dict:
        """Scan specific ports on a host"""
        result = {
            'target': target,
            'open_ports': [],
            'services': []
        }
        
        try:
            if NMAP_AVAILABLE:
                self.nm.scan(target, ports, arguments=f"-sS -T{self.timing_template}")
                
                if target in self.nm.all_hosts():
                    host_info = self.nm[target]
                    
                    if 'tcp' in host_info:
                        for port, port_info in host_info['tcp'].items():
                            if port_info['state'] == 'open':
                                result['open_ports'].append(port)
                                result['services'].append({
                                    'port': port,
                                    'name': port_info.get('name', ''),
                                    'version': port_info.get('version', '')
                                })
            else:
                # Fallback to basic scanning
                port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
                for port in port_list:
                    if self._check_port(target, port, timeout=2):
                        result['open_ports'].append(port)
                        service_info = self._identify_service(target, port)
                        result['services'].append(service_info)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Port scan error for {target}: {e}")
            return result
    
    async def _generate_scan_summary(self, hosts: Dict) -> Dict:
        """Generate summary of scan results"""
        summary = {
            'total_hosts': len(hosts),
            'hosts_up': 0,
            'total_open_ports': 0,
            'common_services': {},
            'operating_systems': {},
            'potential_vulnerabilities': 0
        }
        
        try:
            for host, host_data in hosts.items():
                if host_data.get('state') == 'up':
                    summary['hosts_up'] += 1
                
                open_ports = host_data.get('open_ports', [])
                summary['total_open_ports'] += len(open_ports)
                
                # Count services
                services = host_data.get('services', [])
                for service in services:
                    service_name = service.get('name', 'unknown')
                    summary['common_services'][service_name] = summary['common_services'].get(service_name, 0) + 1
                
                # Count OS
                os_info = host_data.get('os_info', {})
                os_name = os_info.get('name', 'Unknown')
                summary['operating_systems'][os_name] = summary['operating_systems'].get(os_name, 0) + 1
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Summary generation error: {e}")
            return summary
    
    def _load_service_patterns(self):
        """Load service detection patterns"""
        self.service_patterns = {
            'ssh': [
                r'SSH-\d+\.\d+',
                r'OpenSSH',
                r'libssh'
            ],
            'http': [
                r'HTTP/\d+\.\d+',
                r'Apache',
                r'nginx',
                r'IIS'
            ],
            'ftp': [
                r'FTP server',
                r'vsftpd',
                r'ProFTPD'
            ],
            'smtp': [
                r'SMTP',
                r'Postfix',
                r'Sendmail'
            ]
        }
    
    async def discover_network(self, network: str) -> List[str]:
        """Discover active hosts in network"""
        try:
            self.logger.info(f"🌐 Discovering hosts in network {network}")
            
            active_hosts = []
            
            if NMAP_AVAILABLE:
                # Use nmap ping scan
                self.nm.scan(hosts=network, arguments='-sn')
                active_hosts = self.nm.all_hosts()
            else:
                # Fallback to ping sweep
                targets = await self._parse_targets(network)
                for target in targets[:50]:  # Limit to prevent overwhelming
                    if self._ping_host(target):
                        active_hosts.append(target)
            
            self.logger.info(f"🎯 Discovered {len(active_hosts)} active hosts")
            return active_hosts
            
        except Exception as e:
            self.logger.error(f"Network discovery error: {e}")
            return []
