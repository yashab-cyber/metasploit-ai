"""
Metasploit Client Module
Provides interface to Metasploit Framework RPC API
"""

import asyncio
import socket
import json
import ssl
from typing import Dict, List, Optional, Any
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError
import time

from ..utils.logger import get_logger

class MetasploitClient:
    """Advanced Metasploit Framework client with AI integration"""
    
    def __init__(self, config):
        """Initialize Metasploit client"""
        self.config = config
        self.logger = get_logger(__name__)
        self.client = None
        self.connected = False
        self.sessions = {}
        
    async def connect(self) -> bool:
        """Connect to Metasploit RPC server"""
        try:
            self.logger.info(f"🔌 Connecting to Metasploit at {self.config.host}:{self.config.port}")
            
            # Create RPC client
            self.client = MsfRpcClient(
                password=self.config.password,
                server=self.config.host,
                port=self.config.port,
                ssl=self.config.ssl,
                username=self.config.username
            )
            
            # Test connection
            version = self.client.core.version()
            self.connected = True
            
            self.logger.info(f"✅ Connected to Metasploit Framework {version}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to connect to Metasploit: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from Metasploit"""
        if self.client and self.connected:
            try:
                # Clean up sessions
                await self.cleanup_sessions()
                self.client = None
                self.connected = False
                self.logger.info("🔌 Disconnected from Metasploit")
            except Exception as e:
                self.logger.error(f"Error during disconnect: {e}")
    
    def is_connected(self) -> bool:
        """Check if connected to Metasploit"""
        return self.connected and self.client is not None
    
    async def get_exploits(self) -> List[Dict]:
        """Get list of available exploits"""
        if not self.is_connected():
            raise Exception("Not connected to Metasploit")
        
        try:
            exploits = []
            modules = self.client.modules.exploits
            
            for module_name in modules:
                module_info = self.client.modules.use('exploit', module_name)
                exploit_info = {
                    'name': module_name,
                    'description': module_info.description,
                    'targets': getattr(module_info, 'targets', []),
                    'references': getattr(module_info, 'references', []),
                    'rank': getattr(module_info, 'rank', 'Unknown'),
                    'platform': getattr(module_info, 'platform', []),
                    'required_options': self._get_required_options(module_info)
                }
                exploits.append(exploit_info)
            
            return exploits
            
        except Exception as e:
            self.logger.error(f"Failed to get exploits: {e}")
            return []
    
    async def get_payloads(self) -> List[Dict]:
        """Get list of available payloads"""
        if not self.is_connected():
            raise Exception("Not connected to Metasploit")
        
        try:
            payloads = []
            modules = self.client.modules.payloads
            
            for payload_name in modules:
                payload_info = self.client.modules.use('payload', payload_name)
                payload_data = {
                    'name': payload_name,
                    'description': payload_info.description,
                    'platform': getattr(payload_info, 'platform', []),
                    'arch': getattr(payload_info, 'arch', []),
                    'size': getattr(payload_info, 'size', 0),
                    'required_options': self._get_required_options(payload_info)
                }
                payloads.append(payload_data)
            
            return payloads
            
        except Exception as e:
            self.logger.error(f"Failed to get payloads: {e}")
            return []
    
    async def get_module_info(self, module_name: str, module_type: str = 'exploit') -> Optional[Dict]:
        """Get detailed information about a module"""
        if not self.is_connected():
            return None
        
        try:
            module = self.client.modules.use(module_type, module_name)
            if not module:
                return None
            
            return {
                'name': module_name,
                'type': module_type,
                'description': module.description,
                'author': getattr(module, 'author', []),
                'references': getattr(module, 'references', []),
                'targets': getattr(module, 'targets', []),
                'platform': getattr(module, 'platform', []),
                'arch': getattr(module, 'arch', []),
                'rank': getattr(module, 'rank', 'Unknown'),
                'disclosure_date': getattr(module, 'disclosure_date', ''),
                'required_options': self._get_required_options(module),
                'optional_options': self._get_optional_options(module)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get module info for {module_name}: {e}")
            return None
    
    async def execute_exploit(self, exploit_name: str, target: str, 
                            payload_name: str, options: Dict = None) -> Dict:
        """Execute an exploit"""
        if not self.is_connected():
            raise Exception("Not connected to Metasploit")
        
        try:
            self.logger.info(f"💥 Executing {exploit_name} against {target}")
            
            # Load exploit module
            exploit = self.client.modules.use('exploit', exploit_name)
            if not exploit:
                raise Exception(f"Exploit {exploit_name} not found")
            
            # Set target
            exploit['RHOSTS'] = target
            
            # Set payload
            exploit.payload = payload_name
            
            # Apply additional options
            if options:
                for key, value in options.items():
                    exploit[key] = value
            
            # Execute exploit
            result = exploit.execute()
            
            # Check for session creation
            session_info = None
            if hasattr(result, 'uuid') and result.uuid:
                sessions = self.client.sessions.list
                if sessions:
                    session_id = list(sessions.keys())[-1]  # Get latest session
                    session_info = {
                        'id': session_id,
                        'uuid': result.uuid,
                        'info': sessions[session_id]
                    }
                    self.sessions[session_id] = session_info
            
            exploit_result = {
                'success': result.uuid is not None if hasattr(result, 'uuid') else False,
                'job_id': getattr(result, 'job_id', None),
                'uuid': getattr(result, 'uuid', None),
                'session': session_info,
                'output': str(result) if result else '',
                'timestamp': time.time()
            }
            
            self.logger.info(f"🎯 Exploit {'succeeded' if exploit_result['success'] else 'failed'}")
            return exploit_result
            
        except Exception as e:
            self.logger.error(f"❌ Exploit execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            }
    
    async def get_sessions(self) -> Dict:
        """Get active sessions"""
        if not self.is_connected():
            return {}
        
        try:
            sessions = self.client.sessions.list
            return sessions
        except Exception as e:
            self.logger.error(f"Failed to get sessions: {e}")
            return {}
    
    async def execute_session_command(self, session_id: str, command: str) -> str:
        """Execute command in a session"""
        if not self.is_connected():
            raise Exception("Not connected to Metasploit")
        
        try:
            session = self.client.sessions.session(session_id)
            if not session:
                raise Exception(f"Session {session_id} not found")
            
            result = session.write(command)
            output = session.read()
            
            return output
            
        except Exception as e:
            self.logger.error(f"Failed to execute command in session {session_id}: {e}")
            raise
    
    async def search_modules(self, query: str, module_type: str = None) -> List[Dict]:
        """Search for modules"""
        if not self.is_connected():
            return []
        
        try:
            search_results = []
            
            # Search exploits
            if not module_type or module_type == 'exploit':
                for module_name in self.client.modules.exploits:
                    if query.lower() in module_name.lower():
                        module_info = await self.get_module_info(module_name, 'exploit')
                        if module_info:
                            search_results.append(module_info)
            
            # Search payloads
            if not module_type or module_type == 'payload':
                for module_name in self.client.modules.payloads:
                    if query.lower() in module_name.lower():
                        module_info = await self.get_module_info(module_name, 'payload')
                        if module_info:
                            search_results.append(module_info)
            
            # Search auxiliaries
            if not module_type or module_type == 'auxiliary':
                for module_name in self.client.modules.auxiliary:
                    if query.lower() in module_name.lower():
                        module_info = await self.get_module_info(module_name, 'auxiliary')
                        if module_info:
                            search_results.append(module_info)
            
            return search_results
            
        except Exception as e:
            self.logger.error(f"Failed to search modules: {e}")
            return []
    
    async def get_compatible_payloads(self, exploit_name: str) -> List[str]:
        """Get compatible payloads for an exploit"""
        if not self.is_connected():
            return []
        
        try:
            exploit = self.client.modules.use('exploit', exploit_name)
            if not exploit:
                return []
            
            compatible_payloads = exploit.compatible_payloads
            return list(compatible_payloads) if compatible_payloads else []
            
        except Exception as e:
            self.logger.error(f"Failed to get compatible payloads: {e}")
            return []
    
    async def cleanup_sessions(self):
        """Clean up all active sessions"""
        try:
            sessions = await self.get_sessions()
            for session_id in sessions:
                try:
                    session = self.client.sessions.session(session_id)
                    session.stop()
                except:
                    pass
            self.sessions.clear()
            self.logger.info("🧹 Cleaned up active sessions")
        except Exception as e:
            self.logger.error(f"Failed to cleanup sessions: {e}")
    
    def _get_required_options(self, module) -> List[str]:
        """Get required options for a module"""
        try:
            required = []
            if hasattr(module, 'required'):
                required = list(module.required)
            elif hasattr(module, 'options'):
                for option_name, option_data in module.options.items():
                    if option_data.get('required', False):
                        required.append(option_name)
            return required
        except:
            return []
    
    def _get_optional_options(self, module) -> List[str]:
        """Get optional options for a module"""
        try:
            optional = []
            if hasattr(module, 'options'):
                for option_name, option_data in module.options.items():
                    if not option_data.get('required', False):
                        optional.append(option_name)
            return optional
        except:
            return []
