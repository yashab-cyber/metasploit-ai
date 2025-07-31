"""
Test Configuration for Metasploit-AI Framework
Provides test utilities and configurations for the test suite
"""

import os
import tempfile
import pytest
from unittest.mock import Mock
from pathlib import Path

# Test configuration
TEST_CONFIG = {
    'database': {
        'type': 'sqlite',
        'path': ':memory:',  # In-memory database for tests
    },
    'logging': {
        'level': 'ERROR',  # Reduce noise during tests
        'console': {'enabled': False},
        'file': {'enabled': False}
    },
    'metasploit': {
        'rpc': {
            'host': '127.0.0.1',
            'port': 55553,
            'username': 'test',
            'password': 'test'
        }
    },
    'scan': {
        'max_threads': 2,
        'default_timeout': 1
    }
}

class MockMetasploitClient:
    """Mock Metasploit client for testing"""
    
    def __init__(self):
        self.connected = False
        self.sessions = {}
        self.modules = {
            'exploits': ['exploit/windows/smb/ms17_010_eternalblue'],
            'payloads': ['windows/x64/meterpreter/reverse_tcp'],
            'auxiliary': ['scanner/portscan/tcp']
        }
    
    async def connect(self):
        """Mock connection"""
        self.connected = True
        return True
    
    async def disconnect(self):
        """Mock disconnection"""
        self.connected = False
    
    async def execute_module(self, module_type, module_name, options=None):
        """Mock module execution"""
        return {
            'job_id': 123,
            'status': 'success',
            'output': f'Executed {module_type}/{module_name}'
        }
    
    async def get_exploits(self):
        """Mock exploit listing"""
        return self.modules['exploits']
    
    async def get_payloads(self):
        """Mock payload listing"""
        return self.modules['payloads']

@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def mock_config():
    """Provide test configuration"""
    return TEST_CONFIG

@pytest.fixture
def mock_metasploit_client():
    """Provide mock Metasploit client"""
    return MockMetasploitClient()

@pytest.fixture
def sample_vulnerability_data():
    """Sample vulnerability data for testing"""
    return {
        'cve_id': 'CVE-2017-0144',
        'description': 'SMB vulnerability allowing remote code execution',
        'cvss_score': 8.1,
        'affected_systems': ['Windows 7', 'Windows Server 2008'],
        'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144']
    }

@pytest.fixture
def sample_scan_results():
    """Sample network scan results"""
    return {
        'target': '192.168.1.100',
        'status': 'up',
        'ports': [
            {'port': 22, 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 7.4'},
            {'port': 80, 'state': 'open', 'service': 'http', 'version': 'Apache 2.4.6'},
            {'port': 443, 'state': 'open', 'service': 'https', 'version': 'Apache 2.4.6'}
        ],
        'os': 'Linux 3.X',
        'scan_time': '2025-07-31T12:00:00Z'
    }

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "ai: mark test as AI/ML related"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
