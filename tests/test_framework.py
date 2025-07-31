"""
Unit Tests for Core Framework
Tests the main framework functionality
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from src.core.framework import MetasploitAIFramework
from src.core.config import Config

class TestMetasploitAIFramework:
    """Test cases for the main framework"""
    
    @pytest.fixture
    def framework(self, mock_config):
        """Create framework instance for testing"""
        with patch('src.core.config.Config.load') as mock_load:
            mock_load.return_value = mock_config
            config = Config()
            return MetasploitAIFramework(config)
    
    def test_framework_initialization(self, framework):
        """Test framework initializes correctly"""
        assert framework is not None
        assert framework.config is not None
        assert framework.database is not None
        assert framework.ai_analyzer is not None
    
    @pytest.mark.asyncio
    async def test_initialize_framework(self, framework):
        """Test framework initialization process"""
        with patch.object(framework.database, 'initialize', new_callable=AsyncMock) as mock_db_init:
            mock_db_init.return_value = True
            
            result = await framework.initialize()
            assert result is True
            mock_db_init.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_start_services(self, framework):
        """Test starting framework services"""
        with patch.object(framework.metasploit_client, 'connect', new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = True
            
            result = await framework.start_services()
            assert result is True
            mock_connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_run_scan(self, framework, sample_scan_results):
        """Test network scanning functionality"""
        target = "192.168.1.100"
        
        with patch.object(framework.scanner, 'scan_host', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = sample_scan_results
            
            result = await framework.run_scan(target)
            assert result is not None
            assert result['target'] == target
            mock_scan.assert_called_once_with(target)
    
    @pytest.mark.asyncio 
    async def test_analyze_vulnerabilities(self, framework, sample_vulnerability_data):
        """Test vulnerability analysis"""
        vulnerabilities = [sample_vulnerability_data]
        
        with patch.object(framework.ai_analyzer, 'analyze_vulnerability', new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = {
                'severity': 'HIGH',
                'exploitability': 0.8,
                'recommendations': ['Apply security patches']
            }
            
            results = await framework.analyze_vulnerabilities(vulnerabilities)
            assert len(results) == 1
            assert results[0]['severity'] == 'HIGH'
            mock_analyze.assert_called_once()
    
    def test_get_status(self, framework):
        """Test framework status reporting"""
        status = framework.get_status()
        assert 'framework' in status
        assert 'services' in status
        assert 'statistics' in status
    
    @pytest.mark.asyncio
    async def test_shutdown(self, framework):
        """Test framework shutdown process"""
        with patch.object(framework.metasploit_client, 'disconnect', new_callable=AsyncMock) as mock_disconnect:
            mock_disconnect.return_value = True
            
            await framework.shutdown()
            mock_disconnect.assert_called_once()

class TestFrameworkIntegration:
    """Integration tests for framework components"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self, framework, sample_scan_results, sample_vulnerability_data):
        """Test complete scan and analysis workflow"""
        target = "192.168.1.100"
        
        # Mock all external dependencies
        with patch.object(framework.scanner, 'scan_host', new_callable=AsyncMock) as mock_scan, \
             patch.object(framework.ai_analyzer, 'analyze_vulnerability', new_callable=AsyncMock) as mock_analyze, \
             patch.object(framework.database, 'save_scan_results', new_callable=AsyncMock) as mock_save:
            
            mock_scan.return_value = sample_scan_results
            mock_analyze.return_value = {
                'severity': 'MEDIUM',
                'exploitability': 0.6,
                'recommendations': ['Update software']
            }
            mock_save.return_value = True
            
            # Run full workflow
            await framework.initialize()
            scan_results = await framework.run_scan(target)
            analysis_results = await framework.analyze_vulnerabilities([sample_vulnerability_data])
            
            # Verify results
            assert scan_results['target'] == target
            assert len(analysis_results) == 1
            assert analysis_results[0]['severity'] == 'MEDIUM'
            
            # Verify all mocks were called
            mock_scan.assert_called_once()
            mock_analyze.assert_called_once()
    
    @pytest.mark.integration
    def test_configuration_loading(self, mock_config):
        """Test configuration loading and validation"""
        with patch('src.core.config.Config.load') as mock_load:
            mock_load.return_value = mock_config
            
            config = Config()
            framework = MetasploitAIFramework(config)
            
            assert framework.config is not None
            assert hasattr(framework.config, 'database')
            assert hasattr(framework.config, 'metasploit')

if __name__ == "__main__":
    pytest.main([__file__])
