# Plugin Development Guide

Complete guide for developing plugins and extensions for the Metasploit-AI framework.

## Table of Contents

1. [Plugin System Overview](#plugin-system-overview)
2. [Plugin Architecture](#plugin-architecture)
3. [Plugin Types](#plugin-types)
4. [Development Environment](#development-environment)
5. [Creating Your First Plugin](#creating-your-first-plugin)
6. [Scanner Plugin Development](#scanner-plugin-development)
7. [AI Model Plugin Development](#ai-model-plugin-development)
8. [Exploit Plugin Development](#exploit-plugin-development)
9. [UI Plugin Development](#ui-plugin-development)
10. [Plugin Configuration](#plugin-configuration)
11. [Testing and Debugging](#testing-and-debugging)
12. [Publishing and Distribution](#publishing-and-distribution)

## Plugin System Overview

The Metasploit-AI framework features a robust plugin architecture that allows developers to extend functionality without modifying core code. Plugins can add new scanning capabilities, AI models, exploitation modules, user interface components, and integration with external tools.

### Key Benefits

- **Modular Architecture**: Clean separation between core framework and extensions
- **Hot-Pluggable**: Load and unload plugins at runtime
- **Type Safety**: Full type hint support for plugin interfaces
- **Event System**: Rich event-driven communication
- **Dependency Injection**: Automatic dependency resolution
- **Configuration Management**: Centralized plugin configuration

### Plugin Lifecycle

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Plugin    │───▶│   Plugin    │───▶│   Plugin    │
│  Discovery  │    │   Loading   │    │Initialization│
└─────────────┘    └─────────────┘    └─────────────┘
        │                  │                  │
        ▼                  ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Plugin    │───▶│   Plugin    │───▶│   Plugin    │
│Registration │    │Validation   │    │  Execution  │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Plugin Architecture

### Base Plugin Interface

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import logging

@dataclass
class PluginMetadata:
    """Plugin metadata information."""
    name: str
    version: str
    description: str
    author: str
    category: str
    dependencies: List[str]
    min_framework_version: str
    max_framework_version: Optional[str] = None
    
class PluginInterface(ABC):
    """Base interface for all Metasploit-AI plugins."""
    
    def __init__(self, metadata: PluginMetadata):
        self.metadata = metadata
        self.logger = logging.getLogger(f"plugin.{metadata.name}")
        self.framework = None
        self.config = {}
        self._initialized = False
    
    @abstractmethod
    def initialize(self, framework: 'Framework', config: Dict[str, Any]) -> bool:
        """Initialize the plugin with framework instance and configuration.
        
        Args:
            framework: The main framework instance
            config: Plugin-specific configuration
            
        Returns:
            True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    def execute(self, context: 'ExecutionContext') -> Any:
        """Execute the main plugin functionality.
        
        Args:
            context: Execution context with parameters and state
            
        Returns:
            Plugin execution result
        """
        pass
    
    def cleanup(self) -> None:
        """Clean up plugin resources before unloading."""
        self.logger.info(f"Cleaning up plugin: {self.metadata.name}")
    
    def get_configuration_schema(self) -> Dict[str, Any]:
        """Return JSON schema for plugin configuration.
        
        Returns:
            JSON schema describing expected configuration format
        """
        return {}
    
    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        """Validate plugin configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid
        """
        return True
    
    @property
    def is_initialized(self) -> bool:
        """Check if plugin is initialized."""
        return self._initialized
```

### Plugin Manager

```python
from typing import Dict, List, Type
import importlib
import inspect
from pathlib import Path

class PluginManager:
    """Manages plugin discovery, loading, and lifecycle."""
    
    def __init__(self, framework: 'Framework'):
        self.framework = framework
        self.plugins: Dict[str, PluginInterface] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        self.plugin_paths: List[Path] = []
        self.logger = logging.getLogger(__name__)
    
    def add_plugin_path(self, path: Path) -> None:
        """Add a path to search for plugins."""
        if path.exists() and path.is_dir():
            self.plugin_paths.append(path)
            self.logger.info(f"Added plugin path: {path}")
    
    def discover_plugins(self) -> List[PluginMetadata]:
        """Discover available plugins in plugin paths.
        
        Returns:
            List of discovered plugin metadata
        """
        discovered = []
        
        for plugin_path in self.plugin_paths:
            for py_file in plugin_path.glob("**/*.py"):
                if py_file.name.startswith("__"):
                    continue
                
                try:
                    plugin_metadata = self._extract_plugin_metadata(py_file)
                    if plugin_metadata:
                        discovered.append(plugin_metadata)
                except Exception as e:
                    self.logger.warning(f"Failed to process {py_file}: {e}")
        
        return discovered
    
    def load_plugin(self, plugin_name: str, config: Dict[str, Any] = None) -> bool:
        """Load and initialize a plugin.
        
        Args:
            plugin_name: Name of the plugin to load
            config: Plugin configuration
            
        Returns:
            True if plugin loaded successfully
        """
        try:
            # Find plugin file
            plugin_file = self._find_plugin_file(plugin_name)
            if not plugin_file:
                self.logger.error(f"Plugin file not found: {plugin_name}")
                return False
            
            # Import plugin module
            module = self._import_plugin_module(plugin_file)
            
            # Find plugin class
            plugin_class = self._find_plugin_class(module)
            if not plugin_class:
                self.logger.error(f"No plugin class found in {plugin_file}")
                return False
            
            # Instantiate plugin
            plugin_instance = plugin_class()
            
            # Validate dependencies
            if not self._validate_dependencies(plugin_instance.metadata):
                return False
            
            # Initialize plugin
            config = config or self.plugin_configs.get(plugin_name, {})
            if plugin_instance.initialize(self.framework, config):
                self.plugins[plugin_name] = plugin_instance
                self.logger.info(f"Successfully loaded plugin: {plugin_name}")
                return True
            else:
                self.logger.error(f"Failed to initialize plugin: {plugin_name}")
                return False
        
        except Exception as e:
            self.logger.error(f"Error loading plugin {plugin_name}: {e}")
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin.
        
        Args:
            plugin_name: Name of the plugin to unload
            
        Returns:
            True if plugin unloaded successfully
        """
        if plugin_name in self.plugins:
            try:
                self.plugins[plugin_name].cleanup()
                del self.plugins[plugin_name]
                self.logger.info(f"Successfully unloaded plugin: {plugin_name}")
                return True
            except Exception as e:
                self.logger.error(f"Error unloading plugin {plugin_name}: {e}")
                return False
        else:
            self.logger.warning(f"Plugin not loaded: {plugin_name}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Get a loaded plugin instance.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin instance or None if not found
        """
        return self.plugins.get(plugin_name)
    
    def list_plugins(self, category: str = None) -> List[str]:
        """List loaded plugins, optionally filtered by category.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of plugin names
        """
        if category:
            return [
                name for name, plugin in self.plugins.items()
                if plugin.metadata.category == category
            ]
        return list(self.plugins.keys())
    
    def execute_plugin(self, plugin_name: str, context: 'ExecutionContext') -> Any:
        """Execute a plugin.
        
        Args:
            plugin_name: Name of the plugin to execute
            context: Execution context
            
        Returns:
            Plugin execution result
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_name}")
        
        if not plugin.is_initialized:
            raise RuntimeError(f"Plugin not initialized: {plugin_name}")
        
        return plugin.execute(context)
```

## Plugin Types

### Scanner Plugins

Scanner plugins extend the framework's scanning capabilities with new discovery and assessment techniques.

```python
from abc import abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class ScanResult:
    """Represents scan results."""
    target: str
    scan_type: str
    hosts_found: List[Dict[str, Any]]
    services_found: List[Dict[str, Any]]
    vulnerabilities_found: List[Dict[str, Any]]
    duration: float
    metadata: Dict[str, Any]

class ScannerPlugin(PluginInterface):
    """Base class for scanner plugins."""
    
    @abstractmethod
    def scan(self, targets: List[str], options: Dict[str, Any]) -> ScanResult:
        """Perform scan on targets.
        
        Args:
            targets: List of targets to scan
            options: Scan configuration options
            
        Returns:
            Scan results
        """
        pass
    
    @abstractmethod
    def get_scan_options(self) -> Dict[str, Any]:
        """Get available scan options and their descriptions.
        
        Returns:
            Dictionary of option name to option metadata
        """
        pass
    
    def supports_target_type(self, target_type: str) -> bool:
        """Check if scanner supports specific target type.
        
        Args:
            target_type: Type of target (ip, hostname, url, etc.)
            
        Returns:
            True if target type is supported
        """
        return True
```

### AI Model Plugins

AI Model plugins add new machine learning capabilities for vulnerability analysis and exploitation.

```python
from abc import abstractmethod
import numpy as np
from typing import Union, Dict, Any, Optional

class AIModelPlugin(PluginInterface):
    """Base class for AI model plugins."""
    
    @abstractmethod
    def load_model(self, model_path: str) -> bool:
        """Load the AI model from file.
        
        Args:
            model_path: Path to model file
            
        Returns:
            True if model loaded successfully
        """
        pass
    
    @abstractmethod
    def predict(self, input_data: Union[np.ndarray, Dict[str, Any]]) -> Any:
        """Make prediction using the loaded model.
        
        Args:
            input_data: Input data for prediction
            
        Returns:
            Model prediction
        """
        pass
    
    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the model.
        
        Returns:
            Model metadata including version, type, capabilities
        """
        pass
    
    def preprocess_data(self, raw_data: Any) -> Any:
        """Preprocess raw data for model input.
        
        Args:
            raw_data: Raw input data
            
        Returns:
            Preprocessed data ready for model
        """
        return raw_data
    
    def postprocess_results(self, raw_results: Any) -> Any:
        """Postprocess model results.
        
        Args:
            raw_results: Raw model output
            
        Returns:
            Processed results
        """
        return raw_results
```

### Exploit Plugins

Exploit plugins provide custom exploitation capabilities beyond the standard Metasploit modules.

```python
from abc import abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

@dataclass
class ExploitResult:
    """Results of exploit execution."""
    success: bool
    session_id: Optional[str]
    output: str
    error: Optional[str]
    metadata: Dict[str, Any]

class ExploitPlugin(PluginInterface):
    """Base class for exploit plugins."""
    
    @abstractmethod
    def check(self, target: str, options: Dict[str, Any]) -> bool:
        """Check if target is vulnerable to this exploit.
        
        Args:
            target: Target to check
            options: Check options
            
        Returns:
            True if target appears vulnerable
        """
        pass
    
    @abstractmethod
    def exploit(self, target: str, options: Dict[str, Any]) -> ExploitResult:
        """Execute exploit against target.
        
        Args:
            target: Target to exploit
            options: Exploit options
            
        Returns:
            Exploit execution results
        """
        pass
    
    @abstractmethod
    def get_exploit_info(self) -> Dict[str, Any]:
        """Get information about the exploit.
        
        Returns:
            Exploit metadata including CVE, description, requirements
        """
        pass
    
    def get_payloads(self) -> List[str]:
        """Get list of compatible payloads.
        
        Returns:
            List of payload names
        """
        return []
    
    def validate_options(self, options: Dict[str, Any]) -> bool:
        """Validate exploit options.
        
        Args:
            options: Options to validate
            
        Returns:
            True if options are valid
        """
        return True
```

## Development Environment

### Setting Up Plugin Development

```bash
# Create plugin development environment
mkdir metasploit-ai-plugins
cd metasploit-ai-plugins

# Create virtual environment
python -m venv plugin-env
source plugin-env/bin/activate  # Linux/macOS
# plugin-env\Scripts\activate  # Windows

# Install development dependencies
pip install metasploit-ai-sdk
pip install pytest pytest-cov
pip install black flake8 mypy
```

### Plugin Project Structure

```
my-awesome-plugin/
├── setup.py
├── README.md
├── requirements.txt
├── my_awesome_plugin/
│   ├── __init__.py
│   ├── plugin.py
│   ├── scanner.py
│   ├── config.yaml
│   └── tests/
│       ├── __init__.py
│       ├── test_plugin.py
│       └── fixtures/
├── docs/
│   ├── README.md
│   └── configuration.md
└── examples/
    └── usage_example.py
```

### Plugin Template

```python
# my_awesome_plugin/plugin.py
from metasploit_ai.plugins import PluginInterface, PluginMetadata
from metasploit_ai.core import Framework, ExecutionContext
from typing import Dict, Any
import logging

# Plugin metadata
METADATA = PluginMetadata(
    name="my_awesome_plugin",
    version="1.0.0",
    description="An awesome plugin that does amazing things",
    author="Your Name <your.email@example.com>",
    category="scanner",  # scanner, ai, exploit, ui, integration
    dependencies=["requests", "beautifulsoup4"],
    min_framework_version="1.0.0"
)

class MyAwesomePlugin(PluginInterface):
    """My awesome plugin implementation."""
    
    def __init__(self):
        super().__init__(METADATA)
    
    def initialize(self, framework: Framework, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        try:
            self.framework = framework
            self.config = config
            
            # Validate configuration
            if not self.validate_configuration(config):
                return False
            
            # Initialize plugin-specific resources
            self._setup_resources()
            
            self._initialized = True
            self.logger.info("Plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    def execute(self, context: ExecutionContext) -> Any:
        """Execute plugin functionality."""
        if not self.is_initialized:
            raise RuntimeError("Plugin not initialized")
        
        self.logger.info("Executing awesome functionality")
        
        # Plugin logic here
        results = self._do_awesome_things(context.params)
        
        return results
    
    def get_configuration_schema(self) -> Dict[str, Any]:
        """Return configuration schema."""
        return {
            "type": "object",
            "properties": {
                "api_key": {
                    "type": "string",
                    "description": "API key for external service"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds",
                    "default": 30
                },
                "enable_cache": {
                    "type": "boolean",
                    "description": "Enable result caching",
                    "default": True
                }
            },
            "required": ["api_key"]
        }
    
    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        """Validate plugin configuration."""
        required_keys = ["api_key"]
        for key in required_keys:
            if key not in config:
                self.logger.error(f"Missing required configuration: {key}")
                return False
        return True
    
    def _setup_resources(self):
        """Set up plugin-specific resources."""
        self.api_key = self.config["api_key"]
        self.timeout = self.config.get("timeout", 30)
        self.enable_cache = self.config.get("enable_cache", True)
    
    def _do_awesome_things(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Implement the core plugin functionality."""
        # Awesome implementation here
        return {"result": "awesome", "params": params}
    
    def cleanup(self):
        """Clean up plugin resources."""
        super().cleanup()
        # Plugin-specific cleanup here

# Plugin factory function
def create_plugin() -> PluginInterface:
    """Factory function to create plugin instance."""
    return MyAwesomePlugin()
```

## Creating Your First Plugin

### Step 1: Define Plugin Metadata

```python
# my_first_plugin/metadata.py
from metasploit_ai.plugins import PluginMetadata

PLUGIN_METADATA = PluginMetadata(
    name="http_header_scanner",
    version="1.0.0",
    description="Scans HTTP headers for security information",
    author="Security Researcher <researcher@example.com>",
    category="scanner",
    dependencies=["requests"],
    min_framework_version="1.0.0"
)
```

### Step 2: Implement Scanner Logic

```python
# my_first_plugin/scanner.py
import requests
from typing import Dict, Any, List
from urllib.parse import urlparse

class HTTPHeaderScanner:
    """Scans HTTP headers for security information."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Metasploit-AI-Scanner/1.0'
        })
    
    def scan_headers(self, url: str) -> Dict[str, Any]:
        """Scan HTTP headers for a given URL."""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            results = {
                'url': url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'security_analysis': self._analyze_security_headers(response.headers),
                'server_info': self._extract_server_info(response.headers)
            }
            
            return results
            
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'error': str(e),
                'headers': {},
                'security_analysis': {},
                'server_info': {}
            }
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security-related headers."""
        security_headers = {
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Referrer-Policy': headers.get('Referrer-Policy')
        }
        
        issues = []
        if not security_headers['Content-Security-Policy']:
            issues.append("Missing Content-Security-Policy header")
        if not security_headers['X-Frame-Options']:
            issues.append("Missing X-Frame-Options header")
        if not security_headers['X-XSS-Protection']:
            issues.append("Missing X-XSS-Protection header")
        
        return {
            'headers': security_headers,
            'issues': issues,
            'score': max(0, 10 - len(issues))
        }
    
    def _extract_server_info(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract server information from headers."""
        return {
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown'),
            'framework': headers.get('X-AspNet-Version', headers.get('X-Django-Version', 'Unknown'))
        }
```

### Step 3: Create Plugin Class

```python
# my_first_plugin/plugin.py
from metasploit_ai.plugins import ScannerPlugin
from metasploit_ai.core import ExecutionContext
from .metadata import PLUGIN_METADATA
from .scanner import HTTPHeaderScanner
from typing import Dict, Any, List

class HTTPHeaderScannerPlugin(ScannerPlugin):
    """HTTP Header Scanner Plugin."""
    
    def __init__(self):
        super().__init__(PLUGIN_METADATA)
        self.scanner = None
    
    def initialize(self, framework, config: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        try:
            self.framework = framework
            self.config = config
            
            timeout = config.get('timeout', 30)
            self.scanner = HTTPHeaderScanner(timeout=timeout)
            
            self._initialized = True
            self.logger.info("HTTP Header Scanner plugin initialized")
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    def scan(self, targets: List[str], options: Dict[str, Any]) -> Any:
        """Perform HTTP header scan on targets."""
        results = []
        
        for target in targets:
            # Ensure target is a valid URL
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            self.logger.info(f"Scanning HTTP headers for: {target}")
            result = self.scanner.scan_headers(target)
            results.append(result)
        
        return {
            'scan_type': 'http_headers',
            'target_count': len(targets),
            'results': results,
            'summary': self._generate_summary(results)
        }
    
    def get_scan_options(self) -> Dict[str, Any]:
        """Get available scan options."""
        return {
            'timeout': {
                'type': 'integer',
                'description': 'Request timeout in seconds',
                'default': 30,
                'min': 1,
                'max': 300
            },
            'follow_redirects': {
                'type': 'boolean',
                'description': 'Follow HTTP redirects',
                'default': True
            },
            'verify_ssl': {
                'type': 'boolean',
                'description': 'Verify SSL certificates',
                'default': False
            }
        }
    
    def supports_target_type(self, target_type: str) -> bool:
        """Check if scanner supports target type."""
        return target_type in ['url', 'hostname', 'ip']
    
    def execute(self, context: ExecutionContext) -> Any:
        """Execute the scanner."""
        targets = context.params.get('targets', [])
        options = context.params.get('options', {})
        return self.scan(targets, options)
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of scan results."""
        total_targets = len(results)
        successful_scans = len([r for r in results if 'error' not in r])
        
        security_scores = [
            r.get('security_analysis', {}).get('score', 0)
            for r in results if 'error' not in r
        ]
        
        avg_security_score = sum(security_scores) / len(security_scores) if security_scores else 0
        
        return {
            'total_targets': total_targets,
            'successful_scans': successful_scans,
            'average_security_score': round(avg_security_score, 2),
            'scan_success_rate': round((successful_scans / total_targets) * 100, 2) if total_targets > 0 else 0
        }

# Plugin factory
def create_plugin() -> ScannerPlugin:
    """Create plugin instance."""
    return HTTPHeaderScannerPlugin()
```

### Step 4: Create Plugin Configuration

```yaml
# my_first_plugin/config.yaml
name: http_header_scanner
enabled: true

configuration:
  timeout: 30
  follow_redirects: true
  verify_ssl: false
  
  # Custom headers to send with requests
  custom_headers:
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    Accept-Language: "en-US,en;q=0.5"
    Cache-Control: "no-cache"

# Security headers to check
security_headers:
  - Content-Security-Policy
  - X-Frame-Options
  - X-XSS-Protection
  - X-Content-Type-Options
  - Strict-Transport-Security
  - Referrer-Policy
  - X-Permitted-Cross-Domain-Policies
  - Feature-Policy
  - Permissions-Policy

# Server fingerprinting headers
fingerprint_headers:
  - Server
  - X-Powered-By
  - X-AspNet-Version
  - X-Django-Version
  - X-Rails-Version
  - X-PHP-Version
```

### Step 5: Write Tests

```python
# my_first_plugin/tests/test_plugin.py
import pytest
from unittest.mock import Mock, patch
from my_first_plugin.plugin import HTTPHeaderScannerPlugin
from my_first_plugin.scanner import HTTPHeaderScanner
from metasploit_ai.core import ExecutionContext

class TestHTTPHeaderScannerPlugin:
    """Test HTTP Header Scanner Plugin."""
    
    @pytest.fixture
    def plugin(self):
        """Create plugin instance for testing."""
        return HTTPHeaderScannerPlugin()
    
    @pytest.fixture
    def mock_framework(self):
        """Create mock framework instance."""
        return Mock()
    
    def test_plugin_initialization(self, plugin, mock_framework):
        """Test plugin initialization."""
        config = {'timeout': 30}
        
        result = plugin.initialize(mock_framework, config)
        
        assert result is True
        assert plugin.is_initialized
        assert plugin.scanner is not None
    
    def test_plugin_initialization_failure(self, plugin, mock_framework):
        """Test plugin initialization failure."""
        config = {}  # Invalid config
        
        with patch.object(plugin, 'validate_configuration', return_value=False):
            result = plugin.initialize(mock_framework, config)
        
        assert result is False
        assert not plugin.is_initialized
    
    @patch('requests.Session.get')
    def test_scan_execution(self, mock_get, plugin, mock_framework):
        """Test scan execution."""
        # Setup
        plugin.initialize(mock_framework, {'timeout': 30})
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx/1.18.0',
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY'
        }
        mock_get.return_value = mock_response
        
        # Execute
        context = ExecutionContext(params={
            'targets': ['https://example.com'],
            'options': {}
        })
        
        result = plugin.execute(context)
        
        # Verify
        assert result['scan_type'] == 'http_headers'
        assert result['target_count'] == 1
        assert len(result['results']) == 1
        assert result['results'][0]['status_code'] == 200
    
    def test_get_scan_options(self, plugin):
        """Test scan options retrieval."""
        options = plugin.get_scan_options()
        
        assert 'timeout' in options
        assert 'follow_redirects' in options
        assert 'verify_ssl' in options
    
    def test_supports_target_type(self, plugin):
        """Test target type support."""
        assert plugin.supports_target_type('url')
        assert plugin.supports_target_type('hostname')
        assert plugin.supports_target_type('ip')
        assert not plugin.supports_target_type('file')

class TestHTTPHeaderScanner:
    """Test HTTP Header Scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return HTTPHeaderScanner(timeout=30)
    
    @patch('requests.Session.get')
    def test_scan_headers_success(self, mock_get, scanner):
        """Test successful header scan."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'Apache/2.4.41',
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'SAMEORIGIN'
        }
        mock_get.return_value = mock_response
        
        result = scanner.scan_headers('https://example.com')
        
        assert result['url'] == 'https://example.com'
        assert result['status_code'] == 200
        assert 'Server' in result['headers']
        assert result['security_analysis']['score'] > 0
    
    @patch('requests.Session.get')
    def test_scan_headers_failure(self, mock_get, scanner):
        """Test header scan with request failure."""
        mock_get.side_effect = requests.exceptions.RequestException("Connection failed")
        
        result = scanner.scan_headers('https://invalid-url.com')
        
        assert 'error' in result
        assert result['headers'] == {}
        assert result['security_analysis'] == {}
```

## Scanner Plugin Development

### Advanced Scanner Features

```python
class AdvancedScannerPlugin(ScannerPlugin):
    """Advanced scanner with parallel execution and caching."""
    
    def __init__(self):
        super().__init__(PLUGIN_METADATA)
        self.thread_pool = None
        self.cache = {}
        
    def initialize(self, framework, config: Dict[str, Any]) -> bool:
        """Initialize with thread pool and caching."""
        super().initialize(framework, config)
        
        from concurrent.futures import ThreadPoolExecutor
        max_workers = config.get('max_workers', 10)
        self.thread_pool = ThreadPoolExecutor(max_workers=max_workers)
        
        # Initialize cache if enabled
        if config.get('enable_cache', True):
            cache_size = config.get('cache_size', 1000)
            from functools import lru_cache
            self._cached_scan = lru_cache(maxsize=cache_size)(self._perform_scan)
        else:
            self._cached_scan = self._perform_scan
            
        return True
    
    def scan(self, targets: List[str], options: Dict[str, Any]) -> Any:
        """Perform parallel scanning with optional caching."""
        from concurrent.futures import as_completed
        import time
        
        start_time = time.time()
        
        # Submit scan tasks to thread pool
        future_to_target = {
            self.thread_pool.submit(self._cached_scan, target, options): target
            for target in targets
        }
        
        results = []
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                self.logger.error(f"Scan failed for {target}: {e}")
                results.append({
                    'target': target,
                    'error': str(e)
                })
        
        duration = time.time() - start_time
        
        return {
            'scan_type': self.metadata.name,
            'targets': targets,
            'results': results,
            'duration': duration,
            'summary': self._generate_summary(results)
        }
    
    def _perform_scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform actual scan on single target."""
        # Implement specific scanning logic here
        pass
    
    def cleanup(self):
        """Clean up thread pool."""
        if self.thread_pool:
            self.thread_pool.shutdown(wait=True)
        super().cleanup()
```

### Progress Tracking

```python
class ProgressTrackingScannerPlugin(ScannerPlugin):
    """Scanner with progress tracking and real-time updates."""
    
    def scan(self, targets: List[str], options: Dict[str, Any]) -> Any:
        """Scan with progress tracking."""
        total_targets = len(targets)
        completed = 0
        results = []
        
        for target in targets:
            # Emit progress event
            self.framework.event_system.emit('scan_progress', {
                'plugin': self.metadata.name,
                'completed': completed,
                'total': total_targets,
                'current_target': target,
                'progress_percent': (completed / total_targets) * 100
            })
            
            # Perform scan
            result = self._scan_target(target, options)
            results.append(result)
            completed += 1
            
            # Emit target completed event
            self.framework.event_system.emit('target_scanned', {
                'plugin': self.metadata.name,
                'target': target,
                'result': result
            })
        
        # Emit completion event
        self.framework.event_system.emit('scan_completed', {
            'plugin': self.metadata.name,
            'total_targets': total_targets,
            'results_count': len(results)
        })
        
        return {
            'scan_type': self.metadata.name,
            'results': results,
            'completed_targets': completed,
            'total_targets': total_targets
        }
```

## AI Model Plugin Development

### Custom AI Model Integration

```python
import numpy as np
from typing import Union, Dict, Any, Optional
import pickle
import joblib

class CustomAIModelPlugin(AIModelPlugin):
    """Custom AI model for vulnerability classification."""
    
    def __init__(self):
        super().__init__(METADATA)
        self.model = None
        self.scaler = None
        self.feature_names = []
        
    def load_model(self, model_path: str) -> bool:
        """Load custom AI model."""
        try:
            # Load the main model
            with open(f"{model_path}/model.pkl", 'rb') as f:
                self.model = pickle.load(f)
            
            # Load feature scaler
            with open(f"{model_path}/scaler.pkl", 'rb') as f:
                self.scaler = pickle.load(f)
            
            # Load feature names
            with open(f"{model_path}/features.txt", 'r') as f:
                self.feature_names = [line.strip() for line in f]
            
            self.logger.info("Custom AI model loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            return False
    
    def predict(self, input_data: Union[np.ndarray, Dict[str, Any]]) -> Dict[str, Any]:
        """Make prediction using the model."""
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        # Preprocess input data
        processed_data = self.preprocess_data(input_data)
        
        # Make prediction
        prediction = self.model.predict(processed_data)
        prediction_proba = self.model.predict_proba(processed_data)
        
        # Postprocess results
        results = self.postprocess_results({
            'prediction': prediction,
            'probabilities': prediction_proba
        })
        
        return results
    
    def preprocess_data(self, raw_data: Union[Dict[str, Any], np.ndarray]) -> np.ndarray:
        """Preprocess data for model input."""
        if isinstance(raw_data, dict):
            # Convert dictionary to feature vector
            features = []
            for feature_name in self.feature_names:
                features.append(raw_data.get(feature_name, 0))
            feature_vector = np.array(features).reshape(1, -1)
        else:
            feature_vector = raw_data
        
        # Apply scaling if scaler is available
        if self.scaler is not None:
            feature_vector = self.scaler.transform(feature_vector)
        
        return feature_vector
    
    def postprocess_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Postprocess model results."""
        prediction = raw_results['prediction'][0]
        probabilities = raw_results['probabilities'][0]
        
        # Map prediction to class names
        class_names = ['low', 'medium', 'high', 'critical']
        predicted_class = class_names[prediction]
        
        # Create confidence scores
        confidence_scores = {
            class_name: float(prob)
            for class_name, prob in zip(class_names, probabilities)
        }
        
        return {
            'predicted_severity': predicted_class,
            'confidence': float(max(probabilities)),
            'class_probabilities': confidence_scores,
            'recommendation': self._generate_recommendation(predicted_class, confidence_scores)
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            'name': 'Custom Vulnerability Classifier',
            'version': '1.0.0',
            'type': 'sklearn_classifier',
            'input_features': len(self.feature_names),
            'output_classes': ['low', 'medium', 'high', 'critical'],
            'feature_names': self.feature_names
        }
    
    def _generate_recommendation(self, predicted_class: str, confidence_scores: Dict[str, float]) -> str:
        """Generate recommendation based on prediction."""
        confidence = max(confidence_scores.values())
        
        if predicted_class in ['high', 'critical'] and confidence > 0.8:
            return "Immediate action required - high confidence vulnerability detected"
        elif predicted_class in ['medium', 'high'] and confidence > 0.6:
            return "Investigation recommended - potential security issue"
        else:
            return "Low priority - monitor for changes"
```

### TensorFlow/Keras Model Plugin

```python
import tensorflow as tf
from tensorflow import keras
import numpy as np

class TensorFlowModelPlugin(AIModelPlugin):
    """TensorFlow/Keras model plugin."""
    
    def __init__(self):
        super().__init__(METADATA)
        self.model = None
        self.input_shape = None
        
    def load_model(self, model_path: str) -> bool:
        """Load TensorFlow model."""
        try:
            self.model = keras.models.load_model(model_path)
            self.input_shape = self.model.input_shape
            
            self.logger.info(f"TensorFlow model loaded: {model_path}")
            self.logger.info(f"Input shape: {self.input_shape}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load TensorFlow model: {e}")
            return False
    
    def predict(self, input_data: Union[np.ndarray, Dict[str, Any]]) -> Dict[str, Any]:
        """Make prediction using TensorFlow model."""
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        # Preprocess input
        processed_input = self.preprocess_data(input_data)
        
        # Make prediction
        prediction = self.model.predict(processed_input)
        
        return self.postprocess_results(prediction)
    
    def preprocess_data(self, raw_data: Union[Dict[str, Any], np.ndarray]) -> np.ndarray:
        """Preprocess data for TensorFlow model."""
        if isinstance(raw_data, dict):
            # Convert dict to numpy array based on expected input shape
            features = self._extract_features_from_dict(raw_data)
            processed_data = np.array(features).reshape(1, -1)
        else:
            processed_data = raw_data
        
        # Ensure correct shape
        if len(processed_data.shape) == 1:
            processed_data = processed_data.reshape(1, -1)
        
        return processed_data.astype(np.float32)
    
    def postprocess_results(self, raw_results: np.ndarray) -> Dict[str, Any]:
        """Postprocess TensorFlow model results."""
        # Assuming classification output
        probabilities = raw_results[0]
        predicted_class = np.argmax(probabilities)
        confidence = float(np.max(probabilities))
        
        return {
            'predicted_class': int(predicted_class),
            'confidence': confidence,
            'probabilities': probabilities.tolist(),
            'interpretation': self._interpret_results(predicted_class, confidence)
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get TensorFlow model information."""
        if self.model is None:
            return {}
        
        return {
            'name': 'TensorFlow Neural Network',
            'framework': 'TensorFlow/Keras',
            'input_shape': self.input_shape,
            'output_shape': self.model.output_shape,
            'parameters': self.model.count_params(),
            'layers': len(self.model.layers),
            'optimizer': self.model.optimizer.__class__.__name__ if self.model.optimizer else None
        }
```

## Testing and Debugging

### Plugin Testing Framework

```python
# plugin_test_framework.py
import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, Type
from metasploit_ai.plugins import PluginInterface
from metasploit_ai.core import Framework, ExecutionContext

class PluginTestFramework:
    """Testing framework for plugins."""
    
    @staticmethod
    def create_mock_framework() -> Mock:
        """Create a mock framework for testing."""
        framework = Mock(spec=Framework)
        framework.event_system = Mock()
        framework.database = Mock()
        framework.config = {}
        return framework
    
    @staticmethod
    def create_execution_context(params: Dict[str, Any] = None) -> ExecutionContext:
        """Create an execution context for testing."""
        return ExecutionContext(params=params or {})
    
    @staticmethod
    def test_plugin_lifecycle(plugin_class: Type[PluginInterface], config: Dict[str, Any] = None):
        """Test complete plugin lifecycle."""
        # Create plugin instance
        plugin = plugin_class()
        
        # Test initialization
        framework = PluginTestFramework.create_mock_framework()
        config = config or {}
        
        assert plugin.initialize(framework, config) is True
        assert plugin.is_initialized is True
        
        # Test execution
        context = PluginTestFramework.create_execution_context({'test': 'data'})
        result = plugin.execute(context)
        assert result is not None
        
        # Test cleanup
        plugin.cleanup()
        
        return plugin, result

# Example test using the framework
class TestMyPlugin:
    """Test my plugin using the test framework."""
    
    def test_plugin_lifecycle(self):
        """Test complete plugin lifecycle."""
        config = {'api_key': 'test_key', 'timeout': 30}
        plugin, result = PluginTestFramework.test_plugin_lifecycle(MyAwesomePlugin, config)
        
        assert isinstance(result, dict)
        assert 'result' in result
```

### Debugging Techniques

```python
class DebuggablePlugin(PluginInterface):
    """Plugin with enhanced debugging capabilities."""
    
    def __init__(self):
        super().__init__(METADATA)
        self.debug_enabled = False
        self.debug_data = {}
    
    def initialize(self, framework, config: Dict[str, Any]) -> bool:
        """Initialize with debug mode."""
        self.debug_enabled = config.get('debug', False)
        
        if self.debug_enabled:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug("Debug mode enabled")
        
        return super().initialize(framework, config)
    
    def execute(self, context: ExecutionContext) -> Any:
        """Execute with debug information collection."""
        if self.debug_enabled:
            self.debug_data['execution_start'] = time.time()
            self.debug_data['input_params'] = context.params.copy()
        
        try:
            result = self._execute_internal(context)
            
            if self.debug_enabled:
                self.debug_data['execution_success'] = True
                self.debug_data['result_type'] = type(result).__name__
                self.debug_data['execution_end'] = time.time()
                self.debug_data['execution_duration'] = (
                    self.debug_data['execution_end'] - self.debug_data['execution_start']
                )
            
            return result
            
        except Exception as e:
            if self.debug_enabled:
                self.debug_data['execution_success'] = False
                self.debug_data['error'] = str(e)
                self.debug_data['error_type'] = type(e).__name__
                
                # Log detailed debug information
                self.logger.debug(f"Plugin execution failed: {e}")
                self.logger.debug(f"Debug data: {self.debug_data}")
            
            raise
    
    def get_debug_info(self) -> Dict[str, Any]:
        """Get debug information."""
        return self.debug_data.copy() if self.debug_enabled else {}
```

## Publishing and Distribution

### Plugin Package Structure

```python
# setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="metasploit-ai-http-scanner",
    version="1.0.0",
    author="Security Researcher",
    author_email="researcher@example.com",
    description="HTTP header security scanner plugin for Metasploit-AI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/researcher/metasploit-ai-http-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "metasploit_ai.plugins": [
            "http_scanner = my_plugin.plugin:create_plugin",
        ],
    },
    include_package_data=True,
    package_data={
        "my_plugin": ["config.yaml", "*.txt"],
    },
)
```

### Plugin Registry

```python
# plugin_registry.py
class PluginRegistry:
    """Central registry for Metasploit-AI plugins."""
    
    def __init__(self):
        self.plugins = {}
        self.categories = {
            'scanner': [],
            'ai': [],
            'exploit': [],
            'ui': [],
            'integration': []
        }
    
    def register_plugin(self, plugin_info: Dict[str, Any]) -> bool:
        """Register a plugin in the registry."""
        name = plugin_info['name']
        category = plugin_info['category']
        
        if name in self.plugins:
            return False  # Plugin already registered
        
        self.plugins[name] = plugin_info
        if category in self.categories:
            self.categories[category].append(name)
        
        return True
    
    def search_plugins(self, query: str = None, category: str = None) -> List[Dict[str, Any]]:
        """Search for plugins by name or category."""
        results = []
        
        for name, info in self.plugins.items():
            # Category filter
            if category and info.get('category') != category:
                continue
            
            # Text search
            if query:
                if query.lower() not in name.lower() and query.lower() not in info.get('description', '').lower():
                    continue
            
            results.append(info)
        
        return results
    
    def get_plugin_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a plugin."""
        return self.plugins.get(name)
```

### Installation Guide

```bash
# Install plugin from PyPI
pip install metasploit-ai-http-scanner

# Install plugin from Git repository
pip install git+https://github.com/researcher/metasploit-ai-http-scanner.git

# Install plugin in development mode
git clone https://github.com/researcher/metasploit-ai-http-scanner.git
cd metasploit-ai-http-scanner
pip install -e .

# Enable plugin in Metasploit-AI
metasploit-ai plugin enable http_scanner

# Configure plugin
metasploit-ai plugin configure http_scanner --config-file http_scanner_config.yaml

# Test plugin
metasploit-ai plugin test http_scanner
```

---

*This plugin development guide is part of the Metasploit-AI documentation suite. For more information, see the [Development Guide](development.md) or visit the [project repository](https://github.com/yashab-cyber/metasploit-ai).*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
