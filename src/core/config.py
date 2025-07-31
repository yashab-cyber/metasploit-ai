"""
Configuration Management Module
Handles loading and managing framework configuration
"""

import yaml
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class MetasploitConfig:
    """Metasploit connection configuration"""
    host: str = "127.0.0.1"
    port: int = 55553
    username: str = "msf"
    password: str = "msf"
    ssl: bool = False
    timeout: int = 30

@dataclass
class AIConfig:
    """AI/ML configuration"""
    enabled: bool = True
    models_path: str = "data/models"
    openai_api_key: str = ""
    tensorflow_models: Dict[str, str] = field(default_factory=dict)
    pytorch_models: Dict[str, str] = field(default_factory=dict)
    model_cache_size: int = 1024  # MB
    
@dataclass
class DatabaseConfig:
    """Database configuration"""
    type: str = "sqlite"
    path: str = "data/metasploit_ai.db"
    host: str = "localhost"
    port: int = 5432
    username: str = ""
    password: str = ""
    database: str = "metasploit_ai"

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: str = "logs/metasploit_ai.log"
    max_size: str = "10MB"
    backup_count: int = 5
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

@dataclass
class WebConfig:
    """Web interface configuration"""
    host: str = "127.0.0.1"
    port: int = 8080
    secret_key: str = "change-this-secret-key"
    session_timeout: int = 3600  # seconds
    max_upload_size: int = 16  # MB

@dataclass
class SecurityConfig:
    """Security configuration"""
    api_key_required: bool = True
    rate_limit: int = 100  # requests per minute
    max_concurrent_scans: int = 5
    allowed_networks: list = field(default_factory=lambda: ["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"])
    encryption_key: str = ""

@dataclass
class ScanConfig:
    """Scanning configuration"""
    default_timeout: int = 300  # seconds
    max_threads: int = 50
    default_ports: str = "1-1000"
    timing_template: int = 4  # nmap timing (0-5)
    stealth_mode: bool = False

@dataclass
class ExploitConfig:
    """Exploit configuration"""
    auto_execute: bool = False
    confidence_threshold: float = 0.8
    max_concurrent_exploits: int = 3
    payload_timeout: int = 60
    session_timeout: int = 300

class Config:
    """Main configuration class"""
    
    def __init__(self):
        self.framework = {
            'name': 'Metasploit-AI',
            'version': '1.0.0',
            'debug': False
        }
        self.metasploit = MetasploitConfig()
        self.ai = AIConfig()
        self.database = DatabaseConfig()
        self.logging = LoggingConfig()
        self.web = WebConfig()
        self.security = SecurityConfig()
        self.scan = ScanConfig()
        self.exploit = ExploitConfig()
        
        # Additional configurations
        self.modules_path = "modules"
        self.data_path = "data"
        self.reports_path = "data/reports"
        
    @classmethod
    def load_config(cls, config_path: str = "config/default.yaml") -> 'Config':
        """Load configuration from YAML file"""
        config = cls()
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                
                config._update_from_dict(yaml_config)
                
            except Exception as e:
                print(f"Warning: Failed to load config from {config_path}: {e}")
                print("Using default configuration")
        else:
            print(f"Config file {config_path} not found, using defaults")
        
        # Override with environment variables
        config._load_from_env()
        
        return config
    
    def _update_from_dict(self, data: Dict[str, Any]):
        """Update configuration from dictionary"""
        if 'framework' in data:
            self.framework.update(data['framework'])
        
        if 'metasploit' in data:
            self._update_dataclass(self.metasploit, data['metasploit'])
        
        if 'ai' in data:
            self._update_dataclass(self.ai, data['ai'])
        
        if 'database' in data:
            self._update_dataclass(self.database, data['database'])
        
        if 'logging' in data:
            self._update_dataclass(self.logging, data['logging'])
        
        if 'web' in data:
            self._update_dataclass(self.web, data['web'])
        
        if 'security' in data:
            self._update_dataclass(self.security, data['security'])
        
        if 'scan' in data:
            self._update_dataclass(self.scan, data['scan'])
        
        if 'exploit' in data:
            self._update_dataclass(self.exploit, data['exploit'])
    
    def _update_dataclass(self, obj, data: Dict[str, Any]):
        """Update dataclass instance from dictionary"""
        for key, value in data.items():
            if hasattr(obj, key):
                setattr(obj, key, value)
    
    def _load_from_env(self):
        """Load configuration from environment variables"""
        # Metasploit settings
        if os.getenv('MSF_HOST'):
            self.metasploit.host = os.getenv('MSF_HOST')
        if os.getenv('MSF_PORT'):
            self.metasploit.port = int(os.getenv('MSF_PORT'))
        if os.getenv('MSF_USERNAME'):
            self.metasploit.username = os.getenv('MSF_USERNAME')
        if os.getenv('MSF_PASSWORD'):
            self.metasploit.password = os.getenv('MSF_PASSWORD')
        
        # AI settings
        if os.getenv('OPENAI_API_KEY'):
            self.ai.openai_api_key = os.getenv('OPENAI_API_KEY')
        
        # Web settings
        if os.getenv('WEB_HOST'):
            self.web.host = os.getenv('WEB_HOST')
        if os.getenv('WEB_PORT'):
            self.web.port = int(os.getenv('WEB_PORT'))
        if os.getenv('SECRET_KEY'):
            self.web.secret_key = os.getenv('SECRET_KEY')
        
        # Debug mode
        if os.getenv('DEBUG'):
            self.framework['debug'] = os.getenv('DEBUG').lower() == 'true'
    
    def save_config(self, config_path: str = "config/current.yaml"):
        """Save current configuration to YAML file"""
        config_data = {
            'framework': self.framework,
            'metasploit': self._dataclass_to_dict(self.metasploit),
            'ai': self._dataclass_to_dict(self.ai),
            'database': self._dataclass_to_dict(self.database),
            'logging': self._dataclass_to_dict(self.logging),
            'web': self._dataclass_to_dict(self.web),
            'security': self._dataclass_to_dict(self.security),
            'scan': self._dataclass_to_dict(self.scan),
            'exploit': self._dataclass_to_dict(self.exploit)
        }
        
        # Ensure config directory exists
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)
    
    def _dataclass_to_dict(self, obj) -> Dict[str, Any]:
        """Convert dataclass to dictionary"""
        return {
            field.name: getattr(obj, field.name) 
            for field in obj.__dataclass_fields__.values()
        }
    
    def validate(self) -> bool:
        """Validate configuration"""
        errors = []
        
        # Validate paths exist
        required_paths = [self.modules_path, self.data_path]
        for path in required_paths:
            if not os.path.exists(path):
                try:
                    os.makedirs(path, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create path {path}: {e}")
        
        # Validate network settings
        if not (1 <= self.metasploit.port <= 65535):
            errors.append("Metasploit port must be between 1 and 65535")
        
        if not (1 <= self.web.port <= 65535):
            errors.append("Web port must be between 1 and 65535")
        
        # Validate security settings
        if self.security.rate_limit <= 0:
            errors.append("Rate limit must be positive")
        
        if self.security.max_concurrent_scans <= 0:
            errors.append("Max concurrent scans must be positive")
        
        # Validate AI settings
        if self.ai.enabled and not self.ai.models_path:
            errors.append("AI models path is required when AI is enabled")
        
        if errors:
            print("Configuration validation errors:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        return True
    
    def get_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        return {
            'framework': self.framework,
            'metasploit_host': f"{self.metasploit.host}:{self.metasploit.port}",
            'web_interface': f"{self.web.host}:{self.web.port}",
            'ai_enabled': self.ai.enabled,
            'database_type': self.database.type,
            'debug_mode': self.framework.get('debug', False)
        }
