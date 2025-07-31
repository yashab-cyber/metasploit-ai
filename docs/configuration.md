# Configuration Guide

Comprehensive guide to configuring the Metasploit-AI Framework for optimal performance and security.

## Configuration Overview

Metasploit-AI uses YAML configuration files to manage framework settings, AI model parameters, database connections, and security options.

### Configuration Files

```
config/
├── default.yaml          # Default configuration template
├── development.yaml      # Development environment settings
├── production.yaml       # Production environment settings
├── config.yaml          # User configuration (created from default)
└── secrets.yaml         # Sensitive configuration (not in version control)
```

## Basic Configuration

### Initial Setup

1. **Copy Default Configuration**
```bash
cp config/default.yaml config/config.yaml
```

2. **Edit Configuration**
```bash
nano config/config.yaml
```

3. **Validate Configuration**
```bash
python scripts/validate_config.py
```

### Core Settings

```yaml
# Core framework configuration
framework:
  name: "Metasploit-AI"
  version: "1.0.0"
  debug: false
  log_level: "INFO"
  
  # Working directories
  data_dir: "./data"
  logs_dir: "./logs"
  reports_dir: "./reports"
  models_dir: "./models"
```

### Network Configuration

```yaml
# Network and interface settings
network:
  # Web interface
  web:
    host: "0.0.0.0"
    port: 8080
    ssl_enabled: false
    ssl_cert: ""
    ssl_key: ""
    
  # API settings
  api:
    enabled: true
    rate_limit: 100  # requests per minute
    authentication_required: true
    
  # RPC settings (for Metasploit integration)
  rpc:
    host: "127.0.0.1"
    port: 55553
    username: "msf"
    password: "your_password_here"
```

## Database Configuration

### Supported Databases

#### SQLite (Default)
```yaml
database:
  type: "sqlite"
  connection:
    path: "data/metasploit_ai.db"
  pool:
    max_connections: 10
    timeout: 30
```

#### PostgreSQL
```yaml
database:
  type: "postgresql"
  connection:
    host: "localhost"
    port: 5432
    database: "metasploit_ai"
    username: "msf_user"
    password: "${DB_PASSWORD}"  # Environment variable
  pool:
    max_connections: 20
    min_connections: 5
    timeout: 30
```

#### MySQL
```yaml
database:
  type: "mysql"
  connection:
    host: "localhost"
    port: 3306
    database: "metasploit_ai"
    username: "msf_user"
    password: "${DB_PASSWORD}"
  pool:
    max_connections: 20
    timeout: 30
```

### Database Setup

#### PostgreSQL Setup
```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE metasploit_ai;
CREATE USER msf_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE metasploit_ai TO msf_user;
\q

# Initialize database
python scripts/init_database.py --config config/config.yaml
```

#### MySQL Setup
```bash
# Install MySQL
sudo apt install mysql-server

# Create database and user
mysql -u root -p
CREATE DATABASE metasploit_ai;
CREATE USER 'msf_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON metasploit_ai.* TO 'msf_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Initialize database
python scripts/init_database.py --config config/config.yaml
```

## AI/ML Configuration

### Model Configuration

```yaml
# AI and Machine Learning settings
ai:
  # Model storage and caching
  models:
    cache_dir: "./models/cache"
    download_on_startup: true
    auto_update: false
    
  # Vulnerability analyzer
  vulnerability_analyzer:
    model_type: "neural_network"
    model_path: "models/vuln_classifier.pkl"
    confidence_threshold: 0.8
    batch_size: 32
    
  # Exploit recommender
  exploit_recommender:
    model_type: "ensemble"
    model_path: "models/exploit_recommender.pkl"
    similarity_threshold: 0.7
    max_recommendations: 10
    
  # Payload generator
  payload_generator:
    model_type: "transformer"
    model_path: "models/payload_generator.pkl"
    creativity_level: 0.5
    safety_checks: true
```

### GPU Configuration

```yaml
# GPU acceleration settings
gpu:
  enabled: true
  device: "cuda:0"  # or "cpu" for CPU-only
  memory_limit: 8192  # MB
  mixed_precision: true
  
  # For multiple GPUs
  devices: ["cuda:0", "cuda:1"]
  strategy: "data_parallel"
```

### Model Training

```yaml
# Training configuration
training:
  # Data paths
  training_data: "data/training/"
  validation_data: "data/validation/"
  
  # Training parameters
  batch_size: 64
  learning_rate: 0.001
  epochs: 100
  early_stopping: true
  patience: 10
  
  # Model saving
  checkpoint_dir: "models/checkpoints/"
  save_best_only: true
  save_frequency: 10
```

## Security Configuration

### Authentication

```yaml
# Authentication settings
authentication:
  # Session management
  session_timeout: 3600  # seconds
  max_sessions_per_user: 5
  
  # Password requirements
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special: true
    
  # Multi-factor authentication
  mfa:
    enabled: false
    type: "totp"  # or "sms", "email"
    backup_codes: true
```

### Encryption

```yaml
# Encryption settings
encryption:
  # Data at rest
  database_encryption: true
  file_encryption: true
  
  # Data in transit
  force_https: true
  tls_version: "1.3"
  
  # Key management
  key_rotation_interval: 2592000  # 30 days in seconds
  backup_encryption_key: true
```

### Access Control

```yaml
# Role-based access control
rbac:
  enabled: true
  
  roles:
    admin:
      permissions: ["*"]
      
    analyst:
      permissions: 
        - "scan.*"
        - "analyze.*"
        - "report.read"
        
    readonly:
      permissions:
        - "*.read"
        - "report.read"
```

## Performance Configuration

### Scanning Performance

```yaml
# Scanning configuration
scanning:
  # Thread management
  max_threads: 50
  thread_pool_size: 20
  
  # Timing and delays
  default_timing: "normal"
  scan_delay: 0  # milliseconds between scans
  timeout: 30  # seconds
  
  # Rate limiting
  rate_limit:
    enabled: true
    max_requests_per_second: 10
    burst_size: 50
```

### Memory Management

```yaml
# Memory configuration
memory:
  # Cache settings
  cache_size: 1024  # MB
  cache_ttl: 3600  # seconds
  
  # Garbage collection
  gc_interval: 300  # seconds
  max_memory_usage: 4096  # MB
  
  # Buffer sizes
  scan_buffer_size: 1000
  result_buffer_size: 5000
```

### Logging Configuration

```yaml
# Logging configuration
logging:
  # Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: "INFO"
  
  # Log files
  files:
    application: "logs/metasploit-ai.log"
    security: "logs/security.log"
    audit: "logs/audit.log"
    error: "logs/error.log"
    
  # Log rotation
  rotation:
    max_size: 100  # MB
    backup_count: 10
    
  # Remote logging
  remote:
    enabled: false
    syslog_server: "syslog.example.com"
    syslog_port: 514
```

## Integration Configuration

### Metasploit Integration

```yaml
# Metasploit Framework integration
metasploit:
  # Installation path
  install_path: "/usr/share/metasploit-framework"
  
  # RPC settings
  rpc:
    host: "127.0.0.1"
    port: 55553
    username: "msf"
    password: "${MSF_PASSWORD}"
    ssl: false
    
  # Database connection
  database:
    adapter: "postgresql"
    host: "localhost"
    port: 5432
    database: "msf"
    username: "msf"
    password: "${MSF_DB_PASSWORD}"
```

### External Tool Integration

```yaml
# External tool integrations
integrations:
  # Nmap integration
  nmap:
    enabled: true
    binary_path: "/usr/bin/nmap"
    default_args: "-sS -sV -O"
    
  # Nessus integration
  nessus:
    enabled: false
    server: "https://nessus.example.com:8834"
    api_key: "${NESSUS_API_KEY}"
    verify_ssl: true
    
  # Burp Suite integration
  burp:
    enabled: false
    api_url: "http://localhost:1337"
    api_key: "${BURP_API_KEY}"
    
  # OSINT tools
  osint:
    shodan:
      api_key: "${SHODAN_API_KEY}"
    virustotal:
      api_key: "${VT_API_KEY}"
    censys:
      api_id: "${CENSYS_API_ID}"
      api_secret: "${CENSYS_API_SECRET}"
```

## Environment-Specific Configuration

### Development Configuration

```yaml
# development.yaml
framework:
  debug: true
  log_level: "DEBUG"
  
database:
  type: "sqlite"
  connection:
    path: "data/dev.db"
    
ai:
  models:
    download_on_startup: false
    auto_update: false
    
security:
  authentication:
    session_timeout: 86400  # 24 hours for development
```

### Production Configuration

```yaml
# production.yaml
framework:
  debug: false
  log_level: "WARNING"
  
database:
  type: "postgresql"
  connection:
    host: "${DB_HOST}"
    port: 5432
    database: "metasploit_ai_prod"
    username: "${DB_USER}"
    password: "${DB_PASSWORD}"
    
security:
  authentication:
    session_timeout: 1800  # 30 minutes
    mfa:
      enabled: true
      
  encryption:
    database_encryption: true
    force_https: true
```

## Environment Variables

### Required Variables

```bash
# Database credentials
export DB_PASSWORD="your_secure_password"
export MSF_PASSWORD="metasploit_rpc_password"

# API keys
export SHODAN_API_KEY="your_shodan_key"
export VT_API_KEY="your_virustotal_key"

# Security
export SECRET_KEY="your_secret_key_for_sessions"
export ENCRYPTION_KEY="your_encryption_key"
```

### Configuration Loading

```bash
# Load environment-specific configuration
export MSF_AI_ENV="production"
python app.py  # Loads production.yaml

# Override with custom config
export MSF_AI_CONFIG="config/custom.yaml"
python app.py
```

## Configuration Validation

### Validation Script

```bash
# Validate configuration
python scripts/validate_config.py

# Validate specific environment
python scripts/validate_config.py --env production

# Check configuration syntax
python scripts/validate_config.py --syntax-only
```

### Common Validation Errors

1. **Missing Required Fields**
```
Error: Missing required field 'database.connection.host'
Solution: Add the missing field to your configuration
```

2. **Invalid Database Connection**
```
Error: Cannot connect to database
Solution: Check database credentials and connectivity
```

3. **Model Files Not Found**
```
Error: Model file not found: models/vuln_classifier.pkl
Solution: Download models or disable auto-loading
```

## Best Practices

### Security Best Practices

1. **Protect Sensitive Configuration**
```bash
# Use environment variables for secrets
export DB_PASSWORD="$(cat /etc/msf-ai/db_password)"

# Set proper file permissions
chmod 600 config/secrets.yaml
```

2. **Regular Key Rotation**
```bash
# Rotate encryption keys regularly
python scripts/rotate_keys.py --backup-old-keys
```

3. **Audit Configuration Changes**
```bash
# Track configuration changes
git add config/
git commit -m "Update database configuration"
```

### Performance Best Practices

1. **Database Optimization**
```yaml
database:
  pool:
    max_connections: 20  # Adjust based on system resources
    timeout: 30
```

2. **Memory Management**
```yaml
memory:
  cache_size: 2048  # Increase for better performance
  max_memory_usage: 8192  # Set based on available RAM
```

3. **Scanning Optimization**
```yaml
scanning:
  max_threads: 100  # Increase for faster scans
  rate_limit:
    max_requests_per_second: 50  # Adjust based on target tolerance
```

## Troubleshooting

### Common Issues

1. **Configuration Not Loading**
```bash
# Check file permissions
ls -la config/config.yaml

# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"
```

2. **Database Connection Issues**
```bash
# Test database connection
python scripts/test_db_connection.py

# Check database logs
tail -f /var/log/postgresql/postgresql.log
```

3. **Model Loading Errors**
```bash
# Check model file integrity
python scripts/verify_models.py

# Download missing models
python scripts/download_models.py
```

---

*For additional help with configuration, see the [Troubleshooting Guide](troubleshooting.md) or [FAQ](faq.md).*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
