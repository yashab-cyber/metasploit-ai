# Troubleshooting Guide

Common issues and solutions for the Metasploit-AI Framework.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Configuration Problems](#configuration-problems)
3. [Database Issues](#database-issues)
4. [Scanning Problems](#scanning-problems)
5. [AI/ML Issues](#aiml-issues)
6. [Exploitation Problems](#exploitation-problems)
7. [Performance Issues](#performance-issues)
8. [Network and Connectivity](#network-and-connectivity)
9. [Permission and Security](#permission-and-security)
10. [Error Codes Reference](#error-codes-reference)

## Installation Issues

### Python Version Compatibility

**Problem:** Framework fails to start with Python version errors
```
Error: This framework requires Python 3.8 or higher
```

**Solution:**
```bash
# Check Python version
python --version

# Install Python 3.8+ (Ubuntu/Debian)
sudo apt update
sudo apt install python3.8 python3.8-pip

# Install Python 3.8+ (CentOS/RHEL)
sudo yum install python38 python38-pip

# Use specific Python version
python3.8 -m pip install -r requirements.txt
python3.8 app.py
```

### Dependency Installation Failures

**Problem:** Package installation fails with compilation errors
```
Error: Failed building wheel for some-package
```

**Solution:**
```bash
# Install build dependencies (Ubuntu/Debian)
sudo apt install build-essential python3-dev libffi-dev libssl-dev

# Install build dependencies (CentOS/RHEL)
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel libffi-devel openssl-devel

# Use conda for problematic packages
conda install package-name

# Install from wheel if available
pip install --only-binary=all package-name
```

### Metasploit Framework Not Found

**Problem:** Cannot connect to Metasploit Framework
```
Error: Metasploit Framework not found or not running
```

**Solution:**
```bash
# Install Metasploit Framework (Kali Linux)
sudo apt update
sudo apt install metasploit-framework

# Install Metasploit Framework (Ubuntu/Debian)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
sudo ./msfinstall

# Start Metasploit RPC server
sudo systemctl start metasploit
msfconsole -q -x "load msgrpc Pass=your_password ServerPort=55553"

# Verify installation
msfconsole --version
```

## Configuration Problems

### Configuration File Not Found

**Problem:** Framework cannot find configuration files
```
Error: Configuration file not found: config/config.yaml
```

**Solution:**
```bash
# Copy default configuration
cp config/default.yaml config/config.yaml

# Set configuration path
export MSF_AI_CONFIG="$(pwd)/config/config.yaml"

# Verify file permissions
ls -la config/config.yaml
chmod 644 config/config.yaml
```

### Invalid Configuration Syntax

**Problem:** YAML syntax errors in configuration
```
Error: Invalid YAML syntax in configuration file
```

**Solution:**
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"

# Use YAML validator
pip install yamllint
yamllint config/config.yaml

# Common fixes:
# - Check indentation (spaces, not tabs)
# - Ensure proper quoting of special characters
# - Verify all brackets and braces are closed
```

### Environment Variable Issues

**Problem:** Environment variables not loading correctly
```
Error: Database password not found in environment
```

**Solution:**
```bash
# Check environment variables
echo $DB_PASSWORD
env | grep MSF_AI

# Load from .env file
export $(cat .env | xargs)

# Set required variables
export DB_PASSWORD="your_password"
export MSF_PASSWORD="metasploit_password"

# Make variables persistent
echo 'export DB_PASSWORD="your_password"' >> ~/.bashrc
source ~/.bashrc
```

## Database Issues

### Database Connection Failed

**Problem:** Cannot connect to database
```
Error: Could not connect to database: Connection refused
```

**Solution:**

**For PostgreSQL:**
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql
sudo systemctl start postgresql

# Check connection settings
sudo -u postgres psql -c "SELECT version();"

# Reset password
sudo -u postgres psql
ALTER USER postgres PASSWORD 'newpassword';

# Check pg_hba.conf for authentication
sudo nano /etc/postgresql/13/main/pg_hba.conf
```

**For MySQL:**
```bash
# Check if MySQL is running
sudo systemctl status mysql
sudo systemctl start mysql

# Reset root password
sudo mysql_secure_installation

# Check connection
mysql -u root -p -e "SELECT version();"
```

**For SQLite:**
```bash
# Check file permissions
ls -la data/metasploit_ai.db
chmod 664 data/metasploit_ai.db

# Verify directory exists
mkdir -p data/
```

### Database Migration Errors

**Problem:** Database schema migration fails
```
Error: Migration failed: table already exists
```

**Solution:**
```bash
# Check migration status
python scripts/check_migrations.py

# Force migration reset
python scripts/reset_database.py --confirm

# Manual migration
python scripts/migrate_database.py --step-by-step

# Backup before migration
python scripts/backup_database.py --output backup_$(date +%Y%m%d).sql
```

### Database Performance Issues

**Problem:** Slow database queries and timeouts
```
Error: Database query timeout after 30 seconds
```

**Solution:**
```bash
# Check database size
du -sh data/metasploit_ai.db  # For SQLite

# For PostgreSQL
sudo -u postgres psql -c "SELECT pg_size_pretty(pg_database_size('metasploit_ai'));"

# Optimize database
python scripts/optimize_database.py

# Increase timeout in config
# config.yaml:
database:
  pool:
    timeout: 60
```

## Scanning Problems

### Nmap Not Found

**Problem:** Nmap scanner not available
```
Error: nmap command not found
```

**Solution:**
```bash
# Install Nmap (Ubuntu/Debian)
sudo apt install nmap

# Install Nmap (CentOS/RHEL)
sudo yum install nmap

# Install Nmap (macOS)
brew install nmap

# Verify installation
nmap --version

# Set custom path in config
integrations:
  nmap:
    binary_path: "/usr/local/bin/nmap"
```

### Permission Denied for Raw Sockets

**Problem:** Cannot perform SYN scans due to permissions
```
Error: You requested a scan type which requires root privileges
```

**Solution:**
```bash
# Run with sudo (not recommended for production)
sudo python app.py

# Set capabilities for nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Use TCP connect scans instead
msf-ai> scan 192.168.1.0/24 --technique connect

# Configure alternative scan methods
scanning:
  default_technique: "connect"
  require_root: false
```

### Scan Timeout Issues

**Problem:** Scans timing out or hanging
```
Error: Scan timeout after 300 seconds
```

**Solution:**
```bash
# Increase timeout in configuration
scanning:
  timeout: 600  # 10 minutes
  max_retries: 3

# Use faster timing templates
msf-ai> scan 192.168.1.0/24 --timing aggressive

# Reduce scan scope
msf-ai> scan 192.168.1.0/24 --ports 1-1000

# Check network connectivity
ping 192.168.1.1
traceroute 192.168.1.100
```

## AI/ML Issues

### Model Loading Failures

**Problem:** AI models fail to load
```
Error: Cannot load model: models/vuln_classifier.pkl
```

**Solution:**
```bash
# Download missing models
python scripts/download_models.py

# Check model file integrity
python scripts/verify_models.py

# Use alternative model path
ai:
  vulnerability_analyzer:
    model_path: "models/backup/vuln_classifier.pkl"

# Disable AI features temporarily
ai:
  vulnerability_analyzer:
    enabled: false
```

### GPU/CUDA Issues

**Problem:** CUDA not available or GPU errors
```
Error: CUDA device not found
```

**Solution:**
```bash
# Check CUDA installation
nvidia-smi
nvcc --version

# Install CUDA drivers
sudo apt install nvidia-driver-470
sudo apt install nvidia-cuda-toolkit

# Use CPU fallback
gpu:
  enabled: false
  device: "cpu"

# Check PyTorch CUDA support
python -c "import torch; print(torch.cuda.is_available())"
```

### Memory Issues with AI Models

**Problem:** Out of memory errors during AI operations
```
Error: CUDA out of memory
```

**Solution:**
```bash
# Reduce batch size
ai:
  vulnerability_analyzer:
    batch_size: 16  # Reduce from 32

# Limit GPU memory
gpu:
  memory_limit: 4096  # 4GB instead of 8GB

# Use mixed precision
gpu:
  mixed_precision: true

# Monitor memory usage
python scripts/monitor_memory.py
```

## Exploitation Problems

### Metasploit RPC Connection Issues

**Problem:** Cannot connect to Metasploit RPC server
```
Error: Connection refused to Metasploit RPC server
```

**Solution:**
```bash
# Start Metasploit RPC server
msfconsole -q -x "load msgrpc Pass=your_password ServerPort=55553 ServerHost=0.0.0.0"

# Check if RPC is listening
netstat -tlnp | grep 55553

# Update configuration
metasploit:
  rpc:
    host: "127.0.0.1"
    port: 55553
    username: "msf"
    password: "your_password"

# Test RPC connection
python scripts/test_msf_rpc.py
```

### Exploit Execution Failures

**Problem:** Exploits fail to execute or return errors
```
Error: Exploit execution failed: target not vulnerable
```

**Solution:**
```bash
# Verify target vulnerability
msf-ai> exploits check ms17_010_eternalblue --target 192.168.1.100

# Check exploit options
msf-ai> exploits info ms17_010_eternalblue

# Use AI recommendations
msf-ai> ai recommend --target 192.168.1.100

# Check network connectivity
telnet 192.168.1.100 445

# Update exploit database
msfconsole -q -x "msfupdate"
```

### Payload Generation Issues

**Problem:** Payloads fail to generate or execute
```
Error: Payload generation failed
```

**Solution:**
```bash
# Check payload compatibility
msf-ai> payload info windows/meterpreter/reverse_tcp

# Use alternative payload
msf-ai> payload generate windows/shell/reverse_tcp

# Check firewall settings
# Ensure LPORT is not blocked

# Test payload locally
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.1.50; set LPORT 4444; run"
```

## Performance Issues

### High Memory Usage

**Problem:** Framework consuming excessive memory
```
Warning: Memory usage exceeding 8GB
```

**Solution:**
```bash
# Monitor memory usage
top -p $(pgrep -f "python.*app.py")
htop

# Adjust memory limits
memory:
  max_memory_usage: 4096  # 4GB limit
  cache_size: 512  # Reduce cache

# Enable garbage collection
memory:
  gc_interval: 60  # seconds

# Restart framework periodically
python scripts/restart_framework.py --schedule daily
```

### Slow Performance

**Problem:** Framework running slowly
```
Warning: Operations taking longer than expected
```

**Solution:**
```bash
# Check system resources
free -h
df -h
iostat

# Optimize database
python scripts/optimize_database.py

# Increase thread pools
scanning:
  max_threads: 100
  thread_pool_size: 50

# Use SSD storage
# Move database to SSD
# Enable database caching
```

### High CPU Usage

**Problem:** Excessive CPU consumption
```
Warning: CPU usage consistently above 90%
```

**Solution:**
```bash
# Check process usage
top -p $(pgrep -f "python.*app.py")

# Limit scan threads
scanning:
  max_threads: 20  # Reduce from 50

# Adjust AI model batch sizes
ai:
  vulnerability_analyzer:
    batch_size: 8  # Reduce processing load

# Use process affinity
taskset -c 0,1 python app.py  # Use only CPU cores 0 and 1
```

## Network and Connectivity

### Firewall Blocking Scans

**Problem:** Scans blocked by firewall
```
Error: Host seems down (no response to ping)
```

**Solution:**
```bash
# Disable ping requirement
msf-ai> scan 192.168.1.0/24 --no-ping

# Check firewall rules
sudo iptables -L
sudo ufw status

# Use alternative scan techniques
msf-ai> scan 192.168.1.0/24 --technique ack

# Test connectivity
nmap -sn 192.168.1.0/24
```

### DNS Resolution Issues

**Problem:** Cannot resolve hostnames
```
Error: Failed to resolve hostname
```

**Solution:**
```bash
# Check DNS configuration
cat /etc/resolv.conf
nslookup example.com

# Use IP addresses instead
msf-ai> scan 192.168.1.100  # Instead of hostname

# Configure DNS servers
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# Flush DNS cache
sudo systemctl restart systemd-resolved
```

### Proxy Configuration Issues

**Problem:** Framework doesn't work through proxy
```
Error: Connection timed out through proxy
```

**Solution:**
```bash
# Set proxy environment variables
export HTTP_PROXY="http://proxy.example.com:8080"
export HTTPS_PROXY="http://proxy.example.com:8080"

# Configure proxy in settings
network:
  proxy:
    enabled: true
    http: "http://proxy.example.com:8080"
    https: "http://proxy.example.com:8080"

# Bypass proxy for local addresses
export NO_PROXY="localhost,127.0.0.1,192.168.1.0/24"
```

## Permission and Security

### Insufficient Privileges

**Problem:** Operations fail due to lack of permissions
```
Error: Permission denied
```

**Solution:**
```bash
# Check current user
whoami
id

# Add user to required groups
sudo usermod -a -G sudo username

# Set file permissions
chmod +x scripts/*.py
chmod 644 config/*.yaml

# Use sudo for specific operations
sudo python scripts/system_check.py
```

### SSL/TLS Certificate Issues

**Problem:** SSL certificate verification failures
```
Error: SSL certificate verification failed
```

**Solution:**
```bash
# Disable SSL verification (testing only)
export PYTHONHTTPSVERIFY=0

# Add certificate to trust store
sudo cp custom_ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Configure in settings
network:
  ssl:
    verify_certificates: false  # For testing only
```

### Authentication Failures

**Problem:** Login or authentication issues
```
Error: Authentication failed
```

**Solution:**
```bash
# Reset admin password
python scripts/reset_password.py --user admin

# Check user configuration
msf-ai> users list
msf-ai> users info admin

# Verify authentication settings
authentication:
  session_timeout: 3600
  max_login_attempts: 5
```

## Error Codes Reference

### Common Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| MSF_AI_001 | Configuration file not found | Copy default.yaml to config.yaml |
| MSF_AI_002 | Database connection failed | Check database service and credentials |
| MSF_AI_003 | Metasploit RPC connection failed | Start Metasploit RPC server |
| MSF_AI_004 | Model loading failed | Download or verify model files |
| MSF_AI_005 | Insufficient permissions | Run with appropriate privileges |
| MSF_AI_006 | Network timeout | Check network connectivity |
| MSF_AI_007 | Invalid target format | Use correct IP/hostname format |
| MSF_AI_008 | Scan failed | Check target availability and permissions |
| MSF_AI_009 | Exploit execution failed | Verify exploit compatibility |
| MSF_AI_010 | Session creation failed | Check payload and network settings |

### Debug Mode

Enable debug mode for detailed error information:

```bash
# Start with debug mode
python app.py --mode cli --debug

# Enable debug logging
logging:
  level: "DEBUG"
  files:
    debug: "logs/debug.log"

# View debug logs
tail -f logs/debug.log
```

## Getting Additional Help

### Log Analysis

```bash
# Check application logs
tail -f logs/metasploit-ai.log

# Check error logs
grep -i error logs/metasploit-ai.log

# Check system logs
journalctl -u metasploit-ai -f
```

### Diagnostic Scripts

```bash
# Run comprehensive system check
python scripts/system_check.py --verbose

# Generate diagnostic report
python scripts/generate_diagnostics.py --output diagnostics.txt

# Test all components
python scripts/test_all.py
```

### Community Support

- **GitHub Issues**: [Report bugs](https://github.com/yashab-cyber/metasploit-ai/issues)
- **GitHub Discussions**: [Ask questions](https://github.com/yashab-cyber/metasploit-ai/discussions)
- **Email Support**: yashabalam707@gmail.com
- **WhatsApp Business**: [ZehraSec Channel](https://whatsapp.com/channel/0029Vaoa1GfKLaHlL0Kc8k1q)

---

*If you can't find a solution here, please check the [FAQ](faq.md) or create an issue on GitHub.*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
