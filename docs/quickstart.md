# Quick Start Guide

Welcome to Metasploit-AI! This guide will help you get up and running with the framework in just a few minutes.

## Prerequisites

Before starting, ensure you have:
- Python 3.8 or higher installed
- Metasploit Framework installed and configured
- Administrative/root privileges on your system
- At least 4GB of available RAM

## Quick Installation

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai

# Install dependencies
pip install -r requirements.txt

# Quick setup
python setup.py develop
```

### 2. Basic Configuration

```bash
# Copy default configuration
cp config/default.yaml config/config.yaml

# Edit configuration (optional for quick start)
nano config/config.yaml
```

### 3. Launch the Framework

**Option A: Web Interface (Recommended for beginners)**
```bash
python app.py --mode web --host 0.0.0.0 --port 8080
```
Open your browser to `http://localhost:8080`

**Option B: Command Line Interface**
```bash
python app.py --mode cli
```

## First Steps

### 1. System Check

Verify your installation:
```bash
python scripts/system_check.py
```

### 2. Basic Scan

Perform your first AI-powered scan:

**Web Interface:**
1. Navigate to "Scanner" tab
2. Enter target IP/range: `192.168.1.0/24`
3. Select scan type: "Basic Discovery"
4. Click "Start Scan"

**CLI Interface:**
```bash
msf-ai> scan 192.168.1.0/24 --type basic
msf-ai> show results
```

### 3. AI Vulnerability Analysis

Let AI analyze discovered vulnerabilities:

**Web Interface:**
1. Go to "AI Analysis" tab
2. Select your scan results
3. Click "Analyze Vulnerabilities"
4. Review AI recommendations

**CLI Interface:**
```bash
msf-ai> ai analyze --target 192.168.1.100
msf-ai> ai recommend --severity high
```

### 4. Smart Exploitation

Use AI-recommended exploits:

**Web Interface:**
1. Navigate to "Exploits" tab
2. Select target from scan results
3. Choose AI-recommended exploit
4. Configure payload options
5. Execute exploit

**CLI Interface:**
```bash
msf-ai> ai exploit --target 192.168.1.100 --auto
msf-ai> sessions --list
```

## Common Use Cases

### Scenario 1: Internal Network Assessment

```bash
# 1. Network discovery
msf-ai> scan 10.0.0.0/8 --type discovery

# 2. Service enumeration
msf-ai> scan --targets-from-file discovered.txt --type services

# 3. AI vulnerability analysis
msf-ai> ai analyze --all-targets

# 4. Generate report
msf-ai> report generate --format html --output internal_assessment.html
```

### Scenario 2: Single Target Deep Dive

```bash
# 1. Comprehensive scan
msf-ai> scan 192.168.1.50 --type comprehensive

# 2. AI analysis and recommendations
msf-ai> ai analyze --target 192.168.1.50 --deep

# 3. Automated exploitation
msf-ai> ai exploit --target 192.168.1.50 --chain

# 4. Post-exploitation
msf-ai> sessions --interact 1
msf-ai> ai post-exploit --gather-intel
```

### Scenario 3: Web Application Testing

```bash
# 1. Web application scan
msf-ai> scan https://example.com --type web

# 2. AI-powered vulnerability detection
msf-ai> ai web-analyze --url https://example.com

# 3. Exploit recommendations
msf-ai> ai recommend --target-type web --severity critical
```

## Key Features Overview

### 🤖 AI-Powered Analysis
- Intelligent vulnerability classification
- Smart exploit recommendations
- Automated payload generation
- Risk assessment and prioritization

### 🔍 Advanced Scanning
- Multi-threaded network discovery
- Service enumeration and fingerprinting
- Stealth scanning techniques
- Custom scan profiles

### 💥 Smart Exploitation
- AI-driven exploit selection
- Success probability prediction
- Automated exploit chaining
- Post-exploitation automation

### 📊 Comprehensive Reporting
- Executive summaries
- Technical reports
- Risk matrices
- Compliance mapping

## Next Steps

After completing this quick start:

1. **[Read the User Manual](user-manual.md)** - Comprehensive feature documentation
2. **[Configure the Framework](configuration.md)** - Customize for your environment
3. **[Learn Security Best Practices](security-best-practices.md)** - Use safely and legally
4. **[Explore Tutorials](tutorials/)** - Hands-on learning scenarios

## Getting Help

If you encounter issues:

- **Check**: [Troubleshooting Guide](troubleshooting.md)
- **Search**: [FAQ](faq.md)
- **Ask**: [GitHub Discussions](https://github.com/yashab-cyber/metasploit-ai/discussions)
- **Report**: [GitHub Issues](https://github.com/yashab-cyber/metasploit-ai/issues)

## Security Notice

⚠️ **Important**: This framework is for authorized penetration testing only. Always:
- Obtain proper authorization before testing
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Use only in controlled environments

---

**Ready to explore advanced features? Continue with the [User Manual](user-manual.md)!**

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
