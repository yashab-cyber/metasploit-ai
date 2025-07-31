# Installation Guide

This guide will walk you through installing and setting up the Metasploit-AI Framework on your system.

## System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 20.04+), macOS 10.15+, Windows 10+
- **Python**: 3.8 or higher
- **Memory**: 4 GB RAM minimum, 8 GB recommended
- **Storage**: 2 GB free space minimum, 10 GB recommended
- **Network**: Internet connection for downloading dependencies

### Recommended Requirements
- **Operating System**: Kali Linux, Ubuntu 22.04+, or macOS 12+
- **Python**: 3.11 or higher
- **Memory**: 16 GB RAM or more
- **Storage**: 50 GB free space (for models and data)
- **GPU**: NVIDIA GPU with CUDA support (optional, for AI acceleration)

### Prerequisites

#### Metasploit Framework
Metasploit-AI requires the Metasploit Framework to be installed:

**Kali Linux:**
```bash
sudo apt update
sudo apt install metasploit-framework
```

**Ubuntu/Debian:**
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

**macOS:**
```bash
brew install metasploit
```

**Windows:**
Download the installer from [Rapid7's website](https://www.metasploit.com/).

#### Python Dependencies
Install Python development tools:

**Linux:**
```bash
sudo apt install python3-dev python3-pip python3-venv build-essential
```

**macOS:**
```bash
brew install python3
xcode-select --install
```

## Installation Methods

### Method 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai

# Run the installation script
chmod +x scripts/install.sh
./scripts/install.sh
```

### Method 2: Manual Installation

#### Step 1: Clone Repository
```bash
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai
```

#### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 4: Install Development Dependencies (Optional)
```bash
pip install -r requirements-dev.txt
```

#### Step 5: Setup Configuration
```bash
# Copy example configuration
cp config/default.yaml config/config.yaml

# Edit configuration for your environment
nano config/config.yaml
```

#### Step 6: Initialize Database
```bash
python scripts/setup_database.py
```

#### Step 7: Download AI Models
```bash
python scripts/download_models.py
```

#### Step 8: Install Framework
```bash
python setup.py install
```

### Method 3: Docker Installation

#### Using Docker Compose (Recommended)
```bash
# Clone repository
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai

# Start with Docker Compose
docker-compose up -d
```

#### Using Docker
```bash
# Build the image
docker build -t metasploit-ai .

# Run the container
docker run -d \
  --name metasploit-ai \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  metasploit-ai
```

## Configuration

### Basic Configuration

Edit `config/config.yaml` to customize your installation:

```yaml
# Basic settings
app:
  debug: false
  environment: "production"

# Server configuration
server:
  host: "127.0.0.1"
  port: 5000

# Database settings
database:
  type: "sqlite"
  path: "data/metasploit_ai.db"

# Metasploit integration
metasploit:
  rpc:
    host: "127.0.0.1"
    port: 55553
    username: "msf"
    password: "msf"
```

### Security Configuration

For production deployments, configure security settings:

```yaml
security:
  authentication:
    method: "token"
    token_expiry: 86400
    max_login_attempts: 5
  
  encryption:
    algorithm: "AES-256-GCM"
    key_size: 256
  
  api:
    rate_limit: 1000
    api_key_required: true
```

### AI/ML Configuration

Configure AI models and settings:

```yaml
ai:
  models:
    vulnerability_model:
      path: "models/vulnerability_classifier.pkl"
      confidence_threshold: 0.75
    
    exploit_model:
      path: "models/exploit_recommender.pkl"
      top_k: 10
  
  compute:
    device: "auto"  # auto, cpu, cuda
    memory_limit: "2GB"
```

## Post-Installation Setup

### Start Metasploit RPC Service
```bash
# Start Metasploit RPC server
sudo msfconsole -x "load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf"
```

### Initialize Framework
```bash
# Initialize the framework
python app.py --mode cli
```

### Verify Installation
```bash
# Run system check
python scripts/system_check.py

# Run tests
pytest tests/
```

## Platform-Specific Instructions

### Kali Linux

Kali Linux is the recommended platform for Metasploit-AI:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install python3-dev python3-pip python3-venv git build-essential

# Install Metasploit (if not already installed)
sudo apt install metasploit-framework

# Clone and install Metasploit-AI
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai
./scripts/install.sh
```

### Ubuntu/Debian

```bash
# Install prerequisites
sudo apt update
sudo apt install python3-dev python3-pip python3-venv git build-essential curl

# Install Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Install Metasploit-AI
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai
./scripts/install.sh
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 git metasploit

# Install Xcode command line tools
xcode-select --install

# Install Metasploit-AI
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai
./scripts/install.sh
```

### Windows

1. **Install Python 3.8+** from [python.org](https://python.org)
2. **Install Git** from [git-scm.com](https://git-scm.com)
3. **Install Metasploit** from [Rapid7](https://www.metasploit.com/)
4. **Install Visual Studio Build Tools** for compiling dependencies

```powershell
# Clone repository
git clone https://github.com/yashab-cyber/metasploit-ai.git
cd metasploit-ai

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup configuration
copy config\default.yaml config\config.yaml

# Initialize framework
python setup.py install
```

## GPU Support (Optional)

For AI acceleration with NVIDIA GPUs:

### CUDA Installation
```bash
# Install CUDA toolkit (Linux)
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-ubuntu2204.pin
sudo mv cuda-ubuntu2204.pin /etc/apt/preferences.d/cuda-repository-pin-600
wget https://developer.download.nvidia.com/compute/cuda/12.2.0/local_installers/cuda-repo-ubuntu2204-12-2-local_12.2.0-535.54.03-1_amd64.deb
sudo dpkg -i cuda-repo-ubuntu2204-12-2-local_12.2.0-535.54.03-1_amd64.deb
sudo cp /var/cuda-repo-ubuntu2204-12-2-local/cuda-*-keyring.gpg /usr/share/keyrings/
sudo apt-get update
sudo apt-get -y install cuda
```

### PyTorch with CUDA
```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

### TensorFlow with CUDA
```bash
pip install tensorflow[and-cuda]
```

## Troubleshooting

### Common Issues

#### Issue: "Metasploit RPC connection failed"
**Solution:**
```bash
# Start Metasploit RPC service
sudo msfconsole -x "load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf"

# Check if port is available
netstat -an | grep 55553
```

#### Issue: "Permission denied" errors
**Solution:**
```bash
# Fix permissions
sudo chown -R $USER:$USER data/ logs/
chmod +x scripts/*.sh
```

#### Issue: "AI models not found"
**Solution:**
```bash
# Download models
python scripts/download_models.py

# Check model directory
ls -la models/
```

#### Issue: Python import errors
**Solution:**
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Check Python path
python -c "import sys; print(sys.path)"
```

### Getting Help

If you encounter issues:

1. **Check logs**: `tail -f logs/metasploit_ai.log`
2. **Run system check**: `python scripts/system_check.py`
3. **Check documentation**: [Troubleshooting Guide](troubleshooting.md)
4. **Report issues**: [GitHub Issues](https://github.com/yashab-cyber/metasploit-ai/issues)
5. **Contact support**: yashabalam707@gmail.com

## Next Steps

After successful installation:

1. **Read the [Quick Start Guide](quickstart.md)**
2. **Configure your environment**: [Configuration Guide](configuration.md)
3. **Learn the CLI**: [CLI Reference](cli-reference.md)
4. **Explore the web interface**: [Web Interface Guide](web-interface.md)
5. **Review security practices**: [Security Best Practices](security-best-practices.md)

## Updating

To update Metasploit-AI to the latest version:

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install --upgrade -r requirements.txt

# Run database migrations
python scripts/migrate_database.py

# Download new models
python scripts/download_models.py
```

---

**Need help?** Contact the ZehraSec team at yashabalam707@gmail.com or visit [www.zehrasec.com](https://www.zehrasec.com)
