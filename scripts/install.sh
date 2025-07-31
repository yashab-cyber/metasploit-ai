#!/bin/bash

# Metasploit-AI Framework Installation Script
# Advanced AI-Powered Penetration Testing Framework
# Created by Yashab Alam (ZehraSec)

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
cat << "EOF"
 __  __      _                   _       _ _              _    ___ 
|  \/  | ___| |_ __ _ ___ _ __   | | ___ (_) |_        /\ /\ |_ _|
| |\/| |/ _ \ __/ _` / __| '_ \  | |/ _ \| | __|_____ /  V  \ | | 
| |  | |  __/ || (_| \__ \ |_) | | | (_) | | ||_____| \_/\_/ | | 
|_|  |_|\___|\__\__,_|___/ .__/  |_|\___/|_|\__|      \   /  |___|
                         |_|                           \_/        
EOF
echo -e "${NC}"
echo -e "${CYAN}Advanced AI-Powered Penetration Testing Framework${NC}"
echo -e "${YELLOW}Created by Yashab Alam - ZehraSec (www.zehrasec.com)${NC}"
echo ""

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   print_status "Please run as a regular user with sudo privileges"
   exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if command -v apt-get &> /dev/null; then
        DISTRO="debian"
    elif command -v yum &> /dev/null; then
        DISTRO="redhat"
    elif command -v pacman &> /dev/null; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    DISTRO="macos"
else
    OS="unknown"
    DISTRO="unknown"
fi

print_status "Detected OS: $OS ($DISTRO)"

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
    print_error "Python 3.8+ required, found Python $python_version"
    print_status "Please upgrade Python and run this script again"
    exit 1
fi

print_success "Python $python_version found"

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    if [[ "$DISTRO" == "debian" ]]; then
        sudo apt-get update -qq
        sudo apt-get install -y \
            python3-dev \
            python3-pip \
            python3-venv \
            build-essential \
            git \
            curl \
            wget \
            nmap \
            netcat \
            postgresql-client \
            libpq-dev \
            libffi-dev \
            libssl-dev \
            libnmap-dev \
            libpcap-dev \
            || { print_error "Failed to install system dependencies"; exit 1; }
    elif [[ "$DISTRO" == "redhat" ]]; then
        sudo yum update -y
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y \
            python3-devel \
            python3-pip \
            git \
            curl \
            wget \
            nmap \
            netcat \
            postgresql-devel \
            libffi-devel \
            openssl-devel \
            libpcap-devel \
            || { print_error "Failed to install system dependencies"; exit 1; }
    elif [[ "$DISTRO" == "arch" ]]; then
        sudo pacman -Syu --noconfirm
        sudo pacman -S --noconfirm \
            python \
            python-pip \
            base-devel \
            git \
            curl \
            wget \
            nmap \
            openbsd-netcat \
            postgresql-libs \
            libffi \
            openssl \
            libpcap \
            || { print_error "Failed to install system dependencies"; exit 1; }
    elif [[ "$DISTRO" == "macos" ]]; then
        if ! command -v brew &> /dev/null; then
            print_status "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew update
        brew install \
            python3 \
            git \
            nmap \
            netcat \
            postgresql \
            libffi \
            openssl \
            libpcap \
            || { print_error "Failed to install system dependencies"; exit 1; }
    else
        print_warning "Unknown distribution, skipping system dependency installation"
        print_status "Please manually install: python3-dev, build-essential, git, nmap, libpcap-dev"
    fi
    
    print_success "System dependencies installed"
}

# Check if Metasploit is installed
check_metasploit() {
    print_status "Checking Metasploit installation..."
    
    if command -v msfconsole &> /dev/null; then
        msf_version=$(msfconsole --version 2>/dev/null | head -n1 || echo "Unknown")
        print_success "Metasploit Framework found: $msf_version"
    else
        print_warning "Metasploit Framework not found"
        print_status "Installing Metasploit Framework..."
        
        if [[ "$DISTRO" == "debian" ]]; then
            # Install Metasploit on Debian/Ubuntu
            if grep -q "kali" /etc/os-release 2>/dev/null; then
                # Kali Linux
                sudo apt-get install -y metasploit-framework
            else
                # Ubuntu/Debian
                curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
                chmod 755 /tmp/msfinstall
                sudo /tmp/msfinstall
            fi
        elif [[ "$DISTRO" == "arch" ]]; then
            # Install from AUR or build from source
            print_warning "Please install Metasploit manually on Arch Linux"
            print_status "Visit: https://github.com/rapid7/metasploit-framework"
        elif [[ "$DISTRO" == "macos" ]]; then
            brew install metasploit
        else
            print_warning "Please install Metasploit Framework manually"
            print_status "Visit: https://www.metasploit.com/"
        fi
        
        # Verify installation
        if command -v msfconsole &> /dev/null; then
            print_success "Metasploit Framework installed successfully"
        else
            print_error "Failed to install Metasploit Framework"
            print_status "Please install manually and run this script again"
            exit 1
        fi
    fi
}

# Create virtual environment
setup_venv() {
    print_status "Setting up Python virtual environment..."
    
    if [[ -d "venv" ]]; then
        print_warning "Virtual environment already exists, removing..."
        rm -rf venv
    fi
    
    python3 -m venv venv || { print_error "Failed to create virtual environment"; exit 1; }
    source venv/bin/activate || { print_error "Failed to activate virtual environment"; exit 1; }
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel || { print_error "Failed to upgrade pip"; exit 1; }
    
    print_success "Virtual environment created and activated"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    source venv/bin/activate
    
    # Install main dependencies
    pip install -r requirements.txt || { print_error "Failed to install main dependencies"; exit 1; }
    
    # Install development dependencies if requested
    if [[ "$1" == "dev" ]]; then
        print_status "Installing development dependencies..."
        pip install -r requirements-dev.txt || { print_error "Failed to install dev dependencies"; exit 1; }
    fi
    
    print_success "Python dependencies installed"
}

# Setup configuration
setup_config() {
    print_status "Setting up configuration..."
    
    # Create config file if it doesn't exist
    if [[ ! -f "config/config.yaml" ]]; then
        cp config/default.yaml config/config.yaml
        print_success "Configuration file created: config/config.yaml"
    else
        print_warning "Configuration file already exists"
    fi
    
    # Create necessary directories
    mkdir -p data logs models reports temp backups
    
    # Set permissions
    chmod 700 data logs
    chmod 755 models reports temp backups
    
    print_success "Directories created and configured"
}

# Download AI models
download_models() {
    print_status "Downloading AI models..."
    
    source venv/bin/activate
    
    # Create models directory
    mkdir -p models
    
    # For now, create placeholder files
    # In a real implementation, you would download actual trained models
    touch models/vulnerability_classifier.pkl
    touch models/exploit_recommender.pkl
    touch models/payload_generator.pkl
    
    print_success "AI models downloaded (placeholders created)"
    print_status "To use actual models, train them or download from the project repository"
}

# Initialize database
init_database() {
    print_status "Initializing database..."
    
    source venv/bin/activate
    
    # Run database initialization script
    python -c "
from src.core.database import Database
from src.core.config import Config
import asyncio

async def init_db():
    config = Config()
    db = Database(config)
    await db.initialize()
    print('Database initialized successfully')

asyncio.run(init_db())
" || { print_error "Failed to initialize database"; exit 1; }
    
    print_success "Database initialized"
}

# Install framework
install_framework() {
    print_status "Installing Metasploit-AI Framework..."
    
    source venv/bin/activate
    
    # Install in development mode
    pip install -e . || { print_error "Failed to install framework"; exit 1; }
    
    print_success "Framework installed"
}

# Run system check
run_system_check() {
    print_status "Running system check..."
    
    source venv/bin/activate
    
    python -c "
import sys
import importlib
import subprocess

def check_import(module_name):
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False

def check_command(command):
    try:
        subprocess.run([command, '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

# Check Python modules
modules = ['flask', 'sqlalchemy', 'sklearn', 'numpy', 'pandas', 'requests', 'aiohttp']
print('Checking Python modules:')
for module in modules:
    status = '✓' if check_import(module) else '✗'
    print(f'  {status} {module}')

# Check commands
commands = ['msfconsole', 'nmap']
print('\nChecking system commands:')
for cmd in commands:
    status = '✓' if check_command(cmd) else '✗'
    print(f'  {status} {cmd}')

print('\nSystem check completed!')
"
    
    print_success "System check completed"
}

# Main installation function
main() {
    print_status "Starting Metasploit-AI installation..."
    
    # Parse arguments
    dev_mode=false
    if [[ "$1" == "--dev" ]]; then
        dev_mode=true
        print_status "Development mode enabled"
    fi
    
    # Check if we're in the correct directory
    if [[ ! -f "setup.py" ]] || [[ ! -f "requirements.txt" ]]; then
        print_error "Please run this script from the Metasploit-AI root directory"
        exit 1
    fi
    
    # Installation steps
    install_system_deps
    check_metasploit
    setup_venv
    
    if [[ "$dev_mode" == true ]]; then
        install_python_deps "dev"
    else
        install_python_deps
    fi
    
    setup_config
    download_models
    init_database
    install_framework
    run_system_check
    
    # Success message
    echo ""
    print_success "Metasploit-AI installation completed successfully!"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo -e "  1. Activate virtual environment: ${YELLOW}source venv/bin/activate${NC}"
    echo -e "  2. Start Metasploit RPC: ${YELLOW}sudo msfconsole -x \"load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf\"${NC}"
    echo -e "  3. Configure settings: ${YELLOW}nano config/config.yaml${NC}"
    echo -e "  4. Start web interface: ${YELLOW}python app.py --mode web${NC}"
    echo -e "  5. Start CLI interface: ${YELLOW}python app.py --mode cli${NC}"
    echo ""
    echo -e "${CYAN}Documentation:${NC} docs/README.md"
    echo -e "${CYAN}Support:${NC} yashabalam707@gmail.com"
    echo -e "${CYAN}Website:${NC} https://www.zehrasec.com"
    echo ""
    echo -e "${PURPLE}Thank you for using Metasploit-AI!${NC}"
    echo -e "${YELLOW}Created with ❤️ by Yashab Alam (ZehraSec)${NC}"
}

# Run main function
main "$@"
