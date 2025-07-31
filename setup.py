#!/usr/bin/env python3
"""
Setup script for Metasploit-AI Framework
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")

def check_metasploit():
    """Check if Metasploit Framework is installed"""
    try:
        result = subprocess.run(['msfconsole', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Metasploit Framework detected")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    print("⚠️  Metasploit Framework not detected")
    print("Please install Metasploit Framework: https://metasploit.help.rapid7.com/docs/installing-metasploit")
    return False

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = [
        'data',
        'data/exploits',
        'data/payloads',
        'data/reports',
        'data/models',
        'logs',
        'config',
        'modules',
        'modules/exploits',
        'modules/payloads',
        'modules/scanners',
        'modules/ai'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Created directory: {directory}")

def create_config():
    """Create default configuration files"""
    config_content = """# Metasploit-AI Framework Configuration
framework:
  name: "Metasploit-AI"
  version: "1.0.0"
  debug: false

metasploit:
  host: "127.0.0.1"
  port: 55553
  username: "msf"
  password: "msf"
  ssl: false

ai:
  enabled: true
  models_path: "data/models"
  openai_api_key: ""
  
database:
  type: "sqlite"
  path: "data/metasploit_ai.db"

logging:
  level: "INFO"
  file: "logs/metasploit_ai.log"
  max_size: "10MB"
  backup_count: 5

web:
  host: "127.0.0.1"
  port: 8080
  secret_key: "change-this-secret-key"

security:
  api_key_required: true
  rate_limit: 100
  max_concurrent_scans: 5
"""
    
    with open('config/default.yaml', 'w') as f:
        f.write(config_content)
    print("⚙️  Created default configuration")

def main():
    """Main setup function"""
    print("🚀 Setting up Metasploit-AI Framework...")
    print("="*50)
    
    # Check Python version
    check_python_version()
    
    # Check Metasploit
    check_metasploit()
    
    # Create directories
    create_directories()
    
    # Install dependencies
    install_dependencies()
    
    # Create configuration
    create_config()
    
    print("\n" + "="*50)
    print("✅ Setup completed successfully!")
    print("\nNext steps:")
    print("1. Review and update config/default.yaml")
    print("2. Run: python app.py --mode web")
    print("3. Visit: http://127.0.0.1:8080")
    print("\nFor CLI mode: python app.py --mode cli")

if __name__ == "__main__":
    main()
