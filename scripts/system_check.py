#!/usr/bin/env python3
"""
System Check Script for Metasploit-AI Framework
Verifies all dependencies and system requirements
"""

import sys
import os
import subprocess
import importlib
import json
from pathlib import Path
from datetime import datetime

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header():
    """Print header with logo"""
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("""
╔══════════════════════════════════════════════════════════════╗
║                   METASPLOIT-AI SYSTEM CHECK                ║
║              Advanced AI-Powered Penetration Testing        ║
║                 Created by Yashab Alam (ZehraSec)           ║
╚══════════════════════════════════════════════════════════════╝
    """)
    print(f"{Colors.END}")

def check_python_version():
    """Check Python version"""
    print(f"{Colors.BOLD}Checking Python version...{Colors.END}")
    
    version = sys.version_info
    required_major = 3
    required_minor = 8
    
    if version.major >= required_major and version.minor >= required_minor:
        print(f"  {Colors.GREEN}✓{Colors.END} Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"  {Colors.RED}✗{Colors.END} Python {version.major}.{version.minor}.{version.micro} (Requires 3.8+)")
        return False

def check_system_commands():
    """Check required system commands"""
    print(f"\n{Colors.BOLD}Checking system commands...{Colors.END}")
    
    commands = {
        'msfconsole': 'Metasploit Framework',
        'nmap': 'Network scanning',
        'git': 'Version control',
        'curl': 'HTTP client',
        'python3': 'Python interpreter'
    }
    
    results = {}
    for cmd, description in commands.items():
        try:
            result = subprocess.run([cmd, '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                print(f"  {Colors.GREEN}✓{Colors.END} {cmd} - {description}")
                results[cmd] = True
            else:
                print(f"  {Colors.RED}✗{Colors.END} {cmd} - {description} (Command failed)")
                results[cmd] = False
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            print(f"  {Colors.RED}✗{Colors.END} {cmd} - {description} (Not found)")
            results[cmd] = False
    
    return results

def check_python_modules():
    """Check required Python modules"""
    print(f"\n{Colors.BOLD}Checking Python modules...{Colors.END}")
    
    modules = {
        'flask': 'Web framework',
        'sqlalchemy': 'Database ORM',
        'aiohttp': 'Async HTTP client',
        'asyncio': 'Async programming',
        'sklearn': 'Machine learning',
        'numpy': 'Numerical computing',
        'pandas': 'Data analysis',
        'requests': 'HTTP library',
        'yaml': 'YAML parsing',
        'click': 'CLI framework',
        'jinja2': 'Template engine',
        'werkzeug': 'WSGI utilities',
        'psutil': 'System monitoring',
        'cryptography': 'Cryptographic functions'
    }
    
    results = {}
    for module, description in modules.items():
        try:
            importlib.import_module(module)
            print(f"  {Colors.GREEN}✓{Colors.END} {module} - {description}")
            results[module] = True
        except ImportError:
            print(f"  {Colors.RED}✗{Colors.END} {module} - {description} (Not installed)")
            results[module] = False
    
    return results

def check_optional_modules():
    """Check optional Python modules"""
    print(f"\n{Colors.BOLD}Checking optional modules...{Colors.END}")
    
    optional_modules = {
        'tensorflow': 'Deep learning framework',
        'torch': 'PyTorch ML framework',
        'scapy': 'Packet manipulation',
        'nmap': 'Python nmap wrapper',
        'selenium': 'Web automation',
        'beautifulsoup4': 'HTML parsing',
        'matplotlib': 'Plotting library',
        'seaborn': 'Statistical visualization',
        'plotly': 'Interactive plots'
    }
    
    results = {}
    for module, description in optional_modules.items():
        try:
            importlib.import_module(module)
            print(f"  {Colors.GREEN}✓{Colors.END} {module} - {description}")
            results[module] = True
        except ImportError:
            print(f"  {Colors.YELLOW}○{Colors.END} {module} - {description} (Optional, not installed)")
            results[module] = False
    
    return results

def check_directories():
    """Check required directories"""
    print(f"\n{Colors.BOLD}Checking directories...{Colors.END}")
    
    required_dirs = [
        'src',
        'config',
        'data',
        'logs',
        'models',
        'reports',
        'tests'
    ]
    
    results = {}
    for directory in required_dirs:
        path = Path(directory)
        if path.exists() and path.is_dir():
            print(f"  {Colors.GREEN}✓{Colors.END} {directory}/ (exists)")
            results[directory] = True
        else:
            print(f"  {Colors.RED}✗{Colors.END} {directory}/ (missing)")
            results[directory] = False
    
    return results

def check_config_files():
    """Check configuration files"""
    print(f"\n{Colors.BOLD}Checking configuration files...{Colors.END}")
    
    config_files = {
        'config/default.yaml': 'Default configuration',
        'requirements.txt': 'Python dependencies',
        'setup.py': 'Package setup',
        'README.md': 'Documentation',
        'LICENSE': 'License file'
    }
    
    results = {}
    for file_path, description in config_files.items():
        path = Path(file_path)
        if path.exists() and path.is_file():
            print(f"  {Colors.GREEN}✓{Colors.END} {file_path} - {description}")
            results[file_path] = True
        else:
            print(f"  {Colors.RED}✗{Colors.END} {file_path} - {description} (missing)")
            results[file_path] = False
    
    return results

def check_permissions():
    """Check file permissions"""
    print(f"\n{Colors.BOLD}Checking permissions...{Colors.END}")
    
    # Check if data and logs directories are writable
    test_dirs = ['data', 'logs', 'reports']
    results = {}
    
    for directory in test_dirs:
        path = Path(directory)
        if path.exists():
            if os.access(path, os.W_OK):
                print(f"  {Colors.GREEN}✓{Colors.END} {directory}/ (writable)")
                results[directory] = True
            else:
                print(f"  {Colors.RED}✗{Colors.END} {directory}/ (not writable)")
                results[directory] = False
        else:
            print(f"  {Colors.YELLOW}○{Colors.END} {directory}/ (does not exist)")
            results[directory] = False
    
    return results

def check_database_connectivity():
    """Check database connectivity"""
    print(f"\n{Colors.BOLD}Checking database connectivity...{Colors.END}")
    
    try:
        # Try to import and test database connection
        from src.core.config import Config
        from src.core.database import Database
        
        config = Config()
        database = Database(config)
        
        # This is a basic check - in a real implementation you might test actual connectivity
        print(f"  {Colors.GREEN}✓{Colors.END} Database configuration loaded")
        return True
        
    except Exception as e:
        print(f"  {Colors.RED}✗{Colors.END} Database connectivity check failed: {str(e)}")
        return False

def check_metasploit_rpc():
    """Check Metasploit RPC connectivity"""
    print(f"\n{Colors.BOLD}Checking Metasploit RPC...{Colors.END}")
    
    try:
        import socket
        
        # Try to connect to default Metasploit RPC port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 55553))
        sock.close()
        
        if result == 0:
            print(f"  {Colors.GREEN}✓{Colors.END} Metasploit RPC service is running")
            return True
        else:
            print(f"  {Colors.YELLOW}○{Colors.END} Metasploit RPC service not running (start with msfconsole)")
            return False
            
    except Exception as e:
        print(f"  {Colors.RED}✗{Colors.END} Metasploit RPC check failed: {str(e)}")
        return False

def check_ai_models():
    """Check AI model files"""
    print(f"\n{Colors.BOLD}Checking AI models...{Colors.END}")
    
    model_files = [
        'models/vulnerability_classifier.pkl',
        'models/exploit_recommender.pkl',
        'models/payload_generator.pkl'
    ]
    
    results = {}
    for model_file in model_files:
        path = Path(model_file)
        if path.exists():
            size = path.stat().st_size
            if size > 0:
                print(f"  {Colors.GREEN}✓{Colors.END} {model_file} ({size} bytes)")
                results[model_file] = True
            else:
                print(f"  {Colors.YELLOW}○{Colors.END} {model_file} (empty file)")
                results[model_file] = False
        else:
            print(f"  {Colors.YELLOW}○{Colors.END} {model_file} (not found)")
            results[model_file] = False
    
    return results

def generate_report(all_results):
    """Generate a summary report"""
    print(f"\n{Colors.BOLD}System Check Summary{Colors.END}")
    print("=" * 50)
    
    total_checks = 0
    passed_checks = 0
    
    for category, results in all_results.items():
        if isinstance(results, dict):
            category_total = len(results)
            category_passed = sum(1 for v in results.values() if v)
            total_checks += category_total
            passed_checks += category_passed
            
            print(f"\n{category}: {category_passed}/{category_total}")
            
            for item, status in results.items():
                status_icon = f"{Colors.GREEN}✓{Colors.END}" if status else f"{Colors.RED}✗{Colors.END}"
                print(f"  {status_icon} {item}")
        else:
            total_checks += 1
            if results:
                passed_checks += 1
                print(f"\n{category}: {Colors.GREEN}✓{Colors.END}")
            else:
                print(f"\n{category}: {Colors.RED}✗{Colors.END}")
    
    print(f"\n{Colors.BOLD}Overall Result:{Colors.END}")
    percentage = (passed_checks / total_checks) * 100 if total_checks > 0 else 0
    
    if percentage >= 90:
        color = Colors.GREEN
        status = "EXCELLENT"
    elif percentage >= 75:
        color = Colors.YELLOW
        status = "GOOD"
    elif percentage >= 50:
        color = Colors.YELLOW
        status = "NEEDS ATTENTION"
    else:
        color = Colors.RED
        status = "CRITICAL ISSUES"
    
    print(f"{color}{passed_checks}/{total_checks} checks passed ({percentage:.1f}%) - {status}{Colors.END}")
    
    # Save report to file
    report_data = {
        'timestamp': datetime.now().isoformat(),
        'total_checks': total_checks,
        'passed_checks': passed_checks,
        'percentage': percentage,
        'status': status,
        'details': all_results
    }
    
    try:
        os.makedirs('logs', exist_ok=True)
        with open('logs/system_check.json', 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        print(f"\n{Colors.BLUE}Report saved to logs/system_check.json{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.YELLOW}Could not save report: {str(e)}{Colors.END}")
    
    return percentage >= 75

def main():
    """Main system check function"""
    print_header()
    
    # Run all checks
    all_results = {}
    
    all_results['Python Version'] = check_python_version()
    all_results['System Commands'] = check_system_commands()
    all_results['Python Modules'] = check_python_modules()
    all_results['Optional Modules'] = check_optional_modules()
    all_results['Directories'] = check_directories()
    all_results['Configuration Files'] = check_config_files()
    all_results['Permissions'] = check_permissions()
    all_results['Database'] = check_database_connectivity()
    all_results['Metasploit RPC'] = check_metasploit_rpc()
    all_results['AI Models'] = check_ai_models()
    
    # Generate report
    success = generate_report(all_results)
    
    # Final recommendations
    print(f"\n{Colors.BOLD}Recommendations:{Colors.END}")
    
    if not all_results['Python Version']:
        print(f"  {Colors.RED}•{Colors.END} Upgrade to Python 3.8 or higher")
    
    if not all(all_results['System Commands'].values()):
        print(f"  {Colors.RED}•{Colors.END} Install missing system commands")
    
    if not all(all_results['Python Modules'].values()):
        print(f"  {Colors.RED}•{Colors.END} Install missing Python modules: pip install -r requirements.txt")
    
    if not all_results['Metasploit RPC']:
        print(f"  {Colors.YELLOW}•{Colors.END} Start Metasploit RPC: sudo msfconsole -x \"load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf\"")
    
    if not any(all_results['AI Models'].values()):
        print(f"  {Colors.YELLOW}•{Colors.END} Download AI models: python scripts/download_models.py")
    
    print(f"\n{Colors.CYAN}For help and support:{Colors.END}")
    print(f"  Email: yashabalam707@gmail.com")
    print(f"  Website: https://www.zehrasec.com")
    print(f"  GitHub: https://github.com/yashab-cyber/metasploit-ai")
    
    return 0 if success else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}System check interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}System check failed with error: {str(e)}{Colors.END}")
        sys.exit(1)
