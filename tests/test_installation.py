#!/usr/bin/env python3
"""
Metasploit-AI Installation Test Script
Verifies that the framework is properly installed and configured
"""

import sys
import os
import subprocess
from pathlib import Path

def test_imports():
    """Test if all core modules can be imported"""
    print("🔍 Testing imports...")
    try:
        from src.core.config import Config
        from src.core.framework import MetasploitAIFramework
        from src.utils.logger import setup_logger
        print("✅ Core imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_config():
    """Test configuration loading"""
    print("⚙️ Testing configuration...")
    try:
        from src.core.config import Config
        config = Config.load_config()
        print(f"✅ Config loaded: {config.framework['name']} v{config.framework['version']}")
        return True
    except Exception as e:
        print(f"❌ Config error: {e}")
        return False

def test_framework_init():
    """Test framework initialization"""
    print("🚀 Testing framework initialization...")
    try:
        from src.core.config import Config
        from src.core.framework import MetasploitAIFramework
        
        config = Config.load_config()
        framework = MetasploitAIFramework(config)
        print("✅ Framework initialization successful")
        return True
    except Exception as e:
        print(f"❌ Framework initialization error: {e}")
        return False

def test_cli_help():
    """Test CLI help command"""
    print("📋 Testing CLI help...")
    try:
        result = subprocess.run([sys.executable, 'app.py', '--help'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and 'Metasploit-AI Framework' in result.stdout:
            print("✅ CLI help working")
            return True
        else:
            print(f"❌ CLI help failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ CLI test error: {e}")
        return False

def test_dependencies():
    """Test key dependencies"""
    print("📦 Testing dependencies...")
    required_packages = [
        'flask', 'requests', 'sqlalchemy', 'pytest',
        'yaml', 'cryptography', 'paramiko'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"❌ Missing packages: {', '.join(missing)}")
        return False
    else:
        print("✅ All key dependencies available")
        return True

def main():
    """Run all tests"""
    print("🧪 Metasploit-AI Installation Test")
    print("=" * 40)
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Imports", test_imports),
        ("Configuration", test_config),
        ("Framework Init", test_framework_init),
        ("CLI Help", test_cli_help)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔧 Running {test_name} test...")
        try:
            if test_func():
                passed += 1
            else:
                print(f"⚠️ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
    
    print("\n" + "=" * 40)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Metasploit-AI is ready to use.")
        print("\n📝 Next steps:")
        print("   • Start CLI: python app.py --mode cli")
        print("   • Start Web: python app.py --mode web --host 0.0.0.0 --port 8080")
        print("   • Run tests: pytest tests/")
        return 0
    else:
        print("⚠️ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
