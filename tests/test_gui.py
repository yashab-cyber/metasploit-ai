#!/usr/bin/env python3
"""
Metasploit-AI Framework GUI Test
Quick test of the GUI interface without heavy dependencies
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Mock framework for testing
class MockFramework:
    """Mock framework for GUI testing"""
    
    def __init__(self):
        self.config = MockConfig()
        self.logger = MockLogger()
    
    def get_status(self):
        return {"status": "ready", "ai_engine": "online", "database": "connected"}

class MockConfig:
    """Mock configuration"""
    
    def __init__(self):
        self.data = {
            "framework": {
                "name": "Metasploit-AI",
                "version": "1.0.0"
            }
        }

class MockLogger:
    """Mock logger"""
    
    def info(self, message):
        print(f"INFO: {message}")
    
    def error(self, message):
        print(f"ERROR: {message}")
    
    def warning(self, message):
        print(f"WARNING: {message}")

def main():
    """Test the GUI interface"""
    print("🚀 Starting Metasploit-AI GUI Test")
    
    try:
        # Test GUI dependencies
        try:
            import customtkinter as ctk
            print("✅ CustomTkinter available")
        except ImportError:
            print("❌ CustomTkinter not installed")
            print("💡 Install with: pip install customtkinter")
            return 1
        
        try:
            from PIL import Image, ImageTk
            print("✅ Pillow available")
        except ImportError:
            print("❌ Pillow not installed")
            print("💡 Install with: pip install pillow")
            return 1
        
        # Test GUI import
        try:
            from src.gui import MetasploitAIGUI, start_gui_interface
            print("✅ GUI module imported successfully")
        except ImportError as e:
            print(f"❌ GUI module import failed: {e}")
            return 1
        
        # Create mock framework
        framework = MockFramework()
        
        # Start GUI
        print("🖥️ Starting GUI interface...")
        print("📝 Note: This is a test run with mock data")
        
        return start_gui_interface(framework)
        
    except KeyboardInterrupt:
        print("\n🛑 GUI test stopped by user")
        return 0
    except Exception as e:
        print(f"❌ GUI test error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
