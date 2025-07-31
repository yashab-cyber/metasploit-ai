#!/usr/bin/env python3
"""
Test script for Metasploit-AI Framework interfaces
This demonstrates the different interface modes without requiring full dependencies
"""

import sys
import argparse

def main():
    """Main entry point for testing interface modes"""
    parser = argparse.ArgumentParser(
        description="Metasploit-AI Framework - Advanced AI-powered cybersecurity tool"
    )
    
    parser.add_argument(
        '--mode', 
        choices=['cli', 'web', 'gui'], 
        default='cli',
        help='Execution mode (default: cli)'
    )
    
    parser.add_argument(
        '--config', 
        type=str, 
        default='config/default.yaml',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--debug', 
        action='store_true',
        help='Enable debug mode'
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=8080,
        help='Web server port (default: 8080)'
    )
    
    parser.add_argument(
        '--host', 
        type=str, 
        default='127.0.0.1',
        help='Web server host (default: 127.0.0.1)'
    )
    
    args = parser.parse_args()
    
    print("🚀 Metasploit-AI Framework - Interface Test")
    print(f"Mode: {args.mode}")
    print(f"Config: {args.config}")
    print(f"Debug: {args.debug}")
    
    if args.mode == 'cli':
        print("\n🖥️  CLI Mode Selected")
        print("Features:")
        print("  • Rich terminal interface with colors")
        print("  • Interactive command completion")
        print("  • AI-powered recommendations")
        print("  • Real-time scanning and exploitation")
        print("  • Session management")
        print("\nTo start CLI interface:")
        print("  python app.py --mode cli")
        
    elif args.mode == 'web':
        print(f"\n🌐 Web Mode Selected")
        print(f"Server: http://{args.host}:{args.port}")
        print("Features:")
        print("  • Modern web dashboard")
        print("  • Real-time updates via WebSocket")
        print("  • Bootstrap 5 responsive design")
        print("  • AI analysis and reporting")
        print("  • Session-based authentication")
        print("\nTo start web interface:")
        print(f"  python app.py --mode web --host {args.host} --port {args.port}")
        
    elif args.mode == 'gui':
        print("\n🖥️  GUI Mode Selected")
        print("Features:")
        print("  • Desktop application with CustomTkinter")
        print("  • Dark themed modern interface")
        print("  • Drag-and-drop target import")
        print("  • Real-time progress monitoring")
        print("  • Interactive AI assistant chat")
        print("\nTo start GUI interface:")
        print("  python app.py --mode gui")
        print("\nGUI Dependencies:")
        print("  pip install customtkinter pillow")
    
    print(f"\n📁 Configuration file: {args.config}")
    print("💡 Use --debug flag for verbose output")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
