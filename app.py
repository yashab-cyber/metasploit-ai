#!/usr/bin/env python3
"""
Metasploit-AI Framework
Advanced AI-powered cybersecurity and penetration testing framework

Author: Cybersecurity Team
Version: 1.0.0
License: MIT
"""

import sys
import os
import argparse
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.core.framework import MetasploitAIFramework
from src.core.config import Config
from src.utils.logger import setup_logger
from src.web.app import create_web_app

def main():
    """Main entry point for Metasploit-AI Framework"""
    parser = argparse.ArgumentParser(
        description="Metasploit-AI Framework - Advanced AI-powered cybersecurity tool"
    )
    
    parser.add_argument(
        '--mode', 
        choices=['cli', 'web', 'gui', 'api'], 
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
    
    # Setup logging
    log_level = 'DEBUG' if args.debug else 'INFO'
    logger = setup_logger('metasploit-ai', log_level)
    
    try:
        # Initialize configuration
        config = Config.load_config(args.config)
        
        # Initialize framework
        framework = MetasploitAIFramework(config)
        
        logger.info("🚀 Starting Metasploit-AI Framework")
        logger.info(f"Mode: {args.mode}")
        logger.info(f"Config: {args.config}")
        
        if args.mode == 'cli':
            # Start CLI interface
            from src.cli.interface import start_cli_interface
            return start_cli_interface(framework)
            
        elif args.mode == 'web':
            # Start web interface
            app, socketio = create_web_app(framework)
            logger.info(f"🌐 Starting web server on http://{args.host}:{args.port}")
            socketio.run(app, host=args.host, port=args.port, debug=args.debug)
            
        elif args.mode == 'gui':
            # Start GUI interface
            logger.info("🖥️ Starting desktop GUI interface")
            try:
                from src.gui import start_gui_interface
                return start_gui_interface(framework)
            except ImportError as e:
                logger.error("❌ GUI dependencies not available. Install with: pip install customtkinter pillow")
                logger.error(f"Import error: {e}")
                sys.exit(1)
            
        elif args.mode == 'api':
            # Start API server (future implementation)
            logger.warning("⚠️ API mode not yet implemented")
            logger.info("💡 Use 'web' mode for web interface with API endpoints")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("🛑 Framework stopped by user")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"❌ Framework error: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
