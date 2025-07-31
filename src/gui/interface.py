"""
GUI Interface Module
Entry point for the desktop GUI application
"""

# This file is created for consistency but the main GUI implementation
# is in __init__.py to avoid circular imports
from . import MetasploitAIGUI, start_gui_interface

__all__ = ['MetasploitAIGUI', 'start_gui_interface']
