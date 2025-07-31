"""
GUI Module for Metasploit-AI Framework
Modern desktop interface built with CustomTkinter
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
from PIL import Image, ImageTk
import threading
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
import sys
import os

# Set appearance mode and color theme
ctk.set_appearance_mode("dark")  # "system", "light", "dark"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"

class MetasploitAIGUI:
    """Main GUI application for Metasploit-AI Framework"""
    
    def __init__(self, framework):
        self.framework = framework
        self.current_target = None
        self.current_exploit = None
        self.scan_results = {}
        self.sessions = {}
        self.jobs = {}
        
        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("Metasploit-AI Framework - Advanced Penetration Testing")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Load and set icon
        self.setup_icon()
        
        # Initialize GUI components
        self.setup_styles()
        self.create_menu()
        self.create_layout()
        self.create_widgets()
        self.create_status_bar()
        
        # Start background tasks
        self.start_background_tasks()
    
    def setup_icon(self):
        """Set up application icon"""
        try:
            # Try multiple paths for the logo
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "..", "public", "Metaspolit-AI.png"),
                os.path.join(os.path.dirname(__file__), "..", "web", "static", "images", "Metaspolit-AI.png"),
                "src/public/Metaspolit-AI.png",
                "src/web/static/images/Metaspolit-AI.png"
            ]
            
            icon_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    icon_path = path
                    break
            
            if icon_path:
                print(f"Loading GUI icon from: {icon_path}")
                icon_image = Image.open(icon_path)
                icon_image = icon_image.resize((32, 32), Image.Resampling.LANCZOS)
                self.icon = ImageTk.PhotoImage(icon_image)
                self.root.iconphoto(True, self.icon)
                print("✅ GUI window icon loaded successfully")
            else:
                print("⚠️ Warning: Could not find logo file for window icon")
        except Exception as e:
            print(f"❌ Warning: Could not load window icon: {e}")
    
    def setup_styles(self):
        """Configure custom styles and colors"""
        self.colors = {
            'primary': '#1f6aa5',
            'success': '#198754',
            'danger': '#dc3545',
            'warning': '#ffc107',
            'info': '#0dcaf0',
            'dark': '#212529',
            'light': '#f8f9fa'
        }
    
    def create_menu(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Project", command=self.new_project)
        file_menu.add_command(label="Open Project", command=self.open_project)
        file_menu.add_command(label="Save Project", command=self.save_project)
        file_menu.add_separator()
        file_menu.add_command(label="Import Targets", command=self.import_targets)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Scanner", command=self.open_scanner)
        tools_menu.add_command(label="Exploit Browser", command=self.open_exploit_browser)
        tools_menu.add_command(label="Payload Generator", command=self.open_payload_generator)
        tools_menu.add_command(label="Session Manager", command=self.open_session_manager)
        
        # AI menu
        ai_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="AI", menu=ai_menu)
        ai_menu.add_command(label="Target Analysis", command=self.ai_analyze_target)
        ai_menu.add_command(label="Exploit Recommendations", command=self.ai_recommend_exploits)
        ai_menu.add_command(label="Payload Optimization", command=self.ai_optimize_payload)
        ai_menu.add_command(label="Generate Report", command=self.ai_generate_report)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Console", command=self.toggle_console)
        view_menu.add_command(label="Logs", command=self.show_logs)
        view_menu.add_command(label="Jobs", command=self.show_jobs)
        view_menu.add_separator()
        view_menu.add_command(label="Full Screen", command=self.toggle_fullscreen)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="Tutorials", command=self.show_tutorials)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_layout(self):
        """Create main application layout"""
        # Main container
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header frame with logo and title
        self.header_frame = ctk.CTkFrame(self.main_frame)
        self.header_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        # Content area with tabview
        self.content_frame = ctk.CTkFrame(self.main_frame)
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Status bar frame
        self.status_frame = ctk.CTkFrame(self.main_frame)
        self.status_frame.pack(fill="x", padx=10, pady=(5, 10))
    
    def create_widgets(self):
        """Create all GUI widgets"""
        self.create_header()
        self.create_tabview()
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_exploits_tab()
        self.create_payloads_tab()
        self.create_sessions_tab()
        self.create_reports_tab()
        self.create_ai_tab()
        self.create_console_tab()
    
    def create_header(self):
        """Create header with logo and title"""
        # Logo and title
        title_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_frame.pack(side="left", fill="y", padx=10, pady=10)
        
        # Load logo
        try:
            # Try multiple paths for the header logo
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "..", "public", "Metaspolit-AI.png"),
                os.path.join(os.path.dirname(__file__), "..", "web", "static", "images", "Metaspolit-AI.png"),
                "src/public/Metaspolit-AI.png",
                "src/web/static/images/Metaspolit-AI.png"
            ]
            
            logo_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    logo_path = path
                    break
            
            if logo_path:
                print(f"Loading header logo from: {logo_path}")
                logo_image = Image.open(logo_path)
                logo_image = logo_image.resize((80, 80), Image.Resampling.LANCZOS)
                self.logo_photo = ctk.CTkImage(light_image=logo_image, dark_image=logo_image, size=(80, 80))
                
                logo_label = ctk.CTkLabel(
                    title_frame, 
                    image=self.logo_photo, 
                    text="",
                    width=80,
                    height=80
                )
                logo_label.pack(side="left", padx=(0, 20))
                print("✅ Header logo loaded successfully")
            else:
                print("⚠️ Warning: Could not find logo file for header")
                # Create a placeholder if no logo found
                placeholder_label = ctk.CTkLabel(
                    title_frame,
                    text="🛡️",
                    font=ctk.CTkFont(size=48),
                    width=80,
                    height=80
                )
                placeholder_label.pack(side="left", padx=(0, 20))
        except Exception as e:
            print(f"❌ Warning: Could not load header logo: {e}")
            # Create a placeholder if logo loading fails
            placeholder_label = ctk.CTkLabel(
                title_frame,
                text="🛡️",
                font=ctk.CTkFont(size=48),
                width=80,
                height=80
            )
            placeholder_label.pack(side="left", padx=(0, 20))
        
        # Title and subtitle
        title_text_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        title_text_frame.pack(side="left", fill="y")
        
        title_label = ctk.CTkLabel(
            title_text_frame, 
            text="Metasploit-AI Framework",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack(anchor="w")
        
        subtitle_label = ctk.CTkLabel(
            title_text_frame,
            text="Advanced AI-Powered Penetration Testing Platform",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle_label.pack(anchor="w")
        
        # Status indicators
        status_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        status_frame.pack(side="right", fill="y", padx=10, pady=10)
        
        # AI Status
        self.ai_status_label = ctk.CTkLabel(
            status_frame,
            text="🤖 AI Engine: Online",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="green"
        )
        self.ai_status_label.pack(anchor="e", pady=2)
        
        # Database Status
        self.db_status_label = ctk.CTkLabel(
            status_frame,
            text="🗄️ Database: Connected",
            font=ctk.CTkFont(size=12),
            text_color="green"
        )
        self.db_status_label.pack(anchor="e", pady=2)
        
        # Current Time
        self.time_label = ctk.CTkLabel(
            status_frame,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.time_label.pack(anchor="e", pady=2)
        self.update_time()
    
    def create_tabview(self):
        """Create main tabview for different sections"""
        self.tabview = ctk.CTkTabview(self.content_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add tabs
        self.tab_dashboard = self.tabview.add("Dashboard")
        self.tab_scanner = self.tabview.add("Scanner")
        self.tab_exploits = self.tabview.add("Exploits")
        self.tab_payloads = self.tabview.add("Payloads")
        self.tab_sessions = self.tabview.add("Sessions")
        self.tab_reports = self.tabview.add("Reports")
        self.tab_ai = self.tabview.add("AI Assistant")
        self.tab_console = self.tabview.add("Console")
    
    def create_dashboard_tab(self):
        """Create dashboard tab with overview"""
        # Welcome panel with logo
        welcome_frame = ctk.CTkFrame(self.tab_dashboard)
        welcome_frame.pack(fill="x", padx=20, pady=20)
        
        # Welcome header with logo
        welcome_header = ctk.CTkFrame(welcome_frame, fg_color="transparent")
        welcome_header.pack(pady=20)
        
        # Add logo to welcome panel
        try:
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "..", "public", "Metaspolit-AI.png"),
                os.path.join(os.path.dirname(__file__), "..", "web", "static", "images", "Metaspolit-AI.png"),
                "src/public/Metaspolit-AI.png",
                "src/web/static/images/Metaspolit-AI.png"
            ]
            
            logo_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    logo_path = path
                    break
            
            if logo_path:
                welcome_logo_image = Image.open(logo_path)
                welcome_logo_image = welcome_logo_image.resize((100, 100), Image.Resampling.LANCZOS)
                self.welcome_logo_photo = ctk.CTkImage(light_image=welcome_logo_image, dark_image=welcome_logo_image, size=(100, 100))
                
                welcome_logo_label = ctk.CTkLabel(
                    welcome_header,
                    image=self.welcome_logo_photo,
                    text=""
                )
                welcome_logo_label.pack(pady=(0, 10))
        except Exception as e:
            print(f"Warning: Could not load welcome logo: {e}")
        
        welcome_label = ctk.CTkLabel(
            welcome_header,
            text="Welcome to Metasploit-AI Framework",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        welcome_label.pack()
        
        subtitle_label = ctk.CTkLabel(
            welcome_header,
            text="Advanced AI-Powered Penetration Testing Platform",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle_label.pack(pady=(5, 0))
        
        # Quick stats grid
        stats_frame = ctk.CTkFrame(self.tab_dashboard)
        stats_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # Configure grid
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # Stats cards
        self.create_stat_card(stats_frame, "Active Scans", "0", "🔍", 0, 0)
        self.create_stat_card(stats_frame, "Vulnerabilities", "0", "⚠️", 0, 1)
        self.create_stat_card(stats_frame, "Active Sessions", "0", "💻", 0, 2)
        self.create_stat_card(stats_frame, "AI Recommendations", "0", "🤖", 0, 3)
        
        # Recent activity
        activity_frame = ctk.CTkFrame(self.tab_dashboard)
        activity_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        activity_label = ctk.CTkLabel(
            activity_frame,
            text="Recent Activity",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        activity_label.pack(pady=(20, 10))
        
        # Activity log
        self.activity_text = ctk.CTkTextbox(activity_frame, height=200)
        self.activity_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Initial activity log entry
        self.log_activity("Framework initialized successfully")
        self.log_activity("AI engine loaded and ready")
        self.log_activity("Database connection established")
    
    def create_stat_card(self, parent, title, value, icon, row, col):
        """Create a statistics card"""
        card = ctk.CTkFrame(parent)
        card.grid(row=row, column=col, padx=10, pady=10, sticky="ew")
        
        icon_label = ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=24))
        icon_label.pack(pady=(15, 5))
        
        title_label = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=14, weight="bold"))
        title_label.pack()
        
        value_label = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=20, weight="bold"))
        value_label.pack(pady=(5, 15))
        
        # Store reference for updates
        setattr(self, f"stat_{title.lower().replace(' ', '_')}_value", value_label)
    
    def create_scanner_tab(self):
        """Create network scanner tab"""
        # Target input frame
        target_frame = ctk.CTkFrame(self.tab_scanner)
        target_frame.pack(fill="x", padx=20, pady=20)
        
        target_label = ctk.CTkLabel(target_frame, text="Target Configuration", font=ctk.CTkFont(size=18, weight="bold"))
        target_label.pack(pady=(15, 10))
        
        # Target input
        input_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(input_frame, text="Target (IP/CIDR):").pack(side="left", padx=(0, 10))
        
        self.target_entry = ctk.CTkEntry(input_frame, placeholder_text="192.168.1.0/24")
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.scan_button = ctk.CTkButton(
            input_frame,
            text="Start Scan",
            command=self.start_scan,
            width=100
        )
        self.scan_button.pack(side="right")
        
        # Scan options
        options_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        self.scan_type = ctk.CTkOptionMenu(
            options_frame,
            values=["Quick Scan", "Full Scan", "Stealth Scan", "Aggressive Scan"]
        )
        self.scan_type.pack(side="left", padx=(0, 10))
        
        self.ai_analysis = ctk.CTkCheckBox(options_frame, text="Enable AI Analysis")
        self.ai_analysis.pack(side="left", padx=(0, 10))
        self.ai_analysis.select()  # Enable by default
        
        # Progress bar
        self.scan_progress = ctk.CTkProgressBar(target_frame)
        self.scan_progress.pack(fill="x", padx=20, pady=(0, 15))
        self.scan_progress.set(0)
        
        # Results frame
        results_frame = ctk.CTkFrame(self.tab_scanner)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        results_label = ctk.CTkLabel(results_frame, text="Scan Results", font=ctk.CTkFont(size=18, weight="bold"))
        results_label.pack(pady=(15, 10))
        
        # Results tree
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=("IP", "Port", "Service", "State", "Version"),
            show="headings",
            height=15
        )
        
        # Configure columns
        self.results_tree.heading("IP", text="IP Address")
        self.results_tree.heading("Port", text="Port")
        self.results_tree.heading("Service", text="Service")
        self.results_tree.heading("State", text="State")
        self.results_tree.heading("Version", text="Version")
        
        self.results_tree.column("IP", width=120)
        self.results_tree.column("Port", width=80)
        self.results_tree.column("Service", width=100)
        self.results_tree.column("State", width=80)
        self.results_tree.column("Version", width=200)
        
        # Scrollbar for results
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        # Pack results tree
        self.results_tree.pack(side="left", fill="both", expand=True, padx=(20, 0), pady=(0, 20))
        results_scrollbar.pack(side="right", fill="y", pady=(0, 20))
    
    def create_exploits_tab(self):
        """Create exploits management tab"""
        # Search frame
        search_frame = ctk.CTkFrame(self.tab_exploits)
        search_frame.pack(fill="x", padx=20, pady=20)
        
        search_label = ctk.CTkLabel(search_frame, text="Exploit Search", font=ctk.CTkFont(size=18, weight="bold"))
        search_label.pack(pady=(15, 10))
        
        # Search input
        search_input_frame = ctk.CTkFrame(search_frame, fg_color="transparent")
        search_input_frame.pack(fill="x", padx=20, pady=10)
        
        self.exploit_search_entry = ctk.CTkEntry(search_input_frame, placeholder_text="Search exploits...")
        self.exploit_search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        search_btn = ctk.CTkButton(
            search_input_frame,
            text="Search",
            command=self.search_exploits,
            width=100
        )
        search_btn.pack(side="right", padx=(0, 10))
        
        ai_recommend_btn = ctk.CTkButton(
            search_input_frame,
            text="🤖 AI Recommend",
            command=self.ai_recommend_exploits,
            width=150
        )
        ai_recommend_btn.pack(side="right")
        
        # Filters
        filter_frame = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        self.platform_filter = ctk.CTkOptionMenu(
            filter_frame,
            values=["All Platforms", "Windows", "Linux", "macOS", "Multi"]
        )
        self.platform_filter.pack(side="left", padx=(0, 10))
        
        self.rank_filter = ctk.CTkOptionMenu(
            filter_frame,
            values=["All Ranks", "Excellent", "Great", "Good", "Normal", "Average"]
        )
        self.rank_filter.pack(side="left", padx=(0, 10))
        
        # Exploits list
        exploits_frame = ctk.CTkFrame(self.tab_exploits)
        exploits_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        exploits_label = ctk.CTkLabel(exploits_frame, text="Available Exploits", font=ctk.CTkFont(size=18, weight="bold"))
        exploits_label.pack(pady=(15, 10))
        
        # Exploits tree
        self.exploits_tree = ttk.Treeview(
            exploits_frame,
            columns=("Name", "Platform", "Rank", "Date"),
            show="headings",
            height=15
        )
        
        self.exploits_tree.heading("Name", text="Exploit Name")
        self.exploits_tree.heading("Platform", text="Platform")
        self.exploits_tree.heading("Rank", text="Rank")
        self.exploits_tree.heading("Date", text="Date")
        
        self.exploits_tree.column("Name", width=400)
        self.exploits_tree.column("Platform", width=100)
        self.exploits_tree.column("Rank", width=100)
        self.exploits_tree.column("Date", width=100)
        
        # Double-click to select exploit
        self.exploits_tree.bind("<Double-1>", self.select_exploit)
        
        exploits_scrollbar = ttk.Scrollbar(exploits_frame, orient="vertical", command=self.exploits_tree.yview)
        self.exploits_tree.configure(yscrollcommand=exploits_scrollbar.set)
        
        self.exploits_tree.pack(side="left", fill="both", expand=True, padx=(20, 0), pady=(0, 20))
        exploits_scrollbar.pack(side="right", fill="y", pady=(0, 20))
        
        # Load sample exploits
        self.load_sample_exploits()
    
    def create_payloads_tab(self):
        """Create payload generation tab"""
        # Configuration frame
        config_frame = ctk.CTkFrame(self.tab_payloads)
        config_frame.pack(fill="x", padx=20, pady=20)
        
        config_label = ctk.CTkLabel(config_frame, text="Payload Configuration", font=ctk.CTkFont(size=18, weight="bold"))
        config_label.pack(pady=(15, 10))
        
        # Payload options grid
        options_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=10)
        
        options_frame.grid_columnconfigure((0, 1), weight=1)
        
        # Payload type
        ctk.CTkLabel(options_frame, text="Payload Type:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=5)
        self.payload_type = ctk.CTkOptionMenu(
            options_frame,
            values=["windows/meterpreter/reverse_tcp", "linux/x86/meterpreter/reverse_tcp", "php/meterpreter/reverse_tcp"]
        )
        self.payload_type.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # LHOST
        ctk.CTkLabel(options_frame, text="LHOST:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=5)
        self.lhost_entry = ctk.CTkEntry(options_frame, placeholder_text="192.168.1.100")
        self.lhost_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # LPORT
        ctk.CTkLabel(options_frame, text="LPORT:").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=5)
        self.lport_entry = ctk.CTkEntry(options_frame, placeholder_text="4444")
        self.lport_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # Output format
        ctk.CTkLabel(options_frame, text="Output Format:").grid(row=3, column=0, sticky="w", padx=(0, 10), pady=5)
        self.output_format = ctk.CTkOptionMenu(
            options_frame,
            values=["exe", "elf", "raw", "c", "python", "powershell"]
        )
        self.output_format.grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # Options
        options_check_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        options_check_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        self.enable_encoder = ctk.CTkCheckBox(options_check_frame, text="Enable Encoding")
        self.enable_encoder.pack(side="left", padx=(0, 20))
        
        self.ai_optimization = ctk.CTkCheckBox(options_check_frame, text="AI Optimization")
        self.ai_optimization.pack(side="left")
        self.ai_optimization.select()  # Enable by default
        
        # Generate button
        generate_btn = ctk.CTkButton(
            config_frame,
            text="Generate Payload",
            command=self.generate_payload,
            height=40,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        generate_btn.pack(pady=(0, 15))
        
        # Output frame
        output_frame = ctk.CTkFrame(self.tab_payloads)
        output_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        output_label = ctk.CTkLabel(output_frame, text="Generated Payload", font=ctk.CTkFont(size=18, weight="bold"))
        output_label.pack(pady=(15, 10))
        
        self.payload_output = ctk.CTkTextbox(output_frame, height=300)
        self.payload_output.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    
    def create_sessions_tab(self):
        """Create session management tab"""
        # Sessions list
        sessions_frame = ctk.CTkFrame(self.tab_sessions)
        sessions_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        sessions_label = ctk.CTkLabel(sessions_frame, text="Active Sessions", font=ctk.CTkFont(size=18, weight="bold"))
        sessions_label.pack(pady=(15, 10))
        
        # Sessions tree
        self.sessions_tree = ttk.Treeview(
            sessions_frame,
            columns=("ID", "Type", "Info", "Via", "CheckIn", "User@Host"),
            show="headings",
            height=20
        )
        
        for col in ["ID", "Type", "Info", "Via", "CheckIn", "User@Host"]:
            self.sessions_tree.heading(col, text=col)
            self.sessions_tree.column(col, width=120)
        
        sessions_scrollbar = ttk.Scrollbar(sessions_frame, orient="vertical", command=self.sessions_tree.yview)
        self.sessions_tree.configure(yscrollcommand=sessions_scrollbar.set)
        
        self.sessions_tree.pack(side="left", fill="both", expand=True, padx=(20, 0), pady=(0, 20))
        sessions_scrollbar.pack(side="right", fill="y", pady=(0, 20))
    
    def create_reports_tab(self):
        """Create reports tab"""
        # Report configuration
        config_frame = ctk.CTkFrame(self.tab_reports)
        config_frame.pack(fill="x", padx=20, pady=20)
        
        config_label = ctk.CTkLabel(config_frame, text="Report Configuration", font=ctk.CTkFont(size=18, weight="bold"))
        config_label.pack(pady=(15, 10))
        
        # Report options
        options_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=10)
        
        options_frame.grid_columnconfigure((0, 1), weight=1)
        
        ctk.CTkLabel(options_frame, text="Report Type:").grid(row=0, column=0, sticky="w", pady=5)
        self.report_type = ctk.CTkOptionMenu(
            options_frame,
            values=["Vulnerability Assessment", "Penetration Test", "Executive Summary", "Technical Report"]
        )
        self.report_type.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        ctk.CTkLabel(options_frame, text="Format:").grid(row=1, column=0, sticky="w", pady=5)
        self.report_format = ctk.CTkOptionMenu(
            options_frame,
            values=["PDF", "HTML", "Word", "JSON"]
        )
        self.report_format.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # AI options
        ai_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        ai_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        self.include_ai_analysis = ctk.CTkCheckBox(ai_frame, text="Include AI Analysis")
        self.include_ai_analysis.pack(side="left", padx=(0, 20))
        self.include_ai_analysis.select()
        
        self.include_recommendations = ctk.CTkCheckBox(ai_frame, text="Include AI Recommendations")
        self.include_recommendations.pack(side="left")
        self.include_recommendations.select()
        
        # Generate report button
        generate_report_btn = ctk.CTkButton(
            config_frame,
            text="🤖 Generate AI Report",
            command=self.generate_report,
            height=40,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        generate_report_btn.pack(pady=(0, 15))
        
        # Reports list
        reports_frame = ctk.CTkFrame(self.tab_reports)
        reports_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        reports_label = ctk.CTkLabel(reports_frame, text="Generated Reports", font=ctk.CTkFont(size=18, weight="bold"))
        reports_label.pack(pady=(15, 10))
        
        self.reports_tree = ttk.Treeview(
            reports_frame,
            columns=("Name", "Type", "Date", "Size"),
            show="headings",
            height=15
        )
        
        for col in ["Name", "Type", "Date", "Size"]:
            self.reports_tree.heading(col, text=col)
            self.reports_tree.column(col, width=150)
        
        reports_scrollbar = ttk.Scrollbar(reports_frame, orient="vertical", command=self.reports_tree.yview)
        self.reports_tree.configure(yscrollcommand=reports_scrollbar.set)
        
        self.reports_tree.pack(side="left", fill="both", expand=True, padx=(20, 0), pady=(0, 20))
        reports_scrollbar.pack(side="right", fill="y", pady=(0, 20))
    
    def create_ai_tab(self):
        """Create AI assistant tab"""
        # AI status frame
        ai_status_frame = ctk.CTkFrame(self.tab_ai)
        ai_status_frame.pack(fill="x", padx=20, pady=20)
        
        ai_title = ctk.CTkLabel(ai_status_frame, text="🤖 AI Assistant", font=ctk.CTkFont(size=24, weight="bold"))
        ai_title.pack(pady=(15, 10))
        
        ai_description = ctk.CTkLabel(
            ai_status_frame,
            text="Advanced AI-powered vulnerability analysis and exploitation recommendations",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        ai_description.pack(pady=(0, 15))
        
        # AI capabilities grid
        capabilities_frame = ctk.CTkFrame(self.tab_ai)
        capabilities_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        capabilities_frame.grid_columnconfigure((0, 1), weight=1)
        
        # Target Analysis
        analysis_card = ctk.CTkFrame(capabilities_frame)
        analysis_card.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        ctk.CTkLabel(analysis_card, text="🎯", font=ctk.CTkFont(size=32)).pack(pady=(15, 5))
        ctk.CTkLabel(analysis_card, text="Target Analysis", font=ctk.CTkFont(size=16, weight="bold")).pack()
        ctk.CTkLabel(analysis_card, text="AI-powered vulnerability assessment", text_color="gray").pack(pady=(0, 10))
        
        analysis_btn = ctk.CTkButton(analysis_card, text="Analyze Target", command=self.ai_analyze_target)
        analysis_btn.pack(pady=(0, 15))
        
        # Exploit Recommendations
        exploit_card = ctk.CTkFrame(capabilities_frame)
        exploit_card.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        ctk.CTkLabel(exploit_card, text="💥", font=ctk.CTkFont(size=32)).pack(pady=(15, 5))
        ctk.CTkLabel(exploit_card, text="Exploit Recommendations", font=ctk.CTkFont(size=16, weight="bold")).pack()
        ctk.CTkLabel(exploit_card, text="Smart exploit selection", text_color="gray").pack(pady=(0, 10))
        
        exploit_btn = ctk.CTkButton(exploit_card, text="Get Recommendations", command=self.ai_recommend_exploits)
        exploit_btn.pack(pady=(0, 15))
        
        # AI Chat interface
        chat_frame = ctk.CTkFrame(self.tab_ai)
        chat_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        chat_label = ctk.CTkLabel(chat_frame, text="AI Chat Assistant", font=ctk.CTkFont(size=18, weight="bold"))
        chat_label.pack(pady=(15, 10))
        
        # Chat display
        self.ai_chat_display = ctk.CTkTextbox(chat_frame, height=300)
        self.ai_chat_display.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        
        # Chat input
        chat_input_frame = ctk.CTkFrame(chat_frame, fg_color="transparent")
        chat_input_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.ai_chat_entry = ctk.CTkEntry(chat_input_frame, placeholder_text="Ask AI assistant...")
        self.ai_chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.ai_chat_entry.bind("<Return>", self.send_ai_message)
        
        send_btn = ctk.CTkButton(chat_input_frame, text="Send", command=self.send_ai_message, width=80)
        send_btn.pack(side="right")
        
        # Initial AI message
        self.ai_chat_display.insert("end", "🤖 AI Assistant: Hello! I'm your AI penetration testing assistant. I can help you with:\n")
        self.ai_chat_display.insert("end", "• Target analysis and vulnerability assessment\n")
        self.ai_chat_display.insert("end", "• Exploit recommendations based on findings\n")
        self.ai_chat_display.insert("end", "• Payload optimization and evasion techniques\n")
        self.ai_chat_display.insert("end", "• Report generation and analysis\n\n")
        self.ai_chat_display.insert("end", "How can I assist you today?\n\n")
    
    def create_console_tab(self):
        """Create console/terminal tab"""
        # Console frame
        console_frame = ctk.CTkFrame(self.tab_console)
        console_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        console_label = ctk.CTkLabel(console_frame, text="Framework Console", font=ctk.CTkFont(size=18, weight="bold"))
        console_label.pack(pady=(15, 10))
        
        # Console output
        self.console_output = ctk.CTkTextbox(
            console_frame,
            font=ctk.CTkFont(family="Courier", size=12),
            height=400
        )
        self.console_output.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        
        # Console input
        console_input_frame = ctk.CTkFrame(console_frame, fg_color="transparent")
        console_input_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        prompt_label = ctk.CTkLabel(console_input_frame, text="msf-ai>", font=ctk.CTkFont(family="Courier", weight="bold"))
        prompt_label.pack(side="left", padx=(0, 10))
        
        self.console_entry = ctk.CTkEntry(
            console_input_frame,
            font=ctk.CTkFont(family="Courier", size=12),
            placeholder_text="Enter command..."
        )
        self.console_entry.pack(fill="x", expand=True)
        self.console_entry.bind("<Return>", self.execute_console_command)
        
        # Initial console output
        self.console_output.insert("end", "Metasploit-AI Framework Console\n")
        self.console_output.insert("end", "Type 'help' for available commands\n\n")
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        # Status indicators
        status_left = ctk.CTkFrame(self.status_frame, fg_color="transparent")
        status_left.pack(side="left", fill="y", padx=10, pady=5)
        
        self.status_label = ctk.CTkLabel(status_left, text="Ready", font=ctk.CTkFont(size=12))
        self.status_label.pack(side="left")
        
        # Right side status
        status_right = ctk.CTkFrame(self.status_frame, fg_color="transparent")
        status_right.pack(side="right", fill="y", padx=10, pady=5)
        
        self.connection_status = ctk.CTkLabel(status_right, text="● Connected", text_color="green", font=ctk.CTkFont(size=12))
        self.connection_status.pack(side="right", padx=(0, 10))
        
        self.version_label = ctk.CTkLabel(status_right, text="v1.0.0", text_color="gray", font=ctk.CTkFont(size=12))
        self.version_label.pack(side="right", padx=(0, 10))
    
    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.configure(text=f"🕒 {current_time}")
        self.root.after(1000, self.update_time)  # Update every second
    
    def start_background_tasks(self):
        """Start background tasks"""
        # Start time update
        self.update_time()
        
        # Start status monitoring
        self.monitor_system_status()
    
    def monitor_system_status(self):
        """Monitor system status in background"""
        def check_status():
            while True:
                try:
                    # Update status indicators
                    self.root.after(0, self.update_status_indicators)
                    time.sleep(10)  # Check every 10 seconds
                except Exception as e:
                    print(f"Status monitoring error: {e}")
        
        status_thread = threading.Thread(target=check_status, daemon=True)
        status_thread.start()
    
    def update_status_indicators(self):
        """Update status indicators"""
        # This would normally check actual system status
        pass
    
    # ============================================================================
    # EVENT HANDLERS
    # ============================================================================
    
    def start_scan(self):
        """Start network scan"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.current_target = target
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.log_activity(f"Starting scan on {target}")
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=self._perform_scan, args=(target,), daemon=True)
        scan_thread.start()
    
    def _perform_scan(self, target):
        """Perform scan in background thread"""
        try:
            # Simulate scan progress
            for i in range(101):
                progress = i / 100.0
                self.root.after(0, lambda p=progress: self.scan_progress.set(p))
                time.sleep(0.05)
            
            # Mock scan results
            results = [
                (target, "22", "SSH", "Open", "OpenSSH 7.4"),
                (target, "80", "HTTP", "Open", "Apache 2.4.6"),
                (target, "443", "HTTPS", "Open", "Apache 2.4.6"),
                (target, "3389", "RDP", "Open", "Microsoft Terminal Services")
            ]
            
            # Update results tree
            self.root.after(0, lambda: self._update_scan_results(results))
            
            # Re-enable scan button
            self.root.after(0, lambda: self.scan_button.configure(state="normal", text="Start Scan"))
            self.root.after(0, lambda: self.log_activity(f"Scan completed on {target} - {len(results)} ports found"))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
            self.root.after(0, lambda: self.scan_button.configure(state="normal", text="Start Scan"))
    
    def _update_scan_results(self, results):
        """Update scan results in tree"""
        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Add new results
        for result in results:
            self.results_tree.insert("", "end", values=result)
    
    def search_exploits(self):
        """Search for exploits"""
        search_term = self.exploit_search_entry.get().strip()
        if not search_term:
            messagebox.showwarning("Warning", "Please enter search terms")
            return
        
        self.log_activity(f"Searching exploits for: {search_term}")
        # This would normally search the actual exploit database
        
    def load_sample_exploits(self):
        """Load sample exploits into tree"""
        sample_exploits = [
            ("exploit/windows/smb/ms17_010_eternalblue", "Windows", "Excellent", "2017-03-14"),
            ("exploit/linux/ssh/ssh_login", "Linux", "Normal", "2018-05-12"),
            ("exploit/multi/http/struts2_content_type_ognl", "Multi", "Great", "2017-03-06"),
            ("auxiliary/scanner/http/dir_scanner", "Multi", "Normal", "2019-01-15"),
            ("exploit/windows/local/ms16_032_secondary_logon_handle_privesc", "Windows", "Excellent", "2016-03-21")
        ]
        
        for exploit in sample_exploits:
            self.exploits_tree.insert("", "end", values=exploit)
    
    def select_exploit(self, event):
        """Handle exploit selection"""
        selection = self.exploits_tree.selection()
        if selection:
            item = self.exploits_tree.item(selection[0])
            exploit_name = item['values'][0]
            self.current_exploit = exploit_name
            self.log_activity(f"Selected exploit: {exploit_name}")
            messagebox.showinfo("Exploit Selected", f"Selected: {exploit_name}")
    
    def generate_payload(self):
        """Generate payload"""
        payload_type = self.payload_type.get()
        lhost = self.lhost_entry.get().strip()
        lport = self.lport_entry.get().strip()
        
        if not lhost or not lport:
            messagebox.showerror("Error", "Please fill in LHOST and LPORT")
            return
        
        self.log_activity(f"Generating payload: {payload_type}")
        
        # Mock payload generation
        payload_code = f"""# Generated Payload: {payload_type}
# LHOST: {lhost}
# LPORT: {lport}

import socket
import subprocess
import sys

def connect_back():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{lhost}', {lport}))
        # Payload code would continue here...
        return s
    except:
        pass

if __name__ == "__main__":
    connect_back()
"""
        
        self.payload_output.delete("1.0", "end")
        self.payload_output.insert("1.0", payload_code)
        
        self.log_activity("Payload generated successfully")
    
    def generate_report(self):
        """Generate security report"""
        report_type = self.report_type.get()
        report_format = self.report_format.get()
        
        self.log_activity(f"Generating {report_type} report in {report_format} format")
        
        # Mock report generation
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"{report_type.replace(' ', '_')}_{timestamp}"
        
        self.reports_tree.insert("", "end", values=(
            report_name,
            report_type,
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            "2.3 MB"
        ))
        
        messagebox.showinfo("Report Generated", f"Report '{report_name}' generated successfully!")
    
    def ai_analyze_target(self):
        """AI target analysis"""
        if not self.current_target:
            messagebox.showwarning("Warning", "Please set a target first")
            return
        
        self.log_activity(f"AI analyzing target: {self.current_target}")
        
        # Mock AI analysis
        analysis_result = f"""🤖 AI Analysis Results for {self.current_target}

🎯 Target Risk Level: HIGH
🔍 Confidence Score: 95%

📊 Findings:
• SMB service vulnerable to EternalBlue (CVE-2017-0144)
• Weak SSH configuration detected
• Outdated Apache server with known vulnerabilities
• No intrusion detection system detected

⚡ Recommended Actions:
1. Use exploit/windows/smb/ms17_010_eternalblue
2. Attempt SSH brute force attack
3. Scan for web application vulnerabilities
4. Check for privilege escalation opportunities

🛡️ Evasion Recommendations:
• Use staged payloads to avoid AV detection
• Implement random delays between attempts
• Consider using HTTPS C2 channel"""
        
        messagebox.showinfo("AI Analysis Complete", analysis_result)
        self.ai_chat_display.insert("end", f"🤖 AI Assistant: Completed analysis of {self.current_target}\n\n")
        self.ai_chat_display.insert("end", analysis_result + "\n\n")
    
    def ai_recommend_exploits(self):
        """Get AI exploit recommendations"""
        if not self.current_target:
            messagebox.showwarning("Warning", "Please set a target first")
            return
        
        recommendations = """🤖 AI Exploit Recommendations:

1. exploit/windows/smb/ms17_010_eternalblue (95% confidence)
   → SMB service detected, high probability of success

2. auxiliary/scanner/ssh/ssh_login (78% confidence)
   → SSH service with potential weak credentials

3. exploit/multi/http/struts2_content_type_ognl (82% confidence)
   → Web application vulnerability detected"""
        
        messagebox.showinfo("AI Recommendations", recommendations)
        self.ai_chat_display.insert("end", "🤖 AI Assistant: Generated exploit recommendations\n\n")
        self.ai_chat_display.insert("end", recommendations + "\n\n")
    
    def send_ai_message(self, event=None):
        """Send message to AI assistant"""
        message = self.ai_chat_entry.get().strip()
        if not message:
            return
        
        # Add user message
        self.ai_chat_display.insert("end", f"👤 You: {message}\n")
        
        # Clear input
        self.ai_chat_entry.delete(0, "end")
        
        # Mock AI response
        responses = [
            "I can help you with that! Let me analyze the available options.",
            "Based on the current target information, I recommend focusing on the SMB vulnerability.",
            "That's a great question! For better evasion, consider using encoded payloads.",
            "I suggest running a comprehensive scan first to gather more information.",
            "The AI analysis indicates a high success probability for that approach."
        ]
        
        import random
        ai_response = random.choice(responses)
        
        self.ai_chat_display.insert("end", f"🤖 AI Assistant: {ai_response}\n\n")
        
        # Auto-scroll to bottom
        self.ai_chat_display.see("end")
    
    def execute_console_command(self, event=None):
        """Execute console command"""
        command = self.console_entry.get().strip()
        if not command:
            return
        
        # Add command to output
        self.console_output.insert("end", f"msf-ai> {command}\n")
        
        # Clear input
        self.console_entry.delete(0, "end")
        
        # Mock command execution
        if command == "help":
            help_text = """Available commands:
  help     - Show this help
  version  - Show framework version
  target   - Set target host
  scan     - Perform network scan
  use      - Select exploit module
  exploit  - Execute current exploit
  sessions - List active sessions
  jobs     - Show background jobs
  clear    - Clear console
"""
            self.console_output.insert("end", help_text)
        elif command == "version":
            self.console_output.insert("end", "Metasploit-AI Framework v1.0.0\n")
        elif command == "clear":
            self.console_output.delete("1.0", "end")
            self.console_output.insert("end", "Metasploit-AI Framework Console\n")
            self.console_output.insert("end", "Type 'help' for available commands\n\n")
        else:
            self.console_output.insert("end", f"Unknown command: {command}\n")
        
        self.console_output.insert("end", "\n")
        self.console_output.see("end")
    
    def log_activity(self, message):
        """Log activity to dashboard"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.activity_text.insert("end", log_entry)
        self.activity_text.see("end")
    
    # ============================================================================
    # MENU HANDLERS
    # ============================================================================
    
    def new_project(self):
        messagebox.showinfo("New Project", "New project functionality would be implemented here")
    
    def open_project(self):
        filename = filedialog.askopenfilename(
            title="Open Project",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.log_activity(f"Opened project: {filename}")
    
    def save_project(self):
        filename = filedialog.asksaveasfilename(
            title="Save Project",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.log_activity(f"Saved project: {filename}")
    
    def import_targets(self):
        filename = filedialog.askopenfilename(
            title="Import Targets",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.log_activity(f"Imported targets from: {filename}")
    
    def export_results(self):
        filename = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.log_activity(f"Exported results to: {filename}")
    
    def open_scanner(self):
        self.tabview.set("Scanner")
    
    def open_exploit_browser(self):
        self.tabview.set("Exploits")
    
    def open_payload_generator(self):
        self.tabview.set("Payloads")
    
    def open_session_manager(self):
        self.tabview.set("Sessions")
    
    def ai_optimize_payload(self):
        messagebox.showinfo("AI Optimization", "AI payload optimization would be implemented here")
    
    def ai_generate_report(self):
        self.tabview.set("Reports")
    
    def toggle_console(self):
        self.tabview.set("Console")
    
    def show_logs(self):
        messagebox.showinfo("Logs", "System logs would be displayed here")
    
    def show_jobs(self):
        messagebox.showinfo("Background Jobs", "Background jobs would be displayed here")
    
    def toggle_fullscreen(self):
        self.root.attributes('-fullscreen', not self.root.attributes('-fullscreen'))
    
    def show_documentation(self):
        messagebox.showinfo("Documentation", "Framework documentation would open here")
    
    def show_tutorials(self):
        messagebox.showinfo("Tutorials", "Interactive tutorials would open here")
    
    def show_shortcuts(self):
        shortcuts = """Keyboard Shortcuts:

Ctrl+N    - New Project
Ctrl+O    - Open Project
Ctrl+S    - Save Project
Ctrl+T    - New Target
Ctrl+R    - Start Scan
Ctrl+E    - Search Exploits
Ctrl+P    - Generate Payload
Ctrl+L    - Toggle Console
F11       - Toggle Fullscreen
Ctrl+Q    - Quit Application
"""
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)
    
    def show_about(self):
        about_text = """Metasploit-AI Framework v1.0.0

Advanced AI-Powered Penetration Testing Platform

Created by ZehraSec
https://www.zehrasec.com

This framework combines the power of Metasploit with 
advanced artificial intelligence to automate and enhance 
penetration testing workflows.

Features:
• AI-powered vulnerability analysis
• Smart exploit recommendations  
• Automated payload generation
• Intelligent report generation
• Modern desktop interface

© 2025 ZehraSec. All rights reserved."""
        
        messagebox.showinfo("About Metasploit-AI", about_text)
    
    def run(self):
        """Start the GUI application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            print("GUI application interrupted")
        except Exception as e:
            print(f"GUI error: {e}")


def start_gui_interface(framework):
    """Start the GUI interface"""
    try:
        app = MetasploitAIGUI(framework)
        app.run()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        return 1
    
    return 0
