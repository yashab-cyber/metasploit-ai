"""
Command Line Interface Module
Interactive CLI for Metasploit-AI Framework
"""

import asyncio
import cmd
import json
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional
import argparse
import shlex
import time
import threading

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track, Progress
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.tree import Tree
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich import print as rprint

from ..utils.logger import get_logger

class CLIInterface(cmd.Cmd):
    """Interactive command-line interface for Metasploit-AI"""
    
    intro = """
╔═══════════════════════════════════════════════════════════════════╗
║                      🤖 METASPLOIT-AI FRAMEWORK                   ║
║                   Advanced AI-Powered Penetration Testing         ║
║                        Created by ZehraSec                        ║
╚═══════════════════════════════════════════════════════════════════╝

Welcome to the Metasploit-AI Framework - The Next Generation of Penetration Testing

Type 'help' for available commands or 'help <command>' for specific help.
Type 'exit' or 'quit' to exit the framework.
Type 'banner' to display the banner again.
"""
    
    prompt = "[bold green]msf-ai[/bold green]> "
    
    def __init__(self, framework):
        """Initialize CLI interface"""
        super().__init__()
        self.framework = framework
        self.console = Console()
        self.logger = get_logger(__name__)
        
        # CLI state
        self.current_target = None
        self.current_exploit = None
        self.current_payload = None
        self.session_vars = {}
        self.scan_jobs = {}
        self.exploit_jobs = {}
        
        # Display settings
        self.show_timestamp = True
        self.show_colors = True
        self.verbose_mode = False
        
        # Initialize components
        self._init_completer()
        self._display_banner()
    
    def _init_completer(self):
        """Initialize command completion"""
        self.complete_use = self._complete_modules
        self.complete_set = self._complete_options
        self.complete_show = self._complete_show_options
        
    def _display_banner(self):
        """Display the main banner"""
        banner_text = """
    ███╗   ███╗███████╗████████╗ █████╗ ███████╗██████╗ ██╗      ██████╗ ██╗████████╗       █████╗ ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝      ██╔══██╗██║
    ██╔████╔██║█████╗     ██║   ███████║███████╗██████╔╝██║     ██║   ██║██║   ██║   █████╗███████║██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════╝██╔══██║██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████║██║     ███████╗╚██████╔╝██║   ██║         ██║  ██║██║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝         ╚═╝  ╚═╝╚═╝
        """
        
        panel = Panel(
            Align.center(Text(banner_text, style="bold cyan")),
            title="[bold red]Metasploit-AI Framework[/bold red]",
            subtitle="[italic]Advanced AI-Powered Penetration Testing[/italic]",
            border_style="bright_blue"
        )
        
        self.console.print(panel)
        self.console.print(f"[bold yellow]Framework Version:[/bold yellow] [green]{getattr(self.framework, 'version', '1.0.0')}[/green]")
        self.console.print(f"[bold yellow]AI Engine Status:[/bold yellow] [green]Online[/green]")
        self.console.print(f"[bold yellow]Current Time:[/bold yellow] [cyan]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
        self.console.print("")
    
    def cmdloop(self, intro=None):
        """Enhanced command loop with error handling"""
        try:
            super().cmdloop(intro)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Use 'exit' or 'quit' to leave the framework[/yellow]")
            self.cmdloop()
        except Exception as e:
            self.logger.error(f"CLI error: {e}")
            self.console.print(f"[red]Error: {e}[/red]")
    
    # ============================================================================
    # BASIC COMMANDS
    # ============================================================================
    
    def do_banner(self, args):
        """Display the framework banner"""
        self._display_banner()
    
    def do_help(self, args):
        """Enhanced help command with categories"""
        if not args:
            self._show_help_menu()
        else:
            super().do_help(args)
    
    def _show_help_menu(self):
        """Display categorized help menu"""
        categories = {
            "Core Commands": {
                "help": "Show this help menu",
                "banner": "Display framework banner",
                "version": "Show framework version",
                "exit/quit": "Exit the framework",
                "clear": "Clear the screen"
            },
            "Target & Scanning": {
                "target": "Set target host/network",
                "scan": "Perform network scan",
                "nmap": "Run nmap scan",
                "discover": "Network discovery",
                "port_scan": "Port scanning"
            },
            "Exploitation": {
                "use": "Select exploit module",
                "exploit": "Execute current exploit",
                "search": "Search for exploits/modules",
                "info": "Show module information",
                "options": "Show module options"
            },
            "Payloads": {
                "payload": "Set payload",
                "generate": "Generate payload",
                "encode": "Encode payload",
                "listener": "Start payload listener"
            },
            "AI Features": {
                "ai_analyze": "AI vulnerability analysis",
                "ai_recommend": "Get AI recommendations",
                "ai_optimize": "AI payload optimization",
                "ai_report": "Generate AI report"
            },
            "Session Management": {
                "sessions": "List active sessions",
                "session": "Interact with session",
                "jobs": "Show background jobs",
                "kill": "Kill job or session"
            },
            "Configuration": {
                "set": "Set variable value",
                "unset": "Unset variable",
                "show": "Show options/variables",
                "save": "Save configuration",
                "load": "Load configuration"
            }
        }
        
        for category, commands in categories.items():
            table = Table(title=f"[bold cyan]{category}[/bold cyan]", show_header=True)
            table.add_column("Command", style="green", width=20)
            table.add_column("Description", style="white")
            
            for cmd, desc in commands.items():
                table.add_row(cmd, desc)
            
            self.console.print(table)
            self.console.print("")
    
    def do_version(self, args):
        """Show framework version and components"""
        info_table = Table(title="[bold]Framework Information[/bold]")
        info_table.add_column("Component", style="cyan")
        info_table.add_column("Version", style="green")
        info_table.add_column("Status", style="yellow")
        
        info_table.add_row("Metasploit-AI Framework", "1.0.0", "Active")
        info_table.add_row("AI Engine", "1.0.0", "Online")
        info_table.add_row("Metasploit Core", "6.3.0", "Connected")
        info_table.add_row("Database", "PostgreSQL", "Connected")
        
        self.console.print(info_table)
    
    def do_clear(self, args):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        self._display_banner()
    
    def do_exit(self, args):
        """Exit the framework"""
        self.console.print("[yellow]Goodbye! Thank you for using Metasploit-AI Framework[/yellow]")
        return True
    
    def do_quit(self, args):
        """Exit the framework"""
        return self.do_exit(args)
    
    # ============================================================================
    # TARGET & SCANNING COMMANDS
    # ============================================================================
    
    def do_target(self, args):
        """Set target host or network
        Usage: target <ip/cidr>
        Example: target 192.168.1.100
                 target 192.168.1.0/24
        """
        if not args:
            if self.current_target:
                self.console.print(f"[yellow]Current target:[/yellow] [green]{self.current_target}[/green]")
            else:
                self.console.print("[red]No target set[/red]")
            return
        
        self.current_target = args.strip()
        self.console.print(f"[green]Target set to:[/green] [cyan]{self.current_target}[/cyan]")
        
        # Auto-suggest AI analysis
        self.console.print("[yellow]💡 Tip: Use 'ai_analyze' to get AI-powered target analysis[/yellow]")
    
    def do_scan(self, args):
        """Perform network scan on target
        Usage: scan [options]
        Options:
            -p, --ports    Port range (default: 1-1000)
            -t, --type     Scan type (quick, full, stealth)
            --ai           Enable AI analysis
        """
        if not self.current_target:
            self.console.print("[red]No target set. Use 'target <ip>' first[/red]")
            return
        
        # Parse arguments
        parser = argparse.ArgumentParser(description="Network scan")
        parser.add_argument('-p', '--ports', default='1-1000', help='Port range')
        parser.add_argument('-t', '--type', default='quick', choices=['quick', 'full', 'stealth'])
        parser.add_argument('--ai', action='store_true', help='Enable AI analysis')
        
        try:
            parsed_args = parser.parse_args(shlex.split(args))
        except SystemExit:
            return
        
        # Start scan
        self.console.print(f"[yellow]Starting {parsed_args.type} scan on {self.current_target}[/yellow]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            
            # Simulate scan progress
            for i in range(100):
                time.sleep(0.05)
                progress.update(task, advance=1)
        
        # Mock scan results
        scan_results = {
            'open_ports': [22, 80, 443, 3389],
            'services': {
                22: 'SSH',
                80: 'HTTP',
                443: 'HTTPS', 
                3389: 'RDP'
            },
            'os': 'Linux Ubuntu 20.04'
        }
        
        self._display_scan_results(scan_results, parsed_args.ai)
    
    def _display_scan_results(self, results, ai_analysis=False):
        """Display scan results in a formatted table"""
        # Port results table
        port_table = Table(title="[bold]Open Ports[/bold]")
        port_table.add_column("Port", style="cyan")
        port_table.add_column("Service", style="green")
        port_table.add_column("State", style="yellow")
        
        for port in results['open_ports']:
            service = results['services'].get(port, 'Unknown')
            port_table.add_row(str(port), service, "Open")
        
        self.console.print(port_table)
        
        # OS Information
        if 'os' in results:
            os_panel = Panel(
                f"[green]{results['os']}[/green]",
                title="[bold]Operating System[/bold]",
                border_style="blue"
            )
            self.console.print(os_panel)
        
        # AI Analysis
        if ai_analysis:
            self.console.print("\n[bold cyan]🤖 AI Analysis:[/bold cyan]")
            ai_panel = Panel(
                """[yellow]• SSH service detected - potential for brute force attacks
• Web services (80, 443) - recommend web application testing
• RDP service exposed - high risk if weak credentials
• Linux system - check for privilege escalation vulnerabilities[/yellow]""",
                title="[bold]AI Recommendations[/bold]",
                border_style="yellow"
            )
            self.console.print(ai_panel)
    
    # ============================================================================
    # EXPLOITATION COMMANDS
    # ============================================================================
    
    def do_search(self, args):
        """Search for exploits, payloads, or modules
        Usage: search <term>
        Example: search windows smb
                 search type:exploit platform:linux
        """
        if not args:
            self.console.print("[red]Please provide search terms[/red]")
            return
        
        # Mock search results
        search_results = [
            {
                'name': 'exploit/windows/smb/ms17_010_eternalblue',
                'rank': 'excellent',
                'description': 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption'
            },
            {
                'name': 'exploit/linux/ssh/ssh_login',
                'rank': 'normal',
                'description': 'SSH Login Check Scanner'
            },
            {
                'name': 'auxiliary/scanner/http/dir_scanner',
                'rank': 'normal',
                'description': 'HTTP Directory Scanner'
            }
        ]
        
        results_table = Table(title=f"[bold]Search Results for: {args}[/bold]")
        results_table.add_column("Name", style="green")
        results_table.add_column("Rank", style="yellow")
        results_table.add_column("Description", style="white")
        
        for result in search_results:
            rank_color = "red" if result['rank'] == 'excellent' else "yellow"
            results_table.add_row(
                result['name'],
                f"[{rank_color}]{result['rank']}[/{rank_color}]",
                result['description']
            )
        
        self.console.print(results_table)
        self.console.print(f"\n[cyan]Found {len(search_results)} modules matching '{args}'[/cyan]")
    
    def do_use(self, args):
        """Select an exploit or module
        Usage: use <module_path>
        Example: use exploit/windows/smb/ms17_010_eternalblue
        """
        if not args:
            if self.current_exploit:
                self.console.print(f"[yellow]Current module:[/yellow] [green]{self.current_exploit}[/green]")
            else:
                self.console.print("[red]No module selected[/red]")
            return
        
        self.current_exploit = args.strip()
        self.console.print(f"[green]Module selected:[/green] [cyan]{self.current_exploit}[/cyan]")
        
        # Show module info
        self.do_info("")
    
    def do_info(self, args):
        """Show information about current module"""
        if not self.current_exploit:
            self.console.print("[red]No module selected. Use 'use <module>' first[/red]")
            return
        
        # Mock module info
        info_panel = Panel(f"""
[bold]Name:[/bold] MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
[bold]Module:[/bold] {self.current_exploit}
[bold]Platform:[/bold] Windows
[bold]Arch:[/bold] x86, x64
[bold]Privileged:[/bold] Yes
[bold]License:[/bold] Metasploit Framework License (BSD)
[bold]Rank:[/bold] [red]Excellent[/red]
[bold]Disclosed:[/bold] 2017-03-14

[bold]Description:[/bold]
This module exploits a vulnerability in Microsoft SMBv1 servers (MS17-010) to
achieve arbitrary code execution. The exploit targets the srv.sys driver and
will often crash the target if unsuccessful.

[bold]References:[/bold]
• https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
• https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
        """, title="[bold]Module Information[/bold]", border_style="cyan")
        
        self.console.print(info_panel)
    
    def do_options(self, args):
        """Show module options"""
        if not self.current_exploit:
            self.console.print("[red]No module selected. Use 'use <module>' first[/red]")
            return
        
        options_table = Table(title="[bold]Module Options[/bold]")
        options_table.add_column("Name", style="cyan")
        options_table.add_column("Current Setting", style="green")
        options_table.add_column("Required", style="yellow")
        options_table.add_column("Description", style="white")
        
        # Mock options
        mock_options = [
            ("RHOSTS", self.current_target or "", "yes", "The target host(s)"),
            ("RPORT", "445", "yes", "The target port"),
            ("LHOST", "", "yes", "The listen address"),
            ("LPORT", "4444", "yes", "The listen port"),
            ("TARGET", "0", "yes", "The target index")
        ]
        
        for name, value, required, desc in mock_options:
            req_color = "red" if required == "yes" else "green"
            options_table.add_row(
                name,
                value,
                f"[{req_color}]{required}[/{req_color}]",
                desc
            )
        
        self.console.print(options_table)
    
    def do_set(self, args):
        """Set option value
        Usage: set <option> <value>
        Example: set RHOSTS 192.168.1.100
                 set LHOST 192.168.1.10
        """
        if not args:
            self.console.print("[red]Usage: set <option> <value>[/red]")
            return
        
        parts = args.split(' ', 1)
        if len(parts) != 2:
            self.console.print("[red]Usage: set <option> <value>[/red]")
            return
        
        option, value = parts
        self.session_vars[option.upper()] = value
        self.console.print(f"[green]{option.upper()} => {value}[/green]")
        
        # Auto-set related options
        if option.upper() == "RHOSTS" and not self.current_target:
            self.current_target = value
            self.console.print(f"[yellow]Auto-set target to {value}[/yellow]")
    
    # ============================================================================
    # AI COMMANDS
    # ============================================================================
    
    def do_ai_analyze(self, args):
        """AI-powered target analysis"""
        if not self.current_target:
            self.console.print("[red]No target set. Use 'target <ip>' first[/red]")
            return
        
        self.console.print(f"[yellow]🤖 Running AI analysis on {self.current_target}...[/yellow]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]AI Analysis...", total=100)
            for i in range(100):
                time.sleep(0.03)
                progress.update(task, advance=1)
        
        # Mock AI analysis
        ai_analysis = Panel(f"""
[bold green]🎯 Target Analysis Complete[/bold green]

[bold]Risk Level:[/bold] [red]HIGH[/red]
[bold]Confidence:[/bold] [green]95%[/green]

[bold cyan]🔍 Findings:[/bold cyan]
• SMB service vulnerable to EternalBlue (CVE-2017-0144)
• Weak SSH configuration detected
• Outdated web server with known vulnerabilities
• No intrusion detection system detected

[bold yellow]⚡ Recommended Exploits:[/bold yellow]
1. exploit/windows/smb/ms17_010_eternalblue (Rank: Excellent)
2. auxiliary/scanner/ssh/ssh_login (Brute force)
3. exploit/multi/http/struts2_content_type_ognl (Web app)

[bold blue]🛡️ Evasion Recommendations:[/bold blue]
• Use staged payloads to avoid AV detection
• Implement random delays between attempts
• Consider using HTTPS C2 channel
        """, title="[bold]🤖 AI Analysis Results[/bold]", border_style="green")
        
        self.console.print(ai_analysis)
    
    def do_ai_recommend(self, args):
        """Get AI exploit recommendations"""
        if not self.current_target:
            self.console.print("[red]No target set. Use 'target <ip>' first[/red]")
            return
        
        self.console.print("[yellow]🤖 Generating AI recommendations...[/yellow]")
        
        recommendations = [
            {
                'exploit': 'exploit/windows/smb/ms17_010_eternalblue',
                'confidence': 95,
                'reason': 'SMB service detected, high probability of success'
            },
            {
                'exploit': 'auxiliary/scanner/ssh/ssh_login',
                'confidence': 78,
                'reason': 'SSH service with potential weak credentials'
            },
            {
                'exploit': 'exploit/multi/http/struts2_content_type_ognl',
                'confidence': 82,
                'reason': 'Web application vulnerability detected'
            }
        ]
        
        rec_table = Table(title="[bold]🤖 AI Exploit Recommendations[/bold]")
        rec_table.add_column("Exploit", style="green")
        rec_table.add_column("Confidence", style="yellow")
        rec_table.add_column("Reason", style="white")
        
        for rec in recommendations:
            confidence_color = "red" if rec['confidence'] > 90 else "yellow" if rec['confidence'] > 70 else "blue"
            rec_table.add_row(
                rec['exploit'],
                f"[{confidence_color}]{rec['confidence']}%[/{confidence_color}]",
                rec['reason']
            )
        
        self.console.print(rec_table)
        
        # Auto-suggest best option
        best = max(recommendations, key=lambda x: x['confidence'])
        self.console.print(f"\n[bold green]💡 Best option:[/bold green] [cyan]{best['exploit']}[/cyan] ({best['confidence']}% confidence)")
        self.console.print(f"[yellow]Use 'use {best['exploit']}' to select this exploit[/yellow]")
    
    # ============================================================================
    # COMPLETION HELPERS
    # ============================================================================
    
    def _complete_modules(self, text, line, begidx, endidx):
        """Auto-complete module names"""
        modules = [
            'exploit/windows/smb/ms17_010_eternalblue',
            'exploit/linux/ssh/ssh_login',
            'auxiliary/scanner/http/dir_scanner',
            'payload/windows/meterpreter/reverse_tcp',
            'payload/linux/x86/meterpreter/reverse_tcp'
        ]
        return [m for m in modules if m.startswith(text)]
    
    def _complete_options(self, text, line, begidx, endidx):
        """Auto-complete option names"""
        options = ['RHOSTS', 'RPORT', 'LHOST', 'LPORT', 'TARGET', 'PAYLOAD']
        return [opt for opt in options if opt.startswith(text.upper())]
    
    def _complete_show_options(self, text, line, begidx, endidx):
        """Auto-complete show command options"""
        show_options = ['options', 'targets', 'payloads', 'advanced', 'sessions', 'jobs']
        return [opt for opt in show_options if opt.startswith(text)]
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        self.console.print(f"[red]Unknown command: {line}[/red]")
        self.console.print("[yellow]Type 'help' for available commands[/yellow]")
    
    def start(self):
        """Start the CLI interface"""
        try:
            # Initialize framework
            asyncio.run(self._initialize_framework())
            
            # Show intro and start command loop
            self.console.print(self.intro, style="bold cyan")
            self.cmdloop()
            
        except KeyboardInterrupt:
            self.console.print("\n👋 Goodbye!", style="bold yellow")
            sys.exit(0)
        except Exception as e:
            self.console.print(f"❌ CLI Error: {e}", style="bold red")
            sys.exit(1)
    
    async def _initialize_framework(self):
        """Initialize the framework asynchronously"""
        with self.console.status("[bold green]Initializing Metasploit-AI Framework..."):
            success = await self.framework.initialize()
            if not success:
                raise Exception("Framework initialization failed")
        
        self.console.print("✅ Framework initialized successfully!", style="bold green")


def start_cli_interface(framework):
    """Start the CLI interface"""
    try:
        cli = CLIInterface(framework)
        cli.start()
    except KeyboardInterrupt:
        print("\nExiting Metasploit-AI Framework...")
    except Exception as e:
        print(f"CLI Error: {e}")
        return 1
    
    return 0
    
    def do_status(self, args):
        """Show framework status"""
        try:
            status = self.framework.get_status()
            
            table = Table(title="🤖 Framework Status")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details", style="yellow")
            
            table.add_row("Active Scans", str(status['active_scans']), "Running scan operations")
            table.add_row("Active Exploits", str(status['active_exploits']), "Running exploit operations")
            table.add_row("Metasploit Connection", 
                         "✅ Connected" if status['metasploit_connected'] else "❌ Disconnected",
                         "MSF RPC connection status")
            table.add_row("AI Models", 
                         "✅ Loaded" if status['ai_models_loaded'] else "❌ Not Loaded",
                         "Machine learning models")
            
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"❌ Error getting status: {e}", style="bold red")
    
    def do_scan(self, args):
        """Perform network scan
        Usage: scan <target> [scan_type]
        Example: scan 192.168.1.1 comprehensive
        """
        try:
            if not args:
                self.console.print("❌ Usage: scan <target> [scan_type]", style="bold red")
                return
            
            parts = args.split()
            target = parts[0]
            scan_type = parts[1] if len(parts) > 1 else "comprehensive"
            
            self.current_target = target
            
            with self.console.status(f"[bold yellow]Scanning {target}..."):
                # Run scan asynchronously
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    self.framework.scan_target(target, scan_type)
                )
                loop.close()
            
            self.current_scan_results = result
            self.current_vulnerabilities = result.vulnerabilities
            
            # Display results
            self._display_scan_results(result)
            
        except Exception as e:
            self.console.print(f"❌ Scan failed: {e}", style="bold red")
    
    def _display_scan_results(self, result):
        """Display scan results in a formatted table"""
        # Host information
        host_panel = Panel(
            f"Target: {result.target}\n"
            f"Timestamp: {result.timestamp}\n"
            f"Risk Score: {result.risk_score:.2f}/10\n"
            f"Services Found: {len(result.services)}\n"
            f"Vulnerabilities: {len(result.vulnerabilities)}",
            title="🎯 Scan Results",
            border_style="green"
        )
        self.console.print(host_panel)
        
        # Services table
        if result.services:
            services_table = Table(title="🔍 Discovered Services")
            services_table.add_column("Port", style="cyan")
            services_table.add_column("Service", style="green")
            services_table.add_column("Version", style="yellow")
            
            for service in result.services[:10]:  # Show top 10
                services_table.add_row(
                    str(service.get('port', 'N/A')),
                    service.get('name', 'Unknown'),
                    service.get('version', 'Unknown')
                )
            
            self.console.print(services_table)
        
        # Vulnerabilities table
        if result.vulnerabilities:
            vulns_table = Table(title="🚨 Discovered Vulnerabilities")
            vulns_table.add_column("Severity", style="red")
            vulns_table.add_column("Type", style="cyan")
            vulns_table.add_column("Description", style="white")
            vulns_table.add_column("Score", style="yellow")
            
            for vuln in result.vulnerabilities[:10]:  # Show top 10
                severity_style = self._get_severity_style(vuln.get('severity', 'Medium'))
                vulns_table.add_row(
                    vuln.get('severity', 'Medium'),
                    vuln.get('type', 'Unknown'),
                    vuln.get('description', 'No description')[:60] + "...",
                    f"{vuln.get('severity_score', 0):.1f}",
                    style=severity_style
                )
            
            self.console.print(vulns_table)
        else:
            self.console.print("✅ No vulnerabilities detected", style="bold green")
    
    def do_recommend(self, args):
        """Get exploit recommendations for current vulnerabilities
        Usage: recommend [target]
        """
        try:
            if not self.current_vulnerabilities:
                self.console.print("❌ No vulnerabilities available. Run a scan first.", style="bold red")
                return
            
            target = args if args else self.current_target
            if not target:
                self.console.print("❌ No target specified", style="bold red")
                return
            
            with self.console.status("[bold yellow]Generating exploit recommendations..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                recommendations = loop.run_until_complete(
                    self.framework.recommend_exploits(target, self.current_vulnerabilities)
                )
                loop.close()
            
            self.current_exploits = recommendations
            self._display_recommendations(recommendations)
            
        except Exception as e:
            self.console.print(f"❌ Recommendation failed: {e}", style="bold red")
    
    def _display_recommendations(self, recommendations):
        """Display exploit recommendations"""
        if not recommendations:
            self.console.print("ℹ️ No exploit recommendations available", style="bold yellow")
            return
        
        rec_table = Table(title="🎯 Exploit Recommendations")
        rec_table.add_column("#", style="cyan")
        rec_table.add_column("Exploit", style="green")
        rec_table.add_column("Confidence", style="yellow")
        rec_table.add_column("Success Probability", style="red")
        rec_table.add_column("Difficulty", style="blue")
        rec_table.add_column("Description", style="white")
        
        for i, rec in enumerate(recommendations[:10], 1):
            confidence = rec.get('confidence', 0)
            success_prob = rec.get('success_probability', 0)
            difficulty = rec.get('execution_difficulty', 'Medium')
            
            rec_table.add_row(
                str(i),
                rec.get('exploit_name', 'Unknown'),
                f"{confidence:.2f}",
                f"{success_prob:.2f}",
                difficulty,
                rec.get('description', 'No description')[:50] + "..."
            )
        
        self.console.print(rec_table)
        self.console.print("\nℹ️ Use 'exploit <number>' to execute a recommended exploit", style="bold blue")
    
    def do_exploit(self, args):
        """Execute an exploit
        Usage: exploit <number> [options]
        Example: exploit 1 LHOST=192.168.1.100
        """
        try:
            if not args:
                self.console.print("❌ Usage: exploit <number> [options]", style="bold red")
                return
            
            if not self.current_exploits:
                self.console.print("❌ No exploits available. Run 'recommend' first.", style="bold red")
                return
            
            parts = args.split()
            try:
                exploit_num = int(parts[0]) - 1
                if exploit_num < 0 or exploit_num >= len(self.current_exploits):
                    raise IndexError()
            except (ValueError, IndexError):
                self.console.print("❌ Invalid exploit number", style="bold red")
                return
            
            exploit = self.current_exploits[exploit_num]
            exploit_name = exploit['exploit_name']
            
            # Parse options
            options = {}
            for part in parts[1:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    options[key] = value
            
            # Confirm execution
            if not Confirm.ask(f"Execute exploit '{exploit_name}' against {self.current_target}?"):
                self.console.print("❌ Exploit execution cancelled", style="bold yellow")
                return
            
            with self.console.status(f"[bold red]Executing {exploit_name}..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    self.framework.execute_exploit(self.current_target, exploit_name, options)
                )
                loop.close()
            
            self._display_exploit_result(result)
            
        except Exception as e:
            self.console.print(f"❌ Exploit execution failed: {e}", style="bold red")
    
    def _display_exploit_result(self, result):
        """Display exploit execution result"""
        if result.success:
            success_panel = Panel(
                f"✅ Exploit executed successfully!\n"
                f"Target: {result.target}\n"
                f"Exploit: {result.exploit_name}\n"
                f"Payload: {result.payload}\n"
                f"Timestamp: {result.timestamp}",
                title="🎯 Exploit Success",
                border_style="green"
            )
            self.console.print(success_panel)
            
            # Check for session
            if result.details.get('session'):
                session_info = result.details['session']
                self.active_sessions[session_info['id']] = session_info
                self.console.print(f"🔥 Session {session_info['id']} created!", style="bold green")
        else:
            error_panel = Panel(
                f"❌ Exploit failed\n"
                f"Target: {result.target}\n"
                f"Exploit: {result.exploit_name}\n"
                f"Error: {result.details.get('error', 'Unknown error')}\n"
                f"Timestamp: {result.timestamp}",
                title="💥 Exploit Failed",
                border_style="red"
            )
            self.console.print(error_panel)
    
    def do_sessions(self, args):
        """Manage active sessions
        Usage: sessions [list|interact <id>|kill <id>]
        """
        try:
            if not args or args == "list":
                # List sessions
                if not self.active_sessions:
                    self.console.print("ℹ️ No active sessions", style="bold yellow")
                    return
                
                sessions_table = Table(title="🔥 Active Sessions")
                sessions_table.add_column("ID", style="cyan")
                sessions_table.add_column("Target", style="green")
                sessions_table.add_column("Type", style="yellow")
                sessions_table.add_column("Info", style="white")
                
                for session_id, session_info in self.active_sessions.items():
                    sessions_table.add_row(
                        str(session_id),
                        session_info.get('target', 'Unknown'),
                        session_info.get('type', 'Unknown'),
                        str(session_info.get('info', {}))[:50] + "..."
                    )
                
                self.console.print(sessions_table)
            
            elif args.startswith("interact"):
                parts = args.split()
                if len(parts) != 2:
                    self.console.print("❌ Usage: sessions interact <id>", style="bold red")
                    return
                
                session_id = parts[1]
                if session_id not in self.active_sessions:
                    self.console.print(f"❌ Session {session_id} not found", style="bold red")
                    return
                
                self._interact_with_session(session_id)
            
            elif args.startswith("kill"):
                parts = args.split()
                if len(parts) != 2:
                    self.console.print("❌ Usage: sessions kill <id>", style="bold red")
                    return
                
                session_id = parts[1]
                if session_id in self.active_sessions:
                    del self.active_sessions[session_id]
                    self.console.print(f"🔥 Session {session_id} terminated", style="bold red")
                else:
                    self.console.print(f"❌ Session {session_id} not found", style="bold red")
            
        except Exception as e:
            self.console.print(f"❌ Session management error: {e}", style="bold red")
    
    def _interact_with_session(self, session_id):
        """Interactive session shell"""
        self.console.print(f"🔥 Entering session {session_id}. Type 'exit' to return.", style="bold green")
        
        while True:
            try:
                command = Prompt.ask(f"session-{session_id}>")
                
                if command.lower() in ['exit', 'quit', 'back']:
                    break
                
                # Execute command in session
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                output = loop.run_until_complete(
                    self.framework.msf_client.execute_session_command(session_id, command)
                )
                loop.close()
                
                if output:
                    self.console.print(output, style="white")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.console.print(f"❌ Command error: {e}", style="bold red")
        
        self.console.print("🔙 Returned to main console", style="bold blue")
    
    def do_autotest(self, args):
        """Run automated penetration test
        Usage: autotest <targets>
        Example: autotest 192.168.1.1,192.168.1.2
        """
        try:
            if not args:
                self.console.print("❌ Usage: autotest <targets>", style="bold red")
                return
            
            targets = [t.strip() for t in args.split(',')]
            
            if not Confirm.ask(f"Run automated penetration test on {len(targets)} targets?"):
                self.console.print("❌ Automated test cancelled", style="bold yellow")
                return
            
            with Progress() as progress:
                task = progress.add_task("[green]Running automated penetration test...", total=len(targets))
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(
                    self.framework.automated_penetration_test(targets)
                )
                loop.close()
                
                progress.update(task, completed=len(targets))
            
            self._display_autotest_results(results)
            
        except Exception as e:
            self.console.print(f"❌ Automated test failed: {e}", style="bold red")
    
    def _display_autotest_results(self, results):
        """Display automated test results"""
        summary_panel = Panel(
            f"🤖 Automated Penetration Test Results\n\n"
            f"Targets Scanned: {len(results['scan_results'])}\n"
            f"Exploits Executed: {len(results['exploit_results'])}\n"
            f"Successful Exploits: {sum(1 for r in results['exploit_results'] if r.success)}\n"
            f"Total Vulnerabilities: {sum(len(r.vulnerabilities) for r in results['scan_results'])}",
            title="📊 Test Summary",
            border_style="blue"
        )
        self.console.print(summary_panel)
        
        # Show detailed results for each target
        for scan_result in results['scan_results']:
            self.console.print(f"\n🎯 Target: {scan_result.target}")
            self.console.print(f"Risk Score: {scan_result.risk_score:.2f}")
            self.console.print(f"Vulnerabilities: {len(scan_result.vulnerabilities)}")
            
            # Show exploit results for this target
            target_exploits = [r for r in results['exploit_results'] if r.target == scan_result.target]
            if target_exploits:
                self.console.print(f"Exploit Attempts: {len(target_exploits)}")
                successful = sum(1 for r in target_exploits if r.success)
                self.console.print(f"Successful Exploits: {successful}")
    
    def do_payload(self, args):
        """Generate custom payload
        Usage: payload <target> <exploit> [options]
        """
        try:
            if not args:
                self.console.print("❌ Usage: payload <target> <exploit> [options]", style="bold red")
                return
            
            parts = args.split()
            if len(parts) < 2:
                self.console.print("❌ Target and exploit required", style="bold red")
                return
            
            target = parts[0]
            exploit_name = parts[1]
            
            # Parse options
            options = {}
            for part in parts[2:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    options[key] = value
            
            with self.console.status("[bold yellow]Generating payload..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                payload = loop.run_until_complete(
                    self.framework.payload_generator.generate(target, exploit_name, options)
                )
                loop.close()
            
            payload_panel = Panel(
                f"Generated Payload: {payload}\n"
                f"Target: {target}\n"
                f"Exploit: {exploit_name}\n"
                f"Options: {options}",
                title="🚀 Payload Generated",
                border_style="green"
            )
            self.console.print(payload_panel)
            
        except Exception as e:
            self.console.print(f"❌ Payload generation failed: {e}", style="bold red")
    
    def do_info(self, args):
        """Show information about exploits, payloads, or modules
        Usage: info <type> <name>
        Example: info exploit windows/smb/ms17_010_eternalblue
        """
        try:
            if not args:
                self.console.print("❌ Usage: info <type> <name>", style="bold red")
                return
            
            parts = args.split(None, 1)
            if len(parts) != 2:
                self.console.print("❌ Type and name required", style="bold red")
                return
            
            info_type, name = parts
            
            if info_type.lower() == 'exploit':
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                info = loop.run_until_complete(
                    self.framework.msf_client.get_module_info(name, 'exploit')
                )
                loop.close()
                
                if info:
                    self._display_module_info(info)
                else:
                    self.console.print(f"❌ Exploit '{name}' not found", style="bold red")
            
            elif info_type.lower() == 'payload':
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                info = loop.run_until_complete(
                    self.framework.payload_generator.get_payload_info(name)
                )
                loop.close()
                
                self._display_payload_info(info)
            
            else:
                self.console.print("❌ Invalid type. Use 'exploit' or 'payload'", style="bold red")
                
        except Exception as e:
            self.console.print(f"❌ Info retrieval failed: {e}", style="bold red")
    
    def _display_module_info(self, info):
        """Display module information"""
        info_text = f"""
Name: {info.get('name', 'Unknown')}
Type: {info.get('type', 'Unknown')}
Description: {info.get('description', 'No description')}
Author: {', '.join(info.get('author', []))}
Rank: {info.get('rank', 'Unknown')}
Platform: {', '.join(info.get('platform', []))}
Targets: {len(info.get('targets', []))} available
References: {len(info.get('references', []))} available
Required Options: {', '.join(info.get('required_options', []))}
        """
        
        info_panel = Panel(
            info_text.strip(),
            title=f"ℹ️ Module Information",
            border_style="blue"
        )
        self.console.print(info_panel)
    
    def _display_payload_info(self, info):
        """Display payload information"""
        info_text = f"""
Name: {info.get('name', 'Unknown')}
Platform: {info.get('platform', 'Unknown')}
Architecture: {info.get('arch', 'Unknown')}
Type: {info.get('type', 'Unknown')}
Size: {info.get('size', 'Unknown')}
        """
        
        info_panel = Panel(
            info_text.strip(),
            title=f"🚀 Payload Information",
            border_style="blue"
        )
        self.console.print(info_panel)
    
    def do_search(self, args):
        """Search for exploits or modules
        Usage: search <query>
        """
        try:
            if not args:
                self.console.print("❌ Usage: search <query>", style="bold red")
                return
            
            with self.console.status(f"[bold yellow]Searching for '{args}'..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(
                    self.framework.msf_client.search_modules(args)
                )
                loop.close()
            
            if not results:
                self.console.print(f"❌ No results found for '{args}'", style="bold yellow")
                return
            
            search_table = Table(title=f"🔍 Search Results for '{args}'")
            search_table.add_column("Type", style="cyan")
            search_table.add_column("Name", style="green")
            search_table.add_column("Rank", style="yellow")
            search_table.add_column("Description", style="white")
            
            for result in results[:20]:  # Show top 20
                search_table.add_row(
                    result.get('type', 'Unknown'),
                    result.get('name', 'Unknown'),
                    result.get('rank', 'Unknown'),
                    result.get('description', 'No description')[:60] + "..."
                )
            
            self.console.print(search_table)
            
        except Exception as e:
            self.console.print(f"❌ Search failed: {e}", style="bold red")
    
    def do_clear(self, args):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def do_exit(self, args):
        """Exit the framework"""
        return self._exit()
    
    def do_quit(self, args):
        """Quit the framework"""
        return self._exit()
    
    def _exit(self):
        """Exit the framework with cleanup"""
        self.console.print("🧹 Cleaning up and exiting...", style="bold yellow")
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.framework.cleanup())
            loop.close()
        except Exception as e:
            self.console.print(f"⚠️ Cleanup warning: {e}", style="yellow")
        
        self.console.print("👋 Goodbye!", style="bold green")
        return True
    
    def _get_severity_style(self, severity):
        """Get style for severity level"""
        styles = {
            'Critical': 'bold red',
            'High': 'red',
            'Medium': 'yellow',
            'Low': 'green'
        }
        return styles.get(severity, 'white')
    
    def emptyline(self):
        """Handle empty line input"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        self.console.print(f"❌ Unknown command: {line}", style="bold red")
        self.console.print("💡 Type 'help' for available commands", style="bold blue")
