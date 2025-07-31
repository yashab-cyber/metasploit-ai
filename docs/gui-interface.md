# Desktop GUI Interface

The Metasploit-AI Framework includes a modern desktop GUI application built with CustomTkinter, providing a comprehensive and user-friendly interface for penetration testing activities.

## Overview

The desktop GUI offers a complete penetration testing workflow in a native desktop application with:

- **Modern Design**: Dark-themed interface with professional styling
- **AI Integration**: Built-in AI assistant for analysis and recommendations
- **Real-time Updates**: Live status monitoring and progress tracking
- **Comprehensive Tools**: All framework features accessible through intuitive interface
- **Session Management**: Interactive session handling and monitoring

## Starting the GUI

```bash
# Basic start
python app.py --mode gui

# With debug mode
python app.py --mode gui --debug
```

## Interface Components

### Header Section
- **Framework Logo**: Metasploit-AI branding and visual identity
- **Status Indicators**: Real-time system status (AI Engine, Database, Connection)
- **Current Time**: System time display for session tracking

### Main Navigation Tabs

#### 1. Dashboard
- **Quick Statistics**: Overview of active scans, vulnerabilities, sessions, and AI recommendations
- **Recent Activity**: Real-time log of framework activities and operations
- **System Status**: Health monitoring and resource utilization

#### 2. Scanner
- **Target Configuration**: Input for IP addresses, CIDR ranges, and scan parameters
- **Scan Types**: Quick, Full, Stealth, and Aggressive scanning options
- **AI Analysis**: Toggle for automatic AI-powered vulnerability analysis
- **Results Display**: Interactive table showing discovered hosts, ports, services, and versions
- **Progress Tracking**: Real-time scan progress with visual indicators

#### 3. Exploits
- **Exploit Search**: Search and filter exploit database
- **AI Recommendations**: Smart exploit suggestions based on scan results
- **Platform Filtering**: Filter by Windows, Linux, macOS, Multi-platform
- **Rank Filtering**: Filter by exploit reliability (Excellent, Great, Good, etc.)
- **Exploit Details**: Comprehensive information about selected exploits

#### 4. Payloads
- **Payload Configuration**: Select payload types and parameters
- **Network Settings**: Configure LHOST, LPORT, and connection details
- **Output Formats**: Generate payloads in various formats (EXE, ELF, Python, etc.)
- **AI Optimization**: Automatic payload optimization for target environment
- **Encoding Options**: Enable payload encoding for evasion

#### 5. Sessions
- **Active Sessions**: Real-time display of established sessions
- **Session Details**: Information about session type, target, and connection status
- **Session Interaction**: Direct session management and command execution
- **Health Monitoring**: Session stability and performance metrics

#### 6. Reports
- **Report Configuration**: Select report types and formats
- **AI Enhancement**: Include AI analysis and recommendations in reports
- **Export Options**: Generate reports in PDF, HTML, Word, or JSON formats
- **Report History**: Browse and manage previously generated reports

#### 7. AI Assistant
- **Target Analysis**: AI-powered vulnerability assessment and risk evaluation
- **Exploit Recommendations**: Smart suggestions based on discovered vulnerabilities
- **Interactive Chat**: Natural language interaction with AI assistant
- **Capability Overview**: Visual representation of AI features and functions

#### 8. Console
- **Framework Console**: Direct command-line interface within the GUI
- **Command History**: Browse and reuse previous commands
- **Syntax Highlighting**: Enhanced readability for commands and output
- **Auto-completion**: Smart command completion and suggestions

## Menu System

### File Menu
- **New Project**: Create new penetration testing project
- **Open Project**: Load existing project files
- **Save Project**: Save current session and configurations
- **Import Targets**: Load target lists from external files
- **Export Results**: Save scan results and findings

### Tools Menu
- **Network Scanner**: Quick access to scanning functionality
- **Exploit Browser**: Browse and search exploit database
- **Payload Generator**: Create custom payloads
- **Session Manager**: Manage active sessions

### AI Menu
- **Target Analysis**: Comprehensive AI-powered target assessment
- **Exploit Recommendations**: Get AI suggestions for exploitation
- **Payload Optimization**: Optimize payloads using AI
- **Generate Report**: Create AI-enhanced reports

### View Menu
- **Console**: Toggle console visibility
- **Logs**: View system logs and debugging information
- **Jobs**: Monitor background tasks and processes
- **Full Screen**: Toggle full-screen mode

### Help Menu
- **Documentation**: Access framework documentation
- **Tutorials**: Interactive learning modules
- **Keyboard Shortcuts**: Quick reference for hotkeys
- **About**: Version and credits information

## Key Features

### AI Integration
The GUI provides seamless access to AI-powered features:

- **Intelligent Analysis**: Automatic vulnerability assessment with confidence scoring
- **Smart Recommendations**: Context-aware exploit and payload suggestions
- **Risk Assessment**: AI-driven risk scoring and prioritization
- **Natural Language Interface**: Chat with AI for guidance and assistance

### Real-time Updates
All interface components update in real-time:

- **Live Scan Progress**: Visual progress bars and status indicators
- **Session Monitoring**: Automatic session status updates
- **Activity Logging**: Real-time activity feed on dashboard
- **Status Indicators**: Dynamic system health monitoring

### Modern UX/UX Design
Professional interface designed for penetration testers:

- **Dark Theme**: Reduces eye strain during long testing sessions
- **Intuitive Layout**: Logical organization of tools and information
- **Responsive Design**: Adapts to different screen sizes and resolutions
- **Visual Feedback**: Clear indicators for all user actions

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New Project |
| `Ctrl+O` | Open Project |
| `Ctrl+S` | Save Project |
| `Ctrl+T` | New Target |
| `Ctrl+R` | Start Scan |
| `Ctrl+E` | Search Exploits |
| `Ctrl+P` | Generate Payload |
| `Ctrl+L` | Toggle Console |
| `F11` | Toggle Fullscreen |
| `Ctrl+Q` | Quit Application |

## Dependencies

The GUI interface requires additional dependencies:

```bash
# Install GUI dependencies
pip install customtkinter pillow

# Or install all requirements
pip install -r requirements.txt
```

## System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows, macOS, or Linux with GUI support
- **Memory**: Minimum 4GB RAM recommended
- **Display**: 1200x800 minimum resolution (1400x900 recommended)

## Troubleshooting

### Common Issues

#### GUI Won't Start
```bash
# Check if dependencies are installed
pip install customtkinter pillow

# Verify tkinter is available
python -c "import tkinter; print('tkinter available')"
```

#### Missing Icons or Images
- Ensure the `src/public/Metaspolit-AI.png` logo file is present
- Check file permissions for the public directory

#### Performance Issues
- Close unnecessary background applications
- Reduce scan thread count in configuration
- Monitor system resources during operation

### Debug Mode
Start the GUI with debug mode for detailed error information:

```bash
python app.py --mode gui --debug
```

## Integration with Other Interfaces

The GUI seamlessly integrates with other framework interfaces:

- **Shared Configuration**: Uses the same configuration files as CLI and web interfaces
- **Database Integration**: Shares scan results and session data across interfaces
- **API Compatibility**: Can interact with web interface API endpoints
- **Session Continuity**: Resume sessions started in other interfaces

## Future Enhancements

Planned improvements for the GUI interface:

- **Plugin System**: Support for custom GUI plugins and extensions
- **Multi-tabbed Sessions**: Handle multiple penetration testing projects simultaneously
- **Enhanced Visualizations**: Network topology and attack path visualization
- **Mobile Companion**: Companion mobile app for remote monitoring
- **Collaborative Features**: Multi-user support for team penetration testing

## Contributing

Contributions to the GUI interface are welcome:

1. **UI/UX Improvements**: Enhance visual design and user experience
2. **Feature Development**: Add new tools and capabilities
3. **Performance Optimization**: Improve responsiveness and resource usage
4. **Bug Fixes**: Report and fix issues with the interface
5. **Documentation**: Improve help text and user guides

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed contribution guidelines.
