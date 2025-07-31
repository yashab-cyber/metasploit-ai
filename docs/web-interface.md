# Web Interface Guide

Complete guide to using the Metasploit-AI web interface for penetration testing and security assessments.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Navigation and Layout](#navigation-and-layout)
4. [Target Management](#target-management)
5. [Scanning Operations](#scanning-operations)
6. [AI Analysis Features](#ai-analysis-features)
7. [Exploitation Management](#exploitation-management)
8. [Session Management](#session-management)
9. [Reporting Interface](#reporting-interface)
10. [Settings and Configuration](#settings-and-configuration)
11. [User Management](#user-management)
12. [Advanced Features](#advanced-features)

## Getting Started

### Launching the Web Interface

```bash
# Start the web interface
python app.py --mode web --host 0.0.0.0 --port 8080

# Start with HTTPS (recommended)
python app.py --mode web --host 0.0.0.0 --port 8443 --ssl

# Start with custom configuration
python app.py --mode web --config config/production.yaml
```

### Accessing the Interface

1. **Open your web browser**
2. **Navigate to**: `http://localhost:8080` or `https://localhost:8443`
3. **Login with default credentials**:
   - Username: `admin`
   - Password: `admin`
4. **Change default password** (highly recommended)

### Browser Compatibility

**Supported Browsers:**
- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+
- ❌ Internet Explorer (not supported)

**Required Features:**
- JavaScript enabled
- WebSocket support
- Local storage enabled
- Modern CSS support

## Dashboard Overview

### Main Dashboard Layout

```
┌─────────────────────────────────────────────────────────────┐
│ Header: Logo | Navigation | User Menu | Notifications       │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│ │   Active    │ │   Targets   │ │ Vulnera-    │ │ Session │ │
│ │   Scans     │ │  Discovered │ │ bilities    │ │ Count   │ │
│ │      5      │ │     127     │ │    43       │ │    3    │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────┤
│ ┌───────────────────────────┐ ┌───────────────────────────┐ │
│ │     Recent Activity       │ │     System Status         │ │
│ │  • Scan completed: Web... │ │  ✅ Framework: Healthy   │ │
│ │  • Exploit successful:... │ │  ✅ Database: Connected  │ │
│ │  • New vuln discovered   │ │  ✅ AI Models: Loaded    │ │
│ └───────────────────────────┘ └───────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────┐ │
│ │              Network Topology Visualization             │ │
│ │     [Interactive network map showing discovered        │ │
│ │      targets, connections, and vulnerability status]   │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Metrics Cards

**Active Scans Card:**
- Shows currently running scans
- Progress indicators for each scan
- Quick access to scan details
- Real-time status updates

**Targets Discovered Card:**
- Total number of discovered targets
- Breakdown by status (up/down/unknown)
- Quick filter options
- Direct link to targets page

**Vulnerabilities Card:**
- Total vulnerability count
- Severity breakdown (Critical/High/Medium/Low)
- Risk score indicators
- Quick access to vulnerability details

**Sessions Card:**
- Active exploitation sessions
- Session type breakdown
- Quick session interaction
- Connection status indicators

### Real-Time Updates

The dashboard provides real-time updates through WebSocket connections:
- **Live scan progress**: Progress bars update automatically
- **New discoveries**: Targets and vulnerabilities appear instantly
- **Session status**: Connection status changes in real-time
- **System alerts**: Important notifications appear immediately

## Navigation and Layout

### Primary Navigation

**Main Menu Items:**
1. **🏠 Dashboard** - Overview and system status
2. **🎯 Targets** - Target management and organization
3. **🔍 Scanner** - Network discovery and vulnerability scanning
4. **🧠 AI Analysis** - Machine learning-powered analysis
5. **💥 Exploits** - Exploitation framework and payload management
6. **💻 Sessions** - Active session management and interaction
7. **📊 Reports** - Report generation and export tools
8. **⚙️ Settings** - System configuration and preferences

### Secondary Navigation

**Context-Sensitive Menus:**
- **Target Actions**: Scan, Analyze, Exploit, Report
- **Scan Options**: Configure, Monitor, Results, Export
- **Exploit Options**: Configure, Execute, Monitor, Cleanup
- **Session Actions**: Interact, Upload, Download, Execute

### Breadcrumb Navigation

Shows current location within the application:
```
Home > Targets > 192.168.1.100 > Vulnerabilities > CVE-2021-34527
```

### Search Functionality

**Global Search Bar:**
- Search targets by IP, hostname, or description
- Find vulnerabilities by CVE, description, or severity
- Locate exploits by name, platform, or target
- Search sessions by target or session type

## Target Management

### Target Discovery Interface

**Add Targets:**
1. **Single Target**: Enter IP address or hostname
2. **IP Range**: Specify CIDR notation (e.g., 192.168.1.0/24)
3. **Import from File**: Upload text file with target list
4. **Bulk Entry**: Paste multiple targets (comma-separated)

**Target Input Form:**
```
┌─────────────────────────────────────────────────┐
│ Add New Targets                                 │
├─────────────────────────────────────────────────┤
│ Target(s): [192.168.1.0/24                   ] │
│ Label:     [Production Network               ] │
│ Tags:      [web, production, internal        ] │
│ Priority:  [High ▼]                            │
│ Notes:     [Critical business systems        ] │
│                                                 │
│ [ Add Targets ]  [ Import File ]  [ Cancel ]   │
└─────────────────────────────────────────────────┘
```

### Target List View

**Table Columns:**
- **IP Address**: Target IP with clickable link
- **Hostname**: Resolved hostname (if available)
- **Status**: Online/Offline/Unknown with status indicators
- **OS**: Operating system detection
- **Ports**: Number of open ports
- **Vulnerabilities**: Vulnerability count by severity
- **Last Scan**: Time of last scan activity
- **Actions**: Quick action buttons

**Filtering and Sorting:**
- **Filter by Status**: Online, Offline, Unknown
- **Filter by OS**: Windows, Linux, macOS, Other
- **Filter by Severity**: Critical, High, Medium, Low
- **Sort Options**: IP, Hostname, Status, Last Scan

### Target Details View

**Information Tabs:**
1. **Overview**: Basic target information and summary
2. **Services**: Detailed port and service information
3. **Vulnerabilities**: Security vulnerabilities and risk assessment
4. **Exploits**: Available exploits and recommendations
5. **Sessions**: Active sessions and history
6. **Notes**: User annotations and comments

**Service Information Display:**
```
┌─────────────────────────────────────────────────┐
│ Services for 192.168.1.100                     │
├─────────────────────────────────────────────────┤
│ Port │ Protocol │ Service │ Version │ State    │
├─────────────────────────────────────────────────┤
│ 22   │ TCP      │ SSH     │ OpenSSH │ 🟢 Open │
│ 80   │ TCP      │ HTTP    │ Apache  │ 🟢 Open │
│ 443  │ TCP      │ HTTPS   │ Apache  │ 🟢 Open │
│ 3306 │ TCP      │ MySQL   │ 5.7.29  │ 🟢 Open │
└─────────────────────────────────────────────────┘
```

## Scanning Operations

### Scan Configuration Interface

**Scan Type Selection:**
```
┌─────────────────────────────────────────────────┐
│ Create New Scan                                 │
├─────────────────────────────────────────────────┤
│ Scan Type:                                      │
│ ○ Discovery     ○ Service Enumeration          │
│ ○ Vulnerability ○ Comprehensive                │
│ ○ Web App       ○ Custom                       │
├─────────────────────────────────────────────────┤
│ Targets: [Select from list ▼] [192.168.1.0/24] │
│ Timing:  [Normal ▼] (Paranoid|Sneaky|Polite|   │
│          Normal|Aggressive|Insane)              │
│ Threads: [50                              ]     │
│ Ports:   [1-65535                         ]     │
├─────────────────────────────────────────────────┤
│ Advanced Options:                               │
│ ☑ Service Version Detection                     │
│ ☑ OS Fingerprinting                            │
│ ☐ Script Scanning                              │
│ ☐ Stealth Mode                                 │
├─────────────────────────────────────────────────┤
│ [ Start Scan ]  [ Save Template ]  [ Cancel ]  │
└─────────────────────────────────────────────────┘
```

### Scan Monitoring

**Real-Time Progress Display:**
```
┌─────────────────────────────────────────────────┐
│ Scan Progress: Network Discovery                │
├─────────────────────────────────────────────────┤
│ Status: Running                                 │
│ Progress: ████████████░░░░░░░░░░ 60% (153/255)  │
│ Elapsed: 00:03:42                              │
│ ETA: 00:02:18                                  │
├─────────────────────────────────────────────────┤
│ Current Activity:                               │
│ • Scanning 192.168.1.150...                   │
│ • 5 hosts discovered                           │
│ • 127 ports scanned                            │
├─────────────────────────────────────────────────┤
│ [ Pause ]  [ Stop ]  [ View Details ]          │
└─────────────────────────────────────────────────┘
```

### Scan Results Visualization

**Results Dashboard:**
- **Summary Statistics**: Hosts up/down, ports open/closed
- **Service Distribution**: Pie chart of discovered services
- **Vulnerability Heatmap**: Visual representation of risk levels
- **Timeline View**: Scan progress over time

**Interactive Network Map:**
- Nodes represent discovered hosts
- Edges show network connections
- Colors indicate vulnerability severity
- Hover for detailed information
- Click to drill down into target details

## AI Analysis Features

### Vulnerability Analysis Interface

**AI Analysis Dashboard:**
```
┌─────────────────────────────────────────────────┐
│ AI Vulnerability Analysis                       │
├─────────────────────────────────────────────────┤
│ Analysis Status: ✅ Complete (2 min 34 sec)    │
│ Targets Analyzed: 127                          │
│ Vulnerabilities Processed: 43                  │
│ AI Confidence: 92.4%                           │
├─────────────────────────────────────────────────┤
│ Risk Assessment:                                │
│ • Critical Risk Score: 8.7/10                  │
│ • High Priority Targets: 12                    │
│ • Exploitation Probability: 85%                │
│ • Business Impact: High                        │
├─────────────────────────────────────────────────┤
│ [ View Recommendations ] [ Export Analysis ]   │
└─────────────────────────────────────────────────┘
```

### Exploit Recommendations

**AI Recommendation Engine:**
- **Success Probability**: ML-calculated success rates
- **Difficulty Assessment**: Easy/Medium/Hard classification
- **Impact Analysis**: Potential damage assessment
- **Environmental Context**: Target-specific considerations

**Recommendation Display:**
```
┌─────────────────────────────────────────────────┐
│ Top AI Recommendations for 192.168.1.100       │
├─────────────────────────────────────────────────┤
│ 1. ms17_010_eternalblue                        │
│    Success Rate: 95% | Difficulty: Easy        │
│    Impact: Remote Code Execution               │
│    [ Select ] [ Details ] [ Configure ]        │
├─────────────────────────────────────────────────┤
│ 2. apache_struts_rce                           │
│    Success Rate: 78% | Difficulty: Medium      │
│    Impact: Web Shell Access                    │
│    [ Select ] [ Details ] [ Configure ]        │
├─────────────────────────────────────────────────┤
│ 3. mysql_privilege_escalation                  │
│    Success Rate: 65% | Difficulty: Hard        │
│    Impact: Database Access                     │
│    [ Select ] [ Details ] [ Configure ]        │
└─────────────────────────────────────────────────┘
```

### Smart Payload Generation

**AI Payload Generator Interface:**
```
┌─────────────────────────────────────────────────┐
│ AI Payload Generator                            │
├─────────────────────────────────────────────────┤
│ Target: 192.168.1.100 (Windows Server 2019)    │
│ Exploit: ms17_010_eternalblue                   │
├─────────────────────────────────────────────────┤
│ Payload Options:                                │
│ Type: [Meterpreter ▼] Shell|Meterpreter|Custom │
│ Architecture: [x64 ▼] x86|x64|ARM              │
│ Evasion Level: [High ▼] None|Low|Medium|High   │
├─────────────────────────────────────────────────┤
│ AI Enhancements:                                │
│ ☑ Automatic Encoding                           │
│ ☑ AV Evasion Techniques                        │
│ ☑ Polymorphic Generation                       │
│ ☑ Anti-Analysis Features                       │
├─────────────────────────────────────────────────┤
│ Generated Payload Preview:                      │
│ [Encoded payload bytes display...]             │
├─────────────────────────────────────────────────┤
│ [ Generate ] [ Test ] [ Deploy ] [ Save ]      │
└─────────────────────────────────────────────────┘
```

## Exploitation Management

### Exploit Selection Interface

**Exploit Browser:**
- **Category Filter**: By platform, type, or target
- **Search Function**: Text search across exploit database
- **Compatibility Check**: Automatic target compatibility
- **Ranking System**: AI-powered exploit ranking

**Exploit Configuration:**
```
┌─────────────────────────────────────────────────┐
│ Configure Exploit: ms17_010_eternalblue         │
├─────────────────────────────────────────────────┤
│ Target Configuration:                           │
│ RHOSTS: [192.168.1.100              ]          │
│ RPORT:  [445                        ]          │
├─────────────────────────────────────────────────┤
│ Payload Configuration:                          │
│ LHOST:  [192.168.1.50               ]          │
│ LPORT:  [4444                       ]          │
├─────────────────────────────────────────────────┤
│ Advanced Options:                               │
│ TIMEOUT: [30        ] seconds                   │
│ THREADS: [1         ]                           │
│ VERBOSE: [☑] Enable verbose output              │
├─────────────────────────────────────────────────┤
│ AI Recommendations:                             │
│ • Success Probability: 95%                     │
│ • Optimal Timing: Normal                       │
│ • Suggested Payload: windows/x64/meterpreter   │
├─────────────────────────────────────────────────┤
│ [ Execute ] [ Test ] [ Save Config ] [ Reset ] │
└─────────────────────────────────────────────────┘
```

### Exploitation Monitoring

**Live Exploitation Dashboard:**
- **Execution Status**: Real-time exploit execution status
- **Progress Indicators**: Step-by-step execution progress
- **Error Handling**: Automatic error detection and reporting
- **Success Metrics**: Session establishment confirmation

## Session Management

### Active Sessions Overview

**Session List Interface:**
```
┌─────────────────────────────────────────────────┐
│ Active Sessions                                 │
├─────────────────────────────────────────────────┤
│ ID │ Target        │ Type      │ User    │ Uptime │
├─────────────────────────────────────────────────┤
│ 1  │ 192.168.1.100 │ Meterpreter │ SYSTEM  │ 00:15:23 │
│ 2  │ 192.168.1.101 │ Shell     │ www-data│ 00:08:45 │
│ 3  │ 192.168.1.102 │ Meterpreter │ admin   │ 00:03:12 │
├─────────────────────────────────────────────────┤
│ [ Interact ] [ Upload ] [ Download ] [ Kill ]  │
└─────────────────────────────────────────────────┘
```

### Interactive Session Interface

**Web-Based Terminal:**
```
┌─────────────────────────────────────────────────┐
│ Session 1: 192.168.1.100 (SYSTEM)              │
├─────────────────────────────────────────────────┤
│ meterpreter > sysinfo                          │
│ Computer        : WIN-SERVER2019                │
│ OS              : Windows Server 2019           │
│ Architecture    : x64                           │
│ System Language : en_US                        │
│ Domain          : WORKGROUP                     │
│ Logged On Users : 2                             │
│ Meterpreter     : x64/windows                   │
│                                                 │
│ meterpreter > █                                 │
├─────────────────────────────────────────────────┤
│ Command: [ps                              ] ⏎   │
├─────────────────────────────────────────────────┤
│ [ Upload File ] [ Download ] [ Screenshot ]    │
│ [ Background ] [ Kill Session ] [ Help ]       │
└─────────────────────────────────────────────────┘
```

### File Management Interface

**File Browser:**
- **Directory Navigation**: Click-to-navigate file system
- **File Operations**: Upload, download, delete, rename
- **Permission Display**: File permissions and ownership
- **Search Functionality**: Find files by name or content

## Reporting Interface

### Report Generation Wizard

**Step 1: Report Type Selection:**
```
┌─────────────────────────────────────────────────┐
│ Generate New Report                             │
├─────────────────────────────────────────────────┤
│ Select Report Type:                             │
│ ○ Executive Summary                             │
│ ○ Technical Report                              │
│ ○ Compliance Report                             │
│ ○ Custom Report                                 │
├─────────────────────────────────────────────────┤
│ Format Options:                                 │
│ ☑ HTML   ☑ PDF   ☐ Word   ☐ JSON               │
├─────────────────────────────────────────────────┤
│ [ Next: Configure ] [ Cancel ]                 │
└─────────────────────────────────────────────────┘
```

**Step 2: Content Configuration:**
```
┌─────────────────────────────────────────────────┐
│ Report Configuration                            │
├─────────────────────────────────────────────────┤
│ Include Sections:                               │
│ ☑ Executive Summary                             │
│ ☑ Methodology                                   │
│ ☑ Findings Summary                              │
│ ☑ Vulnerability Details                         │
│ ☑ Exploitation Evidence                         │
│ ☑ Risk Assessment                               │
│ ☑ Recommendations                               │
│ ☐ Technical Appendices                          │
├─────────────────────────────────────────────────┤
│ Filter Options:                                 │
│ Severity: [All ▼] All|Critical|High|Medium|Low │
│ Targets:  [All Selected ▼]                     │
│ Date Range: [Last 30 Days ▼]                   │
├─────────────────────────────────────────────────┤
│ [ Generate Report ] [ Preview ] [ Back ]       │
└─────────────────────────────────────────────────┘
```

### Report Preview

**Live Report Preview:**
- **Real-time rendering**: See report as it's being generated
- **Section navigation**: Jump to specific report sections
- **Edit capabilities**: Modify content before final generation
- **Export options**: Multiple format downloads

## Settings and Configuration

### System Configuration Interface

**General Settings:**
```
┌─────────────────────────────────────────────────┐
│ System Configuration                            │
├─────────────────────────────────────────────────┤
│ Framework Settings:                             │
│ Debug Mode:     [☐] Enable debug logging       │
│ Log Level:      [INFO ▼] DEBUG|INFO|WARN|ERROR │
│ Auto-save:      [☑] Auto-save configurations   │
│ Update Check:   [☑] Check for updates          │
├─────────────────────────────────────────────────┤
│ Performance Settings:                           │
│ Max Threads:    [50                    ]        │
│ Scan Timeout:   [300       ] seconds            │
│ Memory Limit:   [4096      ] MB                 │
│ Cache Size:     [1024      ] MB                 │
├─────────────────────────────────────────────────┤
│ [ Save Changes ] [ Reset Defaults ] [ Cancel ] │
└─────────────────────────────────────────────────┘
```

### AI Model Configuration

**AI Settings Panel:**
```
┌─────────────────────────────────────────────────┐
│ AI Model Configuration                          │
├─────────────────────────────────────────────────┤
│ Vulnerability Analyzer:                         │
│ Model: [neural_network_v2.pkl ▼]               │
│ Confidence Threshold: [0.8    ] (0.0-1.0)      │
│ Batch Size: [32   ]                             │
│ Status: ✅ Loaded and Ready                     │
├─────────────────────────────────────────────────┤
│ Exploit Recommender:                            │
│ Model: [ensemble_recommender.pkl ▼]            │
│ Max Recommendations: [10  ]                     │
│ Min Success Rate: [0.5    ] (0.0-1.0)          │
│ Status: ✅ Loaded and Ready                     │
├─────────────────────────────────────────────────┤
│ GPU Acceleration:                               │
│ Enable GPU: [☑] Use CUDA if available          │
│ Device: [cuda:0 ▼] cpu|cuda:0|cuda:1           │
│ Memory Limit: [8192    ] MB                     │
├─────────────────────────────────────────────────┤
│ [ Update Models ] [ Test Models ] [ Save ]     │
└─────────────────────────────────────────────────┘
```

## User Management

### User Administration Interface

**User List:**
```
┌─────────────────────────────────────────────────┐
│ User Management                                 │
├─────────────────────────────────────────────────┤
│ Username │ Role        │ Last Login │ Status    │
├─────────────────────────────────────────────────┤
│ admin    │ Administrator │ 2025-07-31 │ 🟢 Active │
│ analyst1 │ Analyst     │ 2025-07-30 │ 🟢 Active │
│ tester1  │ Tester      │ 2025-07-29 │ 🟡 Inactive│
│ viewer1  │ Viewer      │ Never      │ 🔴 Disabled│
├─────────────────────────────────────────────────┤
│ [ Add User ] [ Edit ] [ Delete ] [ Reset Pwd ] │
└─────────────────────────────────────────────────┘
```

### Role Management

**Permission Matrix:**
```
┌─────────────────────────────────────────────────┐
│ Role Permissions                                │
├─────────────────────────────────────────────────┤
│ Permission        │ Admin │ Tester │ Analyst │ Viewer │
├─────────────────────────────────────────────────┤
│ View Dashboard    │   ✅   │   ✅    │   ✅    │   ✅   │
│ Manage Targets    │   ✅   │   ✅    │   ✅    │   ❌   │
│ Run Scans         │   ✅   │   ✅    │   ❌    │   ❌   │
│ Execute Exploits  │   ✅   │   ✅    │   ❌    │   ❌   │
│ Manage Sessions   │   ✅   │   ✅    │   ❌    │   ❌   │
│ Generate Reports  │   ✅   │   ✅    │   ✅    │   ✅   │
│ User Management   │   ✅   │   ❌    │   ❌    │   ❌   │
│ System Config     │   ✅   │   ❌    │   ❌    │   ❌   │
└─────────────────────────────────────────────────┘
```

## Advanced Features

### Automation Interface

**Workflow Builder:**
- **Drag-and-Drop**: Visual workflow creation
- **Pre-built Templates**: Common penetration testing workflows
- **Scheduling**: Automated execution scheduling
- **Conditional Logic**: If-then-else workflow branches

### Integration Management

**External Tool Integration:**
```
┌─────────────────────────────────────────────────┐
│ External Integrations                           │
├─────────────────────────────────────────────────┤
│ Tool        │ Status  │ Version │ Actions       │
├─────────────────────────────────────────────────┤
│ Nmap        │ ✅ Active │ 7.94   │ [ Configure ] │
│ Nessus      │ ❌ Disabled│ -     │ [ Enable ]    │
│ Burp Suite  │ 🟡 Warning│ 2023.x │ [ Update ]    │
│ MISP        │ ✅ Active │ 2.4.x  │ [ Configure ] │
├─────────────────────────────────────────────────┤
│ [ Add Integration ] [ Test All ] [ Refresh ]   │
└─────────────────────────────────────────────────┘
```

### API Management

**API Key Management:**
- **Generate API Keys**: Create new API keys for integrations
- **Permissions**: Granular API permission control
- **Usage Monitoring**: Track API usage and limits
- **Rate Limiting**: Configure API rate limits

### Backup and Recovery

**System Backup Interface:**
```
┌─────────────────────────────────────────────────┐
│ Backup and Recovery                             │
├─────────────────────────────────────────────────┤
│ Backup Components:                              │
│ ☑ Database                                      │
│ ☑ Configuration Files                           │
│ ☑ AI Models                                     │
│ ☑ User Data                                     │
│ ☐ Log Files                                     │
├─────────────────────────────────────────────────┤
│ Backup Schedule:                                │
│ Frequency: [Daily ▼] Manual|Daily|Weekly       │
│ Time: [02:00 AM]                                │
│ Retention: [30 days]                            │
├─────────────────────────────────────────────────┤
│ [ Create Backup ] [ Restore ] [ Schedule ]     │
└─────────────────────────────────────────────────┘
```

## Best Practices

### Performance Optimization

**Browser Performance:**
- Use modern browsers with JavaScript enabled
- Close unused tabs to free memory
- Clear browser cache regularly
- Disable unnecessary browser extensions

**Interface Responsiveness:**
- Use filtering to reduce large data sets
- Implement pagination for large lists
- Enable real-time updates selectively
- Optimize network connection

### Security Considerations

**Web Interface Security:**
- Always use HTTPS in production
- Change default passwords immediately
- Enable session timeouts
- Use strong authentication methods
- Regular security updates

**Access Control:**
- Implement principle of least privilege
- Regular user access reviews
- Monitor user activities
- Secure administrative functions

---

*For additional help with the web interface, see the [User Manual](user-manual.md) or [Troubleshooting Guide](troubleshooting.md).*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
