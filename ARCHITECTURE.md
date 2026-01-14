# SentinelShield: System Architecture

## Overview
SentinelShield is an Advanced Intrusion Detection & Web Protection System (WAF) designed as a practical educational project. It demonstrates threat detection, request inspection, rate limiting, and real-time alerting capabilities.

## System Architecture Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                   HTTP Request Flow                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────┐
         │  Request Parser Engine  │
         │  (request_parser.py)    │
         └────────────┬────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ Detection│ │  Rate    │ │ Behavior │
  │ Engine   │ │ Limiter  │ │Analyzer  │
  └────┬─────┘ └────┬─────┘ └────┬─────┘
       │             │            │
       └─────────────┼────────────┘
                     │
                     ▼
         ┌─────────────────────────┐
         │    Alert Handler        │
         │  (alert_handler.py)     │
         └────────────┬────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
   ┌────────┐  ┌──────────┐  ┌────────────┐
   │ Logging│  │ Dashboard│  │ Alerting   │
   │System  │  │          │  │ System     │
   └────────┘  └──────────┘  └────────────┘
```

## Core Components

### 1. Request Processing Engine (request_parser.py)
**Purpose:** Parse and analyze incoming HTTP requests

**Features:**
- HTTP request parsing (URL, headers, parameters, body)
- Header extraction and analysis
- Parameter parsing (query strings, form data)
- Body content parsing and encoding detection
- Request normalization

**Input:** Raw HTTP requests
**Output:** Parsed request object with categorized components

### 2. Rule-Based Detection Engine (detection_engine.py)
**Purpose:** Identify malicious patterns and attack signatures

**Detects:**
- SQL Injection (quotes, SQL keywords, comments)
- Cross-Site Scripting (XSS) - script tags, event handlers
- Local File Inclusion (LFI) - path traversal patterns
- Directory Traversal (../, ..\)
- Command Injection (shell commands, pipes, redirects)

**Mechanisms:**
- Pattern matching using regex
- Signature-based detection
- Encoding bypass detection
- Multi-layered analysis

### 3. Rate Limiting System (rate_limiter.py)
**Purpose:** Monitor and prevent abuse through traffic analysis

**Features:**
- Per-IP request counting
- Time-window based thresholds
- Automatic IP flagging for excessive requests
- Configurable rate limits

### 4. Logging System (logger.py)
**Purpose:** Record all security events and requests

**Features:**
- JSON-based request logging
- Alert log separation
- Timestamp on all entries
- Severity classification
- Log file management

**Log Types:**
- Request logs (all incoming requests)
- Alert logs (detected threats)

### 5. Alert Handler (alert_handler.py)
**Purpose:** Generate and manage security alerts

**Features:**
- Threat alert generation
- Severity scoring (CRITICAL/HIGH/MEDIUM/LOW)
- Alert formatting and display
- Alert dispatch mechanism
- Real-time notification

### 6. Dashboard & Reporting
**Purpose:** Visualize security events and metrics

**Features:**
- Attack statistics
- Attack type distribution
- Blocked IP addresses
- Real-time alerts
- Historical trend analysis

### 7. Main WAF Engine (main_waf.py)
**Purpose:** Orchestrate all components

**Responsibilities:**
- Receive incoming requests
- Coordinate detection workflow
- Make allow/block decisions
- Trigger alerts and logging
- Maintain system state

## Data Flow

### Request Analysis Workflow
1. **Receive** → HTTP request arrives at WAF
2. **Parse** → Extract components (headers, params, body)
3. **Detect** → Check against attack signatures
4. **Monitor** → Check rate limits per IP
5. **Decide** → Allow or block request
6. **Log** → Record the event
7. **Alert** → Generate alert if needed
8. **Display** → Update dashboard

## Attack Detection Rules

### SQL Injection Signatures
- Single/double quotes with keywords: SELECT, UNION, DROP, INSERT, UPDATE, DELETE
- Comment symbols: --, #, /**/
- Encoded payloads: %27, %22, \x27, \x22

### XSS Signatures
- Script tags: <script>, </script>
- Event handlers: onload=, onclick=, onerror=
- Script execution: javascript:, data:

### LFI/Directory Traversal
- Traversal patterns: ../, ..\
- Null byte injection: %00
- Directory enumeration: /etc/passwd, /windows/system32

### Command Injection
- Shell operators: |, &, ;, &&, ||
- Command substitution: ``, $()
- Redirection: >, <, 2>&1

## Rate Limiting Policy

- **Normal Users:** 100 requests per minute per IP
- **Suspicious Activity:** 20+ requests in 60 seconds
- **Abuse Threshold:** 10+ flagged requests per IP

## Security Levels

1. **CRITICAL:** Definite malicious attempt (blocked immediately)
2. **HIGH:** Suspicious pattern detected (logged, may block)
3. **MEDIUM:** Potential attack indicator (logged)
4. **LOW:** Informational alert (monitored)

## Technology Stack

- **Language:** Python 3.8+
- **Framework:** Flask (for API/Dashboard)
- **Database:** JSON files (logging)
- **Testing:** pytest, curl, Burp Suite
- **Deployment:** Docker compatible

## Performance Characteristics

- **Request Processing:** < 100ms per request
- **Detection Engine:** Pattern matching (optimized)
- **Memory Usage:** Minimal (IP tracking only)
- **Scalability:** Single-threaded, can be multi-threaded

## Integration Points

1. **HTTP Server:** Receives all incoming requests
2. **Database:** Stores logs and configurations
3. **Dashboard:** Displays real-time alerts
4. **Alerting System:** Sends notifications

## Future Enhancements

- Machine learning-based anomaly detection
- Distributed rate limiting across multiple nodes
- Advanced dashboard with visualizations
- API for integration with other security tools
- Automated response mechanisms
- Geographic IP analysis
- Behavioral baseline learning
