# SentinelShield System Architecture

## Overview

SentinelShield is a Web Application Firewall (WAF) system designed to detect and prevent malicious HTTP requests. The architecture follows a modular design pattern with clear separation of concerns.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                   HTTP Requests                       │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│         Request Processing Engine                    │
│  - Parse HTTP Headers, Parameters, Body             │
│  - Decode Payloads                                  │
│  - Extract Suspicious Patterns                      │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
        ┌──────────────┴──────────────┐
        │                             │
        ▼                             ▼
┌───────────────┐          ┌──────────────────┐
│  Rule Engine  │          │ Traffic Analyzer │
│  - Signature  │          │ - Rate Limiting  │
│  - Pattern    │          │ - IP Tracking    │
│  - Matching   │          │ - Behavior Anal. │
└────────┬──────┘          └────────┬─────────┘
         │                          │
         └───────────┬──────────────┘
                     │
                     ▼
         ┌──────────────────────┐
         │  Alert Generator     │
         │  - Decision Logic    │
         │  - Severity Levels   │
         │  - Alert Formatting  │
         └────────┬─────────────┘
                  │
                  ▼
         ┌──────────────────────┐
         │  Logging System      │
         │  - JSON Logs         │
         │  - Timestamps        │
         │  - Event Storage     │
         └────────┬─────────────┘
                  │
                  ▼
         ┌──────────────────────┐
         │  Dashboard & Reports │
         │  - Attack Metrics    │
         │  - Visualization     │
         │  - Trending          │
         └──────────────────────┘
```

## Core Components

### 1. Request Processing Engine (request_processor.py)

**Responsibility**: Parse and analyze incoming HTTP requests

**Functions**:
- Extracts URL, parameters, headers, body
- Decodes URL-encoded and Base64-encoded payloads
- Identifies suspicious keywords and patterns
- Prepares data for rule evaluation

**Input**: Raw HTTP request
**Output**: Structured request object with parsed components

### 2. Rule Engine (rule_engine.py)

**Responsibility**: Signature-based threat detection

**Features**:
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Local File Inclusion (LFI) detection
- Directory Traversal detection
- Command Injection detection
- Pattern matching against known attack signatures

**Input**: Parsed request from Request Processor
**Output**: Detection results with threat categories

### 3. Traffic Analyzer (traffic_analyzer.py)

**Responsibility**: Behavior-based anomaly detection

**Features**:
- Request frequency tracking per IP
- Rate limiting enforcement
- Brute-force detection
- DDoS attack identification
- Suspicious behavior patterns

**Input**: Request with source IP
**Output**: Rate limit violations, abuse indicators

### 4. Alert Generator (alert_generator.py)

**Responsibility**: Create actionable alerts based on threat detection

**Features**:
- Decision logic for blocking/allowing
- Severity classification
- Alert message formatting
- Response determination

**Input**: Detection results, behavior analysis
**Output**: Alert objects, decision (allow/block)

### 5. Logging System (logger.py)

**Responsibility**: Persistent event storage and retrieval

**Features**:
- JSON-formatted event logging
- Timestamp recording
- Searchable log storage
- Event categorization
- Log rotation and cleanup

**Input**: Alert and event data
**Output**: Persisted logs in storage

### 6. WAF Engine (waf_engine.py)

**Responsibility**: Main orchestration and HTTP server

**Features**:
- Flask-based HTTP server
- Request routing
- Component coordination
- Response generation
- Service initialization

**Input**: HTTP requests from clients
**Output**: HTTP responses with allow/block decisions

## Data Flow

### Normal Request Flow (Allowed)

```
1. Client sends HTTP request
   ↓
2. WAF Engine receives request
   ↓
3. Request Processor parses request
   ↓
4. Rule Engine evaluates signatures → No threats
   ↓
5. Traffic Analyzer checks rate limits → Within limits
   ↓
6. Alert Generator → Allow decision
   ↓
7. Logger records allowed request
   ↓
8. Response sent to client (Request forwarded or 200 OK)
```

### Malicious Request Flow (Blocked)

```
1. Client sends HTTP request with malicious payload
   ↓
2. WAF Engine receives request
   ↓
3. Request Processor parses request
   ↓
4. Rule Engine detects SQL Injection signature → THREAT DETECTED
   ↓
5. Alert Generator → Block decision, generate alert
   ↓
6. Logger records blocked request with threat details
   ↓
7. Response sent to client (403 Forbidden or 400 Bad Request)
```

## Attack Detection Categories

### 1. SQL Injection
- **Patterns**: `UNION SELECT`, `DROP TABLE`, `OR 1=1`, `--`, `/**/`
- **Severity**: Critical
- **Action**: Block request

### 2. Cross-Site Scripting (XSS)
- **Patterns**: `<script>`, `javascript:`, `onerror=`, `onclick=`
- **Severity**: High
- **Action**: Block request

### 3. Local File Inclusion (LFI)
- **Patterns**: `../`, `..\\`, `/etc/passwd`, `file://`
- **Severity**: High
- **Action**: Block request

### 4. Directory Traversal
- **Patterns**: `../`, `..\\`, `%2e%2e`, encoded traversal
- **Severity**: Medium
- **Action**: Block request

### 5. Command Injection
- **Patterns**: `; whoami`, `| ls`, `&& cat`, backticks, command substitution
- **Severity**: Critical
- **Action**: Block request

### 6. Rate Limiting Violations
- **Condition**: More than 100 requests per minute from single IP
- **Severity**: Medium
- **Action**: Temporarily block IP

## Configuration

Key parameters in `config.json`:

```json
{
  "waf_enabled": true,
  "listen_port": 5000,
  "request_timeout": 30,
  "rate_limit": {
    "requests_per_minute": 100,
    "window_size_seconds": 60
  },
  "alert_levels": {
    "low": {"score": 1, "action": "log"},
    "medium": {"score": 2, "action": "log"},
    "high": {"score": 3, "action": "block"},
    "critical": {"score": 4, "action": "block"}
  },
  "logging": {
    "format": "json",
    "file_path": "logs/waf_events.log"
  }
}
```

## Security Considerations

1. **False Positives**: Legitimate requests may be blocked if they contain attack-like patterns
2. **Encoding Bypass**: Attackers may use advanced encoding to bypass detection
3. **Zero-Day Attacks**: Unknown attack patterns may not be detected
4. **Performance**: Heavy traffic may impact WAF performance
5. **Logging Storage**: Logs must be securely stored and managed

## Scalability

- Current implementation suitable for educational purposes
- Production deployment requires:
  - Load balancing
  - Distributed logging
  - High-performance rule engines
  - Advanced threat intelligence integration

## Testing Strategy

1. **Positive Tests**: Verify legitimate requests pass through
2. **Negative Tests**: Verify attacks are detected and blocked
3. **Performance Tests**: Ensure system handles concurrent requests
4. **Integration Tests**: Verify component interactions
5. **Log Analysis Tests**: Verify correct logging and alerting

## Future Enhancements

1. Machine learning-based anomaly detection
2. Advanced IP reputation scoring
3. Real-time threat intelligence integration
4. Custom rule editor interface
5. Multi-tenant support
6. API rate limiting
7. Geographic blocking capabilities
8. Advanced encryption support
