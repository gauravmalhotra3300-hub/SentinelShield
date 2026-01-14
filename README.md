# SentinelShield: Advanced Intrusion Detection & Web Protection System

## Project Overview

SentinelShield is an advanced, practical implementation of a Web Application Firewall (WAF) system designed to educate students about modern intrusion detection, threat analysis, and web protection mechanisms. This project simulates real-world cybersecurity operations by detecting malicious requests, analyzing traffic patterns, and generating actionable alerts.

## System Objectives

The project aims to develop a comprehensive understanding of:

1. **HTTP Request Inspection** - Analyzing incoming requests for malicious content
2. **Attack Signature Detection** - Identifying common web attacks (SQL Injection, XSS, LFI, Directory Traversal, Command Injection)
3. **Behavior-Based Monitoring** - Detecting rate-limit violations and automated scanning
4. **Alert Generation & Decision Logic** - Creating real-time alerts based on threat detection
5. **Logging & Analysis** - Comprehensive logging and dashboard visualization

## Core Components

### 1. Request Processing Engine
- Inspects HTTP headers, parameters, body, and URL patterns
- Identifies suspicious strings and encoded payloads
- Logs all incoming requests with metadata

### 2. Rule-Based Detection Engine
- Implements signature matching for known attacks
- Supports pattern-based threat identification
- Configurable rule system for custom detection

### 3. Traffic Monitoring System
- Tracks requests by IP address
- Implements rate limiting
- Detects brute-force and flooding attempts

### 4. Logging & Alert System
- Real-time event logging
- JSON-formatted logs for analysis
- Alert severity classification

### 5. Dashboard & Reporting
- Summary statistics and visualizations
- Attack trend analysis
- False positive/negative metrics

## Attack Types Detected

- **SQL Injection**: Queries attempting database manipulation
- **Cross-Site Scripting (XSS)**: JavaScript injection attempts
- **Local File Inclusion (LFI)**: File traversal attacks
- **Directory Traversal**: Path manipulation attacks
- **Command Injection**: OS command execution attempts
- **Rate Limiting Violations**: Brute-force and DDoS attempts

## Project Structure

```
SentinelShield/
├── src/
│   ├── waf_engine.py          # Main WAF implementation
│   ├── request_parser.py      # HTTP request analysis
│   ├── detection_engine.py    # Threat detection logic
│   ├── rate_limiter.py        # Traffic rate limiting
│   ├── logger.py              # Logging system
│   └── alert_handler.py       # Alert generation
├── rules/
│   ├── attack_signatures.json # Attack pattern definitions
│   └── rate_limits.json       # Rate limiting rules
├── logs/
│   ├── requests.log           # All requests
│   └── alerts.log             # Detected threats
├── reports/
│   └── analysis_reports/      # Dashboard & summaries
├── tests/
│   ├── test_normal_requests.py
│   └── test_attack_payloads.py
├── docs/
│   ├── ARCHITECTURE.md        # System design
│   ├── INSTALLATION.md        # Setup guide
│   └── USAGE.md               # Operation guide
└── README.md
```

## Requirements

- Python 3.8+
- Flask (for web server)
- requests (for testing)
- json (built-in)
- logging (built-in)

## Installation

```bash
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
pip install -r requirements.txt
```

## Usage

```bash
python src/waf_engine.py
```

The WAF will start listening on localhost:5000 and begin analyzing incoming requests.

## Practical Work Deliverables

Students are expected to complete:

1. **Practical Journal** containing:
   - Purpose and objectives
   - Tools and methodology
   - Step-by-step execution with screenshots
   - Observations and log analysis

2. **Final Report** including:
   - Total attacks performed and detected
   - Detection accuracy metrics
   - False positive and false negative analysis
   - Recommended rule improvements

3. **Artifacts**:
   - System architecture diagrams
   - Dashboard screenshots
   - Comprehensive test logs
   - Remediation recommendations

## Learning Outcomes

Upon completion, students will understand:
- How Web Application Firewalls (WAF) protect applications
- Signature-based threat detection principles
- Behavior-based anomaly detection
- Real-world incident response workflows
- Security logging and monitoring best practices
- Cybersecurity operations and SOC functions

## Documentation

Detailed documentation is available in:
- `docs/ARCHITECTURE.md` - System design and workflow
- `docs/INSTALLATION.md` - Step-by-step setup instructions
- `docs/USAGE.md` - Operational guidelines

## Author

Gaurav Malhotra (gaurav.malhotra3300@gmail.com)

## Status

**Project Status**: In Development  
**Last Updated**: January 13, 2026  
**Version**: 1.0.0 (Development)

---

**Note**: This is an educational project designed for learning cybersecurity concepts. It is not intended for production use.


## Project Metrics Dashboard

View the comprehensive project metrics and completion dashboard:

- **[Project Metrics Dashboard](./PROJECT_METRICS_DASHBOARD.html)** - Interactive dashboard showing project status, metrics, test results, and deployment information.
