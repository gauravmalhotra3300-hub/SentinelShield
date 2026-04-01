# SentinelShield: Advanced Intrusion Detection & Web Protection System

## Project Overview

SentinelShield is a defensive cybersecurity project that demonstrates core Web Application Firewall (WAF) concepts in a controlled lab environment. It is designed for security learning, detection engineering practice, and request inspection testing with a focus on visibility, rule-based analysis, rate limiting, and alert generation.

This repository is intended for authorized defensive security research, training, and lab validation. It focuses on detecting suspicious HTTP activity, classifying common attack patterns, and generating structured alerts for analysis.

## Scope & Purpose

SentinelShield provides a practical, hands-on implementation of WAF concepts including:

- **HTTP Request Inspection** – Analyzing incoming requests for malicious content
- **Attack Signature Detection** – Identifying common web attacks (SQL Injection, XSS, LFI, Directory Traversal, Command Injection)
- **Behavior-Based Monitoring** – Detecting rate-limit violations and automated scanning
- **Alert Generation & Decision Logic** – Creating real-time alerts based on threat detection
- **Logging & Analysis** – Comprehensive logging and dashboard visualization

This project is designed as a learning artifact for cybersecurity professionals and students studying defensive security, detection engineering, and SOC operations.

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
- Alert severity classification (Low, Medium, High, Critical)

### 5. Dashboard & Reporting
- Summary statistics and visualizations
- Attack trend analysis
- False positive/negative metrics

## Attack Types Detected

| Attack Type | Description |
|-------------|-------------|
| SQL Injection | Queries attempting database manipulation |
| Cross-Site Scripting (XSS) | JavaScript injection attempts |
| Local File Inclusion (LFI) | File traversal attacks |
| Directory Traversal | Path manipulation attacks |
| Command Injection | OS command execution attempts |
| Rate Limiting Violations | Brute-force and DDoS attempts |

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
├── .github/
│   └── workflows/             # CI/CD pipelines
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

The WAF will start listening on `localhost:5000` and begin analyzing incoming requests.

## Safe Use & Limitations

**Intended Use:**
- Educational and training environments only
- Authorized lab and research settings
- Defensive security skill development
- Portfolio demonstration for cybersecurity roles

**Not Intended For:**
- Production deployment without thorough review
- Offensive security operations
- Real network traffic without explicit authorization

**Known Limitations:**
- Rule-based detection only; no ML/AI anomaly detection
- HTTP traffic only; does not cover HTTPS decryption
- Single-node deployment; not horizontally scalable
- Detection rules require manual updates for new attack patterns

## Detection Coverage

| Category | Coverage Status |
|----------|----------------|
| SQL Injection | Full coverage (signature-based) |
| XSS | Full coverage (signature-based) |
| LFI / Directory Traversal | Full coverage |
| Command Injection | Full coverage |
| Rate Limiting / Brute Force | Configurable thresholds |
| Zero-Day / Unknown Attacks | Limited (pattern-based only) |

## Testing & Validation

The project includes a comprehensive test suite:

- `test_normal_requests.py` – Validates benign traffic passes through
- `test_attack_payloads.py` – Validates attack detection accuracy
- `DETECTION_ACCURACY_REPORT.md` – Full metrics and results
- `KALI_LINUX_TESTING_GUIDE.md` – Lab testing instructions

## Documentation

Detailed documentation is available in:

- `docs/ARCHITECTURE.md` – System design and workflow
- `docs/INSTALLATION.md` – Step-by-step setup instructions
- `docs/USAGE.md` – Operational guidelines
- `PRACTICAL_JOURNAL.md` – Testing observations and methodology

## Project Metrics Dashboard

View the comprehensive project metrics and completion dashboard:

- **[Project Metrics Dashboard](https://github.com/gauravmalhotra3300-hub/SentinelShield/blob/main/PROJECT_METRICS_DASHBOARD.html)** – Interactive dashboard showing project status, metrics, test results, and deployment information.

## License & Compliance

This project is released for educational and defensive research purposes. Users must comply with all applicable laws and organizational policies when deploying or testing this software.

## Author

**Gaurav Malhotra**  
Email: gaurav.malhotra3300@gmail.com  
Location: Delhi NCR, India

## Project Status

**Status**: Stable educational release  
**Version**: 1.0.0  
**Last Updated**: April 1, 2026  
**Latest Release**: [v1.0.0](https://github.com/gauravmalhotra3300-hub/SentinelShield/releases/tag/v1.0.0)

This repository is maintained as a defensive security learning project and portfolio artifact.
