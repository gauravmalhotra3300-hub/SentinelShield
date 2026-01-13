# SentinelShield - Kali Linux Testing Guide

## Complete Setup and Testing Instructions for Kali Linux

This guide provides step-by-step instructions for testing the SentinelShield WAF system on Kali Linux, including environment setup, running the application, and testing various attack payloads.

---

## PART 1: ENVIRONMENT SETUP

### Step 1: Update System
```bash
sudo apt update
sudo apt upgrade -y
```

### Step 2: Install Python and Required Tools
```bash
sudo apt install -y python3 python3-pip python3-venv git curl wget
```

### Step 3: Clone Repository
```bash
cd ~
mkdir sentinel_project
cd sentinel_project
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
```

### Step 4: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Verify installation:
```bash
pip list | grep -i flask
```

---

## PART 2: RUNNING THE WAF ENGINE

### Step 1: Navigate to Source Directory
```bash
cd src
```

### Step 2: Start WAF Engine
```bash
python3 waf_engine.py
```

Expected output:
```
2026-01-14 03:15:00,123 - __main__ - INFO - Starting SentinelShield WAF on port 5000
2026-01-14 03:15:00,124 - __main__ - INFO - WAF Status: ENABLED
 * Running on http://localhost:5000
 * Press CTRL+C to quit
```

### Step 3: Verify WAF is Running (In New Terminal)
```bash
# Open new terminal window
curl http://localhost:5000/health
```

Expected response:
```json
{"status": "healthy", "waf_enabled": true}
```

---

## PART 3: TEST PAYLOADS AND ATTACK SIMULATION

### Test 1: Normal Legitimate Request (Should PASS)
```bash
curl http://localhost:5000/test?name=JohnDoe
```

Expected response: `{"status": "allowed", "message": "Request passed WAF inspection"}`

### Test 2: SQL Injection Attack (Should BLOCK)
```bash
curl "http://localhost:5000/test?id=1' OR '1'='1"
```

Expected response: `{"status": "blocked", "reason": "THREAT_DETECTED: SQL_INJECTION"}`

### Test 3: XSS Attack Payload (Should BLOCK)
```bash
curl "http://localhost:5000/test?search=<script>alert('XSS')</script>"
```

Expected response: `{"status": "blocked", "reason": "THREAT_DETECTED: XSS_ATTACK"}`

### Test 4: Local File Inclusion (Should BLOCK)
```bash
curl "http://localhost:5000/test?file=../../../../etc/passwd"
```

Expected response: `{"status": "blocked", "reason": "THREAT_DETECTED: LOCAL_FILE_INCLUSION"}`

### Test 5: Command Injection (Should BLOCK)
```bash
curl "http://localhost:5000/test?cmd=; whoami"
```

Expected response: `{"status": "blocked", "reason": "THREAT_DETECTED: COMMAND_INJECTION"}`

### Test 6: Directory Traversal (Should BLOCK)
```bash
curl "http://localhost:5000/test?path=../../../etc/shadow"
```

Expected response: `{"status": "blocked", "reason": "THREAT_DETECTED: DIRECTORY_TRAVERSAL"}`

### Test 7: UNION-based SQL Injection (Should BLOCK)
```bash
curl "http://localhost:5000/test?id=1 UNION SELECT username FROM users"
```

Expected response: `{"status": "blocked", "reason": "THREAT_DETECTED: SQL_INJECTION"}`

---

## PART 4: ADVANCED TESTING WITH SCRIPTS

### Script 1: Automated Test Suite
Create file: `test_waf.sh`

```bash
#!/bin/bash

echo "=== SentinelShield WAF Test Suite ==="
echo

# Test 1: Health Check
echo "[TEST 1] Health Check"
curl -s http://localhost:5000/health | python3 -m json.tool
echo

# Test 2: Normal Request
echo "[TEST 2] Normal Request"
curl -s "http://localhost:5000/test?name=ValidUser" | python3 -m json.tool
echo

# Test 3: SQL Injection
echo "[TEST 3] SQL Injection"
curl -s "http://localhost:5000/test?id=1' OR '1'='1" | python3 -m json.tool
echo

# Test 4: XSS
echo "[TEST 4] Cross-Site Scripting"
curl -s "http://localhost:5000/test?msg=<script>alert(1)</script>" | python3 -m json.tool
echo

# Test 5: Statistics
echo "[TEST 5] WAF Statistics"
curl -s http://localhost:5000/stats | python3 -m json.tool
echo
```

Run the script:
```bash
chmod +x test_waf.sh
./test_waf.sh
```

### Script 2: Load Testing with Parallel Requests
```bash
#!/bin/bash

echo "Starting load test..."

for i in {1..10}; do
    curl -s "http://localhost:5000/test?id=$i" &
done

wait
echo "Load test complete"
curl -s http://localhost:5000/stats | python3 -m json.tool
```

---

## PART 5: MONITORING AND LOGGING

### Check WAF Statistics
```bash
curl http://localhost:5000/stats
```

Expected output:
```json
{
  "total_requests": 15,
  "blocked_requests": 6,
  "alerts_generated": 6,
  "allow_rate": 60.0
}
```

### Monitor Real-time Output
While WAF is running, you can see real-time logs in the terminal where the WAF engine is running.

---

## PART 6: USING BURP SUITE / OWASP ZAP FOR TESTING

### Configure Burp Suite
1. Open Burp Suite
2. Go to Proxy > Options > Proxy Listeners
3. Set upstream proxy to localhost:5000
4. Send requests through Burp Intruder/Repeater

### Payload Injection in Repeater
```
GET /test?id=1' UNION SELECT * FROM users HTTP/1.1
Host: localhost:5000
Connection: close
```

---

## PART 7: POST-TESTING ANALYSIS

### Steps to Document Results

1. **Screenshot Requests and Responses**
   - Capture normal requests passing
   - Capture blocked malicious requests
   - Save to documentation

2. **Analyze Attack Detection**
   - Record which payloads were detected
   - Note the threat categories identified
   - Document false positives (if any)

3. **Performance Metrics**
   - Record total requests processed
   - Track blocked vs allowed ratio
   - Measure response times

4. **Create Testing Report**
   - Total attacks performed: __
   - Attacks detected: __
   - Detection rate: __% 
   - False positives: __
   - False negatives: __

---

## TROUBLESHOOTING

### Issue: Port 5000 Already in Use
```bash
sudo lsof -i :5000
sudo kill -9 <PID>
```

### Issue: Module Import Errors
```bash
# Reinstall dependencies
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: Permission Denied
```bash
chmod +x KALI_TESTING_GUIDE.md
chmod +x *.sh
```

---

## APPENDIX: Common SQL Injection Payloads

- `' OR '1'='1`
- `1' UNION SELECT NULL--`
- `1' AND SLEEP(5)--`
- `'; DROP TABLE users;--`
- `1' OR 1=1;--`
- `admin' --`
- `' OR 'a'='a`

## APPENDIX: XSS Payloads

- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg onload=alert('XSS')>`
- `javascript:alert('XSS')`
- `<body onload=alert('XSS')>`

---

## NOTES

- The WAF is designed for educational purposes
- All logs are stored during runtime
- Statistics reset when WAF is restarted
- HTTP requests are logged with full details
- Use responsibly and only on authorized systems

---

**Last Updated:** January 14, 2026
**Version:** 1.0
