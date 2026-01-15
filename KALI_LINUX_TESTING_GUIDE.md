# SentinelShield - Kali Linux Testing Guide

## Overview
This guide provides comprehensive instructions for testing the SentinelShield WAF (Web Application Firewall) on Kali Linux. SentinelShield is an advanced intrusion detection and web protection system designed to detect and prevent various cybersecurity attacks.

## Prerequisites

### System Requirements
- Kali Linux 2024.x or later
- Python 3.8 or higher
- 2GB RAM minimum
- 5GB free disk space
- Internet connection for downloading dependencies

### Required Tools
- git (for cloning the repository)
- Python pip (package manager)
- curl/wget (for HTTP requests)
- Burp Suite Community or OWASP ZAP (optional, for advanced testing)

## Installation Steps

### 1. Update System
```bash
sudo apt-get update
sudo apt-get upgrade -y
```

### 2. Clone the SentinelShield Repository
```bash
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
```

### 3. Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Verify Installation
```bash
python --version
pip list | grep pytest
```

## Testing Framework Overview

SentinelShield includes three comprehensive test suites:

### Test Modules
1. **test_attack_payloads.py** - Tests detection of various attack patterns
   - SQL Injection attacks
   - XSS (Cross-Site Scripting) attacks
   - Path Traversal/LFI attacks
   - Command Injection attacks
   - LDAP Injection attacks
   - XML External Entity (XXE) attacks

2. **test_comprehensive_security.py** - Tests security features
   - Rate limiting functionality
   - Request validation
   - Security headers
   - Comprehensive attack coverage

3. **test_normal_requests.py** - Tests legitimate traffic handling
   - Normal GET requests
   - POST requests with valid data
   - Cookie handling
   - Header processing

## Running Tests on Kali Linux

### Method 1: Run All Tests
```bash
python -m pytest tests/ -v
```

### Method 2: Run Specific Test Suite
```bash
# Test attack payload detection
python -m pytest tests/test_attack_payloads.py -v

# Test security features
python -m pytest tests/test_comprehensive_security.py -v

# Test normal request handling
python -m pytest tests/test_normal_requests.py -v
```

### Method 3: Run Tests with Coverage Report
```bash
pip install coverage
python -m pytest tests/ --cov=src --cov-report=html
firefox htmlcov/index.html  # View coverage report
```

### Method 4: Run Tests with Detailed Output
```bash
python -m pytest tests/ -v -s
```
The `-s` flag shows print statements during test execution.

## Manual Testing on Kali Linux

### 1. SQL Injection Testing
```bash
# Start the WAF engine in a terminal
cd src
python waf_engine.py

# In another terminal, test SQL injection payloads
curl "http://localhost:5000/test?id=1' OR '1'='1"
curl "http://localhost:5000/test?id=1; DROP TABLE users--"
```

### 2. XSS Attack Testing
```bash
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"
curl "http://localhost:5000/test?input=<img src=x onerror=alert('XSS')>"
```

### 3. Path Traversal Testing
```bash
curl "http://localhost:5000/file?path=../../etc/passwd"
curl "http://localhost:5000/file?path=..%2F..%2Fetc%2Fpasswd"
```

### 4. Command Injection Testing
```bash
curl "http://localhost:5000/execute?cmd=ls;whoami"
curl "http://localhost:5000/execute?cmd=cat /etc/passwd"
```

### 5. Rate Limiting Testing
```bash
# Send multiple requests rapidly to test rate limiting
for i in {1..100}; do
  curl http://localhost:5000/api/test
  echo "Request $i"
done
```

## Advanced Testing with Burp Suite

### 1. Configure Burp Suite
- Start Burp Suite: `burpsuite` (if installed)
- Configure proxy to listen on localhost:8080
- Configure browser to use Burp as proxy

### 2. Intercept and Test
- Use Burp Suite to intercept and modify requests
- Test payload delivery with Intruder
- Analyze WAF responses

## Testing with OWASP ZAP

### 1. Install OWASP ZAP
```bash
sudo apt-get install zaproxy
```

### 2. Run Automated Scan
```bash
zaproxy -config api.disablekey=true -cmd \
  -quickurl http://localhost:5000 \
  -quickout /tmp/zap-report.html
```

## Expected Test Results

### Successful Attack Detection
```
Test: SQL Injection Detection - PASSED ✓
Test: XSS Detection - PASSED ✓
Test: Path Traversal Detection - PASSED ✓
Test: Command Injection Detection - PASSED ✓
Test: Rate Limiting - PASSED ✓
Test: Normal Requests - PASSED ✓

Total: 26 tests, 26 passed, 0 failed
```

## Performance Testing

### Measure Response Time
```bash
time curl http://localhost:5000/test?id=1
```

### Load Testing with Apache Bench
```bash
ab -n 1000 -c 10 http://localhost:5000/test?id=1
```

### Using weighttp
```bash
weihttp -n 1000 -c 10 -t 4 http://localhost:5000/test?id=1
```

## Logging and Monitoring

### View Application Logs
```bash
# If using file-based logging
tail -f /tmp/sentinelshield.log

# Check for alerts
grep "ALERT" /tmp/sentinelshield.log
```

### Monitor System Resources
```bash
# In a separate terminal
watch -n 1 'top -b -n 1 | head -20'
```

## Troubleshooting

### Issue: pytest not found
```bash
pip install pytest
```

### Issue: Port 5000 already in use
```bash
# Find process using port 5000
lsof -i :5000
# Kill the process
kill -9 <PID>
```

### Issue: Module import errors
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

### Issue: Permission denied
```bash
# Make test files executable
chmod +x tests/*.py
```

## Security Testing Checklist

- [ ] Install all dependencies successfully
- [ ] Clone repository without errors
- [ ] Run all unit tests - 26/26 passing
- [ ] Test SQL injection detection
- [ ] Test XSS attack detection
- [ ] Test path traversal detection
- [ ] Test command injection detection
- [ ] Verify rate limiting functionality
- [ ] Test with normal requests
- [ ] Check logging output
- [ ] Monitor system performance
- [ ] Document any findings

## Integration with Kali Linux Tools

### Metasploit Integration (Optional)
```bash
# Start Metasploit
msfconsole

# Use custom modules to test SentinelShield
# See Metasploit documentation for custom module development
```

### Using SQLMap for SQL Injection Testing
```bash
sqlmap -u "http://localhost:5000/test?id=1" --dbs
```

### Using nikto for Web Vulnerability Scanning
```bash
nikto -h localhost:5000
```

## Performance Benchmarks

### Expected Performance Metrics
- Average request processing time: < 50ms
- Attack detection rate: > 99%
- False positive rate: < 1%
- Throughput: 1000+ requests per second

## Reporting Test Results

### Document Findings
1. **Test Date**: Record when testing was performed
2. **Environment**: Kali Linux version, Python version
3. **Results**: Pass/fail status for each test
4. **Performance**: Response times and throughput
5. **Issues**: Any problems encountered
6. **Recommendations**: Improvements or configurations

### Generate Test Report
```bash
python -m pytest tests/ -v --html=report.html
```

## Continuous Testing

### Automated Testing Schedule
- Run full test suite: Daily
- Run security scans: Weekly
- Run load tests: Monthly
- Update security rules: As needed

## Resources

- [SentinelShield GitHub Repository](https://github.com/gauravmalhotra3300-hub/SentinelShield)
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Pytest Documentation](https://docs.pytest.org/)

## Support

For issues or questions:
1. Check GitHub Issues: https://github.com/gauravmalhotra3300-hub/SentinelShield/issues
2. Review documentation in the docs/ folder
3. Check test output for detailed error messages

## Version History

- v1.0.0 (January 2026): Initial Kali Linux testing guide

---

**Last Updated**: January 15, 2026
**Author**: Gaurav Malhotra
**License**: MIT
