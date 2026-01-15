# SentinelShield - Kali Linux Testing Quick Reference

## Testing Resources Available

This project includes comprehensive documentation for testing SentinelShield on Kali Linux:

### 📋 Documentation Files

1. **KALI_TESTING_GUIDE.md** - Complete Testing Guide
   - System requirements and prerequisites
   - Detailed installation steps
   - Testing framework overview
   - Multiple testing methods (automated, manual, advanced)
   - Integration with Kali tools
   - Troubleshooting guide
   - Security testing checklist
   - Expected results and performance metrics

2. **KALI_TERMINAL_TEST_COMMANDS.md** - Ready-to-Use Commands
   - Quick start setup commands
   - SQL injection testing payloads
   - XSS attack detection commands
   - Path traversal and LFI testing
   - Command injection examples
   - Rate limiting tests
   - LDAP injection testing
   - XXE attack detection
   - Performance testing commands
   - Quick test sequence scripts

## Quick Start

### 1. Initial Setup (5 minutes)
```bash
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
pip install -r requirements.txt
```

### 2. Run All Tests (2 minutes)
```bash
python -m pytest tests/ -v
```

**Expected Result**: All 26 tests should PASS ✓

### 3. Manual Attack Testing (varies)
```bash
# Test SQL Injection
curl "http://localhost:5000/test?id=1' OR '1'='1"

# Test XSS
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"

# Test Path Traversal
curl "http://localhost:5000/file?path=../../etc/passwd"
```

## Test Coverage

### Attack Types Detected
- ✓ SQL Injection (5+ variants)
- ✓ XSS - Cross-Site Scripting (5+ variants)
- ✓ Path Traversal / LFI (5+ variants)
- ✓ Command Injection (5+ variants)
- ✓ LDAP Injection (3+ variants)
- ✓ XXE - XML External Entity (2+ variants)
- ✓ Rate Limiting / DDoS Prevention

### Test Statistics
- **Total Test Cases**: 26
- **Attack Payload Tests**: 14
- **Security Feature Tests**: 5
- **Normal Request Tests**: 7
- **Expected Pass Rate**: 100%

## Testing Methods

### Automated Testing
Run the comprehensive pytest suite:
```bash
python -m pytest tests/ -v
```

### Manual Testing
Use curl commands from KALI_TERMINAL_TEST_COMMANDS.md to test specific attack vectors.

### Tool Integration
- **SQLMap**: SQL Injection scanning
- **OWASP ZAP**: Web vulnerability scanning
- **Burp Suite**: Intercept and modify requests
- **Nikto**: Web server scanning
- **Apache Bench**: Performance testing

## Expected Performance

### Response Time
- Average: < 50ms per request
- Attack detection: < 100ms
- Rate limiting threshold: 100 requests/second

### Accuracy
- Attack detection rate: > 99%
- False positive rate: < 1%
- Legitimate request pass-through: 100%

## Kali Linux Tools Integration

### SQLMap (SQL Injection Testing)
```bash
sqlmap -u "http://localhost:5000/test?id=1" --dbs
```

### OWASP ZAP (Web Vulnerability Scanner)
```bash
zaproxy -config api.disablekey=true -cmd -quickurl http://localhost:5000
```

### Nikto (Web Server Scanner)
```bash
nikto -h localhost:5000
```

### Apache Bench (Load Testing)
```bash
ab -n 1000 -c 10 http://localhost:5000/test?id=1
```

## Testing Workflow

### Phase 1: Setup (10 minutes)
1. Clone repository
2. Install dependencies
3. Verify Python version (3.8+)
4. Check pytest installation

### Phase 2: Automated Testing (5 minutes)
1. Run full test suite
2. Verify 26/26 tests pass
3. Check coverage report
4. Review test output

### Phase 3: Manual Testing (15-30 minutes)
1. Test SQL injection payloads
2. Test XSS attacks
3. Test path traversal
4. Test command injection
5. Test rate limiting

### Phase 4: Advanced Testing (30-60 minutes)
1. Use SQLMap for SQL injection
2. Run OWASP ZAP scan
3. Test with Burp Suite
4. Perform load testing
5. Monitor system resources

## Success Criteria

✓ **All unit tests pass** (26/26)
✓ **All attack payloads detected**
✓ **Normal requests processed correctly**
✓ **Rate limiting works as expected**
✓ **Response times < 50ms**
✓ **No critical errors in logs**
✓ **System resources stable**

## Troubleshooting

### Tests Fail
1. Check Python version: `python --version`
2. Verify dependencies: `pip list`
3. Reinstall if needed: `pip install --force-reinstall -r requirements.txt`

### Port 5000 In Use
```bash
lsof -i :5000
kill -9 <PID>
```

### Import Errors
```bash
pip install -U pip
pip install --force-reinstall -r requirements.txt
```

## Performance Benchmarking

### Measure Response Time
```bash
time curl http://localhost:5000/test?id=1
```

### Load Test (1000 requests, 10 concurrent)
```bash
ab -n 1000 -c 10 http://localhost:5000/test?id=1
```

### Monitor System During Testing
```bash
top  # CPU and memory usage
netstat -tulpn  # Network connections
ps aux | grep python  # Process info
```

## Security Testing Checklist

Before concluding testing, verify:

- [ ] All 26 unit tests pass
- [ ] SQL injection detected and blocked
- [ ] XSS attacks detected and blocked  
- [ ] Path traversal attempts blocked
- [ ] Command injection attempts blocked
- [ ] Rate limiting prevents flooding
- [ ] Normal requests processed successfully
- [ ] Logging captures all security events
- [ ] Performance meets requirements
- [ ] No critical errors in output
- [ ] System resources within limits
- [ ] All test results documented

## Documentation Structure

```
SentinelShield/
├── KALI_TESTING_GUIDE.md              (Detailed guide)
├── KALI_TERMINAL_TEST_COMMANDS.md    (Ready-to-use commands)
├── KALI_TESTING_SUMMARY.md           (This file - Quick reference)
├── tests/                             (Test suites)
│   ├── test_attack_payloads.py        (Attack detection tests)
│   ├── test_comprehensive_security.py (Security feature tests)
│   └── test_normal_requests.py        (Valid traffic tests)
├── docs/                              (Documentation)
│   ├── ARCHITECTURE.md                (System design)
│   ├── INSTALLATION.md                (Setup guide)
│   └── USAGE.md                       (Usage instructions)
└── src/                               (Source code)
    └── (WAF implementation)
```

## Next Steps

1. **Read KALI_TESTING_GUIDE.md** for comprehensive testing instructions
2. **Use KALI_TERMINAL_TEST_COMMANDS.md** for ready-to-use test commands
3. **Follow the testing workflow** above
4. **Document your results** in a test report
5. **Share findings** with the development team

## Contact & Support

- **GitHub Issues**: https://github.com/gauravmalhotra3300-hub/SentinelShield/issues
- **Documentation**: See docs/ folder for more information
- **Test Results**: Review logs and reports generated during testing

## Testing Tips

- 💡 Use `-v` flag with pytest for verbose output
- 💡 Combine multiple testing methods for comprehensive coverage
- 💡 Monitor logs during testing for detailed information
- 💡 Save test outputs for future reference
- 💡 Use the quick test sequence script for rapid validation
- 💡 Test in a dedicated environment, not production
- 💡 Document any issues or unexpected behavior

## Version

Guide Version: 1.0.0
Created: January 15, 2026
Author: Gaurav Malhotra

---

**Ready to test? Start with KALI_TESTING_GUIDE.md!**
