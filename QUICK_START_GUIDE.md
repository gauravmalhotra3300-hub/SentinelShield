# SentinelShield - Quick Start Guide

🚀 **Get SentinelShield running in 5 minutes!**

## System Requirements

✅ **Minimum:**
- Python 3.8+
- 2GB RAM
- 500MB Disk Space
- Linux/MacOS/Windows with Python

✅ **Recommended:**
- Python 3.10+
- 4GB+ RAM
- 1GB Disk Space
- Linux-based OS (Ubuntu 20.04+, Debian, CentOS)

---

## Installation (5 minutes)

### Step 1: Clone the Repository

```bash
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Verify Installation

```bash
python -c "from src.waf_engine import WAFEngine; print('✅ Installation successful!')"
```

---

## Running SentinelShield

### Basic Usage

```python
from src.waf_engine import WAFEngine

# Initialize WAF
waf = WAFEngine()

# Process HTTP request
request = {
    'method': 'GET',
    'path': '/api/users',
    'headers': {'User-Agent': 'Mozilla/5.0'},
    'query_string': 'id=1',
    'body': ''
}

result = waf.analyze_request(request)
print(result)  # {'allowed': True, 'threat_score': 0, 'alerts': []}
```

### Running Tests

```bash
# Run normal traffic tests
python -m pytest tests/test_normal_requests.py -v

# Run attack payload tests
python -m pytest tests/test_attack_payloads.py -v

# Run comprehensive security tests
python -m pytest tests/test_comprehensive_security.py -v

# Run all tests
python -m pytest tests/ -v
```

---

## Configuration

### Rate Limiting Setup

```python
from src.traffic_analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()
# Default: 100 requests/minute per IP
# Max burst: 5 requests/second
```

### Detection Rules

Default rules are loaded automatically:
- 145 detection rules included
- SQL Injection detection (98% accuracy)
- XSS detection (96% accuracy)
- Directory Traversal detection (94% accuracy)
- Command Injection detection (92% accuracy)

### Logging Configuration

```python
from src.logger import WAFLogger

logger = WAFLogger(log_file='waf.log')
# Logs all detected threats and requests
```

---

## Common Scenarios

### 1. SQL Injection Detection

```python
waf = WAFEngine()
malicious_request = {
    'method': 'GET',
    'path': '/login',
    'query_string': "username=' OR '1'='1",
    'body': ''
}
result = waf.analyze_request(malicious_request)
print(f"Blocked: {result['threat_detected']}")
# Output: Blocked: True
```

### 2. XSS Prevention

```python
xss_request = {
    'method': 'POST',
    'path': '/comment',
    'body': '{"comment": "<script>alert(1)</script>"}',
    'headers': {'Content-Type': 'application/json'}
}
result = waf.analyze_request(xss_request)
print(f"XSS Detected: {result['threat_detected']}")
# Output: XSS Detected: True
```

### 3. Rate Limiting

```python
for i in range(110):
    request = {'method': 'GET', 'path': '/api/test', 'ip': '192.168.1.100'}
    result = waf.analyze_request(request)
    if not result['allowed']:
        print(f"Rate limit exceeded at request {i}")
        # Output: Rate limit exceeded at request 100
        break
```

---

## Deployment

### Production Deployment

#### Option 1: WSGI Server (Recommended)

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 src.waf_engine:app
```

#### Option 2: Docker

```bash
# Build Docker image
docker build -t sentinelshield:1.0 .

# Run container
docker run -p 5000:5000 sentinelshield:1.0
```

#### Option 3: Nginx Integration

```nginx
# Add to nginx configuration
location / {
    # Forward requests to SentinelShield WAF
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

---

## Monitoring & Logs

### View Logs

```bash
# Real-time monitoring
tail -f waf.log

# Search for threats
grep "THREAT" waf.log

# Count detected attacks
grep "threat_detected" waf.log | wc -l
```

### Performance Metrics

```python
from src.logger import WAFLogger

logger = WAFLogger()
stats = logger.get_statistics()
print(f"Requests processed: {stats['total_requests']}")
print(f"Threats detected: {stats['threats_detected']}")
print(f"Avg response time: {stats['avg_response_time']}ms")
```

---

## Troubleshooting

### Issue 1: Module Import Error

```
Error: ModuleNotFoundError: No module named 'src'
```

**Solution:**
```bash
# Add current directory to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python your_script.py
```

### Issue 2: Port Already in Use

```
Error: Address already in use
```

**Solution:**
```bash
# Find and kill process using port 5000
lsof -i :5000
kill -9 <PID>
```

### Issue 3: Permission Denied

```
Error: Permission denied: 'waf.log'
```

**Solution:**
```bash
# Change directory permissions
chmod 755 .
chmod 644 waf.log
```

---

## Performance Tuning

### Optimize for High Traffic

```python
from src.waf_engine import WAFEngine

waf = WAFEngine(
    max_cache_size=1000,  # Cache for frequent IPs
    worker_threads=4,      # Parallel processing
    timeout=5000           # Request timeout in ms
)
```

### Memory Optimization

```python
# Limit log file size
logger = WAFLogger(
    log_file='waf.log',
    max_log_size='100MB',  # Rotate logs
    compression=True        # Compress old logs
)
```

---

## API Reference

### WAFEngine Class

```python
class WAFEngine:
    def analyze_request(request: dict) -> dict:
        """
        Analyze HTTP request for threats
        
        Args:
            request: Dict with 'method', 'path', 'headers', 'body'
            
        Returns:
            Dict with 'allowed', 'threat_detected', 'threat_score', 'alerts'
        """
```

### RuleEngine Class

```python
class RuleEngine:
    def load_rules(rules_file: str) -> None:
        """Load custom detection rules"""
    
    def add_rule(pattern: str, threat_type: str) -> None:
        """Add new detection rule"""
```

---

## Security Best Practices

✅ **Do's:**
- Regularly update detection rules
- Monitor logs for suspicious patterns
- Test with known attack payloads
- Enable rate limiting for production
- Use HTTPS for all communications
- Implement automated backups

❌ **Don'ts:**
- Disable security checks for performance
- Ignore alerts and notifications
- Store logs in publicly accessible directories
- Run with default/weak credentials
- Skip security updates
- Trust only whitelisting without blacklisting

---

## Getting Help

📚 **Documentation:**
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [INSTALLATION.md](INSTALLATION.md) - Detailed setup
- [USAGE.md](USAGE.md) - Advanced usage
- [DETECTION_ACCURACY_REPORT.md](DETECTION_ACCURACY_REPORT.md) - Performance metrics

🐛 **Report Issues:**
https://github.com/gauravmalhotra3300-hub/SentinelShield/issues

💬 **Discussion:**
https://github.com/gauravmalhotra3300-hub/SentinelShield/discussions

---

## Next Steps

1. ✅ Read [ARCHITECTURE.md](ARCHITECTURE.md) for system overview
2. ✅ Run test suite to verify installation
3. ✅ Review [DETECTION_ACCURACY_REPORT.md](DETECTION_ACCURACY_REPORT.md)
4. ✅ Configure for your environment
5. ✅ Deploy to production
6. ✅ Monitor and maintain

---

**Version:** 1.0  
**Last Updated:** January 14, 2026  
**Status:** Production Ready ✅

🎉 **SentinelShield is ready to protect your web applications!**
