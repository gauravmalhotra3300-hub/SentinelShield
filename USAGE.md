# SentinelShield Usage Guide

## Quick Start

### 1. Start the WAF Engine

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Run the main WAF engine
python src/main_waf.py
```

Expected output:
```
* Running on http://localhost:5000
* Dashboard available at http://localhost:5000/dashboard
* API endpoint at http://localhost:5000/api
```

### 2. Access Dashboard

Open browser: `http://localhost:5000/dashboard`

Features:
- Real-time attack alerts
- Request statistics
- Blocked IPs list
- Attack type distribution

## API Endpoints

### 1. Submit Request for Analysis

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"method": "GET", "url": "/search", "params": "q=test"}'
```

### 2. Get Attack Statistics

```bash
curl http://localhost:5000/api/stats
```

### 3. Get Recent Alerts

```bash
curl http://localhost:5000/api/alerts?limit=10
```

### 4. Get Blocked IPs

```bash
curl http://localhost:5000/api/blocked-ips
```

## Testing Attack Detection

### SQL Injection Test

```bash
# Test 1: Basic SQL Injection
curl "http://localhost:5000/api/analyze" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"url": "/login", "params": "username=admin' OR '1'='1"}'

# Expected: BLOCKED - SQL Injection detected
```

### XSS (Cross-Site Scripting) Test

```bash
# Test 2: XSS Payload
curl "http://localhost:5000/api/analyze" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"url": "/comment", "params": "text=<script>alert(1)</script>"}'

# Expected: BLOCKED - XSS detected
```

### LFI (Local File Inclusion) Test

```bash
# Test 3: Directory Traversal
curl "http://localhost:5000/api/analyze" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"url": "/file", "params": "path=../../../../etc/passwd"}'

# Expected: BLOCKED - LFI/Path Traversal detected
```

### Command Injection Test

```bash
# Test 4: Command Injection
curl "http://localhost:5000/api/analyze" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"url": "/execute", "params": "cmd=ls | cat /etc/passwd"}'

# Expected: BLOCKED - Command Injection detected
```

### Rate Limiting Test

```bash
# Test 5: Rate Limit (100 requests/minute)
for i in {1..150}; do
  curl http://localhost:5000/api/analyze \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"url": "/test"}'
done

# Expected: After ~100 requests, IP will be flagged
```

## Interpreting Log Files

### Request Logs (logs/requests.log)

```json
{
  "timestamp": "2026-01-14 14:30:45",
  "ip_address": "192.168.1.100",
  "method": "GET",
  "url": "/search",
  "parameters": "q=test",
  "status": "ALLOWED",
  "detection_category": "NONE"
}
```

### Alert Logs (logs/alerts.log)

```json
{
  "timestamp": "2026-01-14 14:31:12",
  "ip_address": "192.168.1.101",
  "alert_type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "payload": "admin' OR '1'='1",
  "action_taken": "BLOCKED"
}
```

## Configuration

### Modify Rate Limits

Edit `config/config.json`:

```json
{
  "rate_limit_enabled": true,
  "rate_limit_per_minute": 100,
  "suspicious_threshold": 20,
  "abuse_threshold": 10,
  "alert_level": "HIGH"
}
```

### Add Custom Rules

Edit `config/rules.json`:

```json
{
  "custom_pattern": {
    "enabled": true,
    "patterns": ["dangerous_string", "harmful_keyword"]
  }
}
```

## Running Tests

### Unit Tests

```bash
python -m pytest tests/test_parser.py -v
python -m pytest tests/test_detection.py -v
python -m pytest tests/test_rate_limiter.py -v
```

### Integration Tests

```bash
python -m pytest tests/test_integration.py -v
```

### All Tests

```bash
python -m pytest tests/ -v --tb=short
```

## Using with Kali Linux

### 1. Launch in Kali Terminal

```bash
# Open Kali Linux terminal
cd /root/sentinelshield
source venv/bin/activate
python src/main_waf.py
```

### 2. Test with Burp Suite

1. Start Burp Suite
2. Configure proxy to localhost:5000
3. Send requests through proxy
4. Monitor SentinelShield dashboard

### 3. Test with SQLmap

```bash
# SQLmap will test SQL injection vectors
sqlmap -u "http://localhost:5000/api/analyze" \
  --data="{\"url\": \"/test\"}" \
  --batch
```

## Performance Monitoring

### Check Request Rate

```bash
# Watch logs in real-time
tail -f logs/requests.log | grep -c ALLOWED
```

### Monitor Alerts

```bash
# Count alerts by type
grep -o '"alert_type": "[^"]*"' logs/alerts.log | sort | uniq -c
```

### System Resources

```bash
# Monitor process
watch -n 1 'ps aux | grep main_waf'
```

## Troubleshooting

### Port Already in Use

```bash
# Kill process on port 5000
lsof -i :5000
kill -9 <PID>
```

### Module Import Errors

```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

### Logs Not Updating

```bash
# Check log file permissions
chmod 666 logs/*.log
```

## Advanced Usage

### Custom Detection Engine

Add to `detection_engine.py`:

```python
def detect_custom_pattern(request):
    patterns = ['dangerous', 'harmful']
    for pattern in patterns:
        if pattern in request.lower():
            return True
    return False
```

### Integration with External Systems

Example: Send alerts to Slack

```python
import requests

def send_slack_alert(alert):
    webhook_url = "https://hooks.slack.com/..."
    requests.post(webhook_url, json={"text": str(alert)})
```

## Best Practices

1. **Regular Monitoring** - Check logs daily
2. **Rule Updates** - Update detection rules weekly
3. **Backup Logs** - Archive old logs monthly
4. **Performance Testing** - Test rate limits regularly
5. **Security Updates** - Keep dependencies updated

## Additional Resources

- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [INSTALLATION.md](INSTALLATION.md) - Setup guide
- [README.md](README.md) - Project overview
- [Kali Linux Guide](KALI_TESTING_GUIDE.md) - Testing guide
