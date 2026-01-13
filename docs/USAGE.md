# SentinelShield Usage Guide

## Quick Start

### 1. Start the Application
```bash
python3 src/app.py
```

The application will start on `http://localhost:5000`

### 2. Health Check
```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-13T12:00:00.000Z",
  "version": "1.0.0"
}
```

## API Endpoints

### Security Analysis

#### Analyze Request
```bash
POST /api/analyze
Content-Type: application/json

{
  "url": "http://example.com",
  "method": "POST",
  "headers": {"User-Agent": "Mozilla/5.0"},
  "payload": "username=admin&password=test"
}
```

#### Response
```json
{
  "threat_level": "HIGH",
  "detections": [
    {
      "type": "SQL_INJECTION",
      "confidence": 0.95,
      "location": "payload",
      "details": "Potential SQL injection in payload parameter"
    }
  ],
  "timestamp": "2024-01-13T12:00:00.000Z",
  "request_id": "req_123456"
}
```

### Threat Detection

#### Get Threat Signatures
```bash
GET /api/threats/signatures
```

#### Get Recent Detections
```bash
GET /api/detections?limit=100&offset=0
```

## Configuration

### Environment Variables

Create or modify `.env` file:

```bash
# Flask Configuration
FLASK_ENV=development          # development or production
FLASK_APP=app.py
SECRET_KEY=your-secret-key
DEBUG=True

# Logging
LOG_DIR=./logs
LOG_LEVEL=INFO

# Database
THREAT_DB_PATH=./config/threats.db
DATABASE_URL=sqlite:///threats.db

# Performance
MAX_WORKERS=4
REQUEST_TIMEOUT=30
RATE_LIMIT=100  # requests per minute
```

## Kali Linux Integration

### Using with SQLMap

```bash
# Test SQL injection detection
sqlmap -u "http://localhost:5000/api/analyze?id=1" --batch
```

### Using with Burp Suite

1. Configure browser proxy to localhost:8080
2. Start Burp Suite
3. Set up interception
4. Send requests through SentinelShield

### Using with Metasploit

```bash
msfconsole
msf> use exploit/multi/handler
msf> set PAYLOAD windows/shell_reverse_tcp
msf> set LHOST localhost
msf> run
```

## Monitoring

### View Real-time Logs
```bash
tail -f logs/sentinelshield.log
```

### Parse Detections
```bash
grep "THREAT_DETECTED" logs/sentinelshield.log
```

### Monitor System Resources
```bash
watch -n 1 'ps aux | grep python3'
```

## Advanced Features

### Custom Threat Rules

Edit `config/rules.json`:

```json
{
  "rules": [
    {
      "id": "CUSTOM_001",
      "name": "Custom SQL Injection Pattern",
      "pattern": "(?i)(union.*select|select.*from)",
      "severity": "HIGH",
      "enabled": true
    }
  ]
}
```

### Rate Limiting

Default: 100 requests per minute per IP

Modify in configuration:
```python
RATE_LIMIT = 100  # requests/minute
```

## Troubleshooting

### Port Already in Use
```bash
sudo lsof -i :5000
sudo kill -9 <PID>
```

### High Memory Usage
```bash
# Reduce thread workers
export MAX_WORKERS=2
python3 src/app.py
```

### Database Errors
```bash
rm -f config/threats.db
python3 src/init_db.py
```

## Performance Tips

1. Use production mode for deployment
2. Enable caching for threat signatures
3. Implement request batching
4. Monitor resource usage regularly
5. Use load balancer for multiple instances

## Security Best Practices

1. Never expose API keys
2. Use HTTPS in production
3. Implement authentication
4. Regular security audits
5. Keep dependencies updated
6. Use firewall rules
7. Monitor logs regularly

## Support

For issues and questions, refer to [GitHub Issues](../../../issues)
