# SentinelShield Installation Guide

## System Requirements

### Minimum Requirements
- Python 3.8 or higher
- pip (Python package manager)
- 200 MB disk space
- 256 MB RAM

### Recommended Requirements
- Python 3.10+
- 1 GB disk space
- 512 MB RAM
- Linux/Unix-based OS (Kali Linux, Ubuntu, Debian)
- Git for version control

### Supported Operating Systems
- Linux (Ubuntu 18.04+, Debian 10+, Kali Linux)
- macOS (10.14+)
- Windows 10/11 (WSL2 recommended)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Upgrade pip

```bash
pip install --upgrade pip
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Verify Installation

```bash
# Check Python version
python --version

# Check pip packages
pip list

# Verify main modules can be imported
python -c "import flask; print('Flask installed')"
```

## Dependency Installation Details

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|----------|
| Flask | 2.0+ | Web framework for API/Dashboard |
| flask-cors | 3.0+ | CORS support for API |
| requests | 2.25+ | HTTP client library |
| beautifulsoup4 | 4.9+ | HTML/XML parsing |
| python-dotenv | 0.19+ | Environment variable management |

### Optional Dependencies

| Package | Purpose |
|---------|----------|
| pytest | Unit testing |
| black | Code formatting |
| pylint | Code quality analysis |
| flake8 | Linting |

## Quick Start (One-Command Installation)

### On Linux/macOS:

```bash
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git && \
cd SentinelShield && \
python3 -m venv venv && \
source venv/bin/activate && \
pip install --upgrade pip && \
pip install -r requirements.txt && \
echo "Installation complete!"
```

### On Windows (PowerShell):

```powershell
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
echo "Installation complete!"
```

## Docker Installation (Optional)

### Build Docker Image

```bash
docker build -t sentinelshield:latest .
```

### Run Docker Container

```bash
docker run -p 5000:5000 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/config:/app/config \
  sentinelshield:latest
```

## Directory Structure After Installation

```
SentinelShield/
├── src/
│   ├── __init__.py
│   ├── main_waf.py              # Main WAF engine
│   ├── request_parser.py         # Request parsing module
│   ├── detection_engine.py       # Detection engine
│   ├── rate_limiter.py           # Rate limiting module
│   ├── logger.py                 # Logging system
│   ├── alert_handler.py          # Alert handler
│   └── dashboard.py              # Dashboard/UI
├── tests/
│   ├── test_parser.py
│   ├── test_detection.py
│   ├── test_rate_limiter.py
│   └── test_integration.py
├── config/
│   ├── rules.json                # Detection rules
│   └── config.json               # System configuration
├── logs/
│   ├── requests.log              # Request logs
│   └── alerts.log                # Alert logs
├── docs/
│   ├── ARCHITECTURE.md           # System architecture
│   ├── INSTALLATION.md           # This file
│   └── USAGE.md                  # Usage guide
├── requirements.txt              # Python dependencies
├── .gitignore                    # Git ignore file
├── README.md                     # Project overview
└── Dockerfile                    # Docker configuration
```

## Configuration After Installation

### 1. Create Configuration Files

```bash
# Create config directory
mkdir -p config logs

# Create basic config.json
cat > config/config.json << 'EOF'
{
  "rate_limit_enabled": true,
  "rate_limit_per_minute": 100,
  "alert_level": "HIGH",
  "log_level": "INFO",
  "blocking_enabled": true
}
EOF
```

### 2. Set Environment Variables

```bash
# Create .env file
cat > .env << 'EOF'
FLASK_ENV=development
FLASK_DEBUG=False
SECRET_KEY=your-secret-key-here
LOG_DIR=./logs
CONFIG_DIR=./config
EOF
```

### 3. Initialize Log Files

```bash
# Create empty log files
touch logs/requests.log
touch logs/alerts.log
```

## Verification Tests

### Test 1: Import All Modules

```bash
python -c "
import sys
sys.path.insert(0, 'src')
try:
    import main_waf
    import request_parser
    import detection_engine
    import rate_limiter
    import logger
    import alert_handler
    print('✓ All modules imported successfully')
except ImportError as e:
    print(f'✗ Import error: {e}')
"
```

### Test 2: Run Basic Test Suite

```bash
python -m pytest tests/ -v
```

### Test 3: Start Web Dashboard

```bash
python src/main_waf.py
# Access at http://localhost:5000
```

## Troubleshooting

### Issue: Python version not found

```bash
# Solution: Check Python version
python3 --version

# If not installed, install Python 3.8+
# On Ubuntu/Debian:
sudo apt-get install python3 python3-pip python3-venv

# On macOS:
brew install python3
```

### Issue: Virtual environment activation fails

```bash
# Solution: Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
```

### Issue: pip install fails

```bash
# Solution: Upgrade pip and retry
pip install --upgrade pip setuptools wheel
pip install --no-cache-dir -r requirements.txt
```

### Issue: Module not found errors

```bash
# Solution: Ensure virtual environment is activated
# Check with: which python (Linux/macOS) or where python (Windows)

# Reinstall requirements
pip install -r requirements.txt --force-reinstall
```

### Issue: Permission denied (Linux/macOS)

```bash
# Solution: Fix permissions
chmod +x src/*.py
chmod +x tests/*.py
```

## Post-Installation Setup

### 1. Generate SSL Certificates (for HTTPS)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes -out certs/cert.pem -keyout certs/key.pem -days 365
```

### 2. Set Up Logging

```bash
# Create logging configuration
cat > config/logging.json << 'EOF'
{
  "version": 1,
  "disable_existing_loggers": false,
  "formatters": {
    "standard": {
      "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    }
  },
  "handlers": {
    "file": {
      "class": "logging.FileHandler",
      "filename": "logs/sentinelshield.log",
      "formatter": "standard"
    }
  }
}
EOF
```

### 3. Create Sample Rules

```bash
cat > config/rules.json << 'EOF'
{
  "sql_injection": {
    "enabled": true,
    "patterns": ["SELECT", "UNION", "DROP", "--", "/**/"]
  },
  "xss": {
    "enabled": true,
    "patterns": ["<script>", "onerror=", "onclick="]
  },
  "lfi": {
    "enabled": true,
    "patterns": ["../", "..\\", "/etc/passwd"]
  }
}
EOF
```

## Next Steps

1. Read [USAGE.md](USAGE.md) for how to run SentinelShield
2. Review [ARCHITECTURE.md](ARCHITECTURE.md) for system design
3. Run the test suite: `pytest tests/ -v`
4. Start the WAF: `python src/main_waf.py`
5. Access dashboard at `http://localhost:5000`

## Getting Help

- Check the [README.md](README.md) for overview
- Review ARCHITECTURE.md for design details
- Check GitHub Issues for common problems
- See logs/ directory for error messages

## License

SentinelShield is provided as an educational project. See LICENSE file for details.
