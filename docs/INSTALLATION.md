# SentinelShield Installation Guide

## Prerequisites

### System Requirements
- Operating System: Linux (Kali Linux Recommended) or macOS
- Python 3.8 or higher
- pip (Python package manager)
- Git
- Virtual environment capability (venv)

### Kali Linux Specific Requirements
- Kali Linux 2024.1 or later
- Updated system with: `sudo apt update && sudo apt upgrade -y`
- Essential build tools: `sudo apt install -y build-essential python3-dev`

## Installation Steps

### 1. Clone the Repository
```bash
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Upgrade pip
```bash
pip install --upgrade pip setuptools wheel
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

## Configuration

### 1. Environment Variables
Create a `.env` file in the project root:
```bash
cp .env.example .env  # If example exists
# Or create manually:
cat > .env << 'EOF'
FLASK_ENV=development
FLASK_APP=app.py
SECRET_KEY=your-secret-key-here
DEBUG=True
LOG_DIR=./logs
THREAT_DB_PATH=./config/threats.db
EOF
```

### 2. Create Required Directories
```bash
mkdir -p logs config data
```

### 3. Initialize Database (if applicable)
```bash
python3 src/init_db.py
```

## Verification

### Run Application
```bash
python3 src/app.py
```

### Expected Output
```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

### Test Installation
In another terminal:
```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{"status": "healthy", "timestamp": "2024-01-13T..."}
```

## Kali Linux Specific Installation

### Install All Security Tools
```bash
sudo apt install -y \
  sqlmap \
  burpsuite \
  hydra \
  john \
  hashcat \
  metasploit-framework \
  nikto \
  nmap \
  tcpdump \
  wireshark
```

### Configure Network
```bash
sudo ufw allow 5000/tcp
sudo ufw allow 8080/tcp
```

## Troubleshooting

### Port Already in Use
```bash
sudo lsof -i :5000
sudo kill -9 <PID>
```

### Permission Denied
```bash
chmod +x src/app.py
```

### Module Not Found
```bash
pip install --force-reinstall -r requirements.txt
```

### Virtual Environment Issues
```bash
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Next Steps

1. Read the [Usage Guide](./USAGE.md)
2. Review [Security Testing Guide](./SECURITY_TESTING.md)
3. Check the main [README](../README.md)
4. Start the application and explore the API
