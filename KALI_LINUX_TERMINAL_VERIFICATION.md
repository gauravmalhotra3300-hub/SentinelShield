# SentinelShield: Kali Linux Terminal Verification Guide

This guide provides step-by-step commands to verify the SentinelShield project setup and configuration on Kali Linux terminal.

## Prerequisites Check

### 1. Verify Kali Linux Version
```bash
cat /etc/os-release | grep -E "NAME|VERSION"
```

Expected Output:
```
NAME="Kali GNU/Linux"
VERSION="2024.1" (or higher)
```

### 2. Check System Update Status
```bash
echo "Last update: $(stat -c %y /var/cache/apt/pkgcache.bin)"
```

### 3. Verify Required Tools Installation
```bash
echo "=== Checking Python ==="
python3 --version

echo "=== Checking Git ==="
git --version

echo "=== Checking pip ==="
pip3 --version

echo "=== Checking curl ==="
curl --version | head -1

echo "=== Checking wget ==="
wget --version | head -1
```

Expected:
- Python 3.8+
- Git 2.0+
- pip 20.0+
- curl
- wget

## Repository Setup Verification

### 4. Clone Repository
```bash
cd ~
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
```

Verify:
```bash
pwd
ls -la
```

Expected Output:
```
/home/username/SentinelShield
total size with:
  - .git/
  - .gitignore
  - README.md
  - requirements.txt
  - docs/
```

### 5. Check Git Status
```bash
git status
git log --oneline -5
```

Expected:
- Working tree clean or minimal changes
- Recent commit history visible

### 6. Verify Directory Structure
```bash
tree -L 2 -a
# Or if tree is not installed:
find . -type d -maxdepth 2 | sort
```

Expected Structure:
```
.
├── .git
├── .gitignore
├── README.md
├── requirements.txt
└── docs/
    ├── INSTALLATION.md
    └── USAGE.md
```

## Python Environment Setup

### 7. Create Virtual Environment
```bash
python3 -m venv venv
```

Verify:
```bash
ls -la venv/
```

### 8. Activate Virtual Environment
```bash
source venv/bin/activate
```

Verify (Prompt should show (venv)):
```bash
which python
python --version
```

### 9. Upgrade pip
```bash
pip install --upgrade pip setuptools wheel
pip --version
```

## Dependencies Installation

### 10. Install Project Dependencies
```bash
pip install -r requirements.txt
```

Verify installation:
```bash
pip list | grep -E "Flask|requests|pytest"
```

Expected:
```
Flask (version numbers)
Flask-CORS
requests
pytest
```

### 11. Check All Requirements
```bash
pip check
```

Expected Output:
```
No broken requirements found.
```

## Configuration Verification

### 12. Create Project Directories
```bash
mkdir -p logs config data src tests
ls -la
```

### 13. Create Environment Variables File
```bash
cat > .env << 'EOF'
FLASK_ENV=development
FLASK_APP=app.py
SECRET_KEY=test-secret-key-$(date +%s)
DEBUG=True
LOG_DIR=./logs
THREAT_DB_PATH=./config/threats.db
EOF

cat .env
```

### 14. Verify Environment Variables
```bash
source .env
echo "Flask App: $FLASK_APP"
echo "Debug Mode: $DEBUG"
```

## Kali Linux Security Tools Verification

### 15. Check SQLMap Installation
```bash
sqlmap --version
```

Install if missing:
```bash
sudo apt install -y sqlmap
```

### 16. Check Nmap Installation
```bash
nmap --version
```

Install if missing:
```bash
sudo apt install -y nmap
```

### 17. Check Hydra Installation
```bash
hydra -h | head -5
```

Install if missing:
```bash
sudo apt install -y hydra
```

### 18. Check Wireshark Installation
```bash
which wireshark
wireshark --version
```

Install if missing:
```bash
sudo apt install -y wireshark
```

### 19. Check Metasploit Framework
```bash
msfconsole --version
```

Install if missing:
```bash
sudo apt install -y metasploit-framework
```

## Repository Verification

### 20. Verify Git Configuration
```bash
git config --list | grep user
```

Set if needed:
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 21. Check Remote Repository
```bash
git remote -v
```

Expected:
```
origin  https://github.com/gauravmalhotra3300-hub/SentinelShield.git (fetch)
origin  https://github.com/gauravmalhotra3300-hub/SentinelShield.git (push)
```

### 22. Verify All Files Are Committed
```bash
git status --short
```

Expected:
```
(clean working tree - no output)
```

### 23. Check Recent Commits
```bash
git log --oneline -10
git log --stat -3
```

## Documentation Verification

### 24. Verify README.md
```bash
wc -l README.md
head -20 README.md
```

### 25. Verify Installation Guide
```bash
test -f docs/INSTALLATION.md && echo "INSTALLATION.md exists" || echo "INSTALLATION.md missing"
wc -l docs/INSTALLATION.md
```

### 26. Verify Usage Guide
```bash
test -f docs/USAGE.md && echo "USAGE.md exists" || echo "USAGE.md missing"
wc -l docs/USAGE.md
```

### 27. Verify Requirements File
```bash
wc -l requirements.txt
cat requirements.txt
```

## Security & Permissions Check

### 28. Verify File Permissions
```bash
ls -l .git/config
ls -l .env
ls -l requirements.txt
```

### 29. Check for Sensitive Files
```bash
grep -r "password\|secret\|token\|key" . --exclude-dir=.git --exclude-dir=venv 2>/dev/null || echo "No obvious secrets found"
```

### 30. Verify .gitignore
```bash
cat .gitignore
git check-ignore -v venv/ .env 2>/dev/null || echo "Files properly ignored"
```

## System Resource Verification

### 31. Check Disk Space
```bash
df -h .
du -sh .
du -sh venv/
```

### 32. Check Memory and CPU
```bash
free -h
cat /proc/cpuinfo | grep -E "processor|model name" | head -3
```

### 33. Check Python Path and Modules
```bash
which python3
python3 -c "import sys; print('\n'.join(sys.path))"
```

## Network Verification

### 34. Check Internet Connectivity
```bash
ping -c 2 github.com
curl -I https://github.com
```

### 35. Verify GitHub Access
```bash
ssh -T git@github.com 2>&1 || echo "SSH not configured (HTTPS will work)"
```

## Complete Status Report

### 36. Generate Verification Report
```bash
cat > verify_setup.sh << 'EOF'
#!/bin/bash

echo "===== SENTINELSHIELD SETUP VERIFICATION REPORT ====="
echo "Date: $(date)"
echo "User: $(whoami)"
echo "Host: $(hostname)"
echo ""

echo "[1] System Information:"
uname -a
echo ""

echo "[2] Python Setup:"
python3 --version
echo "Virtual Environment: $([ -d venv ] && echo 'YES' || echo 'NO')"
echo "Activated: $([ "$VIRTUAL_ENV" != "" ] && echo 'YES' || echo 'NO')"
echo ""

echo "[3] Dependencies:"
pip list | wc -l
echo "Total packages installed"
echo ""

echo "[4] Repository Status:"
echo "Repo URL: $(git config --get remote.origin.url)"
echo "Current Branch: $(git branch --show-current)"
echo "Total Commits: $(git rev-list --count HEAD)"
echo "Last Commit: $(git log -1 --format=%ci)"
echo ""

echo "[5] Directory Structure:"
find . -type f -name '*.md' -o -name '*.txt' | grep -v venv | grep -v .git | sort
echo ""

echo "[6] Security Tools:"
echo "SQLMap: $(command -v sqlmap > /dev/null && echo 'INSTALLED' || echo 'NOT FOUND')"
echo "Nmap: $(command -v nmap > /dev/null && echo 'INSTALLED' || echo 'NOT FOUND')"
echo "Wireshark: $(command -v wireshark > /dev/null && echo 'INSTALLED' || echo 'NOT FOUND')"
echo "Metasploit: $(command -v msfconsole > /dev/null && echo 'INSTALLED' || echo 'NOT FOUND')"
echo ""

echo "[7] File Statistics:"
echo "README size: $(wc -l README.md | awk '{print $1}') lines"
echo "Requirements: $(wc -l requirements.txt | awk '{print $1}') dependencies"
echo "Docs: $(find docs -name '*.md' -type f | wc -l) files"
echo ""

echo "===== VERIFICATION COMPLETE ====="
EOF

chmod +x verify_setup.sh
bash verify_setup.sh
```

## Troubleshooting Common Issues

### Issue: Permission Denied
```bash
sudo chown -R $USER:$USER .
chmod -R u+rwx .
```

### Issue: Virtual Environment Not Activating
```bash
deactivate 2>/dev/null
rm -rf venv/
python3 -m venv venv
source venv/bin/activate
```

### Issue: Dependencies Not Installing
```bash
pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt
```

### Issue: Git Authentication
```bash
# For HTTPS (recommended):
git remote set-url origin https://github.com/gauravmalhotra3300-hub/SentinelShield.git

# For SSH (if configured):
git remote set-url origin git@github.com:gauravmalhotra3300-hub/SentinelShield.git
```

## Next Steps After Verification

Once all verifications pass:

1. **Ready for Development:**
   ```bash
   python3 src/app.py  # Start application (when ready)
   ```

2. **Running Tests:**
   ```bash
   pytest tests/ -v
   ```

3. **Making Changes:**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin main
   ```

4. **Monitoring Setup:**
   ```bash
   tail -f logs/sentinelshield.log
   ```

## Quick Reference Commands

```bash
# Activate virtual environment
source venv/bin/activate

# Deactivate virtual environment
deactivate

# Check installed packages
pip list

# Show git status
git status

# View recent commits
git log --oneline -5

# Update from remote
git pull origin main

# Commit and push changes
git add .
git commit -m "your message"
git push origin main
```

## Support

For issues:
1. Check this guide first
2. Review the documentation in `docs/`
3. Check GitHub Issues: https://github.com/gauravmalhotra3300-hub/SentinelShield/issues
4. Check system logs: `tail -f logs/sentinelshield.log`
