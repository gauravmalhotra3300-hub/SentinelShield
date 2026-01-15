# SentinelShield - Kali Linux Troubleshooting & Setup Guide

## Your Specific Issues & Solutions

### Issue 1: Repository Already Exists

**Error:**
```
fatal: destination path 'SentinelShield' already exists and is not an empty directory.
```

**Solution:**
The repository is already cloned in `/home/kali/SentinelShield`. You can proceed directly to installing dependencies.

```bash
# Navigate to existing directory
cd ~/SentinelShield

# Verify you're in the right location
pwd
ls -la

# Check if tests folder exists
ls -la tests/
```

### Issue 2: Python Externally-Managed Environment (PEP 668)

**Error:**
```
error: externally-managed-environment
┗─> To install Python packages system-wide, try apt install python3-xyz...
```

**Reason:**
Kali Linux 2024+ enforces PEP 668, which prevents pip from installing packages system-wide to avoid conflicts.

**Solution A: Create Virtual Environment (RECOMMENDED)**

```bash
# Navigate to project directory
cd ~/SentinelShield

# Create Python virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# You should see (venv) prefix in your terminal
# Install dependencies in the virtual environment
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
pip list
python --version
```

**Solution B: Use pipx (Alternative)**

```bash
# Install pipx if not already installed
sudo apt-get install pipx

# Install Python packages with pipx
pipx install pytest
pipx install coverage
```

**Solution C: Use apt Package Manager (For Kali Packages)**

```bash
# Install common testing tools via apt
sudo apt-get install python3-pytest
sudo apt-get install python3-coverage
sudo apt-get install python3-requests
```

**Solution D: Override (NOT RECOMMENDED)**

```bash
# Only use this if you understand the risks
pip install --break-system-packages -r requirements.txt
```

### Issue 3: Tests Directory Not Found

**Error:**
```
ERROR: file or directory not found: tests/
```

**Reason:**
Pytest cannot find the tests directory. This is usually a path issue.

**Solutions:**

```bash
# 1. Verify you're in the correct directory
cd ~/SentinelShield
pwd  # Should print: /home/kali/SentinelShield

# 2. List the contents to verify tests folder exists
ls -la tests/

# 3. Run tests from the correct directory
python -m pytest tests/ -v

# 4. Or run from the parent directory
python -m pytest ./tests/ -v

# 5. Or run specific test file
python -m pytest tests/test_attack_payloads.py -v
```

## Complete Kali Linux Setup (Step-by-Step)

### Step 1: Check Python Installation

```bash
# Verify Python version (should be 3.8 or higher)
python3 --version

# Check pip version
pip --version

# List Python location
which python3
which pip
```

### Step 2: Navigate to Project

```bash
# Go to the existing SentinelShield directory
cd ~/SentinelShield

# Verify location
pwd

# List directory contents
ls -la
```

### Step 3: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Verify activation (should see (venv) prefix)
echo $VIRTUAL_ENV
```

### Step 4: Install Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install from requirements.txt
pip install -r requirements.txt

# Verify installation
pip list
```

### Step 5: Verify Test Setup

```bash
# Check if tests directory exists
ls -la tests/

# List test files
ls -la tests/*.py

# Verify pytest is installed
python -m pytest --version
```

### Step 6: Run Tests

```bash
# Run all tests with verbose output
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_attack_payloads.py -v

# Run with coverage report
python -m pytest tests/ --cov=src --cov-report=term-missing

# Run with detailed output
python -m pytest tests/ -vv -s
```

## Common Kali Linux Problems & Solutions

### Problem 1: pytest Not Found

```bash
# Check if pytest is installed
which pytest
python -m pytest --version

# Install pytest if missing
pip install pytest

# Or install from requirements.txt
pip install -r requirements.txt
```

### Problem 2: Module Import Errors

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall all dependencies
pip install --force-reinstall -r requirements.txt

# Check for missing packages
python -c "import pytest; print('pytest OK')"
python -c "import requests; print('requests OK')"
```

### Problem 3: Permission Denied

```bash
# Make test files executable
chmod +x tests/*.py

# Check permissions
ls -la tests/

# Make sure you have read permissions
chmod 644 tests/*.py
```

### Problem 4: Port Already in Use

```bash
# Find process using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or use different port
export PORT=5001
python -m pytest tests/ -v
```

### Problem 5: Virtual Environment Not Activating

```bash
# Check if venv directory exists
ls -la venv/

# Recreate if corrupted
rm -rf venv
python3 -m venv venv

# Activate with full path
source ~/SentinelShield/venv/bin/activate

# Verify activation
echo $VIRTUAL_ENV
```

## Quick Reference Commands

### Activate Virtual Environment
```bash
cd ~/SentinelShield
source venv/bin/activate
```

### Deactivate Virtual Environment
```bash
deactivate
```

### Install/Update Dependencies
```bash
source venv/bin/activate
pip install --upgrade -r requirements.txt
```

### Run All Tests
```bash
source venv/bin/activate
cd ~/SentinelShield
python -m pytest tests/ -v
```

### Run Specific Test
```bash
source venv/bin/activate
python -m pytest tests/test_attack_payloads.py -v
```

### Check Installation
```bash
source venv/bin/activate
pip list
python --version
```

### View Recent Changes
```bash
cd ~/SentinelShield
git status
git log --oneline -10
```

## Expected Test Output

When tests run successfully, you should see:

```
====================== test session starts =======================
platform linux -- Python 3.13.x, pytest-8.4.2
cachedir: .pytest_cache
rootdir: /home/kali/SentinelShield
plugins: ...
collected 26 items

tests/test_attack_payloads.py ............... [53%]
tests/test_comprehensive_security.py .... [61%]
tests/test_normal_requests.py ....... [100%]

======================== 26 passed in X.XXs ======================
```

## Kali-Specific Tips

### 1. Virtual Environment Location
Kali often uses `/home/kali/` as home directory. Make sure paths match:
```bash
cd /home/kali/SentinelShield
source venv/bin/activate
```

### 2. Python Version Compatibility
Kali 2024+ uses Python 3.13. Most packages are compatible, but some may need updates:
```bash
pip install --upgrade --upgrade-strategy eager -r requirements.txt
```

### 3. System Packages vs Virtual Environment
Always use virtual environment for development:
```bash
# Good - Use virtual environment
source venv/bin/activate
pip install package_name

# Avoid - Installing system-wide
sudo pip install package_name
pip install --break-system-packages package_name
```

### 4. Monitoring During Tests
In a separate terminal, monitor system resources:
```bash
# Terminal 1: Run tests
cd ~/SentinelShield && source venv/bin/activate
python -m pytest tests/ -v

# Terminal 2: Monitor resources
watch -n 1 'ps aux | grep python'
top
htop
```

## Troubleshooting Flowchart

```
Running Tests on Kali?
    |
    v
Error with pip/requirements?
    |--YES--> Create virtual environment
    |         python3 -m venv venv
    |         source venv/bin/activate
    |         pip install -r requirements.txt
    |
    |--NO--> Continue
    |
    v
Test directory not found?
    |--YES--> Check current directory
    |         pwd (should be /home/kali/SentinelShield)
    |         ls tests/
    |
    |--NO--> Continue
    |
    v
pytest not found?
    |--YES--> Install pytest
    |         pip install pytest
    |         or
    |         pip install -r requirements.txt
    |
    |--NO--> Continue
    |
    v
Run tests!
    python -m pytest tests/ -v
```

## After Successful Setup

Once tests are running, proceed with:
1. Review test output for any failures
2. Run manual tests from KALI_TERMINAL_TEST_COMMANDS.md
3. Integrate with Kali tools (SQLMap, OWASP ZAP)
4. Document results

## Getting Help

If issues persist:

1. **Check virtual environment status:**
   ```bash
   which python
   echo $VIRTUAL_ENV
   pip list
   ```

2. **Review logs:**
   ```bash
   cat venv/pyvenv.cfg
   ```

3. **Reinstall from scratch:**
   ```bash
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Contact support:**
   - GitHub Issues: https://github.com/gauravmalhotra3300-hub/SentinelShield/issues
   - Include: Python version, error message, output of `pip list`

---

**Key Takeaway:**
On modern Kali Linux (2024+), always use a virtual environment with `python3 -m venv`. This avoids the PEP 668 restriction and keeps your system clean.

**Last Updated:** January 15, 2026
**Author:** Gaurav Malhotra
