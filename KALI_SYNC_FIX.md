# SentinelShield - Kali Linux Git Sync & Repository Fix

## Problem: Tests Folder Not Found Locally

**Error on Your Kali Machine:**
```
┌──(kali㉿kali)-[~/SentinelShield]
└─$ ls -la tests/
ls: cannot access 'tests/': No such file or directory
```

**Reason:**
Your local clone is outdated/incomplete. The tests folder exists on GitHub but not in your local machine at `/home/kali/SentinelShield`.

## Solution: Sync with GitHub

### Option 1: Quick Sync (RECOMMENDED)

If you have an existing directory, sync the latest changes from GitHub:

```bash
cd ~/SentinelShield

# Check git status
git status

# Pull latest changes from GitHub
git pull origin main

# Verify tests folder now exists
ls -la tests/

# You should see:
# test_attack_payloads.py
# test_comprehensive_security.py
# test_normal_requests.py
```

### Option 2: Fresh Clone (If Sync Fails)

If git pull doesn't work, completely remove and re-clone:

```bash
# Remove old directory
rm -rf ~/SentinelShield

# Clone fresh from GitHub
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git ~/SentinelShield

# Enter directory
cd ~/SentinelShield

# Verify tests exist
ls -la tests/
```

### Option 3: Force Update (If Both Fail)

Reset local changes and pull from remote:

```bash
cd ~/SentinelShield

# Reset to remote state
git fetch origin
git reset --hard origin/main

# Verify
ls -la tests/
```

## Verify Directory Structure

After syncing, you should have:

```
SentinelShield/
├── .github/
│   └── workflows/
│       └── main.yml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── INSTALLATION.md
│   └── USAGE.md
├── src/
│   └── (source code)
├── tests/              ← THIS SHOULD EXIST
│   ├── test_attack_payloads.py
│   ├── test_comprehensive_security.py
│   └── test_normal_requests.py
├── KALI_LINUX_TESTING_GUIDE.md
├── KALI_TERMINAL_TEST_COMMANDS.md
├── KALI_TESTING_SUMMARY.md
├── KALI_TROUBLESHOOTING_SETUP.md
├── README.md
├── requirements.txt
└── .gitignore
```

## Verify Git Configuration

Before syncing, check your git setup:

```bash
# Check current remote
cd ~/SentinelShield
git remote -v

# Should show:
# origin  https://github.com/gauravmalhotra3300-hub/SentinelShield.git (fetch)
# origin  https://github.com/gauravmalhotra3300-hub/SentinelShield.git (push)

# Check current branch
git branch -v

# Should show:
# * main  <latest_commit_hash> Add Kali Linux...

# Check commit history
git log --oneline -5

# Should show recent commits
```

## Complete Fix Sequence

Follow this exact sequence to fix the issue:

```bash
# 1. Navigate to project
cd ~/SentinelShield

# 2. Check status
git status

# 3. Pull latest changes
git pull origin main

# 4. Verify tests exist
ls -la tests/

# 5. List test files
ls -la tests/*.py

# 6. Create virtual environment
python3 -m venv venv

# 7. Activate virtual environment
source venv/bin/activate

# 8. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 9. Verify pytest is installed
python -m pytest --version

# 10. Run tests
python -m pytest tests/ -v
```

## Common Git Issues & Solutions

### Issue: "Not a git repository"

```bash
# Check if .git folder exists
ls -la .git

# If not, initialize git
git init
git remote add origin https://github.com/gauravmalhotra3300-hub/SentinelShield.git
git pull origin main
```

### Issue: "Permission denied" or "Authentication failed"

```bash
# Use SSH instead of HTTPS (if SSH is configured)
git remote remove origin
git remote add origin git@github.com:gauravmalhotra3300-hub/SentinelShield.git
git pull origin main

# Or use HTTPS with personal access token
git clone https://<your_token>@github.com/gauravmalhotra3300-hub/SentinelShield.git
```

### Issue: "Merge conflict"

```bash
# If you have local changes that conflict
git stash  # Save your changes
git pull origin main
git stash pop  # Re-apply your changes
```

## Verify After Syncing

Once you've synced, verify everything:

```bash
# Check tests directory
ls -la tests/

# Should output:
# total XX
# drwxr-xr-x ... .
# drwxr-xr-x ... ..
# -rw-r--r-- ... test_attack_payloads.py
# -rw-r--r-- ... test_comprehensive_security.py
# -rw-r--r-- ... test_normal_requests.py

# Check git status
git status

# Should show:
# On branch main
# Your branch is up to date with 'origin/main'.
# nothing to commit, working tree clean

# Check latest commit
git log -1

# Should show recent commit with Kali content
```

## Next Steps After Fix

1. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run tests:**
   ```bash
   python -m pytest tests/ -v
   ```

4. **Expected output:**
   ```
   ====================== test session starts ======================
   ...
   collected 26 items
   
   tests/test_attack_payloads.py ............... [53%]
   tests/test_comprehensive_security.py .... [61%]
   tests/test_normal_requests.py ....... [100%]
   
   ======================== 26 passed in X.XXs ======================
   ```

## Troubleshooting

### Tests still not found after sync?

```bash
# Check if git pull actually worked
git log --oneline -1

# If commit message doesn't mention "Kali", pull again
git fetch origin
git reset --hard origin/main

# Verify
ls -la tests/
```

### Still getting "No such file or directory"?

```bash
# Check current directory
pwd  # Should print /home/kali/SentinelShield

# List all files
ls -la

# If tests/ is missing, force a fresh clone
cd ~
rm -rf SentinelShield
git clone https://github.com/gauravmalhotra3300-hub/SentinelShield.git
cd SentinelShield
ls -la tests/
```

## Quick Summary

**Your local repo is out of sync with GitHub.** The tests folder exists on GitHub but not locally.

**Quick fix in 3 commands:**
```bash
cd ~/SentinelShield
git pull origin main
ls -la tests/  # Verify it exists now
```

Then proceed with virtual environment setup and testing.

---

**Created:** January 15, 2026
**Author:** Gaurav Malhotra
**For:** Kali Linux Testing Support
