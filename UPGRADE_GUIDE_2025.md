# Upgrade Guide to 2025 Standards

This guide will help you upgrade from previous versions of the NIST 800-53 Scanner to version 2.0.0 with 2025 standards.

## Overview of Changes

Version 2.0.0 represents a major modernization of the codebase to align with 2025 Python development standards. This includes:

- Python 3.12+ requirement
- Modern build system (pyproject.toml)
- Ruff for linting/formatting
- Latest dependencies
- Enhanced CI/CD
- Docker infrastructure updates

## Prerequisites

### Python Version

**CRITICAL**: You must upgrade to Python 3.12 or later.

```bash
# Check your Python version
python --version

# Should show Python 3.12.0 or higher
```

### Installing Python 3.12+

**Ubuntu/Debian:**
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.12 python3.12-venv python3.12-dev
```

**macOS (using Homebrew):**
```bash
brew install python@3.12
```

**Windows:**
Download from [python.org](https://www.python.org/downloads/)

## Step-by-Step Upgrade Process

### 1. Backup Your Current Installation

```bash
# Create a backup of your current environment
pip freeze > old_requirements.txt
cp -r /path/to/nist_800_53_scanner /path/to/backup
```

### 2. Pull Latest Changes

```bash
cd /path/to/nist_800_53_scanner
git fetch origin
git pull origin main
```

### 3. Remove Old Virtual Environment (if exists)

```bash
# Deactivate current environment
deactivate

# Remove old virtual environment
rm -rf venv/
```

### 4. Create New Python 3.12 Virtual Environment

```bash
# Create new virtual environment with Python 3.12
python3.12 -m venv venv

# Activate it
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Verify Python version
python --version  # Should show 3.12.x
```

### 5. Install Updated Dependencies

```bash
# Upgrade pip, setuptools, and wheel
pip install --upgrade pip setuptools wheel

# Install the package with dev dependencies
pip install -e ".[dev]"
```

### 6. Install Pre-commit Hooks

```bash
# Install pre-commit hooks
pre-commit install

# Run on all files to ensure compatibility
pre-commit run --all-files
```

### 7. Update Your CI/CD Configuration

If you have custom CI/CD configurations, update them:

**GitHub Actions:**
```yaml
# Update Python version
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.12'

# Update installation command
- name: Install dependencies
  run: |
    python -m pip install --upgrade pip
    pip install -e ".[dev]"
```

### 8. Update Docker Configuration (if using custom Dockerfiles)

```dockerfile
# Update base image
FROM python:3.12-slim

# Update installation command
RUN pip install -e ".[dev]"
```

### 9. Run Tests

```bash
# Run full test suite
make test

# Or use pytest directly
pytest tests/ -v
```

## Breaking Changes and Migration

### 1. Python 3.12+ Only

**Before:** Supported Python 3.8+
**After:** Requires Python 3.12+

**Action Required:** Upgrade your Python installation.

### 2. Build System Changes

**Before:** Used `setup.py` with potential Poetry support
**After:** Uses `pyproject.toml` (PEP 517/518)

**Action Required:**
- Remove `poetry` commands from your scripts
- Use `pip install -e ".[dev]"` instead of `poetry install`
- Update CI/CD to use pip-based installation

### 3. Linting and Formatting

**Before:** Used flake8, black, isort, pylint
**After:** Uses Ruff for everything

**Action Required:**
```bash
# Remove old tools
pip uninstall flake8 black isort pylint

# Ruff is included in dev dependencies
# Update your IDE/editor settings:
# - VSCode: Install "Ruff" extension
# - PyCharm: Configure Ruff as external tool
```

**VSCode settings.json:**
```json
{
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.fixAll": true,
      "source.organizeImports": true
    }
  }
}
```

### 4. Type Checking

**Before:** mypy only
**After:** mypy + pyright

**Action Required:** No action needed, both installed automatically.

### 5. Dependency Updates

Several major dependency updates may require code changes:

#### NumPy 2.x
```python
# Before (deprecated in NumPy 2.x)
import numpy as np
arr = np.int(5)  # DEPRECATED

# After
arr = int(5)  # Use Python int
# OR
arr = np.int64(5)  # Use specific NumPy type
```

#### Pydantic v2
```python
# Before (Pydantic v1)
from pydantic import BaseModel

class User(BaseModel):
    name: str

    class Config:
        orm_mode = True

# After (Pydantic v2)
from pydantic import BaseModel, ConfigDict

class User(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: str
```

#### SQLAlchemy 2.0
```python
# Before (SQLAlchemy 1.x)
from sqlalchemy import create_engine
engine = create_engine("postgresql://...")
result = engine.execute("SELECT * FROM users")

# After (SQLAlchemy 2.0)
from sqlalchemy import create_engine, text
engine = create_engine("postgresql://...")
with engine.connect() as conn:
    result = conn.execute(text("SELECT * FROM users"))
```

### 6. Docker Compose Updates

**Before:** Old image versions
**After:** Latest 2025 images

**Action Required:**
```bash
# Stop old containers
docker-compose down

# Remove old volumes (OPTIONAL - will delete data)
docker-compose down -v

# Pull new images
docker-compose pull

# Start with new images
docker-compose up -d
```

## New Features to Leverage

### 1. Use Makefile Commands

```bash
# See all available commands
make help

# Common development tasks
make install-dev      # Install with dev dependencies
make test            # Run tests with coverage
make lint            # Run linting
make format          # Format code
make security        # Run security scans
make ci              # Run all CI checks locally
```

### 2. Pre-commit Hooks

```bash
# Install hooks
pre-commit install

# Run on all files
pre-commit run --all-files

# Update hooks to latest versions
pre-commit autoupdate
```

### 3. Modern Type Hints

Take advantage of Python 3.12+ type hints:

```python
# Before (Python 3.8)
from typing import List, Dict, Optional

def process_data(items: List[str]) -> Dict[str, int]:
    result: Optional[Dict[str, int]] = None
    return result or {}

# After (Python 3.12+)
def process_data(items: list[str]) -> dict[str, int]:
    result: dict[str, int] | None = None
    return result or {}
```

### 4. Automated Dependency Updates

Enable Dependabot and Renovate for automatic updates:

- Dependabot is configured in `.github/dependabot.yml`
- Renovate is configured in `renovate.json`
- Both will create PRs for dependency updates automatically

## Troubleshooting

### Issue: "Python 3.12 not found"

**Solution:**
```bash
# Install Python 3.12 (see Prerequisites section)
# Then explicitly use python3.12
python3.12 -m venv venv
```

### Issue: "ImportError: cannot import name 'X' from 'pydantic'"

**Solution:** Update your Pydantic v1 code to v2 syntax. See migration guide above.

### Issue: "Module 'numpy' has no attribute 'int'"

**Solution:** NumPy 2.x removed `np.int`. Use `int` or specific types like `np.int64`.

### Issue: Pre-commit hooks failing

**Solution:**
```bash
# Update hooks to latest versions
pre-commit autoupdate

# Clean and reinstall
pre-commit clean
pre-commit install
pre-commit run --all-files
```

### Issue: Tests failing after upgrade

**Solution:**
```bash
# Ensure all dev dependencies are installed
pip install -e ".[dev]"

# Clear pytest cache
rm -rf .pytest_cache

# Run tests with verbose output
pytest tests/ -vv
```

### Issue: Docker containers not starting

**Solution:**
```bash
# Remove old containers and images
docker-compose down
docker system prune -a

# Pull fresh images
docker-compose pull

# Rebuild and start
docker-compose up -d --build
```

## Verification Checklist

After upgrading, verify everything works:

- [ ] Python version is 3.12+: `python --version`
- [ ] Dependencies installed: `pip list | grep fastapi`
- [ ] Pre-commit working: `pre-commit run --all-files`
- [ ] Tests passing: `make test`
- [ ] Linting passing: `make lint`
- [ ] Type checking passing: `make type-check`
- [ ] Security scans passing: `make security`
- [ ] Docker containers running: `docker-compose ps`

## Getting Help

If you encounter issues during the upgrade:

1. Check the [CHANGELOG.md](CHANGELOG.md) for detailed changes
2. Review this upgrade guide
3. Check existing GitHub issues
4. Create a new issue with:
   - Your Python version
   - Operating system
   - Error messages
   - Steps to reproduce

## Rollback Procedure

If you need to rollback:

```bash
# Restore from backup
cd /path/to/backup
source venv/bin/activate

# Or checkout previous version
git checkout v1.2.0
pip install -e ".[dev]"
```

## Support

For questions or assistance:
- GitHub Issues: https://github.com/your-org/nist-800-53-scanner/issues
- Email: security@example.com

---

**Last Updated:** 2025-11-07
**Upgrade Guide Version:** 2.0.0
