#!/usr/bin/env python
"""
DEPRECATED: This setup.py is maintained for backward compatibility only.
Please use pyproject.toml for all configuration going forward (PEP 517/518).

For installation:
    pip install .
    pip install -e ".[dev]"  # For development
    pip install -e ".[all]"  # For all optional dependencies

This is a minimal shim that delegates to setuptools' pyproject.toml support.
"""
import warnings
from setuptools import setup

warnings.warn(
    "setup.py is deprecated. Please use pyproject.toml and install via "
    "'pip install .' or 'pip install -e .[dev]' for development.",
    DeprecationWarning,
    stacklevel=2,
)

# All configuration is now in pyproject.toml
# This file exists only for backward compatibility
if __name__ == "__main__":
    setup()
