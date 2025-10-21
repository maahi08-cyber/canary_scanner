# scanner/__init__.py
"""
Canary Scanner - A powerful secret scanning tool for developers.

This package provides the core functionality for scanning files and directories
for hardcoded secrets, API keys, passwords, and other sensitive information.
"""

from .core import Scanner, Finding
from .patterns import Pattern, load_patterns

__version__ = "1.0.0"
__all__ = ["Scanner", "Finding", "Pattern", "load_patterns"]
