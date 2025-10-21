
"""
Canary Scanner - A professional, context-aware DevSecOps tool.
"""

# Import from your new files
from .patterns import Pattern, load_patterns
from .context import ContextAnalyzer, ContextType
from .filters import FalsePositiveFilter
from .validators import ValidationClient
from .core import EnhancedScanner, Finding

__version__ = "2.0.0"

# Define what gets imported when someone does 'from scanner import *'
__all__ = [
    "EnhancedScanner",
    "Finding",
    "Pattern",
    "load_patterns",
    "ContextAnalyzer",
    "ContextType",
    "FalsePositiveFilter",
    "ValidationClient"
]
