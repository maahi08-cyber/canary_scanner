"""
False Positive Filter for Phase 4 - Reduce noise from obvious false positives.
"""
import re
from typing import Dict, List, Set
from dataclasses import dataclass

@dataclass
class Finding:
    """Simplified Finding class for type hints."""
    file_path: str
    secret_value: str
    rule_id: str
    context_type: str
    line_number: int = 0

class FalsePositiveFilter:
    """Filter to reduce false positive findings."""

    # Known placeholder patterns
    PLACEHOLDER_PATTERNS = [
        r'^(?:your|my|test|demo|example|sample)[-_]?(?:api[-_]?key|token|secret|password)$',
        r'^(?:replace|change|insert|put|add)[-_\s]+(?:your|this).*$',
        r'^(?:placeholder|dummy|fake|mock|stub).*$',
        r'^x{3,}$',
        r'^y{3,}$',
        r'^z{3,}$',
        r'^\d{4,}$',  # Simple number sequences
        r'^(?:password|secret|token|key)$',
        r'^(?:test|demo|example).*$',
        r'^.*(?:example|demo|test|sample)$'
    ]

    # Known test/dummy values
    KNOWN_TEST_VALUES = {
        # AWS test values
        'AKIAIOSFODNN7EXAMPLE',
        'AKIAI44QH8DHBEXAMPLE',
        'ASIA1234567890EXAMPLE',
        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'your-secret-access-key',

        # GitHub test values
        'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
        'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz1234567890',
        'your-github-token',

        # Generic test values
        'your-api-key',
        'your-secret-key',
        'your-token',
        'test-api-key',
        'demo-secret',
        'example-token',
        'sample-key',
        '1234567890abcdef',
        'abcdef1234567890',

        # Database URLs
        'postgres://user:password@localhost:5432/database',
        'mysql://user:password@localhost:3306/database',
        'mongodb://user:password@localhost:27017/database'
    }

    # File extensions that commonly contain false positives
    FALSE_POSITIVE_EXTENSIONS = {
        '.md', '.txt', '.rst', '.adoc',  # Documentation
        '.json', '.yaml', '.yml',       # Config files
        '.example', '.sample',          # Example files
        '.template', '.tmpl'            # Template files
    }

    # Comment indicators (secrets in comments are often examples)
    COMMENT_PATTERNS = [
        r'^\s*#.*',      # Python/Shell comments
        r'^\s*//.*',     # JavaScript/Java comments
        r'^\s*/\*.*',   # Block comment start
        r'^\s*\*.*',    # Block comment middle
        r'^\s*<!--.*'    # HTML comments
    ]

    def __init__(self):
        """Initialize false positive filter."""
        self.compiled_placeholder_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.PLACEHOLDER_PATTERNS
        ]
        self.compiled_comment_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.COMMENT_PATTERNS
        ]

        # Statistics
        self.stats = {
            'total_checked': 0,
            'false_positives_found': 0,
            'reasons': {}
        }

    def is_false_positive(self, finding) -> bool:
        """Check if a finding is likely a false positive."""
        self.stats['total_checked'] += 1

        # Check various false positive indicators
        reasons = []

        # 1. Known test values
        if self._is_known_test_value(finding.secret_value):
            reasons.append('known_test_value')

        # 2. Placeholder patterns
        if self._matches_placeholder_pattern(finding.secret_value):
            reasons.append('placeholder_pattern')

        # 3. Context-based filtering
        if self._is_test_context(finding):
            reasons.append('test_context')

        # 4. File-based filtering
        if self._is_false_positive_file(finding.file_path):
            reasons.append('documentation_file')

        # 5. Low entropy or simple patterns
        if self._is_low_quality_secret(finding.secret_value):
            reasons.append('low_quality')

        # 6. Comment-based filtering
        if hasattr(finding, 'line_content') and self._is_in_comment(finding.line_content):
            reasons.append('in_comment')

        is_fp = len(reasons) > 0

        if is_fp:
            self.stats['false_positives_found'] += 1
            for reason in reasons:
                self.stats['reasons'][reason] = self.stats['reasons'].get(reason, 0) + 1

        # Store reasons for reporting
        finding._fp_reasons = reasons

        return is_fp

    def get_reason(self, finding) -> str:
        """Get the reason why a finding was marked as false positive."""
        if hasattr(finding, '_fp_reasons') and finding._fp_reasons:
            return ', '.join(finding._fp_reasons)
        return 'unknown'

    def _is_known_test_value(self, secret_value: str) -> bool:
        """Check if secret value is a known test/dummy value."""
        return secret_value in self.KNOWN_TEST_VALUES

    def _matches_placeholder_pattern(self, secret_value: str) -> bool:
        """Check if secret value matches placeholder patterns."""
        for pattern in self.compiled_placeholder_patterns:
            if pattern.match(secret_value.strip()):
                return True
        return False

    def _is_test_context(self, finding) -> bool:
        """Check if finding is in test context."""
        return finding.context_type in ['test', 'example']

    def _is_false_positive_file(self, file_path: str) -> bool:
        """Check if file is likely to contain false positives."""
        file_path_lower = file_path.lower()

        # Check extensions
        for ext in self.FALSE_POSITIVE_EXTENSIONS:
            if file_path_lower.endswith(ext):
                return True

        # Check filename patterns
        if any(indicator in file_path_lower for indicator in 
               ['readme', 'changelog', 'example', 'sample', 'demo', 'template']):
            return True

        return False

    def _is_low_quality_secret(self, secret_value: str) -> bool:
        """Check if secret appears to be low quality/fake."""
        # Too short
        if len(secret_value) < 8:
            return True

        # All same character
        if len(set(secret_value)) == 1:
            return True

        # Simple patterns
        if re.match(r'^[0-9]+$', secret_value):  # All numbers
            return True

        if re.match(r'^[a-zA-Z]+$', secret_value):  # All letters
            return True

        # Common test patterns
        if re.match(r'^(abc|123|test|demo|example)', secret_value, re.IGNORECASE):
            return True

        return False

    def _is_in_comment(self, line_content: str) -> bool:
        """Check if the line appears to be a comment."""
        for pattern in self.compiled_comment_patterns:
            if pattern.match(line_content.strip()):
                return True
        return False

    def get_statistics(self) -> Dict:
        """Get filter statistics."""
        return {
            'total_checked': self.stats['total_checked'],
            'false_positives_found': self.stats['false_positives_found'],
            'false_positive_rate': (
                self.stats['false_positives_found'] / max(self.stats['total_checked'], 1)
            ),
            'reasons_breakdown': self.stats['reasons']
        }

    def add_custom_placeholder(self, pattern: str):
        """Add a custom placeholder pattern."""
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            self.compiled_placeholder_patterns.append(compiled_pattern)
            return True
        except re.error:
            return False

    def add_known_test_value(self, value: str):
        """Add a known test value to the filter."""
        self.KNOWN_TEST_VALUES.add(value)
