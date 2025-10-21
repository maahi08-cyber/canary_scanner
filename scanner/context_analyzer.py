"""
Context Analyzer for Phase 4 - Intelligent context-aware scanning.
"""
import re
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass

class ContextType(Enum):
    """Types of code contexts."""
    PRODUCTION = "production"
    TEST = "test"
    EXAMPLE = "example"
    DOCUMENTATION = "documentation"
    CONFIG = "config"
    TEMPLATE = "template"
    UNKNOWN = "unknown"

@dataclass
class ContextInfo:
    """Information about code context."""
    context_type: ContextType
    confidence: float  # 0.0 - 1.0
    reasons: List[str]
    file_indicators: List[str]
    content_indicators: List[str]

class ContextAnalyzer:
    """Analyzes code context to reduce false positives."""

    # Directory-based context indicators
    CONTEXT_DIRECTORIES = {
        ContextType.TEST: {
            'test', 'tests', 'testing', '__tests__', 'spec', 'specs',
            'unit_tests', 'integration_tests', 'e2e_tests', 'cypress'
        },
        ContextType.EXAMPLE: {
            'example', 'examples', 'demo', 'demos', 'sample', 'samples',
            'tutorial', 'tutorials', 'playground', 'quickstart'
        },
        ContextType.DOCUMENTATION: {
            'docs', 'doc', 'documentation', 'readme', 'wiki', 'guides',
            'manual', 'reference', 'help'
        },
        ContextType.CONFIG: {
            'config', 'configuration', 'settings', 'conf', '.github',
            'deploy', 'deployment', 'ci', 'cd', 'pipeline'
        },
        ContextType.TEMPLATE: {
            'template', 'templates', 'scaffolding', 'boilerplate',
            'skeleton', 'starter'
        }
    }

    # File name patterns
    TEST_FILE_PATTERNS = [
        r'.*test.*\.(py|js|ts|java|rb|go|php|cs)$',
        r'.*spec\.(py|js|ts|java|rb|go|php|cs)$',
        r'test_.*\.(py|js|ts|java|rb|go|php|cs)$',
        r'.*_test\.(py|js|ts|java|rb|go|php|cs)$',
        r'.*Test\.(java|cs)$'
    ]

    EXAMPLE_FILE_PATTERNS = [
        r'example.*\.(py|js|ts|java|rb|go|php|cs)$',
        r'demo.*\.(py|js|ts|java|rb|go|php|cs)$',
        r'sample.*\.(py|js|ts|java|rb|go|php|cs)$'
    ]

    DOC_FILE_PATTERNS = [
        r'.*\.(md|rst|txt|adoc)$',
        r'README.*',
        r'CHANGELOG.*',
        r'.*\.md$'
    ]

    CONFIG_FILE_PATTERNS = [
        r'.*\.(yml|yaml|json|toml|ini|cfg|conf)$',
        r'Dockerfile.*',
        r'docker-compose.*',
        r'\.env.*',
        r'.*\.config\.(js|ts)$'
    ]

    # Content-based indicators
    TEST_CONTENT_INDICATORS = [
        r'import\s+(?:unittest|pytest|jest|mocha|jasmine|rspec)',
        r'from\s+\w+\s+import\s+(?:TestCase|Test)',
        r'@Test\b',
        r'describe\s*\(',
        r'it\s*\(',
        r'test\s*\(',
        r'def\s+test_',
        r'class\s+\w*Test\w*',
        r'assert\s+',
        r'expect\s*\(',
        r'should\s*\.'
    ]

    EXAMPLE_CONTENT_INDICATORS = [
        r'#\s*(?:example|demo|sample)',
        r'//\s*(?:example|demo|sample)',
        r'/\*.*?(?:example|demo|sample).*?\*/',
        r'print\s*\(.*(?:example|demo).*\)',
        r'console\.log\s*\(.*(?:example|demo).*\)'
    ]

    DOC_CONTENT_INDICATORS = [
        r'^#+ ',  # Markdown headers
        r'```',   # Code blocks
        r'\*\*.*?\*\*',  # Bold text
        r'\[.*?\]\(.*?\)',  # Links
        r'TODO:',
        r'FIXME:',
        r'NOTE:'
    ]

    PLACEHOLDER_PATTERNS = [
        r'(?i)(?:your|my|test|demo|example|sample)[-_]?(?:api[-_]?key|token|secret|password)',
        r'(?i)(?:replace|change|insert|put|add)[-_\s]+(?:your|this)',
        r'(?i)(?:placeholder|dummy|fake|mock|stub)',
        r'xxx+',
        r'yyy+', 
        r'zzz+',
        r'123456',
        r'password',
        r'secret',
        r'token'
    ]

    def __init__(self):
        """Initialize context analyzer."""
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict:
        """Compile regex patterns for performance."""
        return {
            'test_files': [re.compile(pattern, re.IGNORECASE) for pattern in self.TEST_FILE_PATTERNS],
            'example_files': [re.compile(pattern, re.IGNORECASE) for pattern in self.EXAMPLE_FILE_PATTERNS],
            'doc_files': [re.compile(pattern, re.IGNORECASE) for pattern in self.DOC_FILE_PATTERNS],
            'config_files': [re.compile(pattern, re.IGNORECASE) for pattern in self.CONFIG_FILE_PATTERNS],
            'test_content': [re.compile(pattern, re.IGNORECASE) for pattern in self.TEST_CONTENT_INDICATORS],
            'example_content': [re.compile(pattern, re.IGNORECASE) for pattern in self.EXAMPLE_CONTENT_INDICATORS],
            'doc_content': [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in self.DOC_CONTENT_INDICATORS],
            'placeholders': [re.compile(pattern, re.IGNORECASE) for pattern in self.PLACEHOLDER_PATTERNS]
        }

    def analyze_file(self, file_path: str, content: str = None) -> ContextInfo:
        """Analyze file context based on path and optionally content."""
        path = Path(file_path)

        # Analyze directory structure
        dir_context = self._analyze_directory_context(path)

        # Analyze filename
        file_context = self._analyze_filename_context(path)

        # Analyze content if provided
        content_context = None
        if content:
            content_context = self._analyze_content_context(content)

        # Combine analyses
        return self._combine_context_analyses(dir_context, file_context, content_context, path)

    def _analyze_directory_context(self, path: Path) -> Dict:
        """Analyze directory structure for context clues."""
        results = {context_type: 0 for context_type in ContextType}
        reasons = []

        path_parts = [part.lower() for part in path.parts]

        for context_type, directories in self.CONTEXT_DIRECTORIES.items():
            for directory in directories:
                if directory in path_parts:
                    results[context_type] += 1
                    reasons.append(f"Directory '{directory}' indicates {context_type.value}")

        return {'scores': results, 'reasons': reasons}

    def _analyze_filename_context(self, path: Path) -> Dict:
        """Analyze filename for context clues."""
        results = {context_type: 0 for context_type in ContextType}
        reasons = []
        filename = path.name

        # Test files
        for pattern in self.compiled_patterns['test_files']:
            if pattern.match(filename):
                results[ContextType.TEST] += 1
                reasons.append(f"Filename '{filename}' matches test pattern")
                break

        # Example files
        for pattern in self.compiled_patterns['example_files']:
            if pattern.match(filename):
                results[ContextType.EXAMPLE] += 1
                reasons.append(f"Filename '{filename}' matches example pattern")
                break

        # Documentation files
        for pattern in self.compiled_patterns['doc_files']:
            if pattern.match(filename):
                results[ContextType.DOCUMENTATION] += 1
                reasons.append(f"Filename '{filename}' matches documentation pattern")
                break

        # Config files
        for pattern in self.compiled_patterns['config_files']:
            if pattern.match(filename):
                results[ContextType.CONFIG] += 1
                reasons.append(f"Filename '{filename}' matches config pattern")
                break

        return {'scores': results, 'reasons': reasons}

    def _analyze_content_context(self, content: str) -> Dict:
        """Analyze file content for context clues."""
        results = {context_type: 0 for context_type in ContextType}
        reasons = []

        # Sample first 2000 characters for performance
        sample_content = content[:2000]

        # Test content
        for pattern in self.compiled_patterns['test_content']:
            matches = pattern.findall(sample_content)
            if matches:
                results[ContextType.TEST] += len(matches)
                reasons.append(f"Content contains test indicators: {len(matches)} matches")
                break

        # Example content
        for pattern in self.compiled_patterns['example_content']:
            matches = pattern.findall(sample_content)
            if matches:
                results[ContextType.EXAMPLE] += len(matches)
                reasons.append(f"Content contains example indicators: {len(matches)} matches")
                break

        # Documentation content
        for pattern in self.compiled_patterns['doc_content']:
            matches = pattern.findall(sample_content)
            if matches:
                results[ContextType.DOCUMENTATION] += len(matches)
                reasons.append(f"Content contains documentation indicators: {len(matches)} matches")
                break

        return {'scores': results, 'reasons': reasons}

    def _combine_context_analyses(self, dir_context: Dict, file_context: Dict, content_context: Dict, path: Path) -> ContextInfo:
        """Combine different context analyses into final result."""
        all_scores = {context_type: 0 for context_type in ContextType}
        all_reasons = []

        # Combine scores with weights
        weights = {'directory': 1.0, 'filename': 1.5, 'content': 1.2}

        # Directory scores
        for context_type, score in dir_context['scores'].items():
            all_scores[context_type] += score * weights['directory']
        all_reasons.extend(dir_context['reasons'])

        # Filename scores
        for context_type, score in file_context['scores'].items():
            all_scores[context_type] += score * weights['filename']
        all_reasons.extend(file_context['reasons'])

        # Content scores
        if content_context:
            for context_type, score in content_context['scores'].items():
                all_scores[context_type] += score * weights['content']
            all_reasons.extend(content_context['reasons'])

        # Determine primary context
        max_score = max(all_scores.values())
        if max_score == 0:
            primary_context = ContextType.PRODUCTION  # Default
            confidence = 0.5
        else:
            primary_context = max(all_scores, key=all_scores.get)
            confidence = min(max_score / 3.0, 1.0)  # Normalize confidence

        # Boost confidence for clear indicators
        if primary_context in [ContextType.TEST, ContextType.EXAMPLE, ContextType.DOCUMENTATION]:
            confidence = min(confidence * 1.2, 1.0)

        return ContextInfo(
            context_type=primary_context,
            confidence=confidence,
            reasons=all_reasons[:5],  # Keep top 5 reasons
            file_indicators=[],
            content_indicators=[]
        )

    def is_likely_placeholder(self, secret_value: str) -> bool:
        """Check if a secret value is likely a placeholder."""
        for pattern in self.compiled_patterns['placeholders']:
            if pattern.search(secret_value):
                return True
        return False
