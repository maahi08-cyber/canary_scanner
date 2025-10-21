"""
Enhanced Canary Scanner Core Engine - Phase 4
Includes context-aware scanning, validation integration, and false positive reduction.
"""
import asyncio
import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import aiohttp
import yaml
from scanner.context import ContextAnalyzer, ContextType
from scanner.filters import FalsePositiveFilter
from scanner.validators import ValidationClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Finding:
    """Enhanced Finding class with Phase 4 fields."""
    file_path: str
    line_number: int
    rule_id: str
    description: str
    confidence: str  # High, Medium, Low
    secret_value: str
    entropy_score: float

    # Phase 4 enhancements
    validation_status: Optional[str] = None
    validation_job_id: Optional[str] = None
    context_type: Optional[str] = None
    context_confidence: Optional[float] = None
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None
    risk_score: Optional[float] = None
    urgency: Optional[str] = None

    # Source tracking
    source_type: str = "manual"
    commit_hash: Optional[str] = None
    branch_name: Optional[str] = None
    author_email: Optional[str] = None

@dataclass
class Pattern:
    """Secret detection pattern."""
    rule_id: str
    description: str
    regex: re.Pattern
    confidence: str
    entropy_threshold: float = 0.0
    keywords: List[str] = field(default_factory=list)

    # Phase 4 validation support
    secret_type: Optional[str] = None  # For validation
    validation_enabled: bool = False

class EnhancedScanner:
    """
    Enhanced Canary Scanner with Phase 4 features:
    - Context-aware scanning
    - Validation integration  
    - False positive reduction
    - Real-time scanning support
    """

    # File extensions to skip
    SKIP_EXTENSIONS = {
        '.pyc', '.pyo', '.class', '.jar', '.exe', '.dll', '.so', '.dylib',
        '.bin', '.dat', '.db', '.sqlite', '.pdf', '.doc', '.docx', '.xls',
        '.xlsx', '.ppt', '.pptx', '.zip', '.tar', '.gz', '.rar', '.7z',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.mp3',
        '.mp4', '.avi', '.mov', '.wav', '.flac', '.ogg', '.woff', '.woff2',
        '.ttf', '.eot', '.map', '.lock'
    }

    # Directories to skip
    SKIP_DIRECTORIES = {
        '.git', '.svn', '.hg', '.bzr', 'node_modules', '__pycache__',
        '.pytest_cache', '.coverage', '.tox', '.venv', 'venv', 'env',
        'dist', 'build', '.idea', '.vscode', '.DS_Store', 'Thumbs.db'
    }

    # Context-aware directory classifications
    CONTEXT_DIRECTORIES = {
        'test': {'test', 'tests', 'testing', '__tests__', 'spec', 'specs'},
        'example': {'example', 'examples', 'demo', 'demos', 'sample', 'samples'},
        'documentation': {'docs', 'doc', 'documentation', 'readme', 'wiki'},
        'config': {'config', 'configuration', 'settings', 'conf'},
        'production': {'src', 'lib', 'app', 'core', 'main', 'production', 'prod'}
    }

    def __init__(self, patterns: List[Pattern], options: Dict = None):
        """Initialize enhanced scanner."""
        self.patterns = patterns
        self.options = options or {}

        # Phase 4 components
        self.context_analyzer = ContextAnalyzer()
        self.false_positive_filter = FalsePositiveFilter()
        self.validation_client = ValidationClient(
            base_url=self.options.get('validation_service_url'),
            api_key=self.options.get('validation_api_key')
        ) if self.options.get('enable_validation') else None

        # Statistics
        self.stats = {
            'files_scanned': 0,
            'lines_scanned': 0,
            'findings_total': 0,
            'findings_after_context_filter': 0,
            'findings_after_fp_filter': 0,
            'validations_requested': 0,
            'scan_start_time': None,
            'scan_end_time': None
        }

    def scan_target(self, target_path: str, **kwargs) -> Dict:
        """
        Enhanced scan with Phase 4 features.

        Args:
            target_path: Path to scan
            **kwargs: Additional options (commit_hash, branch_name, etc.)

        Returns:
            Dict with scan results and metadata
        """
        self.stats['scan_start_time'] = time.time()
        target = Path(target_path)

        logger.info(f"Starting enhanced scan of: {target}")

        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        all_findings = []

        if target.is_file():
            findings = list(self.scan_file(str(target), **kwargs))
            all_findings.extend(findings)
        else:
            findings = list(self.scan_directory(str(target), **kwargs))
            all_findings.extend(findings)

        self.stats['scan_end_time'] = time.time()
        self.stats['findings_total'] = len(all_findings)

        # Apply Phase 4 enhancements
        enhanced_findings = self._apply_phase4_enhancements(all_findings, **kwargs)

        return self._prepare_scan_results(enhanced_findings, target_path, **kwargs)

    def scan_directory(self, directory_path: str, **kwargs) -> Iterator[Finding]:
        """Scan directory with intelligent filtering."""
        directory = Path(directory_path)

        for file_path in directory.rglob('*'):
            if file_path.is_file():
                # Skip files we shouldn't scan
                if self._should_skip_file(file_path):
                    continue

                try:
                    yield from self.scan_file(str(file_path), **kwargs)
                except Exception as e:
                    logger.warning(f"Error scanning {file_path}: {e}")
                    continue

    def scan_file(self, file_path: str, **kwargs) -> Iterator[Finding]:
        """Enhanced file scanning with context awareness."""
        path = Path(file_path)

        # Skip files we shouldn't scan
        if self._should_skip_file(path):
            return

        # Analyze file context
        context_info = self.context_analyzer.analyze_file(str(path))

        try:
            self.stats['files_scanned'] += 1

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    self.stats['lines_scanned'] += 1

                    for pattern in self.patterns:
                        match = pattern.regex.search(line)
                        if match:
                            # Extract the matched secret
                            secret_value = match.group(0)

                            # Calculate entropy if required
                            entropy_score = self._calculate_entropy(secret_value)

                            # Skip if entropy is too low
                            if entropy_score < pattern.entropy_threshold:
                                continue

                            # Create finding with Phase 4 enhancements
                            finding = Finding(
                                file_path=str(path),
                                line_number=line_num,
                                rule_id=pattern.rule_id,
                                description=pattern.description,
                                confidence=pattern.confidence,
                                secret_value=secret_value,
                                entropy_score=entropy_score,
                                context_type=context_info.context_type.value,
                                context_confidence=context_info.confidence,
                                commit_hash=kwargs.get('commit_hash'),
                                branch_name=kwargs.get('branch_name'),
                                author_email=kwargs.get('author_email'),
                                source_type=kwargs.get('source_type', 'manual')
                            )

                            yield finding

        except UnicodeDecodeError:
            # Skip binary files
            pass
        except Exception as e:
            logger.warning(f"Error reading {path}: {e}")

    def scan_file_content(self, content: str, file_path: str, **kwargs) -> Iterator[Finding]:
        """Scan file content directly (for real-time scanning)."""
        # Analyze context
        context_info = self.context_analyzer.analyze_file(file_path)

        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            self.stats['lines_scanned'] += 1

            for pattern in self.patterns:
                match = pattern.regex.search(line)
                if match:
                    secret_value = match.group(0)
                    entropy_score = self._calculate_entropy(secret_value)

                    if entropy_score < pattern.entropy_threshold:
                        continue

                    finding = Finding(
                        file_path=file_path,
                        line_number=line_num,
                        rule_id=pattern.rule_id,
                        description=pattern.description,
                        confidence=pattern.confidence,
                        secret_value=secret_value,
                        entropy_score=entropy_score,
                        context_type=context_info.context_type.value,
                        context_confidence=context_info.confidence,
                        commit_hash=kwargs.get('commit_hash'),
                        branch_name=kwargs.get('branch_name'),
                        author_email=kwargs.get('author_email'),
                        source_type=kwargs.get('source_type', 'webhook')
                    )

                    yield finding

    def _apply_phase4_enhancements(self, findings: List[Finding], **kwargs) -> List[Finding]:
        """Apply Phase 4 enhancements to findings."""
        logger.info(f"Applying Phase 4 enhancements to {len(findings)} findings")

        enhanced_findings = []

        for finding in findings:
            # Apply false positive filtering
            if self.false_positive_filter.is_false_positive(finding):
                finding.is_false_positive = True
                finding.false_positive_reason = self.false_positive_filter.get_reason(finding)

                # Skip false positives unless explicitly requested
                if not self.options.get('include_false_positives'):
                    continue

            # Calculate risk score
            finding.risk_score = self._calculate_risk_score(finding)
            finding.urgency = self._determine_urgency(finding)

            # Request validation if enabled and applicable
            if self.validation_client and self._should_validate(finding):
                finding.validation_job_id = asyncio.run(
                    self._request_validation(finding)
                )
                if finding.validation_job_id:
                    self.stats['validations_requested'] += 1

            enhanced_findings.append(finding)

        self.stats['findings_after_context_filter'] = len([f for f in enhanced_findings if f.context_type != 'test'])
        self.stats['findings_after_fp_filter'] = len([f for f in enhanced_findings if not f.is_false_positive])

        return enhanced_findings

    def _should_skip_file(self, file_path: Path) -> bool:
        """Determine if file should be skipped."""
        # Skip by extension
        if file_path.suffix.lower() in self.SKIP_EXTENSIONS:
            return True

        # Skip by directory
        if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRECTORIES):
            return True

        # Skip very large files (>10MB)
        try:
            if file_path.stat().st_size > 10 * 1024 * 1024:
                return True
        except OSError:
            return True

        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        # Count character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        text_length = len(text)

        for count in frequencies.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)

        return entropy

    def _calculate_risk_score(self, finding: Finding) -> float:
        """Calculate risk score (0.0-10.0) for finding."""
        score = 0.0

        # Base confidence score
        confidence_scores = {'High': 8.0, 'Medium': 5.0, 'Low': 2.0}
        score += confidence_scores.get(finding.confidence, 0.0)

        # Context penalty
        if finding.context_type == 'test':
            score *= 0.3
        elif finding.context_type == 'example':
            score *= 0.4
        elif finding.context_type == 'documentation':
            score *= 0.5

        # Entropy bonus
        if finding.entropy_score > 4.0:
            score += 1.0

        # Validation bonus/penalty
        if finding.validation_status == 'active':
            score += 2.0
        elif finding.validation_status == 'inactive':
            score *= 0.1

        return min(score, 10.0)

    def _determine_urgency(self, finding: Finding) -> str:
        """Determine urgency level based on risk score."""
        if finding.risk_score >= 8.0:
            return 'critical'
        elif finding.risk_score >= 6.0:
            return 'high'
        elif finding.risk_score >= 3.0:
            return 'medium'
        else:
            return 'low'

    def _should_validate(self, finding: Finding) -> bool:
        """Determine if finding should be validated."""
        # Only validate high confidence findings
        if finding.confidence != 'High':
            return False

        # Don't validate test/example findings
        if finding.context_type in ['test', 'example']:
            return False

        # Check if pattern supports validation
        pattern = next((p for p in self.patterns if p.rule_id == finding.rule_id), None)
        return pattern and pattern.validation_enabled

    async def _request_validation(self, finding: Finding) -> Optional[str]:
        """Request validation for a finding."""
        try:
            pattern = next((p for p in self.patterns if p.rule_id == finding.rule_id), None)
            if not pattern or not pattern.secret_type:
                return None

            job_id = await self.validation_client.submit_validation(
                secret_type=pattern.secret_type,
                secret_value=finding.secret_value,
                context={
                    'file_path': finding.file_path,
                    'line_number': finding.line_number,
                    'context_type': finding.context_type
                }
            )

            return job_id

        except Exception as e:
            logger.error(f"Validation request failed: {e}")
            return None

    def _prepare_scan_results(self, findings: List[Finding], target_path: str, **kwargs) -> Dict:
        """Prepare comprehensive scan results."""
        scan_duration = self.stats['scan_end_time'] - self.stats['scan_start_time']

        # Group findings by urgency
        urgency_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            urgency_counts[finding.urgency or 'low'] += 1

        return {
            'scan_metadata': {
                'scanner_version': '2.0.0-phase4',
                'scan_timestamp': datetime.utcnow().isoformat(),
                'target_path': target_path,
                'scan_duration_seconds': round(scan_duration, 2),
                'total_findings': len(findings),
                'commit_hash': kwargs.get('commit_hash'),
                'branch_name': kwargs.get('branch_name'),
                'source_type': kwargs.get('source_type', 'manual')
            },
            'statistics': self.stats,
            'urgency_breakdown': urgency_counts,
            'findings': [self._finding_to_dict(f) for f in findings],
            'ci_metadata': {
                'pipeline_should_fail': urgency_counts['critical'] > 0 or urgency_counts['high'] > 0,
                'recommended_action': 'Block deployment' if urgency_counts['critical'] > 0 else 'Review findings'
            }
        }

    def _finding_to_dict(self, finding: Finding) -> Dict:
        """Convert finding to dictionary."""
        return {
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'rule_id': finding.rule_id,
            'description': finding.description,
            'confidence': finding.confidence,
            'entropy_score': round(finding.entropy_score, 2),
            'validation_status': finding.validation_status,
            'validation_job_id': finding.validation_job_id,
            'context_type': finding.context_type,
            'context_confidence': round(finding.context_confidence, 2) if finding.context_confidence else None,
            'is_false_positive': finding.is_false_positive,
            'false_positive_reason': finding.false_positive_reason,
            'risk_score': round(finding.risk_score, 2) if finding.risk_score else None,
            'urgency': finding.urgency,
            'source_type': finding.source_type,
            'commit_hash': finding.commit_hash,
            'branch_name': finding.branch_name,
            'author_email': finding.author_email
        }

def load_patterns(patterns_file: str) -> List[Pattern]:
    """Load and compile patterns from YAML file."""
    with open(patterns_file, 'r') as f:
        patterns_data = yaml.safe_load(f)

    patterns = []
    for pattern_data in patterns_data.get('patterns', []):
        try:
            compiled_regex = re.compile(pattern_data['regex'])
            pattern = Pattern(
                rule_id=pattern_data['rule_id'],
                description=pattern_data['description'],
                regex=compiled_regex,
                confidence=pattern_data['confidence'],
                entropy_threshold=pattern_data.get('entropy_threshold', 0.0),
                keywords=pattern_data.get('keywords', []),
                secret_type=pattern_data.get('secret_type'),
                validation_enabled=pattern_data.get('validation_enabled', False)
            )
            patterns.append(pattern)
        except Exception as e:
            logger.error(f"Error compiling pattern {pattern_data.get('rule_id')}: {e}")

    return patterns
