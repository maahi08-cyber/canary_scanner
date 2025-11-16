"""
Helper Utilities for Canary Dashboard
====================================

Common utility functions used throughout the dashboard application
for data formatting, calculations, and other shared operations.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

def format_confidence_display(confidence: str) -> str:
    """
    Format confidence level for display with appropriate styling.

    Args:
        confidence: Raw confidence level (High/Medium/Low)

    Returns:
        str: Formatted display string with emoji
    """
    confidence_map = {
        "High": "🔴 Critical",
        "Medium": "🟡 Medium",
        "Low": "🔵 Low"
    }
    return confidence_map.get(confidence, f"❓ {confidence}")

def calculate_risk_score(confidence: str, age_days: int = 0, file_type: str = "") -> float:
    """
    Calculate a risk score for a finding based on multiple factors.

    Args:
        confidence: Confidence level (High/Medium/Low)
        age_days: Age of finding in days
        file_type: Type of file where secret was found

    Returns:
        float: Risk score from 0.0 to 10.0
    """
    # Base score from confidence level
    base_scores = {
        "High": 8.0,
        "Medium": 5.0, 
        "Low": 2.0
    }

    score = base_scores.get(confidence, 0.0)

    # Age multiplier (older findings are more risky)
    if age_days > 30:
        score *= 1.5
    elif age_days > 7:
        score *= 1.2

    # File type adjustments
    risky_extensions = [".env", ".config", ".yaml", ".yml", ".json"]
    if any(file_type.lower().endswith(ext) for ext in risky_extensions):
        score *= 1.3

    # Ensure score stays within bounds
    return min(10.0, max(0.0, score))

def format_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp for human-readable display.

    Args:
        timestamp: DateTime object to format

    Returns:
        str: Formatted timestamp string
    """
    if not timestamp:
        return "Unknown"

    now = datetime.utcnow()
    diff = now - timestamp

    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    else:
        return "Just now"

def get_status_badge_class(status: str) -> str:
    """
    Get CSS class for status badge styling.

    Args:
        status: Finding status

    Returns:
        str: CSS class name
    """
    status_classes = {
        "New": "badge-danger",
        "Acknowledged": "badge-warning",
        "Resolved": "badge-success",
        "False Positive": "badge-secondary"
    }
    return status_classes.get(status, "badge-light")

def paginate_results(results: List[Any], page: int = 1, per_page: int = 20) -> Dict[str, Any]:
    """
    Paginate a list of results.

    Args:
        results: List of items to paginate
        page: Current page number (1-based)
        per_page: Items per page

    Returns:
        dict: Pagination information and paginated results
    """
    total = len(results)
    start = (page - 1) * per_page
    end = start + per_page

    paginated_results = results[start:end]

    total_pages = (total + per_page - 1) // per_page

    return {
        "results": paginated_results,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < total_pages else None
        }
    }

def generate_scan_summary(scan) -> Dict[str, Any]:
    """
    Generate a comprehensive summary of a scan.

    Args:
        scan: Scan model instance

    Returns:
        dict: Scan summary with metrics and insights
    """
    findings = scan.findings

    # Basic counts
    total_findings = len(findings)
    critical_count = len([f for f in findings if f.confidence == "High"])
    resolved_count = len([f for f in findings if f.status == "Resolved"])

    # Calculate resolution rate
    resolution_rate = (resolved_count / total_findings * 100) if total_findings > 0 else 0

    # File distribution
    affected_files = list(set(f.file_path for f in findings))

    # Rule distribution
    rule_counts = {}
    for finding in findings:
        rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1

    # Most problematic rule
    top_rule = max(rule_counts.items(), key=lambda x: x[1]) if rule_counts else None

    return {
        "total_findings": total_findings,
        "critical_findings": critical_count,
        "resolved_findings": resolved_count,
        "resolution_rate": round(resolution_rate, 1),
        "affected_files": len(affected_files),
        "unique_rules": len(rule_counts),
        "top_rule": {
            "rule_id": top_rule[0],
            "count": top_rule[1]
        } if top_rule else None,
        "scan_efficiency": {
            "duration": scan.scan_duration,
            "findings_per_second": round(total_findings / max(scan.scan_duration, 1), 2)
        }
    }

def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        str: Formatted duration string
    """
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)
        return f"{minutes}m {remaining_seconds}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def validate_repository_name(repo_name: str) -> bool:
    """
    Validate repository name format.

    Args:
        repo_name: Repository name to validate

    Returns:
        bool: True if valid format
    """
    if not repo_name or "/" not in repo_name:
        return False

    parts = repo_name.split("/")
    if len(parts) != 2:
        return False

    org, repo = parts
    if not org or not repo:
        return False

    # Basic character validation
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if not all(c in allowed_chars for c in repo_name):
        return False

    return True

def get_trend_direction(current: int, previous: int) -> str:
    """
    Determine trend direction for metrics.

    Args:
        current: Current period value
        previous: Previous period value

    Returns:
        str: Trend direction with emoji
    """
    if current > previous:
        return "📈 Increasing"
    elif current < previous:
        return "📉 Decreasing"
    else:
        return "➡️ Stable"
