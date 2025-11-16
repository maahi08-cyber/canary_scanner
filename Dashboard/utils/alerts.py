"""
Slack Alerting System for Canary Dashboard
==========================================

Handles real-time notifications to Slack when critical security
findings are detected, providing immediate visibility to security teams.
"""

import httpx
import json
import logging
from datetime import datetime
from typing import Optional
from config import settings

logger = logging.getLogger(__name__)

async def send_slack_alert(
    message: str,
    channel: Optional[str] = None,
    username: str = "Canary Scanner",
    icon_emoji: str = ":canary:"
) -> bool:
    """
    Send a message to Slack using webhook.

    Args:
        message: The message to send
        channel: Slack channel (optional, uses configured default)
        username: Bot username for the message
        icon_emoji: Emoji icon for the bot

    Returns:
        bool: True if message sent successfully
    """
    if not settings.slack_webhook_url:
        logger.warning("⚠️ Slack webhook not configured, skipping alert")
        return False

    try:
        payload = {
            "text": message,
            "username": username,
            "icon_emoji": icon_emoji,
            "channel": channel or settings.slack_channel
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                settings.slack_webhook_url,
                json=payload,
                timeout=10.0
            )

        if response.status_code == 200:
            logger.info("✅ Slack alert sent successfully")
            return True
        else:
            logger.error(f"❌ Failed to send Slack alert: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        logger.error(f"❌ Error sending Slack alert: {str(e)}")
        return False

async def send_critical_alert(scan, finding, dashboard_url: str) -> bool:
    """
    Send a critical security alert to Slack.

    Args:
        scan: Scan model instance
        finding: Finding model instance  
        dashboard_url: URL to dashboard for this finding

    Returns:
        bool: True if alert sent successfully
    """
    if finding.confidence != "High":
        logger.debug(f"Skipping alert for non-critical finding: {finding.confidence}")
        return True

    # Format alert message
    alert_message = f"""🚨 *CRITICAL SECURITY ALERT* 🚨

*Repository:* `{scan.repository_name}`
*Branch:* `{scan.branch}`
*Commit:* `{scan.short_commit_hash}`

*🔍 Finding Details:*
• *Type:* {finding.description}
• *File:* `{finding.file_path}:{finding.line_number}`
• *Rule:* {finding.rule_id}
• *Confidence:* {finding.confidence} ({finding.severity_icon})

*⚡ Immediate Actions Required:*
1. 🛑 *DO NOT MERGE* this code
2. 🔄 Rotate the exposed credential immediately
3. 🗑️ Remove the secret from source code
4. 🔐 Use environment variables or secure vaults

*🔗 View Details:* {dashboard_url}

_Detected by Canary Scanner at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC_
"""

    return await send_slack_alert(alert_message)

async def send_scan_summary_alert(scan, critical_count: int, total_count: int, dashboard_url: str) -> bool:
    """
    Send a scan summary alert for scans with multiple findings.

    Args:
        scan: Scan model instance
        critical_count: Number of critical findings
        total_count: Total number of findings
        dashboard_url: URL to scan details page

    Returns:
        bool: True if alert sent successfully
    """
    if total_count == 0:
        return True  # No alert needed for clean scans

    # Choose appropriate emoji and urgency
    if critical_count > 0:
        emoji = "🚨"
        urgency = "CRITICAL"
    elif total_count >= 5:
        emoji = "⚠️"
        urgency = "HIGH"
    else:
        emoji = "ℹ️"
        urgency = "MEDIUM"

    alert_message = f"""{emoji} *{urgency} SECURITY SCAN RESULTS* {emoji}

*Repository:* `{scan.repository_name}`
*Branch:* `{scan.branch}`
*Commit:* `{scan.short_commit_hash}`

*📊 Findings Summary:*
• *Total Findings:* {total_count}
• *Critical (High Confidence):* {critical_count}
• *Scanner Version:* {scan.scanner_version}

*🔗 Full Report:* {dashboard_url}

_Scan completed at {scan.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC_
"""

    return await send_slack_alert(alert_message)

def format_findings_summary(findings: list) -> str:
    """
    Format a summary of findings for alert messages.

    Args:
        findings: List of Finding model instances

    Returns:
        str: Formatted summary string
    """
    if not findings:
        return "No findings detected ✅"

    # Group by confidence level
    by_confidence = {"High": [], "Medium": [], "Low": []}
    for finding in findings:
        by_confidence[finding.confidence].append(finding)

    summary_parts = []

    if by_confidence["High"]:
        summary_parts.append(f"🔴 {len(by_confidence['High'])} Critical")
    if by_confidence["Medium"]:
        summary_parts.append(f"🟡 {len(by_confidence['Medium'])} Medium") 
    if by_confidence["Low"]:
        summary_parts.append(f"🔵 {len(by_confidence['Low'])} Low")

    return " | ".join(summary_parts)

async def test_slack_connection() -> bool:
    """
    Test Slack webhook connection.

    Returns:
        bool: True if connection successful
    """
    test_message = """🧪 *Canary Dashboard Test Alert*

This is a test message to verify Slack integration is working correctly.

✅ If you can see this message, the integration is working!

_Generated at {}_""".format(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))

    return await send_slack_alert(test_message)
