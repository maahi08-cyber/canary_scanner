"""
Configuration Management for Canary Dashboard
=============================================

Centralized configuration management using environment variables
with sensible defaults for development and production deployments.
"""

import os
from typing import Optional
from pydantic import BaseSettings

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Environment Variables:
    - DATABASE_URL: PostgreSQL connection string
    - SLACK_WEBHOOK_URL: Slack webhook for alerts
    - DASHBOARD_BASE_URL: Base URL for dashboard links
    - SECRET_KEY: Secret key for session management
    - LOG_LEVEL: Logging level (DEBUG/INFO/WARNING/ERROR)
    """

    # Database configuration
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:password@localhost:5432/canary_dashboard"
    )

    # Slack integration
    slack_webhook_url: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")
    slack_channel: str = os.getenv("SLACK_CHANNEL", "#security-alerts")

    # Dashboard configuration
    dashboard_base_url: str = os.getenv("DASHBOARD_BASE_URL", "http://localhost:8000")
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")

    # Logging and debugging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Alert thresholds
    critical_alert_threshold: str = os.getenv("CRITICAL_ALERT_THRESHOLD", "High")
    max_findings_per_alert: int = int(os.getenv("MAX_FINDINGS_PER_ALERT", "5"))

    # Performance settings
    db_pool_size: int = int(os.getenv("DB_POOL_SIZE", "10"))
    db_max_overflow: int = int(os.getenv("DB_MAX_OVERFLOW", "20"))

    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

def get_database_url() -> str:
    """Get database URL with validation."""
    url = settings.database_url
    if not url or not url.startswith("postgresql://"):
        raise ValueError("Invalid DATABASE_URL. Must be a valid PostgreSQL URL.")
    return url

def is_slack_enabled() -> bool:
    """Check if Slack integration is properly configured."""
    return bool(settings.slack_webhook_url and settings.slack_webhook_url.startswith("https://hooks.slack.com/"))

def get_alert_config() -> dict:
    """Get alerting configuration."""
    return {
        "enabled": is_slack_enabled(),
        "webhook_url": settings.slack_webhook_url,
        "channel": settings.slack_channel,
        "threshold": settings.critical_alert_threshold,
        "max_findings": settings.max_findings_per_alert
    }
