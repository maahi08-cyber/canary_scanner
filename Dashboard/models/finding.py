"""
Finding Model - Database representation of detected secrets
==========================================================

Represents individual security findings (detected secrets) with
full metadata, status tracking, and relationship to parent scans.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base

class Finding(Base):
    """
    Represents a single detected secret or security finding.

    Each finding is linked to a specific scan and contains all the
    metadata needed to identify, assess, and track the secret.
    """
    __tablename__ = "findings"

    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    # Finding location and details
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    rule_id = Column(String, nullable=False, index=True)
    description = Column(String, nullable=False)
    confidence = Column(String, nullable=False, index=True)  # High/Medium/Low
    secret_preview = Column(String, nullable=False)  # Masked secret

    # Status tracking and management
    status = Column(String, nullable=False, default="New", index=True)  # New/Acknowledged/Resolved/False Positive
    risk_score = Column(Float, nullable=False, default=0.0)  # Calculated risk score
    notes = Column(Text, nullable=True)  # Optional notes from security team

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding(id={self.id}, rule='{self.rule_id}', file='{self.file_path}', confidence='{self.confidence}', status='{self.status}')>"

    @property
    def severity_icon(self) -> str:
        """Return icon based on confidence level."""
        icons = {
            "High": "🔴",
            "Medium": "🟡", 
            "Low": "🔵"
        }
        return icons.get(self.confidence, "❓")

    @property
    def status_icon(self) -> str:
        """Return icon based on status."""
        icons = {
            "New": "🆕",
            "Acknowledged": "👁️",
            "Resolved": "✅",
            "False Positive": "❌"
        }
        return icons.get(self.status, "❓")

    @property
    def short_file_path(self) -> str:
        """Return shortened file path for display."""
        if len(self.file_path) > 50:
            return f"...{self.file_path[-47:]}"
        return self.file_path

    @property
    def age_days(self) -> int:
        """Calculate age of finding in days."""
        if self.created_at:
            return (datetime.utcnow() - self.created_at).days
        return 0

    def mark_resolved(self, notes: str = None):
        """Mark finding as resolved with optional notes."""
        self.status = "Resolved"
        self.resolved_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        if notes:
            self.notes = notes

    def to_dict(self) -> dict:
        """Convert finding to dictionary for API responses."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "description": self.description,
            "confidence": self.confidence,
            "secret_preview": self.secret_preview,
            "status": self.status,
            "risk_score": self.risk_score,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "age_days": self.age_days
        }
