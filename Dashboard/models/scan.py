"""
Scan Model - Database representation of security scans
=====================================================

Represents a complete security scan session, containing metadata
about the scan execution and linking to individual findings.
"""

from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base

class Scan(Base):
    """
    Represents a security scan session.

    A scan is created each time the scanner runs on a repository,
    typically triggered by CI/CD events like commits or pull requests.
    """
    __tablename__ = "scans"

    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    repository_name = Column(String, nullable=False, index=True)
    commit_hash = Column(String, nullable=False)
    branch = Column(String, nullable=False, default="main")

    # Scan metadata
    scanner_version = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    scan_duration = Column(Float, default=0.0)  # Duration in seconds

    # Results summary
    findings_count = Column(Integer, default=0, nullable=False)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, repo='{self.repository_name}', commit='{self.commit_hash[:8]}', findings={self.findings_count})>"

    @property
    def short_commit_hash(self) -> str:
        """Return shortened commit hash for display."""
        return self.commit_hash[:8] if self.commit_hash else ""

    @property 
    def critical_findings_count(self) -> int:
        """Count of high-confidence findings in this scan."""
        return len([f for f in self.findings if f.confidence == "High"])

    @property
    def resolved_findings_count(self) -> int:
        """Count of resolved findings in this scan."""
        return len([f for f in self.findings if f.status == "Resolved"])

    def to_dict(self) -> dict:
        """Convert scan to dictionary for API responses."""
        return {
            "id": self.id,
            "repository_name": self.repository_name,
            "commit_hash": self.commit_hash,
            "branch": self.branch,
            "scanner_version": self.scanner_version,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "scan_duration": self.scan_duration,
            "findings_count": self.findings_count,
            "critical_findings_count": self.critical_findings_count,
            "resolved_findings_count": self.resolved_findings_count
        }
