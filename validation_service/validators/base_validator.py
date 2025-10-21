"""
Base validator class for secret validation.
"""
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Dict, Optional, List
from pydantic import BaseModel

class ValidationStatus(Enum):
    """Status of secret validation."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    INVALID_FORMAT = "invalid_format"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    UNSUPPORTED = "unsupported"

class ValidationResult(BaseModel):
    """Result of secret validation."""
    status: ValidationStatus
    confidence: float = 1.0  # 0.0 - 1.0
    details: Dict = {}
    error_message: Optional[str] = None
    validated_at: datetime = datetime.utcnow()
    service_response_time: Optional[float] = None  # seconds

    def to_dict(self) -> Dict:
        return {
            "status": self.status.value,
            "confidence": self.confidence,
            "details": self.details,
            "error_message": self.error_message,
            "validated_at": self.validated_at.isoformat(),
            "service_response_time": self.service_response_time
        }

class BaseValidator(ABC):
    """Base class for all secret validators."""

    def __init__(self):
        self.description = "Base validator"
        self.supported_operations = ["validate"]
        self.rate_limit_delay = 1.0  # seconds between requests

    @abstractmethod
    async def validate(self, secret_value: str, additional_data: Dict, context: Dict) -> ValidationResult:
        """
        Validate a secret by making API calls to the service.

        Args:
            secret_value: The secret to validate
            additional_data: Additional data needed for validation (e.g., secret key for AWS)
            context: Context about where the secret was found

        Returns:
            ValidationResult with status and details
        """
        pass

    def _sanitize_for_logging(self, secret: str) -> str:
        """Sanitize secret for safe logging."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    async def _rate_limit(self):
        """Apply rate limiting between requests."""
        await asyncio.sleep(self.rate_limit_delay)
