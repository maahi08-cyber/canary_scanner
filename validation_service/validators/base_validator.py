from abc import ABC, abstractmethod
from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

# --- Standardized Models ---

class ValidationStatus(str, Enum):
    """Standardized validation statuses."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    ERROR = "error"

class ValidationResult(BaseModel):
    """
    A standardized Pydantic model for all validation results.
    This ensures consistent output from every validator.
    """
    status: ValidationStatus
    details: str
    is_active: Optional[bool] = None
    
    # Optional metadata that validators can add
    extra_info: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Calculate is_active after initialization."""
        if self.status == ValidationStatus.ACTIVE:
            self.is_active = True
        elif self.status == ValidationStatus.INACTIVE:
            self.is_active = False
        else:
            self.is_active = None

# --- Abstract Base Class ---

class BaseValidator(ABC):
    """
    An abstract base class that defines the contract for all validators.
    Every new validator (e.g., for Azure, Slack, etc.) MUST inherit from
    this class and implement the `validate` method.
    """
    
    # These must be overridden by subclasses
    secret_type: str = "base"
    description: str = "Base Validator"
    
    @abstractmethod
    async def validate(self, secret_value: str, context: Dict[str, Any]) -> ValidationResult:
        """
        The core validation logic for a specific secret type.

        Args:
            secret_value: The secret string to be validated.
            context: A dictionary of context from the scanner (e.g., file_path).

        Returns:
            A ValidationResult object.
        """
        raise NotImplementedError

    def sanitize_secret_for_logging(self, secret: str, visible_chars: int = 4) -> str:
        """
        Sanitizes a secret for logging to prevent accidental exposure.
        Example: "sk_live_1234567890abcdef" -> "sk_live_...bcde"
        """
        if len(secret) <= visible_chars:
            return "****"
        return f"{secret[:(len(secret) - visible_chars) // 2]}...{secret[-visible_chars:]}"
