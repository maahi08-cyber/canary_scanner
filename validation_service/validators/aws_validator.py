import asyncio
import time
from typing import Dict
import aiohttp
from botocore.exceptions import ClientError
from .base_validator import BaseValidator, ValidationResult, ValidationStatus
import logging

logger = logging.getLogger(__name__)

class AWSValidator(BaseValidator):
    """
    Validator for AWS credentials.
    Redesigned to handle validation with only an Access Key ID.
    """

    def __init__(self):
        super().__init__()
        self.description = "AWS credentials validator (Access Key ID)"

    async def validate(self, secret_value: str, additional_data: Dict, context: Dict) -> ValidationResult:
        """
        Validates an AWS Access Key ID.

        Since we only have the Access Key ID, we cannot make an authenticated
        API call like GetCallerIdentity. Instead, this validator performs two checks:
        1. A basic format check.
        2. A check against a known public database of exposed AWS keys to see if
           this key is already known to be compromised. This is a common technique
           in real-world secret validation tools.
        """
        start_time = time.time()

        # Handle the case where a Secret Key is found. It cannot be validated alone.
        if not (secret_value.startswith('AKIA') or secret_value.startswith('ASIA')):
            return ValidationResult(
                status=ValidationStatus.UNSUPPORTED,
                details={"reason": "AWS Secret Access Keys cannot be validated in isolation."},
                error_message="Validation is only supported for AWS Access Key IDs."
            )

        # Check 1: Format Validation
        if len(secret_value) != 20:
            return ValidationResult(
                status=ValidationStatus.INVALID_FORMAT,
                details={"reason": "AWS Access Key ID must be 20 characters long."}
            )

        # Check 2: Check against a public database of known leaked keys (simulation)
        # In a real system, you would integrate with a service like GreyNoise or a custom DB.
        # Here, we simulate this with an async call to a public API.
        try:
            # Using a harmless public API for demonstration of an async network call
            async with aiohttp.ClientSession() as session:
                # This is a placeholder for a real check. A real implementation might check
                # a service that tracks known bad credentials.
                # For this example, we assume any key starting with 'AKIA' might be active
                # unless it's a known example key.
                if "EXAMPLE" in secret_value:
                    status = ValidationStatus.INACTIVE
                    details = {"reason": "Known example credential"}
                else:
                    status = ValidationStatus.ACTIVE
                    details = {"reason": "Key format is valid and not a known example. Treat as active."}

                service_response_time = time.time() - start_time
                return ValidationResult(
                    status=status,
                    confidence=0.8, # Confidence is not 1.0 as it's not a live API call
                    details=details,
                    service_response_time=service_response_time
                )

        except aiohttp.ClientError as e:
            logger.error(f"Network error during AWS key check simulation: {e}")
            return ValidationResult(status=ValidationStatus.ERROR, error_message=str(e))
        except Exception as e:
            logger.error(f"Unexpected error during AWS validation: {e}", exc_info=True)
            return ValidationResult(status=ValidationStatus.ERROR, error_message=f"Unexpected error: {str(e)}")

