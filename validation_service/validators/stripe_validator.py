import aiohttp
import time
from typing import Dict
from .base_validator import BaseValidator, ValidationResult, ValidationStatus
import logging

logger = logging.getLogger(__name__)

class StripeValidator(BaseValidator):
    """Validator for Stripe API keys."""

    STRIPE_API_BASE = "https://api.stripe.com"

    def __init__(self):
        super().__init__()
        self.description = "Stripe API key validator"

    async def validate(self, secret_value: str, additional_data: Dict, context: Dict) -> ValidationResult:
        """
        Validates a Stripe API key by making a safe, read-only API call.
        CORRECTED: Method signature now matches the base class and returns the
                   correct Pydantic ValidationResult object.
        """
        start_time = time.time()

        if not (secret_value.startswith('sk_') or secret_value.startswith('rk_')):
            return ValidationResult(
                status=ValidationStatus.INVALID_FORMAT,
                details={"reason": "Invalid Stripe key format. Must start with 'sk_' or 'rk_'."}
            )

        is_test_key = '_test_' in secret_value
        headers = {"Authorization": f"Bearer {secret_value}"}
        # A safe, read-only endpoint that exists for all keys
        validation_url = f"{self.STRIPE_API_BASE}/v1/balance"

        try:
            async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.get(validation_url) as resp:
                    service_response_time = time.time() - start_time
                    if resp.status == 200:
                        return ValidationResult(
                            status=ValidationStatus.ACTIVE,
                            confidence=1.0,
                            details={"key_type": "test" if is_test_key else "live"},
                            service_response_time=service_response_time
                        )
                    elif resp.status == 401:
                        return ValidationResult(
                            status=ValidationStatus.INACTIVE,
                            confidence=1.0,
                            details={"http_status": 401, "reason": "Invalid or revoked Stripe API key."},
                            service_response_time=service_response_time
                        )
                    else:
                        error_text = await resp.text()
                        logger.warning(f"Stripe validation received unexpected status {resp.status}: {error_text}")
                        return ValidationResult(
                            status=ValidationStatus.ERROR,
                            error_message=f"Stripe API returned HTTP status {resp.status}.",
                            details={"http_status": resp.status, "response_body": error_text[:200]},
                            service_response_time=service_response_time
                        )
        except Exception as e:
            logger.error(f"Error during Stripe validation request: {e}", exc_info=True)
            return ValidationResult(
                status=ValidationStatus.ERROR,
                error_message=f"An unexpected exception occurred: {str(e)}"
            )
