import aiohttp
from .base_validator import BaseValidator, ValidationResult, ValidationStatus

class StripeValidator(BaseValidator):
    STRIPE_API_BASE = "https://api.stripe.com"
    async def validate(self, secret_value: str) -> ValidationResult:
        if not (secret_value.startswith('sk_') or secret_value.startswith('pk_')):
            return ValidationResult(ValidationStatus.INVALID_FORMAT, False, "Invalid Stripe key format")
        is_test_key = '_test_' in secret_value
        if not self.check_rate_limit(f"stripe:{secret_value[:10]}", limit=5, window=60):
            return ValidationResult(ValidationStatus.ERROR, False, "Rate limit exceeded")
        headers = {"Authorization": f"Bearer {secret_value}"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.STRIPE_API_BASE}/v1/balance", headers=headers, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return ValidationResult(ValidationStatus.ACTIVE, True, "Valid Stripe API key", metadata={"key_type": "test" if is_test_key else "live"})
                    elif resp.status == 401:
                        return ValidationResult(ValidationStatus.INACTIVE, False, "Invalid Stripe API key")
                    else:
                        return ValidationResult(ValidationStatus.ERROR, False, f"Stripe API {resp.status}")
        except Exception as e:
            return ValidationResult(ValidationStatus.ERROR, False, f"Validation error: {str(e)}")
