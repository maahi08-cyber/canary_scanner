"""
GitHub token validator.
"""
import asyncio
import time
from typing import Dict
import aiohttp
from .base_validator import BaseValidator, ValidationResult, ValidationStatus

class GitHubValidator(BaseValidator):
    """Validator for GitHub tokens."""

    def __init__(self):
        super().__init__()
        self.description = "GitHub token validator (PAT, OAuth tokens)"
        self.supported_operations = ["validate", "get_user", "check_scopes"]
        self.rate_limit_delay = 1.0

    async def validate(self, secret_value: str, additional_data: Dict, context: Dict) -> ValidationResult:
        """
        Validate GitHub token by calling the GitHub API.
        We use the /user endpoint which is safe and read-only.
        """
        start_time = time.time()

        try:
            # Validate token format first
            if not self._is_valid_github_token_format(secret_value):
                return ValidationResult(
                    status=ValidationStatus.INVALID_FORMAT,
                    confidence=1.0,
                    details={"reason": "Invalid GitHub token format"},
                    error_message="Token does not match GitHub format"
                )

            # Apply rate limiting
            await self._rate_limit()

            # Make GitHub API call
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f'token {secret_value}',
                    'User-Agent': 'Canary-Scanner-Validation-Service/1.0'
                }

                async with session.get('https://api.github.com/user', headers=headers) as response:
                    service_response_time = time.time() - start_time

                    if response.status == 200:
                        user_data = await response.json()
                        scopes = response.headers.get('X-OAuth-Scopes', '')

                        return ValidationResult(
                            status=ValidationStatus.ACTIVE,
                            confidence=1.0,
                            details={
                                "username": user_data.get('login'),
                                "user_id": user_data.get('id'),
                                "scopes": scopes.split(', ') if scopes else [],
                                "service": "GitHub API"
                            },
                            service_response_time=service_response_time
                        )
                    elif response.status == 401:
                        return ValidationResult(
                            status=ValidationStatus.INACTIVE,
                            confidence=1.0,
                            details={"reason": "Invalid or expired token", "http_status": 401},
                            service_response_time=service_response_time
                        )
                    elif response.status == 403:
                        # Could be rate limited or token with no user scope
                        rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
                        if rate_limit_remaining == '0':
                            return ValidationResult(
                                status=ValidationStatus.RATE_LIMITED,
                                confidence=0.5,
                                details={"reason": "GitHub API rate limit exceeded"},
                                service_response_time=service_response_time
                            )
                        else:
                            return ValidationResult(
                                status=ValidationStatus.ACTIVE,
                                confidence=0.8,
                                details={"reason": "Token valid but insufficient permissions", "http_status": 403},
                                service_response_time=service_response_time
                            )
                    else:
                        return ValidationResult(
                            status=ValidationStatus.ERROR,
                            confidence=0.0,
                            details={"reason": "Unexpected API response", "http_status": response.status},
                            error_message=f"HTTP {response.status}",
                            service_response_time=service_response_time
                        )

        except aiohttp.ClientError as e:
            service_response_time = time.time() - start_time
            return ValidationResult(
                status=ValidationStatus.ERROR,
                confidence=0.0,
                details={"reason": "Network error"},
                error_message=str(e),
                service_response_time=service_response_time
            )

        except Exception as e:
            service_response_time = time.time() - start_time
            return ValidationResult(
                status=ValidationStatus.ERROR,
                confidence=0.0,
                details={"reason": "Unexpected error during validation"},
                error_message=str(e),
                service_response_time=service_response_time
            )

    def _is_valid_github_token_format(self, token: str) -> bool:
        """Check if token matches GitHub token format."""
        if not token:
            return False

        # GitHub Personal Access Token (classic): ghp_XXXX (40 chars total)
        if token.startswith('ghp_') and len(token) == 40:
            return True

        # GitHub Fine-grained PAT: github_pat_XXXX
        if token.startswith('github_pat_') and len(token) > 20:
            return True

        # OAuth token: gho_XXXX (36 chars total) 
        if token.startswith('gho_') and len(token) == 36:
            return True

        # GitHub App token: ghs_XXXX (36 chars total)
        if token.startswith('ghs_') and len(token) == 36:
            return True

        # Legacy format (40 chars, hex)
        if len(token) == 40 and all(c in '0123456789abcdef' for c in token.lower()):
            return True

        return False
