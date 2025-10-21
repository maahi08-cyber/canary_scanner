"""
AWS secret validator for validating AWS credentials.
"""
import asyncio
import time
from typing import Dict
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from .base_validator import BaseValidator, ValidationResult, ValidationStatus

class AWSValidator(BaseValidator):
    """Validator for AWS credentials."""

    def __init__(self):
        super().__init__()
        self.description = "AWS credentials validator (Access Keys, Secret Keys)"
        self.supported_operations = ["validate", "get_caller_identity", "list_permissions"]
        self.rate_limit_delay = 2.0  # AWS has strict rate limits

    async def validate(self, secret_value: str, additional_data: Dict, context: Dict) -> ValidationResult:
        """
        Validate AWS credentials.

        For AWS validation, we need both access key and secret key.
        We make a safe, read-only call to AWS STS get_caller_identity.
        """
        start_time = time.time()

        try:
            # Extract credentials from secret_value and additional_data
            access_key = None
            secret_key = None

            # Check if this is an access key or secret key
            if secret_value.startswith('AKIA') or secret_value.startswith('ASIA'):
                # This is an access key
                access_key = secret_value
                secret_key = additional_data.get('secret_key')
            else:
                # This might be a secret key
                secret_key = secret_value
                access_key = additional_data.get('access_key')

            if not access_key or not secret_key:
                return ValidationResult(
                    status=ValidationStatus.UNSUPPORTED,
                    confidence=0.0,
                    details={"reason": "Both access_key and secret_key required for AWS validation"},
                    error_message="Incomplete AWS credentials"
                )

            # Validate format first
            if not self._is_valid_aws_format(access_key, secret_key):
                return ValidationResult(
                    status=ValidationStatus.INVALID_FORMAT,
                    confidence=1.0,
                    details={"reason": "Invalid AWS credential format"},
                    error_message="Credentials do not match AWS format"
                )

            # Apply rate limiting
            await self._rate_limit()

            # Create AWS STS client with the credentials
            # We use a read-only operation that doesn't modify anything
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='us-east-1'  # STS is available in all regions
            )

            # Make the API call in a thread to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                self._get_caller_identity_sync, 
                sts_client
            )

            service_response_time = time.time() - start_time

            if response:
                return ValidationResult(
                    status=ValidationStatus.ACTIVE,
                    confidence=1.0,
                    details={
                        "user_id": response.get('UserId'),
                        "account": response.get('Account'),
                        "arn": response.get('Arn'),
                        "service": "AWS STS"
                    },
                    service_response_time=service_response_time
                )
            else:
                return ValidationResult(
                    status=ValidationStatus.INACTIVE,
                    confidence=1.0,
                    details={"reason": "No valid response from AWS STS"},
                    service_response_time=service_response_time
                )

        except ClientError as e:
            service_response_time = time.time() - start_time
            error_code = e.response.get('Error', {}).get('Code', '')

            if error_code == 'InvalidClientTokenId':
                return ValidationResult(
                    status=ValidationStatus.INACTIVE,
                    confidence=1.0,
                    details={"aws_error_code": error_code, "reason": "Invalid access key"},
                    service_response_time=service_response_time
                )
            elif error_code == 'SignatureDoesNotMatch':
                return ValidationResult(
                    status=ValidationStatus.INACTIVE,
                    confidence=1.0,
                    details={"aws_error_code": error_code, "reason": "Invalid secret key"},
                    service_response_time=service_response_time
                )
            elif error_code == 'TokenRefreshRequired':
                return ValidationResult(
                    status=ValidationStatus.EXPIRED,
                    confidence=1.0,
                    details={"aws_error_code": error_code, "reason": "Credentials expired"},
                    service_response_time=service_response_time
                )
            elif 'Throttling' in error_code:
                return ValidationResult(
                    status=ValidationStatus.RATE_LIMITED,
                    confidence=0.5,
                    details={"aws_error_code": error_code, "reason": "Rate limited by AWS"},
                    error_message=str(e),
                    service_response_time=service_response_time
                )
            else:
                return ValidationResult(
                    status=ValidationStatus.ERROR,
                    confidence=0.0,
                    details={"aws_error_code": error_code, "reason": "AWS API error"},
                    error_message=str(e),
                    service_response_time=service_response_time
                )

        except NoCredentialsError:
            return ValidationResult(
                status=ValidationStatus.INACTIVE,
                confidence=1.0,
                details={"reason": "No credentials provided"},
                error_message="AWS credentials not found"
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

    def _get_caller_identity_sync(self, sts_client):
        """Synchronous wrapper for STS get_caller_identity."""
        try:
            return sts_client.get_caller_identity()
        except Exception:
            return None

    def _is_valid_aws_format(self, access_key: str, secret_key: str) -> bool:
        """Check if credentials match AWS format."""
        # AWS Access Key format: 20 characters, starts with AKIA or ASIA
        if not access_key or len(access_key) != 20:
            return False
        if not (access_key.startswith('AKIA') or access_key.startswith('ASIA')):
            return False

        # AWS Secret Key format: 40 characters, base64-like
        if not secret_key or len(secret_key) != 40:
            return False

        return True
