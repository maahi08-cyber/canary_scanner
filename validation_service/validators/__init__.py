# Validator registry and imports
from .aws_validator import AWSValidator
from .github_validator import GitHubValidator
from .stripe_validator import StripeValidator

VALIDATORS = {
    "aws_access_key": AWSValidator,
    "github_token": GitHubValidator,
    "stripe_api_key": StripeValidator,
}

__all__ = ["AWSValidator", "GitHubValidator", "StripeValidator", "VALIDATORS"]

