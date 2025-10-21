from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from .config import settings
import logging

logger = logging.getLogger(__name__)

# Define the API key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """
    FastAPI dependency to verify the provided API key.
    Checks if the key is present in the VALID_API_KEYS set from config.
    """
    if not api_key:
        logger.warning("API key verification failed: No API key provided.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key in 'X-API-Key' header.",
        )
    if api_key not in settings.VALID_API_KEYS:
        logger.warning(f"API key verification failed: Invalid key provided.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or unauthorized API Key.",
        )
    return api_key

