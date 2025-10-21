"""
Validation Client for communicating with the validation service.
"""
import asyncio
import json
import logging
from typing import Dict, Optional
import aiohttp

logger = logging.getLogger(__name__)

class ValidationClient:
    """Client for interacting with the validation service."""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        """Initialize validation client."""
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if not self.session:
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'

            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self.session

    async def submit_validation(self, secret_type: str, secret_value: str, 
                              context: Dict = None, priority: str = "medium") -> Optional[str]:
        """Submit a secret for validation."""
        try:
            session = await self._get_session()

            payload = {
                "secret_type": secret_type,
                "secret_value": secret_value,
                "context": context or {},
                "priority": priority
            }

            async with session.post(f"{self.base_url}/api/v1/validate", json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get('job_id')
                else:
                    logger.error(f"Validation submission failed: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Validation client error: {e}")
            return None

    async def get_validation_status(self, job_id: str) -> Optional[Dict]:
        """Get validation status for a job."""
        try:
            session = await self._get_session()

            async with session.get(f"{self.base_url}/api/v1/validate/status/{job_id}") as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error(f"Status check failed: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Status check error: {e}")
            return None

    async def close(self):
        """Close the HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
