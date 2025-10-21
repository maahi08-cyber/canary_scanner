from pydantic_settings import BaseSettings
from typing import Set, List
from arq.connections import RedisSettings as ArqRedisSettings
import os

class Settings(BaseSettings):
    """
    Manages service configuration via environment variables using Pydantic.
    For local development, create a `.env` file in this directory.
    """
    # --- Application Metadata ---
    PROJECT_NAME: str = "Canary Secret Validation Service"
    API_V1_STR: str = "/api/v1"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # --- Security ---
    # A comma-separated string of valid API keys in your .env file.
    # e.g., VALID_API_KEYS="key-one-abc,key-two-xyz"
    # CORRECTED: Reads a set of keys, not a single one.
    VALID_API_KEYS: Set[str] = {"default-super-secret-key-replace-me"}

    # --- Redis Job Queue ---
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = os.getenv("REDIS_PASSWORD")
    JOB_TTL_SECONDS: int = 3600 # Time to live for job results in Redis (1 hour)
    VALIDATION_QUEUE_NAME: str = "canary_validation_queue"

    def get_arq_redis_settings(self) -> ArqRedisSettings:
        """Returns a RedisSettings object compatible with the ARQ worker."""
        return ArqRedisSettings(
            host=self.REDIS_HOST,
            port=self.REDIS_PORT,
            database=self.REDIS_DB,
            password=self.REDIS_PASSWORD
        )

    # --- Validator Behavior ---
    VALIDATOR_TIMEOUT_SECONDS: int = 25 # General timeout for validator HTTP requests
    VALIDATOR_USER_AGENT: str = f"{PROJECT_NAME}/2.0"

    class Config:
        env_file = ".env"
        case_sensitive = True

# A single, globally accessible instance of the settings
settings = Settings()
