from pydantic_settings import BaseSettings
from typing import Set, List

class Settings(BaseSettings):
    """
    Manages service configuration via environment variables using Pydantic.
    For local development, create a `.env` file in this directory.
    """
    # --- Application Metadata ---
    PROJECT_NAME: str = "Canary Secret Validation Service"
    API_V1_STR: str = "/api/v1"
    LOG_LEVEL: str = "INFO"

    # --- Security ---
    # A comma-separated string of valid API keys in your .env file.
    # e.g., VALID_API_KEYS="key-one-abc,key-two-xyz"
    VALID_API_KEYS: Set[str] = {"default-super-secret-key-replace-me"}

    # --- Redis Job Queue ---
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None

    def get_redis_settings(self):
        """Returns a RedisSettings object compatible with the ARQ worker."""
        from arq.connections import RedisSettings as ArqRedisSettings
        return ArqRedisSettings(
            host=self.REDIS_HOST,
            port=self.REDIS_PORT,
            database=self.REDIS_DB,
            password=self.REDIS_PASSWORD
        )

    # --- Validator Behavior ---
    VALIDATOR_TIMEOUT: int = 25 # General timeout for validator HTTP requests
    VALIDATOR_USER_AGENT: str = f"{PROJECT_NAME}/2.0"
    
    # --- Stripe Specific Config ---
    STRIPE_API_KEY: str | None = None # A key for the validator to authenticate with Stripe

    class Config:
        env_file = ".env"
        case_sensitive = True

# A single, globally accessible instance of the settings
settings = Settings()


