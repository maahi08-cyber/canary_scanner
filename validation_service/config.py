from pydantic import BaseSettings

class Settings(BaseSettings):
    REDIS_URL: str = "redis://localhost:6379/0"
    API_KEY: str = "your-secure-api-key"
    JOB_TTL: int = 3600  # seconds
    RATE_LIMIT: int = 10  # requests per minute per validator

settings = Settings()

