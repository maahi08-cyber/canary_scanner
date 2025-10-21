from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime
import uuid
import json
import logging

from .config import settings
from .validators import VALIDATORS
from .security import verify_api_key
from arq import create_pool

# Configure logging
logging.basicConfig(level=settings.LOG_LEVEL.upper())
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="2.0.0",
    description="An asynchronous microservice to validate secrets found by Canary Scanner."
)

@app.on_event("startup")
async def startup():
    """On startup, create a Redis pool for arq."""
    app.state.redis = await create_pool(settings.get_arq_redis_settings())
    logger.info("FastAPI app started and Redis pool created.")

@app.on_event("shutdown")
async def shutdown():
    """On shutdown, close the Redis pool."""
    await app.state.redis.close()
    logger.info("FastAPI app shut down and Redis pool closed.")


# --- API Models ---
class ValidationRequest(BaseModel):
    secret_type: str
    secret_value: str
    context: Optional[Dict] = {}

class ValidationResponse(BaseModel):
    job_id: str
    status: str
    message: Optional[str] = "Validation job submitted successfully."

class StatusResponse(BaseModel):
    job_id: str
    status: str
    result: Optional[Dict] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None


# --- API Endpoints ---
@app.post(
    f"{settings.API_V1_STR}/validate",
    response_model=ValidationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_api_key)]
)
async def submit_validation_job(request: ValidationRequest):
    """
    Receives a secret and submits it to the background worker queue for validation.
    """
    if request.secret_type not in VALIDATORS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Validation for secret type '{request.secret_type}' is not supported."
        )

    job_id = str(uuid.uuid4())
    job_data = {
        "job_id": job_id,
        "secret_type": request.secret_type,
        "secret_value": request.secret_value,
        "context": request.context,
        "created_at": datetime.utcnow().isoformat(),
        "status": "queued",
    }

    try:
        # Enqueue the job for the arq worker
        await app.state.redis.enqueue_job(
            'run_validation',  # This must match the task name in worker.py
            job_data,
            _queue_name=settings.VALIDATION_QUEUE_NAME
        )
        logger.info(f"Successfully enqueued validation job {job_id} for type '{request.secret_type}'.")
        return ValidationResponse(job_id=job_id, status="queued")
    except Exception as e:
        logger.error(f"Failed to enqueue job {job_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit job to the validation queue."
        )


@app.get(
    f"{settings.API_V1_STR}/validate/status/{{job_id}}",
    response_model=StatusResponse,
    dependencies=[Depends(verify_api_key)]
)
async def get_validation_status(job_id: str):
    """Retrieves the status and result of a validation job from Redis."""
    try:
        job_json = await app.state.redis.get(f"job_result:{job_id}")
        if not job_json:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Validation job with ID '{job_id}' not found."
            )
        job_data = json.loads(job_json)
        return StatusResponse(**job_data)
    except Exception as e:
        logger.error(f"Failed to retrieve status for job {job_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving job status."
        )

@app.get(f"{settings.API_V1_STR}/health")
async def health_check():
    """Performs a health check of the service and its dependencies (Redis)."""
    try:
        await app.state.redis.ping()
        return {"status": "healthy", "redis_connection": "ok"}
    except Exception:
        logger.error("Health check failed: Could not connect to Redis.")
        raise HTTPException(status_code=503, detail="Service unhealthy: Cannot connect to Redis")
