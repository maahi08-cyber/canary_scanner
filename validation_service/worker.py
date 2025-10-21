import asyncio
import json
import logging
from datetime import datetime
from arq.connections import RedisSettings

from .config import settings
from .validators import VALIDATORS

# Configure logging for the worker
logging.basicConfig(level=settings.LOG_LEVEL.upper())
logger = logging.getLogger("canary.worker")

async def run_validation(ctx, job_data: dict):
    """
    This is the main ARQ task that performs the secret validation.
    It's triggered by jobs enqueued by the FastAPI app.
    """
    job_id = job_data.get("job_id")
    redis = ctx['redis']
    logger.info(f"Worker picked up job {job_id}.")

    try:
        # Update job status to 'in_progress'
        job_data['status'] = 'in_progress'
        await redis.setex(
            f"job_result:{job_id}",
            settings.JOB_TTL_SECONDS,
            json.dumps(job_data)
        )

        secret_type = job_data.get("secret_type")
        secret_value = job_data.get("secret_value")
        context = job_data.get("context", {})

        ValidatorClass = VALIDATORS.get(secret_type)
        if not ValidatorClass:
            raise ValueError(f"No validator found for secret type: {secret_type}")

        validator_instance = ValidatorClass()
        logger.info(f"Executing validator '{validator_instance.description}' for job {job_id}.")

        # The actual validation call
        validation_result = await validator_instance.validate(
            secret_value=secret_value,
            additional_data={}, # Pass context or other data if needed
            context=context
        )

        logger.info(f"Validation for job {job_id} completed with status: {validation_result.status.value}")

        # Store the final result
        job_data['status'] = 'completed'
        job_data['completed_at'] = datetime.utcnow().isoformat()
        job_data['result'] = validation_result.to_dict() # Use the Pydantic model's dict method
        await redis.setex(
            f"job_result:{job_id}",
            settings.JOB_TTL_SECONDS,
            json.dumps(job_data)
        )

    except Exception as e:
        logger.error(f"Validation failed for job {job_id}: {e}", exc_info=True)
        # Store the error information
        job_data['status'] = 'failed'
        job_data['completed_at'] = datetime.utcnow().isoformat()
        job_data['error_message'] = str(e)
        await redis.setex(
            f"job_result:{job_id}",
            settings.JOB_TTL_SECONDS,
            json.dumps(job_data)
        )

    return f"Job {job_id} processed."


# ARQ Worker Settings
class WorkerSettings:
    """
    Defines the configuration for the ARQ worker.
    This class is referenced when you run the worker from the command line.
    """
    functions = [run_validation]
    queue_name = settings.VALIDATION_QUEUE_NAME
    redis_settings = settings.get_arq_redis_settings()

    async def on_startup(ctx):
        logger.info(f"ARQ worker starting up, listening on queue '{settings.VALIDATION_QUEUE_NAME}'...")

    async def on_shutdown(ctx):
        logger.info("ARQ worker shutting down.")
