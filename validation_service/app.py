from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime
import redis
import json
import uuid

from .config import settings
from .validators import VALIDATORS

app = FastAPI(title="Secret Validation Service", version="1.0.0")

redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

class ValidationRequest(BaseModel):
    secret_type: str
    secret_value: str
    metadata: Optional[Dict] = {}

class ValidationResponse(BaseModel):
    job_id: str
    status: str
    message: Optional[str] = None

class StatusResponse(BaseModel):
    job_id: str
    status: str
    result: Optional[Dict] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    message: Optional[str] = None

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@app.post("/api/v1/validate", response_model=ValidationResponse, status_code=202)
async def submit_validation(request: ValidationRequest, api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)
    if request.secret_type not in VALIDATORS:
        raise HTTPException(status_code=400, detail=f"Unknown secret type: {request.secret_type}")

    job_id = str(uuid.uuid4())
    job_data = {
        "job_id": job_id,
        "secret_type": request.secret_type,
        "secret_value": request.secret_value,
        "metadata": request.metadata,
        "created_at": datetime.utcnow().isoformat(),
        "status": "pending",
    }
    redis_client.setex(f"job:{job_id}", settings.JOB_TTL, json.dumps(job_data))
    redis_client.lpush("validation_queue", job_id)

    return ValidationResponse(job_id=job_id, status="pending", message="Validation job submitted")

@app.get("/api/v1/validate/status/{job_id}", response_model=StatusResponse)
async def get_validation_status(job_id: str, api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)
    job_json = redis_client.get(f"job:{job_id}")
    if not job_json:
        raise HTTPException(status_code=404, detail="Job not found")
    job_data = json.loads(job_json)
    return StatusResponse(
        job_id=job_id,
        status=job_data.get("status"),
        result=job_data.get("result"),
        created_at=job_data.get("created_at"),
        completed_at=job_data.get("completed_at"),
        message=job_data.get("message"),
    )

@app.get("/api/v1/health")
async def health_check():
    try:
        redis_client.ping()
        status = "healthy"
    except Exception as e:
        status = f"unhealthy: {str(e)}"
    return {"status": status, "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/v1/validators")
async def list_validators(api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)
    return {"validators": list(VALIDATORS.keys()), "count": len(VALIDATORS)}
