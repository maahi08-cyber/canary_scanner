# Dockerfile (Phase 4 Multi-stage)

# --- Base ---
FROM python:3.11-slim AS base
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONIOENCODING=utf-8
# Install minimal common dependencies if needed across stages
# RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# --- Builder ---
FROM base AS builder
# Install build tools if needed (e.g., gcc for C extensions)
# RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
# Install ALL dependencies (Scanner, Dashboard, Validator) into user space
COPY requirements.txt .
COPY dashboard/requirements.txt ./dashboard-requirements.txt
COPY validation_service/requirements.txt ./validation-requirements.txt
RUN pip install --no-cache-dir --user --upgrade pip \
    && pip install --no-cache-dir --user -r requirements.txt \
    && pip install --no-cache-dir --user -r dashboard-requirements.txt \
    && pip install --no-cache-dir --user -r validation-requirements.txt

# --- Scanner Runtime ---
FROM base AS scanner_runtime
ARG APP_USER=canary
ARG APP_GROUP=canary
RUN groupadd -r ${APP_GROUP} && useradd --no-log-init -r -g ${APP_GROUP} ${APP_USER}
WORKDIR /app
COPY --from=builder /root/.local /home/${APP_USER}/.local
# Copy only necessary scanner code and config
COPY --chown=${APP_USER}:${APP_GROUP} scanner/ ./scanner/
COPY --chown=${APP_USER}:${APP_GROUP} canary.py .
COPY --chown=${APP_USER}:${APP_GROUP} patterns.yml .
COPY --chown=${APP_USER}:${APP_GROUP} config/ ./config/ # For context_rules.yml
USER ${APP_USER}
ENV PATH=/home/${APP_USER}/.local/bin:$PATH
ENTRYPOINT ["python", "canary.py"]
CMD ["--help"]

# --- Dashboard Runtime ---
FROM base AS dashboard_runtime
ARG APP_USER=canary
ARG APP_GROUP=canary
RUN groupadd -r ${APP_GROUP} && useradd --no-log-init -r -g ${APP_GROUP} ${APP_USER}
WORKDIR /app
COPY --from=builder /root/.local /home/${APP_USER}/.local
# Copy dashboard code, needed scanner parts, and config
COPY --chown=${APP_USER}:${APP_GROUP} dashboard/ ./
COPY --chown=${APP_USER}:${APP_GROUP} scanner/ ./scanner/ # For realtime scanning
COPY --chown=${APP_USER}:${APP_GROUP} patterns.yml . # For realtime scanning
COPY --chown=${APP_USER}:${APP_GROUP} config/ ./config/
USER ${APP_USER}
ENV PATH=/home/${APP_USER}/.local/bin:$PATH
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"] # Use workers

# --- Validation Service Runtime ---
FROM base AS validation_runtime
ARG APP_USER=canary
ARG APP_GROUP=canary
RUN groupadd -r ${APP_GROUP} && useradd --no-log-init -r -g ${APP_GROUP} ${APP_USER}
WORKDIR /app
COPY --from=builder /root/.local /home/${APP_USER}/.local
# Copy validation service code and config
COPY --chown=${APP_USER}:${APP_GROUP} validation_service/ ./
COPY --chown=${APP_USER}:${APP_GROUP} config/ ./config/ # For validation_policies.yml
USER ${APP_USER}
ENV PATH=/home/${APP_USER}/.local/bin:$PATH
EXPOSE 8001
# Add healthcheck from validation_service/app.py if implemented there
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost:8001/api/v1/health || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"] # Fewer workers usually ok

# --- Default stage (can set to scanner_runtime if desired) ---
FROM scanner_runtime AS default
