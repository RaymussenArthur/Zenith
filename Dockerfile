# Z.E.N.I.T.H. Middleware — Production Dockerfile
#
# ARCHITECTURAL DECISIONS:
#
# 1. MULTI-BUILD:
#    1 (builder): installs all dependencies including build tools (gcc,
#    Cython headers for numpy/networkx native extensions). This produces
#    compiled wheels in /wheels.
#    2 (runtime): copies ONLY the compiled wheels and application code.
#    No build toolchain in the final image → smaller attack surface, smaller
#    image (~400MB vs ~1.2GB for a naive pip install approach).
#
# 2. DISTROLESS-INSPIRED BASE:
#    python:3.11-slim-bookworm is chosen over python:3.11-alpine because:
#    - Alpine uses musl libc, which causes subtle incompatibilities with scipy/numpy
#      compiled wheels (BLAS/LAPACK linkage issues)
#    - Bookworm (Debian 12) has glibc 2.36, compatible with all PyPI binary wheels
#    - slim variant excludes docs, locales, and package manager cache (~200MB savings)
#
# 3. NON-ROOT USER:
#    The container runs as UID 1000 (non-root). This prevents privilege escalation
#    if a remote code execution vulnerability is found in the FastAPI application.
#    Required for SOC 2 Type II compliance and many enterprise Kubernetes PSPs.
#
# 4. GUNICORN + UVICORN WORKERS:
#    Single uvicorn is used in development. In production k8s deployment, replace
#    CMD with gunicorn -w 4 -k uvicorn.workers.UvicornWorker zenith_middleware:app
#    for multi-process parallelism (4 workers = 4 CPUs fully utilized).
#
# 5. HEALTHCHECK:
#    Docker HEALTHCHECK enables the orchestrator (ECS/Kubernetes) to detect
#    unhealthy containers and restart them without manual intervention. Critical
#    for production uptime SLAs (99.9% for B2B2G environments).
#
# BUILD:
#   docker build -t zenith-middleware:2.0.0 .
#
# RUN (development):
#   docker run -p 8000:8000 \
#     -e ORACLE_PRIVATE_KEY=0x... \
#     -e ZENITH_ESCROW_ADDRESS=0x... \
#     -e WEB3_RPC_URL=https://polygonzkevm-cardona.g.alchemy.com \
#     zenith-middleware:2.0.0
#
# RUN (production — with secret injection):
#   docker run -p 8000:8000 \
#     --env-file .env.production \
#     --read-only \
#     --tmpfs /tmp \
#     zenith-middleware:2.0.0

# 1: Builder — compile wheels for all dependencies
FROM python:3.11-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip setuptools wheel

WORKDIR /wheels

COPY requirements.txt .

RUN pip wheel \
    --no-cache-dir \
    --no-build-isolation \
    --wheel-dir /wheels \
    -r requirements.txt

# 2: Runtime — minimal image with only what's needed to run the app
FROM python:3.11-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libffi8 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /root/.cache

RUN groupadd --gid 1000 zenith \
    && useradd --uid 1000 --gid zenith --shell /bin/false --no-create-home zenith

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl \
    && rm -rf /wheels  # Remove wheel cache after install to reduce image size

WORKDIR /app

COPY zenith_middleware.py .

RUN python -m compileall -b . \
    && find . -name "*.py" -not -name "zenith_middleware.py" -delete 2>/dev/null || true

RUN chown -R zenith:zenith /app
USER zenith

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    WEB3_RPC_URL=https://polygonzkevm-cardona.g.alchemy.com/v2/OTte4QHFtSMXqLUweCjSe \
    CHAIN_ID="2447" \
    ZENITH_ESCROW_ADDRESS="0x0000000000000000000000000000000000000000" \
    ALLOWED_ORIGINS="*"

EXPOSE 8000

HEALTHCHECK --interval=30s \
            --timeout=10s \
            --start-period=30s \
            --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", \
     "zenith_middleware:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--loop", "uvloop", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
