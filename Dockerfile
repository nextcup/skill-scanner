# Multi-stage Dockerfile for Skill Scanner
# Supports production deployment with Gunicorn + Uvicorn workers

# Stage 1: Base image with system dependencies
FROM python:3.12-slim AS base

# Install system dependencies with retry
RUN apt-get update && \
    for i in 1 2 3; do \
        apt-get install -y --no-install-recommends gcc g++ curl && break || sleep 10; \
    done && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Set working directory
WORKDIR /app

# Stage 2: Dependencies installation
FROM base AS dependencies

# Copy dependency definition
COPY pyproject.toml ./

# Install uv package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install dependencies from pyproject.toml (without the package itself)
RUN uv pip install --system \
    fastapi==0.128.0 \
    uvicorn[standard]==0.40.0 \
    python-multipart==0.0.22 \
    pydantic==2.12.5 \
    anthropic==0.76.0 \
    openai==2.15.0 \
    litellm==1.83.0 \
    click==8.3.1 \
    rich==14.2.0 \
    PyYAML==6.0.3 \
    python-frontmatter==1.1.0 \
    yara-x==1.13.0 \
    python-dotenv==1.2.1 \
    httpx==0.28.1 \
    magika==1.0.1 \
    pdfid==1.1.3 \
    oletools==0.60.2 \
    confusable-homoglyphs==3.3.1 \
    --target /app/deps

# Stage 3: Production image
FROM base AS production

# Install gunicorn for production
RUN pip install --no-cache-dir gunicorn==23.0.0

# Create non-root user
RUN useradd -m -u 1000 scanner && \
    mkdir -p /app/.cache && \
    chown -R scanner:scanner /app

# Set working directory
WORKDIR /app

# Copy dependencies from dependencies stage
COPY --from=dependencies --chown=scanner:scanner /app/deps /usr/local/lib/python3.12/site-packages

# Copy project code
COPY --chown=scanner:scanner skill_scanner/ /app/skill_scanner/

# Ensure static directory has correct permissions (static assets copied above)
RUN chown -R scanner:scanner /app/skill_scanner/api/static

# Switch to non-root user
USER scanner

# Set environment variables
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=5).raise_for_status()"

# Gunicorn startup with Uvicorn workers
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "2", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--worker-connections", "1000", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "skill_scanner.api.api:app"]
