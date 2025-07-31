# Metasploit-AI Framework
# Multi-stage Docker build for production deployment

# Stage 1: Base image with dependencies
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    nmap \
    netcat-openbsd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create app user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Stage 2: Development dependencies
FROM base as development

# Install additional development tools
RUN apt-get update && apt-get install -y \
    vim \
    tree \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-dev.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data logs models reports && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8080

# Default command for development
CMD ["python", "app.py", "--mode", "web", "--host", "0.0.0.0", "--port", "8080"]

# Stage 3: Production image
FROM base as production

# Copy requirements
COPY requirements.txt ./

# Install only production dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy application code
COPY --chown=appuser:appuser . .

# Create necessary directories with proper permissions
RUN mkdir -p data logs models reports && \
    chown -R appuser:appuser /app && \
    chmod +x scripts/*.sh

# Remove development files
RUN rm -rf tests/ docs/ .git* *.md requirements-dev.txt

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Production command
CMD ["gunicorn", "--config", "docker/gunicorn.conf.py", "app:app"]

# Stage 4: Testing image
FROM development as testing

# Install additional testing tools
USER root
RUN pip install --no-cache-dir pytest-xdist pytest-cov

USER appuser

# Run tests by default
CMD ["pytest", "tests/", "-v", "--cov=src", "--cov-report=html"]

# Final stage selection
FROM production as final
