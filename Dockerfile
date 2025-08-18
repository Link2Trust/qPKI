# qPKI - Quantum-Safe Hybrid PKI
# Docker image for Linux deployment

FROM python:3.11-slim-bookworm

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WEB_PORT=9090 \
    DEBIAN_FRONTEND=noninteractive \
    FLASK_ENV=production \
    FLASK_APP=app.py

# System dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    pkg-config \
    curl \
  && rm -rf /var/lib/apt/lists/*

# Create non-root user and workdir
RUN groupadd -r qpki && useradd -r -g qpki -d /opt/qpki qpki
WORKDIR /opt/qpki

# Dependency layer (better cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Install package (editable)
RUN pip install -e .

# Runtime dirs & permissions
RUN mkdir -p certificates ca crl keys logs config \
 && chown -R qpki:qpki /opt/qpki

# Use non-root
USER qpki

# Python path for src layout (if applicable)
ENV PYTHONPATH=/opt/qpki/src

# Expose web port
EXPOSE 9090

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:9090/ || exit 1

# Run the application
CMD ["python", "app.py"]
