# qPKI - Quantum-Safe Hybrid PKI
# Docker image for Linux deployment

FROM python:3.11-slim-bookworm

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV WEB_PORT=9090
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create qpki user and group
RUN groupadd -r qpki && useradd -r -g qpki -d /opt/qpki qpki

# Set working directory
WORKDIR /opt/qpki

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install qPKI package
RUN pip install -e .

# Create necessary directories and set permissions
RUN mkdir -p certificates ca crl keys logs && \
    chown -R qpki:qpki /opt/qpki

# Switch to qpki user
USER qpki

# Expose port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/ || exit 1

# Start the application
CMD ["python", "app.py"]
