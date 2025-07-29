FROM ubuntu:22.04

# System packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser

# Create instance directory for database and set permissions
RUN mkdir -p /app/instance && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]
