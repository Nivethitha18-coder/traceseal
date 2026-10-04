# TraceSeal Production Dockerfile for Render / Container Deployment
# Python 3.13 slim, single-process FastAPI + Uvicorn serving frontend + API

FROM python:3.13-slim

# System dependencies needed by cryptography / reportlab
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# Ensure start.sh has unix line endings and executable permissions
RUN sed -i 's/\r$//' /app/start.sh || true && chmod +x /app/start.sh

# Render dynamically injects $PORT at runtime (defaults to 8000 locally)
ENV PORT=8000
EXPOSE 8000

CMD ["/app/start.sh"]
