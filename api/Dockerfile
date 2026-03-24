# ============================================================
# FastAPI Policy Engine - Dockerfile
# ============================================================
# Builds a lightweight Python container that runs our API.
# Uses python:3.13-slim to keep the image small.
# ============================================================

FROM python:3.13-slim

# Install curl so the Docker healthcheck can hit our /health endpoint
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy and install dependencies first (this layer gets cached by Docker,
# so we only re-install when requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Run the FastAPI app with live-reload enabled for development
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
