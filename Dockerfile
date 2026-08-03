# ──────────────────────────────────────────────
#  SecScan — Dockerfile
#  Multi-stage-free, slim Python image.
#  Serves the frontend + API on port 5000.
# ──────────────────────────────────────────────

# Use a slim Python 3.11 image for a small footprint
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies needed for SSL socket probing
# (ca-certificates ensures Python's ssl module trusts real certs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY secscan/   ./secscan/
COPY frontend/  ./frontend/
COPY server.py  .
COPY main.py    .
COPY scanner.py .

# Expose the Flask server port
EXPOSE 5000

# Run as non-root user for security
RUN adduser --disabled-password --gecos "" secscan
USER secscan

# Start the Flask server, binding to all interfaces inside the container
CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "5000"]
