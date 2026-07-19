# Use a lightweight Python base image
FROM python:alpine

# Set environment variables to prevent python from writing pyc files
# and to flush stdout/stderr immediately
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Build arguments for user and group IDs (default to 1000)
ARG PUID=1000
ARG PGID=1000

# Create a non-root group and user with specific IDs
RUN apk add --no-cache su-exec shadow tzdata wireguard-tools openresolv iproute2 openssh-client && \
    addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application files
COPY --chown=appuser:appgroup main.py .
COPY --chown=appuser:appgroup database.py .
COPY --chown=appuser:appgroup routing.py .
COPY --chown=appuser:appgroup mqtt_handler.py .
COPY --chown=appuser:appgroup VERSION.txt .
COPY --chown=appuser:appgroup templates templates/
COPY --chown=appuser:appgroup static static/
COPY entrypoint.sh .

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Create volume mount point for persistent database
VOLUME /app/data

# Use entrypoint script to fix permissions and start the app
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:5001/ || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
