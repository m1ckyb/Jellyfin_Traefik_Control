#!/bin/sh

# Get IDs from environment or use defaults
USER_ID=${PUID:-1000}
GROUP_ID=${PGID:-1000}

# Set timezone if TZ is set
if [ -n "$TZ" ] && [ -f "/usr/share/zoneinfo/$TZ" ]; then
    ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime
    echo "$TZ" > /etc/timezone
fi

# Safely update the group ID if it doesn't match
if [ "$(getent group appgroup | cut -d: -f3)" != "$GROUP_ID" ]; then
    groupmod -o -g "$GROUP_ID" appgroup
fi

# Safely update the user ID if it doesn't match
if [ "$(id -u appuser)" != "$USER_ID" ]; then
    usermod -o -u "$USER_ID" appuser
fi

# Ensure data directory exists
mkdir -p /app/data

# Apply ownership
chown -R appuser:appgroup /app > /dev/null 2>&1
chown -R appuser:appgroup /app/data > /dev/null 2>&1

# Fix permissions: data dir readable/writable by owner only
chmod 700 /app/data > /dev/null 2>&1

# Lock down secret key file if it exists
if [ -f /app/data/.secret_key ]; then
    chmod 600 /app/data/.secret_key > /dev/null 2>&1
fi

# Lock down database file if it exists
if [ -f /app/data/config.db ]; then
    chmod 600 /app/data/config.db > /dev/null 2>&1
fi

# Run the application
echo "[$(date '+%Y-%m-%d %H:%M:%S %z')] 👻 RouteGhost: Starting application..."
exec su-exec appuser:appgroup gunicorn --bind 0.0.0.0:5001 main:app
