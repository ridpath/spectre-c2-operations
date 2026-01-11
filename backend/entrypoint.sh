#!/bin/bash
set -e

echo "Waiting for PostgreSQL to be ready..."
while ! pg_isready -h postgres -p 5432 -U ${POSTGRES_USER} > /dev/null 2>&1; do
  sleep 1
done
echo "PostgreSQL is ready!"

echo "Running database migrations..."
alembic upgrade head

echo "Creating storage directories..."
mkdir -p /app/storage/iq_recordings
mkdir -p /app/storage/evidence
mkdir -p /app/storage/reports
mkdir -p /app/backups

echo "Starting Spectre C2 Backend..."
exec "$@"
