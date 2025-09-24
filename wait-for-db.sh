#!/usr/bin/env sh
set -e
HOST="${1:-db}"
PORT="${2:-5432}"
echo "🔎 Waiting for DB at ${HOST}:${PORT} ..."
until nc -z "$HOST" "$PORT"; do
  sleep 1
done
echo "✅ DB is up."
exec "$@"