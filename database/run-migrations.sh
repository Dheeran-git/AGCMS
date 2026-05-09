#!/bin/bash
# Runs every migration in /docker-entrypoint-initdb.d/migrations in filename order.
# Postgres' entrypoint executes *.sh and *.sql files in /docker-entrypoint-initdb.d/
# alphabetically; this script is named 99- so it runs after 00-init.sql.
set -euo pipefail

MIGRATIONS_DIR="/docker-entrypoint-initdb.d/migrations"

if [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "No migrations dir at $MIGRATIONS_DIR — skipping."
  exit 0
fi

for f in "$MIGRATIONS_DIR"/*.sql; do
  [ -f "$f" ] || continue
  echo ">>> applying migration: $(basename "$f")"
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$f"
done

echo ">>> all migrations applied"
