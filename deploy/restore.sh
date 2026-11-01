#!/bin/sh
# Restore a backup into an EMPTY database (never over live data). Run with the stack stopped
# except postgres:
#   deploy/restore.sh /secure/backups/sentinelops-YYYYmmddTHHMMSSZ.dump
# Then recreate the app login role grants if needed (docs/operations/RUNBOOK.md) and start the
# services. Refuses if the target database already contains tables.
set -eu
DUMP="${1:?usage: restore.sh DUMP_FILE}"
COMPOSE="docker compose -f $(dirname "$0")/compose.prod.yaml --env-file $(dirname "$0")/.env.production"
TABLES="$($COMPOSE exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT count(*) FROM pg_tables WHERE schemaname = '"'"'public'"'"'"')"
if [ "$TABLES" != "0" ]; then
    echo "refusing: target database is not empty ($TABLES tables)" >&2
    exit 1
fi
$COMPOSE exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --exit-on-error' < "$DUMP"
echo "restore complete"
