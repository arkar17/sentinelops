#!/bin/sh
# Logical backup of the production database (custom format, compressed). Run on the host:
#   deploy/backup.sh /secure/backups
# Store backups encrypted and off-host; they contain organization data and ciphertext (the
# SENTINELOPS_SECRET_KEYS / MFA keys are NOT in the dump and must be backed up separately).
set -eu
DEST="${1:?usage: backup.sh DEST_DIR}"
COMPOSE="docker compose -f $(dirname "$0")/compose.prod.yaml --env-file $(dirname "$0")/.env.production"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
umask 077
$COMPOSE exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner' \
    > "$DEST/sentinelops-$STAMP.dump"
$COMPOSE exec -T postgres sh -c 'pg_restore --list /dev/stdin >/dev/null' < "$DEST/sentinelops-$STAMP.dump"
echo "backup written: $DEST/sentinelops-$STAMP.dump"
