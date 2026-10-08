#!/usr/bin/env bash
# Prueba de restauración (hazla una vez al mes, idealmente en el servidor de QA): restaura la última
# copia en una base de datos nueva y comprueba que tiene datos coherentes. Una copia que nunca se
# restauró no es una copia.
#
#   RESTORE_ADMIN_URL   URL de un administrador de PostgreSQL de pruebas (NO la de producción)
#   (más las variables de restic de backup.sh)
set -euo pipefail

: "${RESTORE_ADMIN_URL:?falta RESTORE_ADMIN_URL}"
: "${RESTIC_REPOSITORY:?falta RESTIC_REPOSITORY}"
: "${RESTIC_PASSWORD_FILE:?falta RESTIC_PASSWORD_FILE}"
umask 077

DB="apunte_restore_$(date -u +%Y%m%d%H%M%S)"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; psql "$RESTORE_ADMIN_URL" -qc "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" || true; }
trap cleanup EXIT

restic dump latest apunte.dump --tag apunte > "$WORK/apunte.dump"
psql "$RESTORE_ADMIN_URL" -qc "CREATE DATABASE \"$DB\""
BASE="${RESTORE_ADMIN_URL%/*}"
pg_restore --no-owner --dbname="$BASE/$DB" "$WORK/apunte.dump"

psql "$BASE/$DB" -tA <<'SQL'
SELECT 'migraciones', max(version_id) FROM goose_db_version;
SELECT 'cuentas', count(*) FROM users;
SELECT 'notas', count(*) FROM notes;
SELECT 'carpetas', count(*) FROM folders;
SELECT 'enlaces', count(*) FROM share_links;
SQL
echo "restauración correcta"
