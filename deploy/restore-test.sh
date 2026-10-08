#!/usr/bin/env bash
# Prueba de restauración (hazla una vez al mes, en el PostgreSQL de QA): restaura la última copia de prod en una
# base temporal, comprueba que tiene datos coherentes y la borra. Una copia que nunca se restauró no es una copia.
# (Los datos de prod son texto cifrado de extremo a extremo; aun así, no los dejes en QA: el script los borra.)
#
#   QA_PG_CONTAINER       contenedor de PostgreSQL de QA (por defecto apunte-qa-postgres-1)
#   (más las variables de restic de backup.sh)
set -euo pipefail

: "${RESTIC_REPOSITORY:?falta RESTIC_REPOSITORY}"
: "${RESTIC_PASSWORD_FILE:?falta RESTIC_PASSWORD_FILE}"
umask 077

C="${QA_PG_CONTAINER:-apunte-qa-postgres-1}"
DB="apunte_restore_$(date -u +%Y%m%d%H%M%S)"
psql_q() { docker exec -i "$C" psql -U postgres -v ON_ERROR_STOP=1 -q "$@"; }
cleanup() { psql_q -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" || true; }
trap cleanup EXIT

psql_q -c "CREATE DATABASE \"$DB\""
restic dump latest apunte.dump --tag apunte | docker exec -i "$C" pg_restore --no-owner --username=postgres --dbname="$DB"

docker exec -i "$C" psql -U postgres -d "$DB" -tA <<'SQL'
SELECT 'migraciones', max(version_id) FROM goose_db_version;
SELECT 'cuentas', count(*) FROM users;
SELECT 'notas', count(*) FROM notes;
SELECT 'carpetas', count(*) FROM folders;
SELECT 'enlaces', count(*) FROM share_links;
SQL
echo "restauración correcta"
