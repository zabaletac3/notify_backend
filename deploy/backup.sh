#!/usr/bin/env bash
# Copia de seguridad cifrada de PostgreSQL con restic (D7/§10 del plan 0006).
#
#   pg_dump (formato custom) → restic (cifrado de extremo a extremo con RESTIC_PASSWORD_FILE) → R2/B2
#
# Variables (en /etc/apunte/backup.env, permisos 0600):
#   BACKUP_DATABASE_URL   rol `apunte_backup` (LOGIN BYPASSRLS + pg_read_all_data; ver db-roles.sql).
#                         pg_dump con otro rol dejaría fuera las filas protegidas por RLS.
#   RESTIC_REPOSITORY     p. ej. s3:https://<cuenta>.r2.cloudflarestorage.com/apunte-backups
#   RESTIC_PASSWORD_FILE  archivo con la contraseña del repositorio (guárdala también fuera del servidor)
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   credenciales del bucket (distintas en QA y prod)
#   BACKUP_PING_URL       (opcional) latido tipo healthchecks.io: si no avisa a tiempo, llega un correo
#
# Retención: 7 diarias, 4 semanales, 6 mensuales. Meilisearch no existe: no hay índices que respaldar.
set -euo pipefail

: "${BACKUP_DATABASE_URL:?falta BACKUP_DATABASE_URL}"
: "${RESTIC_REPOSITORY:?falta RESTIC_REPOSITORY}"
: "${RESTIC_PASSWORD_FILE:?falta RESTIC_PASSWORD_FILE}"
umask 077

ping() { [ -n "${BACKUP_PING_URL:-}" ] && curl -fsS -m 10 --retry 3 "${BACKUP_PING_URL}${1:-}" >/dev/null || true; }
trap 'ping /fail' ERR

ping /start
restic cat config >/dev/null 2>&1 || restic init

# El volcado va por una tubería: nunca toca el disco sin cifrar.
pg_dump --format=custom --no-owner --dbname="$BACKUP_DATABASE_URL" \
  | restic backup --stdin --stdin-filename apunte.dump --tag apunte --tag "$(date -u +%Y-%m-%d)"

restic forget --tag apunte --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
restic check --read-data-subset=5%

ping
echo "copia de seguridad terminada: $(date -u +%FT%TZ)"
