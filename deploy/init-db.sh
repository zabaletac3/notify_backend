#!/usr/bin/env bash
# Crea (o rota las contraseñas de) los roles de PostgreSQL de un ambiente. Una vez por ambiente, tras el
# primer `docker compose up -d postgres`, y de nuevo para rotar contraseñas.
#
#   deploy/init-db.sh qa|prod
set -euo pipefail
ENV_NAME="${1:?uso: init-db.sh qa|prod}"
[[ "$ENV_NAME" == "qa" || "$ENV_NAME" == "prod" ]] || { echo "ambiente desconocido: $ENV_NAME" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/etc/apunte/${ENV_NAME}.env"
set -a; . "$ENV_FILE"; set +a
for v in OWNER_PASSWORD API_PASSWORD PURGE_PASSWORD BACKUP_PASSWORD; do : "${!v:?falta $v en $ENV_FILE}"; done

COMPOSE=(docker compose -p "apunte-${ENV_NAME}" --env-file "$ENV_FILE" -f "$HERE/docker-compose.yml" -f "$HERE/compose.${ENV_NAME}.yml")
# Las contraseñas viajan por la entrada estándar de psql como variables; no aparecen en la lista de procesos.
{
  printf '\\set owner_pw  %s\n' "$(printf '%s' "$OWNER_PASSWORD"  | sed "s/'/''/g; s/^/'/; s/\$/'/")"
  printf '\\set api_pw    %s\n' "$(printf '%s' "$API_PASSWORD"    | sed "s/'/''/g; s/^/'/; s/\$/'/")"
  printf '\\set purge_pw  %s\n' "$(printf '%s' "$PURGE_PASSWORD"  | sed "s/'/''/g; s/^/'/; s/\$/'/")"
  printf '\\set backup_pw %s\n' "$(printf '%s' "$BACKUP_PASSWORD" | sed "s/'/''/g; s/^/'/; s/\$/'/")"
  printf '\\set dbname apunte\n'
  cat "$HERE/db-roles.sql"
} | "${COMPOSE[@]}" exec -T postgres psql -U postgres -d apunte -v ON_ERROR_STOP=1 -q
echo "roles de $ENV_NAME listos"
