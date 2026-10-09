#!/usr/bin/env bash
# Despliega una imagen en un ambiente: descarga → respalda → migra → arranca → espera a que esté sana.
# Si la API no queda sana, vuelve sola a la versión anterior.
#
#   deploy/release.sh qa|prod <etiqueta-de-imagen>      p. ej.  deploy/release.sh prod v1.2.0
set -euo pipefail
ENV_NAME="${1:?uso: release.sh qa|prod <etiqueta>}"
TAG="${2:?falta la etiqueta de la imagen}"
[[ "$ENV_NAME" == "qa" || "$ENV_NAME" == "prod" ]] || { echo "ambiente desconocido: $ENV_NAME" >&2; exit 2; }
[[ "$TAG" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || { echo "etiqueta no válida" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="/opt/apunte/state/${ENV_NAME}"
ENV_FILE="/etc/apunte/${ENV_NAME}.env"
mkdir -p "$STATE"
compose() { IMAGE_TAG="$1" docker compose -p "apunte-${ENV_NAME}" --env-file "$ENV_FILE" -f "$HERE/docker-compose.yml" -f "$HERE/compose.${ENV_NAME}.yml" "${@:2}"; }

PREVIOUS="$(cat "$STATE/current" 2>/dev/null || true)"
echo ">> $ENV_NAME: ${PREVIOUS:-(primera vez)} → $TAG"

docker network inspect apunte_edge >/dev/null 2>&1 || docker network create apunte_edge >/dev/null
compose "$TAG" pull api migrate
compose "$TAG" up -d postgres

# Respaldo previo a migrar: un rollback de la API NO deshace migraciones, este volcado sí permite volver
# al estado anterior. Si no se puede respaldar (o el volcado no se lee), no se migra ni se despliega.
# Se conservan los 10 últimos. Los respaldos programados cada 6 h son aparte (apunte-db-backup.timer).
PG="apunte-${ENV_NAME}-postgres-1"
BACKUPS="/opt/apunte/backups/${ENV_NAME}/pre-migrate"
for _ in $(seq 1 30); do
  [[ "$(docker inspect --format '{{.State.Health.Status}}' "$PG" 2>/dev/null || echo starting)" == "healthy" ]] && break
  sleep 2
done
[[ "$(docker inspect --format '{{.State.Health.Status}}' "$PG" 2>/dev/null || echo starting)" == "healthy" ]] \
  || { echo "!! postgres no está sano: no se migra sin respaldo" >&2; exit 1; }
mkdir -p "$BACKUPS"; chmod 700 "$BACKUPS"
DUMP="$BACKUPS/pre-${TAG}-$(date -u +%Y%m%d-%H%M%S).dump"
trap 'rm -f "$DUMP.tmp"' EXIT
( umask 077
  PGPASSWORD="$(grep -m1 '^POSTGRES_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)" \
    docker exec -e PGPASSWORD "$PG" pg_dump -h 127.0.0.1 -U postgres -d apunte -Fc > "$DUMP.tmp" )
docker exec -i "$PG" pg_restore -l < "$DUMP.tmp" >/dev/null \
  || { echo "!! el respaldo no es legible: no se migra" >&2; exit 1; }
mv "$DUMP.tmp" "$DUMP"
find "$BACKUPS" -maxdepth 1 -name 'pre-*.dump' -printf '%T@ %p\n' | sort -rn | tail -n +11 | cut -d' ' -f2- | xargs -r rm -f
echo ">> respaldo previo a migrar: $DUMP ($(du -h "$DUMP" | cut -f1))"

compose "$TAG" run --rm migrate          # migraciones compatibles hacia atrás: la versión anterior sigue funcionando
compose "$TAG" up -d --no-deps api

for i in $(seq 1 30); do
  status="$(docker inspect --format '{{.State.Health.Status}}' "apunte-${ENV_NAME}-api-1" 2>/dev/null || echo starting)"
  [[ "$status" == "healthy" ]] && break
  sleep 3
done
if [[ "${status:-}" != "healthy" ]]; then
  echo "!! la API no quedó sana ($status)" >&2
  compose "$TAG" logs --tail 50 api >&2 || true
  if [[ -n "$PREVIOUS" ]]; then
    echo "!! volviendo a $PREVIOUS" >&2
    compose "$PREVIOUS" up -d --no-deps api
  fi
  exit 1
fi

[[ -n "$PREVIOUS" && "$PREVIOUS" != "$TAG" ]] && echo "$PREVIOUS" > "$STATE/previous"
echo "$TAG" > "$STATE/current"
docker image prune -f >/dev/null
echo ">> $ENV_NAME desplegado: $TAG"
