#!/usr/bin/env bash
# Vuelve a la versión anterior de un ambiente (un solo comando). No deshace migraciones: por eso deben
# ser siempre compatibles hacia atrás (primero se añade lo nuevo; lo viejo se borra en una versión posterior).
#
#   deploy/rollback.sh qa|prod
set -euo pipefail
ENV_NAME="${1:?uso: rollback.sh qa|prod}"
[[ "$ENV_NAME" == "qa" || "$ENV_NAME" == "prod" ]] || { echo "ambiente desconocido: $ENV_NAME" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREV="$(cat "/opt/apunte/state/${ENV_NAME}/previous" 2>/dev/null || true)"
[[ -n "$PREV" ]] || { echo "no hay versión anterior registrada" >&2; exit 1; }
exec "$HERE/release.sh" "$ENV_NAME" "$PREV"
