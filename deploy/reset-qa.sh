#!/usr/bin/env bash
# Vacía por completo la base de datos de QA (para empezar de cero con cuentas de prueba creadas desde
# el cliente real). Rechaza ejecutarse contra producción. NUNCA copies datos reales de prod a QA.
set -euo pipefail
[[ "${1:-}" == "--yes" ]] || { echo "esto BORRA todos los datos de QA; repite con --yes" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/etc/apunte/qa.env"
grep -q '^ENV_NAME=qa$' "$ENV_FILE" || { echo "$ENV_FILE no es de QA" >&2; exit 1; }
COMPOSE=(docker compose -p apunte-qa --env-file "$ENV_FILE" -f "$HERE/docker-compose.yml" -f "$HERE/compose.qa.yml")
IMAGE_TAG="$(cat /opt/apunte/state/qa/current)" "${COMPOSE[@]}" stop api
IMAGE_TAG="$(cat /opt/apunte/state/qa/current)" "${COMPOSE[@]}" exec -T postgres psql -U postgres -d apunte -v ON_ERROR_STOP=1 -q \
  -c "TRUNCATE users, rate_limits, audit_log CASCADE"
IMAGE_TAG="$(cat /opt/apunte/state/qa/current)" "${COMPOSE[@]}" start api
echo "QA vacío"
