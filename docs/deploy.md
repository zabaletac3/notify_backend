# Despliegue: un servidor, dos ambientes (QA y producción)

```
                 Cloudflare (DNS, HTTPS «Full (strict)», anti-DDoS, WAF)
        ┌────────────────────────────┴─────────────────────────────┐
  app.tudominio.com (Pages, main)                       qa.tudominio.com (Pages, develop)
  api.tudominio.com                                     api-qa.tudominio.com  ← protegido con Cloudflare Access
        │                                                           │
        └──────────────────────────┬────────────────────────────────┘
                       VPS Ubuntu (ufw: 22 y 80/443 solo desde Cloudflare)
                       ┌───────────┴────────────┐
                       │ Caddy :80/:443 (único  │  red `apunte_edge`
                       │ con puertos publicados)│
                       └───┬────────────────┬───┘
              apunte-prod  │                │  apunte-qa            (proyectos de Docker Compose separados)
        ┌──────────────────┴──┐        ┌────┴─────────────────┐
        │ api  → postgres      │        │ api  → postgres      │    red `internal` por pila: sin salida a
        │ (volumen propio)     │        │ (volumen propio)     │    internet y sin puertos publicados
        └──────────────────────┘        └──────────────────────┘
```

QA y producción comparten servidor pero **no** comparten red de base de datos, volúmenes, contraseñas ni secretos. Cuando haya usuarios reales, QA se mueve a su propio VPS sin cambiar nada más que el servidor de destino de los secretos de GitHub.

## Qué protege cada capa

| Capa | Control |
|---|---|
| Cloudflare | HTTPS, anti-DDoS, WAF. QA detrás de **Cloudflare Access** (solo tú y tus testers). Regla de limitación sugerida: `POST /v1/auth/*` a 20 peticiones/min por IP |
| Servidor | `ufw`: SSH (con límite) y 80/443 **solo desde rangos de Cloudflare**; regla `DOCKER-USER` equivalente (Docker se salta ufw); SSH solo con llave, sin root, `fail2ban`, actualizaciones automáticas |
| Caddy | Único con puertos publicados; confía en Cloudflare para la IP real y entrega a la API **una sola IP** en `X-Forwarded-For`; límite de cuerpo (9 MB), tiempos máximos, cabeceras de seguridad, registros sin cabeceras |
| Contenedores | `read_only`, `cap_drop: ALL`, `no-new-privileges`, sin `ports:`, límites de memoria y procesos, imagen sin shell ni root |
| Base de datos | Sin puertos; red interna sin salida; `scram-sha-256`; roles con el mínimo de privilegios (`docs/operations.md`); RLS |
| Secretos | En `/etc/apunte/*.env` (`0600`, root). **La API solo ve `<amb>.api.env`**: nunca las credenciales del dueño del esquema ni del superusuario. GitHub solo guarda la llave SSH de despliegue |

## Primera vez (por servidor)

1. **DNS en Cloudflare**: registros `A` (proxy naranja) para `api` y `api-qa` hacia la IP del VPS; SSL/TLS en **Full (strict)**; Cloudflare Access sobre `api-qa` y `qa`.
2. **Servidor**: `sudo DEPLOY_USER=deploy DEPLOY_PUBKEY="ssh-ed25519 …" ./deploy/setup-server.sh`. Antes de cerrar la sesión, comprueba en otra terminal que entras con `deploy` y tu llave.
3. **Secretos**: copia `deploy/env.<amb>.example` → `/etc/apunte/<amb>.env`, `deploy/env.<amb>.api.example` → `/etc/apunte/<amb>.api.env` y `deploy/caddy.env.example` → `/etc/apunte/caddy.env`; rellénalos con `openssl rand -base64 48` (distintos entre ambientes) y `chmod 600`.
4. **Caddy**: `cd deploy/caddy && docker network create apunte_edge && docker compose up -d`.
5. **Base de datos de cada ambiente**: `docker compose -p apunte-<amb> --env-file /etc/apunte/<amb>.env -f deploy/docker-compose.yml -f deploy/compose.<amb>.yml up -d postgres` y después `deploy/init-db.sh <amb>` (crea los roles; repetirlo rota las contraseñas).
6. **Primer despliegue**: `deploy/release.sh <amb> <etiqueta>` (descarga la imagen, migra, arranca y espera a que esté sana).
7. **GitHub** (Settings → Secrets and variables → Actions): `SSH_HOST`, `SSH_USER`, `SSH_KEY` (llave ed25519 **solo** para desplegar), `SSH_KNOWN_HOSTS` (`ssh-keyscan -t ed25519 host`). Settings → Environments: `qa` (sin aprobación) y `production` (**con aprobación manual obligatoria**). Protege `main` y `develop` (PR + CI en verde).
8. **Alertas**: `/ready` en UptimeRobot/Better Stack y latidos de copia y purga (`docs/operations.md`).

## Flujo de trabajo

```
feature/x ──PR──► develop ──push──► CI → imagen sha-<commit> → despliegue automático en QA
                     │
                     └──PR──► main ──etiqueta v1.2.0──► CI → imagen → [aprobación] → despliegue en producción
```

- Cada despliegue **migra primero** y arranca la API después; si la API no queda sana en 90 s, `release.sh` vuelve solo a la versión anterior.
- **Reversión**: `ssh deploy@servidor /opt/apunte/deploy/rollback.sh prod`. No deshace migraciones, por eso deben ser **compatibles hacia atrás**: primero se añade lo nuevo (columnas nulas, tablas); en una versión posterior se borra lo viejo.
- La imagen de producción es la de QA si el commit etiquetado ya tiene imagen; con *squash merge* el commit de `main` es nuevo y se construye una vez (mismo `Dockerfile`, mismas pruebas).
- **QA nunca recibe datos reales**: se llena con cuentas de prueba creadas desde el cliente (los datos van cifrados; el servidor no puede fabricar notas). Para empezar de cero: `deploy/reset-qa.sh --yes`.

## Mudar de servidor (menos de una hora)

`setup-server.sh` → copiar `/etc/apunte` → Caddy → `init-db.sh` → restaurar la copia (`docs/operations.md`) → `release.sh` → cambiar la IP en Cloudflare.
