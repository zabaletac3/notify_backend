# Operación: purga, copias de seguridad y alertas

Todo lo de esta página se ejecuta en el servidor (Ubuntu con Docker). Los secretos viven solo en `/etc/apunte/*.env` (permisos `0600`, dueño `root`); nunca en el repositorio.

## Roles de PostgreSQL

`deploy/db-roles.sql` crea cinco roles con el mínimo de privilegios:

| Rol | Lo usa | Puede |
|---|---|---|
| `apunte_owner` | `cmd/migrate` | todo el esquema (DDL). Solo durante despliegues |
| `apunte_api` (grupo `apunte_app`) | la API | leer/escribir datos **sujeto a RLS**; sin DDL; sin `DELETE` en `users` |
| `apunte_purge` (grupo `apunte_maint`) | `cmd/purge` | borrar lo caducado en todas las cuentas; no modifica notas ni correos |
| `apunte_backup` | `deploy/backup.sh` | leer todo (`BYPASSRLS` + `pg_read_all_data`); no escribe |

## Purga diaria (`cmd/purge`)

Idempotente; borra, por lotes:

| Qué | Cuándo | Variable |
|---|---|---|
| Notas en la papelera (deja una lápida con `seq` nuevo para que los dispositivos las quiten) | > 30 días | `TRASH_RETENTION_DAYS` |
| Cuentas eliminadas (con todo lo suyo, en cascada) | > 30 días | `ACCOUNT_GRACE_DAYS` |
| Lápidas | > 90 días | — |
| Dispositivos cerrados | > 30 días | — |
| Tokens de renovación caducados o revocados | > 7 días | — |
| Códigos de verificación caducados o usados | > 1 día | — |
| Contadores de límites sin actividad ni bloqueo | > 2 días | — |
| Auditoría | > 365 días | `AUDIT_RETENTION_DAYS` |

Instalación (solo en prod): copia `deploy/apunte-purge.{service,timer}` a `/etc/systemd/system/`, crea `/etc/apunte/prod.purge.env` (`chmod 600`) con `PURGE_DATABASE_URL=postgres://apunte_purge:…@postgres:5432/apunte?sslmode=disable` y, si quieres alertas, `PURGE_PING_URL`; después `systemctl enable --now apunte-purge.timer`. Corre dentro de la red interna de la pila, con la misma imagen de la API. Ver los resultados: `journalctl -u apunte-purge`.

## Copias de seguridad (`deploy/backup.sh`)

`pg_dump` → `restic` (cifrado con una contraseña que no sale del servidor salvo en tu gestor de contraseñas) → bucket de R2/B2 **solo de prod**, con credenciales que QA no conoce. Retención: 7 diarias, 4 semanales, 6 mensuales. Tras cada copia se comprueba el 5 % de los datos del repositorio.

Instalación: `/etc/apunte/backup.env` (`BACKUP_PASSWORD`, variables de restic y `BACKUP_PING_URL`; ver la cabecera del script), copiar `deploy/apunte-backup.{service,timer}` a `/etc/systemd/system/` y `systemctl enable --now apunte-backup.timer`. El volcado se hace dentro del contenedor de PostgreSQL (la base no publica puertos).

**Guarda la contraseña de restic fuera del servidor.** Sin ella, las copias no se pueden abrir (a propósito).

### Restaurar (prueba mensual y desastre)

1. Prueba mensual, en QA (con las variables de restic cargadas): `deploy/restore-test.sh`. Restaura la última copia de prod en una base temporal del PostgreSQL de QA, muestra versión de migraciones y recuentos, y la borra.
2. Desastre: servidor nuevo → `deploy/setup-server.sh` → `restic dump latest apunte.dump > apunte.dump` → crear la base y los roles (`deploy/db-roles.sql`) → `pg_restore --no-owner --dbname=… apunte.dump` → arrancar la API → cambiar la IP en Cloudflare.
3. Lo cifrado extremo a extremo se restaura tal cual: el servidor nunca tuvo las claves, así que una copia robada tampoco las contiene.

## Alertas (gratis)

Las alertas por correo salen de servicios externos, que avisan si algo **deja** de ocurrir:

- **Disponibilidad**: UptimeRobot / Better Stack vigilan `https://api…/ready` (comprueba la base de datos) en prod y QA.
- **Latidos** (healthchecks.io o equivalente): una URL para la copia (`BACKUP_PING_URL`) y otra para la purga (`PURGE_PING_URL`). Si el trabajo no avisa a tiempo, o avisa `/fail`, llega el correo. Así se detecta también que el temporizador dejó de ejecutarse.
- **Registros**: JSON con `traceId`; `docker compose logs api | jq 'select(.level=="ERROR")'`. Nunca contienen contraseñas, claves, textos ni correos completos.

## Qué mirar si algo falla

- `429` masivos: revisar `rate_limits` y que `TRUST_PROXY=true` solo esté activo detrás de Caddy (si no, todos comparten IP).
- `503` en `/ready`: la base de datos no responde (la API falla cerrado).
- La purga no borra: comprobar que el rol es miembro de `apunte_maint` y que corrieron todas las migraciones (`cmd/migrate status`).
