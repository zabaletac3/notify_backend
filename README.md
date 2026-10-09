# notify_backend

API de AxoNote (Go + PostgreSQL). Ver `CLAUDE.md` y el plan 0006 en `notify_web`.

```bash
cp .env.example .env      # edita los secretos
make up                   # Postgres local (Docker); con Podman: make up-podman
set -a; . ./.env; set +a
make run                  # http://localhost:8080/health
```

Base de datos: `make up && make migrate` (ver `deploy/db-roles.sql` para los roles reales). Pruebas con Postgres: `make test-db`.

Correo: `MAIL_PROVIDER=log` (dev/QA, escribe en el log) o `resend` (prod). Para añadir otro proveedor, implementa `mailer.Mailer` en `internal/platform/mailer` y regístralo en `factory.go`.
