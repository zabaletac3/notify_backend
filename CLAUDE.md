# Apunte API — guía para asistentes

Backend en Go + PostgreSQL de Apunte (notas con cifrado de extremo a extremo). Plan completo: `docs/plans/0006-backend-go.md` en el repo `notify_web` (contrato en `docs/api/openapi.yaml` de ese repo).

## Reglas clave
- **El servidor nunca descifra.** Guarda metadatos + `wrappedKey` + `payload`. Nunca registrar contraseñas, `authKey`, tokens, códigos ni textos de personas.
- Capas: `internal/modules/*` (negocio) usa `internal/platform/*`; `platform` nunca importa `modules`.
- Correo: solo vía la interfaz `mailer.Mailer`. Un proveedor nuevo = un adaptador nuevo + una línea en `mailer.New`. Los módulos no importan Resend.
- Falla cerrado: sin secretos válidos no arranca; errores desconocidos no exponen detalles (`apperrors.PublicMessage`).
- SQL solo parametrizado (sqlc/pgx). Todas las consultas filtran por `user_id`.
- Cada fase termina con `make test`, `make lint`, `go vet ./...` y `make vuln` en verde.

## Comandos
`make up` (Postgres) · `make run` · `make test` · `make lint` · `make vuln`

## Base de datos
- Migraciones en `migrations/` (goose, embebidas; `make migrate`). Solo hacia adelante y compatibles hacia atrás.
- Tres roles: `apunte_owner` (migraciones), `apunte_api` (la API, sin DDL, sujeto a RLS) y, en la fase 8, uno de mantenimiento para la purga. Ver `deploy/db-roles.sql`.
- Las tablas con datos de personas tienen **RLS**: toda consulta de la API pasa por `database.WithUser` (fija `app.user_id` por transacción). Antes de autenticar se usa `WithoutUser`; el enlace público usa `WithPublicSlug`. Nunca `SET` sin `LOCAL`.
- Pruebas de integración: `TEST_DATABASE_URL` (administrador). Sin ella se omiten en local y fallan en CI. `make up && make test-db`.
