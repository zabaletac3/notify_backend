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

## Seguridad (`internal/platform/security`, `ratelimit`)
- La contraseña nunca llega: se guarda `AuthKeyHasher.Hash(authKey)` (HMAC con pepper + Argon2id). Para cuentas inexistentes usar `VerifyDummy` y `FakeKDF` (mismas formas y tiempos).
- Tokens de renovación y códigos: solo se guarda su hash (`HashToken`, `HashCode` ligado a finalidad y cuenta). Los tokens de acceso son JWT HS256 (`Signer`), con rotación de secreto (`JWT_SECRET_PREVIOUS`).
- Límites: `ratelimit.Limiter` (`Fail` para login, `Take` para el resto, `Reset` tras éxito). Las claves son HMAC de correo/IP. Si devuelve error, **denegar** (fallar cerrado).
- IP del cliente: `httpserver.ClientIP(r, cfg.TrustProxy)`; nunca leer `X-Forwarded-For` a mano.

## Contrato HTTP
- Las respuestas llevan el cuerpo del contrato **sin envoltorio**; los errores tienen la forma `AppError` (`{kind, code?, fields?, retryAfterSec?}`): crear siempre con `apperrors.*` y responder con `response.Error(w, r, log, err)`. Un error desconocido sale como `{kind:"server"}`.
- Rutas bajo `/v1`; cada módulo expone `Routes(chi.Router)` y se monta en `httpserver.NewRouter`.
- Cuerpos JSON estrictos (`decode`: tipo, sin campos desconocidos, sin datos de más).
- Anti-enumeración: `register`, `resend-code`, `forgot` y `prelogin` responden igual exista o no la cuenta; el correo se envía en segundo plano (`Service.send`) para no filtrar por tiempo.
- Sesión: acceso JWT corto + renovación opaca con rotación; reusar un token gastado revoca la familia y el dispositivo. El dispositivo del token (`did`) se comprueba en cada petición (`device-revoked`).
- La API no puede borrar usuarios; solo `discard_unverified_user()` (migración 00004) elimina registros sin verificar.
