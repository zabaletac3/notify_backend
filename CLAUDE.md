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

## Claves y recuperación
- `ChangePassword` re-envuelve la clave maestra (no toca las notas) y conserva la `recoveryWrappedMasterKey` guardada; `RotateRecoveryKey` cambia solo la de recuperación. Ambas exigen la prueba de la contraseña con límite de fallos (`sensitive:<userId>`).
- Restablecer: `forgot` (token de 256 bits, hash SHA-256, 1 h, un solo uso) → `reset/bundle` → `reset` con `keep` (exige `recoveryAuth` vigente; 5 intentos/h por cuenta) o `wipe` (borra notas, carpetas, enlaces y lápidas **de esa cuenta** con RLS). Ambos cierran todas las sesiones y recuperan una cuenta en periodo de gracia.
- Cada cambio de credenciales deja un evento en `audit_log` y avisa por correo al dueño.
- `DELETE /me` solo marca `deleted_at` y cierra sesiones; la purga definitiva (30 días) llega en la fase 8.

## Sincronización (`internal/modules/notesync`)
- `POST /sync` replica `MockSyncServer` de la web: todo se valida antes de aplicar nada (una petición inválida no deja cambios a medias), una sola transacción, `baseRevision` solo en notas (conflicto = se devuelve la versión del servidor, sin pisar), carpetas «gana el último», lápidas para borrados definitivos, carpetas antes que notas en `remoteChanges`.
- `seq` por cuenta con `next_seq()`; las escrituras de una cuenta se serializan (`SELECT … FOR UPDATE` sobre `users`) y el cursor es `account_seq` leído tras escribir, así que nunca salta un cambio (test de concurrencia).
- El dispositivo es el del token (`did`); `deviceId`/`deviceName` del cuerpo se ignoran. Un id que pertenece a otra cuenta da 422 sin detalles (RLS + PK global).
- Límites por configuración: `MAX_SYNC_BODY_BYTES` (8 MiB, solo `/v1/sync`), `MAX_SYNC_CHANGES`, `MAX_NOTES_PER_ACCOUNT`, `MAX_FOLDERS_PER_ACCOUNT` (`forbidden/limit-reached`).
- Los módulos no se importan entre sí: `notesync` recibe una `PrincipalFunc` y el middleware de auth se aplica en `main`.
