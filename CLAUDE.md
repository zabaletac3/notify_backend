# AxoNote API — guía para asistentes

Backend en Go + PostgreSQL de AxoNote (notas con cifrado de extremo a extremo). Plan completo: `docs/plans/0006-backend-go.md` en el repo `notify_web` (contrato en `docs/api/openapi.yaml` de ese repo).

## Reglas clave
- **El servidor nunca descifra.** Guarda metadatos + `wrappedKey` + `payload`. Nunca registrar contraseñas, `authKey`, tokens, códigos ni textos de personas.
- Capas: `internal/modules/*` (negocio) usa `internal/platform/*`; `platform` nunca importa `modules`.
- Correo: solo vía la interfaz `mailer.Mailer`. Un proveedor nuevo = un adaptador nuevo + una línea en `mailer.New`. Los módulos no importan Resend.
- Falla cerrado: sin secretos válidos no arranca; errores desconocidos no exponen detalles (`apperrors.PublicMessage`).
- SQL solo parametrizado (sqlc/pgx). Todas las consultas filtran por `user_id`.
- Cada fase termina con `make test`, `make lint`, `go vet ./...` y `make vuln` en verde.

## Comandos
`make up` (Postgres) · `make run` (carga `.env` si existe; el entorno del proceso manda) · `make test` · `make lint` · `make vuln`

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
- Si cambias una ruta, `make test` falla hasta que el contrato coincida: `internal/contract` compara el router con `../notify_web/docs/api/openapi.yaml` (necesita `TEST_DATABASE_URL`; en CI lo vigila el job `contract`). Orden: YAML → backend → web.
- Cuerpos JSON estrictos (`decode`: tipo, sin campos desconocidos, sin datos de más).
- Anti-enumeración: `register`, `resend-code`, `forgot` y `prelogin` responden igual exista o no la cuenta; el correo se envía en segundo plano (`Service.send`) para no filtrar por tiempo.
- Sesión: acceso JWT corto + renovación opaca con rotación; reusar un token gastado revoca la familia y el dispositivo. El dispositivo del token (`did`) se comprueba en cada petición (`device-revoked`).
- Modo cookie (web, `X-AxoNote-Session: cookie` en `login`/`verify-email`/`refresh`/`logout`): el refresh token viaja solo en la cookie `axonote_rt` (`HttpOnly; Secure; SameSite=Strict; Path=/v1/auth`, `Domain` solo si `COOKIE_DOMAIN`; `accessToken` sigue en el cuerpo); sin la cabecera todo es como antes (refreshToken en el cuerpo). Otra cabecera → 422. CSRF: en modo cookie un `Origin` presente debe estar en `ALLOWED_ORIGINS` (`403 forbidden/csrf`); CORS con credenciales y sin comodín. `/auth/logout` está **fuera** del grupo protegido: en modo cookie revoca por el Bearer si vale o por la cookie, y siempre responde 204 borrando la cookie; en modo cuerpo exige Bearer. `COOKIE_SECURE` por defecto true (false solo en dev; inválido en qa/prod).
- La API no puede borrar usuarios; solo `discard_unverified_user()` (migración 00004) elimina registros sin verificar.

## Claves y recuperación
- `ChangePassword` re-envuelve la clave maestra (no toca las notas) y conserva la `recoveryWrappedMasterKey` guardada; `RotateRecoveryKey` cambia solo la de recuperación. Ambas exigen la prueba de la contraseña con límite de fallos (`sensitive:<userId>`).
- Restablecer: `forgot` (token de 256 bits, hash SHA-256, 1 h, un solo uso) → `reset/bundle` → `reset` con `keep` (exige `recoveryAuth` vigente; 5 intentos/h por cuenta) o `wipe` (borra notas, carpetas, enlaces y lápidas **de esa cuenta** con RLS). Ambos cierran todas las sesiones y recuperan una cuenta en periodo de gracia.
- Cada cambio de credenciales deja un evento en `audit_log` y avisa por correo al dueño.
- `DELETE /me` solo marca `deleted_at` y cierra sesiones; la purga definitiva (30 días) llega en la fase 8.

## Verificación en dos pasos (`internal/modules/auth/mfa.go`)
- TOTP (RFC 6238, SHA-1, 6 dígitos, ±1 paso) + 10 códigos de respaldo de un solo uso (`security/totp.go`, solo biblioteca estándar). Fuente única de verdad: `user_totp.enabled_at IS NOT NULL`.
- El secreto se cifra con AES-256-GCM con clave `security.DeriveKey(pepper, "totp-enc")`; los códigos de respaldo solo guardan su hash (`security.HashCode(pepper, "mfa-recovery", userID, …)`). El paso TOTP aceptado se fija en `last_step` (anti-reutilización, `SELECT … FOR UPDATE`).
- Con MFA activo `POST /auth/login` responden un reto (`MfaChallenge`: `mfaToken` + `expiresAt`) **sin sesión, `keys`, tokens ni cookie**; se completa con `POST /auth/login/mfa`. El segundo paso se exige en toda sesión nueva, también con Google (`completeLogin` es el único camino). Tickets en `auth_tickets` (sin RLS), TTL 5 min, tope de intentos.
- `/mfa` (GET), `/mfa/totp/setup`, `/mfa/totp/enable`, `/mfa/totp/disable`, `/mfa/recovery-codes`. Activar cierra las demás sesiones. Los códigos de respaldo solo se devuelven en claro al activar o regenerar.
- Restablecer: `wipe` exige `mfaCode` con MFA activo (si no, no borra nada); `keep` puede desactivar el MFA con `disableMfa`.

## Acceso con Google (`internal/modules/auth/google.go`, `internal/platform/oidc`)
- Google es **solo identidad** (G1): toda cuenta sigue teniendo contraseña, `authKey`, `KeyBundle` y clave de recuperación. Flujo OAuth de código + PKCE por redirección (sin ventanas ni scripts de Google): `POST /auth/google/start` → callback (302 a `WEB_BASE_URL/auth/google#code=…`, **sin cookies**) → `POST /auth/google/exchange`.
- Dos PKCE: el de la web con la API (`verifier`/`challenge`, ata el resultado al navegador que empezó el flujo) y el de la API con Google (`pkceVerifier`, no sale del servidor). El `id_token` se valida con `github.com/golang-jwt/jwt/v5` (`internal/platform/oidc/google.go`, sin SDK): firma RS256 contra las claves de Google (`kid` con caché en memoria y `Cache-Control`), `iss`, `aud`, `exp` y `nonce`. Ningún proveedor nuevo = adaptador nuevo + una línea en `oidc.New`.
- `exchange` devuelve una unión por `status`: `authenticated` (sesión), `mfa-required` (reto; Google **no** salta el MFA: pasa por `completeLogin`), `link-required` (existe cuenta verificada con ese correo: se pide la contraseña para vincular; **nunca** se vincula por correo) y `signup-required`. `POST /auth/google/register` crea la cuenta **ya verificada** (sin código de correo) y descarta un registro sin verificar previo. `DELETE /me/identities/google` desvincula (exige la contraseña).
- La identidad se guarda por `sub` en `user_identities` (sin RLS; se borra con la cuenta). `User.hasGoogle` se calcula con un `EXISTS` en `userCols`.
- Configuración: `GOOGLE_PROVIDER` (`off` por defecto; las rutas existen y responden `403 forbidden/google-disabled` | `google` | `fake` solo con `APP_ENV=dev`). Con `google` son obligatorias `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` y `GOOGLE_REDIRECT_URL` (https fuera de dev). Falla cerrado.
- Tickets en `auth_tickets`: `google-state` (10 min), `google-result` (5 min), `google-link` (10 min), `google-signup` (15 min). Los errores de Google salen como `apperrors.Unavailable` y se registran sin datos personales.

## Dispositivos de confianza (`internal/modules/auth/trusted.go`)
- Solo para cuentas con Google vinculado (T1). La llave va partida en dos: el navegador guarda una clave AES no exportable y el servidor la clave maestra cifrada con ella (`a1.…`, datos asociados `apunte/v1/mk/<userId>/trusted/<trustId>`). El servidor solo entrega esa mitad a una sesión válida; sin la clave local no sirve, y revocar el dispositivo desde otro lo deja inservible.
- `GET /trusted-devices`, `POST /trusted-devices`, `GET /trusted-devices/{id}` y `DELETE /trusted-devices/{id}`. Alta sin Google (`403 forbidden/google-not-linked`), más de 10 vigentes (`403 forbidden/limit-reached`); alta/lectura/baja dejan evento de auditoría. La lectura exige una sesión completa (un `mfaToken` no vale como Bearer).
- Se revocan al cambiar o restablecer la contraseña (en `wipe`, la MK cambia: se borran) y al desvincular Google. Purga: revocados > 30 días y sin usar > 180 días. Tabla `trusted_devices` con RLS (`own_rows` + `maintenance`).

## Sincronización (`internal/modules/notesync`)
- `POST /sync` replica `MockSyncServer` de la web: todo se valida antes de aplicar nada (una petición inválida no deja cambios a medias), una sola transacción, `baseRevision` solo en notas (conflicto = se devuelve la versión del servidor, sin pisar), carpetas «gana el último», lápidas para borrados definitivos, carpetas antes que notas en `remoteChanges`.
- `seq` por cuenta con `next_seq()`; las escrituras de una cuenta se serializan (`SELECT … FOR UPDATE` sobre `users`) y el cursor es `account_seq` leído tras escribir, así que nunca salta un cambio (test de concurrencia).
- El dispositivo es el del token (`did`); `deviceId`/`deviceName` del cuerpo se ignoran. Un id que pertenece a otra cuenta da 422 sin detalles (RLS + PK global).
- Límites por configuración: `MAX_SYNC_BODY_BYTES` (8 MiB, solo `/v1/sync`), `MAX_SYNC_CHANGES`, `MAX_NOTES_PER_ACCOUNT`, `MAX_FOLDERS_PER_ACCOUNT` (`forbidden/limit-reached`).
- Los módulos no se importan entre sí: `notesync` recibe una `PrincipalFunc` y el middleware de auth se aplica en `main`.

## Compartir (`internal/modules/share`)
- El cliente cifra una copia de la nota con la clave del enlace y elige el `slug` (22 caracteres); la clave va en el fragmento de la URL y nunca llega al servidor. Un `PUT` sobre una nota que ya tiene enlace devuelve el existente.
- Lectura pública (`GET /v1/public/notes/{slug}`) por `database.WithPublicSlug` (RLS: solo `SELECT` de ese slug): solo devuelve `{payload, updatedAt}`; enlace inexistente, revocado o con forma inválida dan el mismo 404; límite por IP; `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`.
- Mover una nota a la papelera (`deletedAt`) o borrarla por `/sync` elimina su enlace; la clave foránea con `ON DELETE CASCADE` cubre el borrado de la nota.
- `internal/testutil` monta la API completa para las pruebas de integración de los módulos.

## Perfil, ajustes y uso
- `/me` (GET/PATCH) y el cambio de correo viven en `auth`: `POST /me/email-change` exige la prueba de la contraseña, envía el código **al correo nuevo** (y si ya tiene cuenta responde igual y avisa a su dueño); `confirm` aplica el cambio y avisa al correo anterior. El código está ligado a la cuenta y al correo nuevo.
- `account`: `/settings` (valores por defecto como la web; PATCH estricto; `twoFactor` es **de solo lectura** y se calcula desde `user_totp`: enviarlo da `422`) y `/storage/usage` (suma `pg_column_size` de lo cifrado; `QUOTA_BYTES`).
- La cuota se aplica en `/sync` (`403 forbidden/quota-exceeded`); borrar siempre se permite.

## Operación (`docs/operations.md`)
- Cuatro roles de BD: owner (migraciones), API (RLS), purga (`apunte_maint`) y copias (`BYPASSRLS` solo lectura). Nunca usar el de migraciones ni el de copias en la API.
- `cmd/purge` (idempotente, por lotes) y `deploy/backup.sh` + `restore-test.sh`; temporizadores systemd en `deploy/`. Los trabajos avisan a un servicio de «latido» (`*_PING_URL`) para alertar si dejan de ejecutarse.
- Las migraciones nuevas que añadan tablas con datos de personas deben decidir su política de purga y, si tienen RLS, su política para `apunte_maint`.

## Nombres históricos
- La marca es **AxoNote** (antes «Apunte»); los nombres vigentes de la sesión web son `X-AxoNote-Session` y la cookie `axonote_rt`.
- Los identificadores internos y operativos conservan «apunte» **a propósito** (se renombrarán en otra fase): roles de PostgreSQL, base y URLs de ejemplo, migraciones, rutas `/opt/apunte` y `/etc/apunte`, unidades systemd, bucket, imagen y dominios. Ver `docs/security.md` («Nombres históricos»).
- Las etiquetas que ya forman parte de datos emitidos no se tocan: audiencia JWT `apunte-api` y prefijos `apunte/v1/…` de `kid`/HKDF.
