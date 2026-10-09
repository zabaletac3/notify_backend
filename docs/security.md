# Seguridad: estado, evidencia y cómo comprobarlo

Este documento mapea los controles del backend con la evidencia que los respalda (pruebas que se ejecutan en cada PR) y lo que **no** cubre. Es un checklist basado en OWASP ASVS nivel 2, no una certificación.

## Modelo de amenazas (resumen)

| Amenaza | Control | Evidencia |
|---|---|---|
| Robo de la base de datos | Solo hay texto cifrado de extremo a extremo y hashes (`authKey`/`recoveryAuth` con HMAC+Argon2id, tokens SHA-256, códigos HMAC) | `TestDatabaseNeverStoresSecrets`, `TestResetTokenIsStoredHashed` |
| Leer datos de otra cuenta (IDOR) | `user_id` en cada consulta + **RLS** de PostgreSQL | `TestRLS*`, `TestSyncRejectsIDsOfOtherAccounts…`, `TestSlugCollisionAndCrossAccountIsolation` |
| Fuerza bruta de contraseña | Argon2id en el cliente; 5 fallos por correo+IP y 20/h por IP con bloqueo progresivo; 60 intentos/min por IP **antes de hashear** | `TestLoginBruteForceIsBlocked`, `TestLoginFloodIsCappedBeforeAnyHashing` |
| Adivinar códigos de 6 dígitos | 5 intentos por código, 15/h por cuenta (cualquier IP) | `TestVerifyAttemptsAreCappedPerAccountAcrossIPs` |
| Enumerar cuentas | Registro, reenvío, olvido, prelogin y cambio de correo responden igual; correo asíncrono; hash ficticio | `TestRegisterDoesNotRevealExistingAccounts`, `TestForgotPasswordHidesAccountsAndThrottles`, `TestDummyVerifyCostsLikeRealVerify` |
| Robo de token de renovación | Rotación + detección de reutilización (revoca la familia) | `TestRefreshRotationAndReuseDetection`, `TestRefreshCookieRotationAndReuse` |
| CSRF en la sesión web | Modo cookie (`X-AxoNote-Session: cookie`): la cabecera obliga al preflight CORS; un `Origin` presente debe estar en `ALLOWED_ORIGINS` (`403 forbidden/csrf`); CORS con credenciales y sin comodín; la cookie es `HttpOnly; Secure; SameSite=Strict` | `TestCookieModeCSRF`, `TestCORSAllowsCredentialsAndSessionHeader` |
| Token manipulado | Solo HS256, emisor/audiencia/caducidad obligatorias, `kid`, rotación de secreto | `TestJWTRejectsTampering`, `FuzzJWTParse` |
| Inyección SQL / de cabeceras | Solo consultas parametrizadas; validación estricta; NUL rechazado | `TestHostileStringsNeverCauseServerErrors` |
| Secretos en registros | Registro por patrón de ruta, sin cuerpos, cabeceras ni correos completos | `TestLogsNeverContainSecrets` |
| DoS por cuerpo/respuesta | Límites de cuerpo (1 MiB; 8 MiB en `/sync`), 500 cambios, `/sync` pagina lo que baja (500 elementos / 8 MiB), tiempos máximos | `TestHostileBodies`, `TestRemoteChangesArePaginatedWithoutLoss` |
| Cuenta comprometida | Lista de dispositivos y revocación, cierre de sesiones al cambiar/restablecer contraseña, avisos por correo, `audit_log` | `TestDevicesAndRevocation`, `TestChangePassword`, `TestResetKeepPreservesNotes` |
| Enlace público | Slug aleatorio, 404 uniforme, límite por IP, RLS de solo `SELECT` de ese slug, slug redactado en los registros de Caddy | `TestPublicEndpointOnlyExposesTheCopy`, `TestPublicReadIsRateLimitedPerIP` |
| Escalada desde la API | Rol sin DDL, sin `BYPASSRLS`, sin `DELETE` en `users`; secretos de migración/superusuario fuera del contenedor de la API | `TestAppRoleIsNotPrivileged`, `docs/deploy.md` |
| Cadena de suministro | `govulncheck` y `gosec` en CI, Dependabot, imagen sin shell ni root | CI (`ci.yml`) |

## Cookies y CSRF (decisión D15)

La web activa el modo cookie con la cabecera `X-AxoNote-Session: cookie` en `login`, `verify-email`, `refresh` y `logout`. Entonces el token de renovación viaja **solo** como cookie `axonote_rt` (`HttpOnly; Secure; SameSite=Strict; Path=/v1/auth`, sin `Domain` salvo `COOKIE_DOMAIN`) y no aparece en el JSON; el token de acceso sigue en el cuerpo. Sin la cabecera nada cambia (escritorio, móvil y bundles antiguos).

- **Anti-CSRF**: la cabecera personalizada fuerza el preflight CORS y un `Origin` presente debe coincidir exactamente con un origen de `ALLOWED_ORIGINS` (si no, `403 forbidden/csrf`). Las peticiones sin `Origin` (clientes no navegador) se permiten. CORS usa credenciales con orígenes explícitos, nunca comodín.
- **Logout**: en modo cookie funciona aunque el token de acceso haya vencido (revoca por la cookie) y **siempre** responde `204` borrando la cookie (`Max-Age=0`); es idempotente y no revela si la cookie valía.
- **`COOKIE_SECURE`**: por defecto `true`; `false` solo en dev, y en qa/prod la configuración falla al arrancar si es `false`.
- **Despliegue**: `SameSite=Strict` exige que la web y la API compartan **dominio registrable** (p. ej. `apunte.app` y `api.apunte.app`). Una web en `*.pages.dev` con la API en otro dominio no recibiría la cookie.

## Nombres históricos

La marca actual es **AxoNote** (antes «Apunte»). Los nombres de sesión web vigentes son `X-AxoNote-Session` y la cookie `axonote_rt`.

Algunos identificadores internos y operativos conservan «apunte» **a propósito** y se renombrarán en otra fase: roles de PostgreSQL (`apunte_owner`, `apunte_api`, `apunte_purge`, `apunte_backup`, grupos `apunte_app`/`apunte_maint`), el nombre de la base y las URLs de conexión de ejemplo, las migraciones, las rutas del servidor (`/opt/apunte`, `/etc/apunte`, `/usr/local/sbin/apunte-*`, `99-apunte.conf`), los proyectos/contenedores/unidades systemd, el bucket `apunte-backups`, `apunte.dump` y la imagen `apunte-api`. Tampoco cambian las etiquetas criptográficas que contienen «apunte» (audiencia JWT `apunte-api`, prefijos `apunte/v1/…` de `kid` y HKDF) porque forman parte de datos ya emitidos.

## Fuzzing

Objetivos nativos de Go (se ejecutan como pruebas con su corpus semilla en cada PR). Para buscar más a fondo:

```bash
go test -run '^$' -fuzz '^FuzzValidate$'          -fuzztime 5m ./internal/modules/notesync/
go test -run '^$' -fuzz '^FuzzValidEmail$'        -fuzztime 2m ./internal/modules/auth/
go test -run '^$' -fuzz '^FuzzValidateRegister$'  -fuzztime 2m ./internal/modules/auth/
go test -run '^$' -fuzz '^FuzzVerifyStoredHash$'  -fuzztime 2m ./internal/platform/security/
go test -run '^$' -fuzz '^FuzzJWTParse$'          -fuzztime 2m ./internal/platform/security/
```

## Pruebas contra QA (manuales, antes de producción)

No se pueden ejecutar desde CI sin un entorno desplegado. Con QA arriba y Cloudflare Access configurado para tu IP/servicio:

```bash
# ZAP (línea base activa contra la API; importa el contrato OpenAPI de la web)
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t https://api-qa.tudominio.com/openapi.yaml -f openapi -r zap.html
# nuclei (plantillas de configuración, exposición y CVE conocidas)
nuclei -u https://api-qa.tudominio.com -severity medium,high,critical
# TLS y cabeceras
testssl.sh --fast https://api-qa.tudominio.com
```

Revisa que: `/v1/*` sin sesión responda 401; no haya `Server`/`X-Powered-By`; HSTS presente; `/ready` no revele detalles; `/v1/public/notes/<slug>` sin `Cache-Control: no-store` sea un hallazgo.

## Lista de comprobación antes de abrir producción

- [ ] Secretos de QA y prod distintos (`JWT_SECRET`, `PEPPER`, contraseñas de PostgreSQL, clave de Resend, credenciales del bucket de copias).
- [ ] `docs/deploy.md` completo; `production` con aprobación manual; ramas `main` y `develop` protegidas.
- [ ] `restore-test.sh` ejecutado con una copia real y recuentos coherentes.
- [ ] Latidos de copia y purga recibiendo avisos; UptimeRobot en `/ready`.
- [x] `caddy validate` del `Caddyfile` (Caddy 2.10, con los filtros de logs) y `docker compose config` de qa y prod: correctos (verificados en el entorno de desarrollo). Repetir `caddy validate` en el servidor con las variables reales.
- [x] Ciclo de copia con restic (volcado con `apunte_backup` → restic → `restic check` → restauración): las filas protegidas por RLS se vuelcan y los recuentos coinciden (probado con un repositorio local). Falta repetirlo contra el bucket real (`restore-test.sh`).
- [ ] ZAP y nuclei contra QA sin hallazgos medios o altos.
- [ ] Política de privacidad: correo y metadatos son datos personales (Ley 1581); contenido de notas cifrado de extremo a extremo; sin recuperación si se pierden contraseña **y** clave de recuperación.

## Limitaciones conocidas (a propósito, con su motivo)

- **Verificación en dos pasos (D12)**: aún no existe; `twoFactor: true` se rechaza para no dar falsa seguridad.
- **Reutilización de un token de renovación** revoca toda la sesión también cuando el cliente reintenta por un fallo de red (dos pestañas a la vez). Es el compromiso seguro; el cliente debe serializar sus renovaciones.
- **`DELETE /me` no pide la contraseña** (el contrato actual no lo prevé): mitigado por el periodo de gracia, el aviso por correo y la recuperación al restablecer.
- **Acciones de GitHub** fijadas por versión (Dependabot las mantiene), no por SHA.
- **Un cliente web comprometido (XSS)** puede leer la clave maestra en memoria: por eso la web mantiene una CSP estricta (ADR 0005 de `notify_web`).
- **Imágenes (D5) y Google (D8)**: diferidos.
