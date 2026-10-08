-- +goose Up

-- Rol de la API: sin login (el login lo da un rol hijo creado al desplegar), sin DDL, sin BYPASSRLS.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_app') THEN
    CREATE ROLE apunte_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$$;
-- +goose StatementEnd

-- Cuenta que hace la petición: se fija con set_config('app.user_id', ..., true) dentro de cada
-- transacción. Sin valor devuelve NULL y todas las políticas de RLS fallan cerrado.
-- +goose StatementBegin
CREATE FUNCTION app_user_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;
-- +goose StatementEnd

-- ── Cuentas ───────────────────────────────────────────────────────
CREATE TABLE users (
  id                uuid PRIMARY KEY,
  email             text NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
  email_verified_at timestamptz,
  kdf               jsonb NOT NULL,
  auth_key_hash     bytea NOT NULL,
  recovery_auth_hash bytea,
  keys              jsonb NOT NULL,
  settings          jsonb NOT NULL DEFAULT '{}',
  account_seq       bigint NOT NULL DEFAULT 0 CHECK (account_seq >= 0),
  deleted_at        timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- ── Datos cifrados (el servidor solo ve metadatos y textos "a1.<iv>.<ct>") ──
CREATE TABLE folders (
  id          uuid PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  revision    integer NOT NULL CHECK (revision >= 1),
  seq         bigint NOT NULL CHECK (seq > 0),
  created_at  timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL,
  wrapped_key text NOT NULL CHECK (wrapped_key ~ '^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' AND length(wrapped_key) <= 512),
  payload     text NOT NULL CHECK (payload ~ '^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' AND length(payload) <= 65536)
);
CREATE INDEX folders_user_seq ON folders (user_id, seq);

-- folder_id no lleva clave foránea: el cliente puede subir una nota antes que su carpeta
-- y borrar una carpeta desvincula sus notas por lógica de /sync.
CREATE TABLE notes (
  id                    uuid PRIMARY KEY,
  user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  folder_id             uuid,
  revision              integer NOT NULL CHECK (revision >= 1),
  seq                   bigint NOT NULL CHECK (seq > 0),
  created_at            timestamptz NOT NULL,
  updated_at            timestamptz NOT NULL,
  deleted_at            timestamptz,
  last_edited_device_id uuid,
  wrapped_key           text NOT NULL CHECK (wrapped_key ~ '^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' AND length(wrapped_key) <= 512),
  payload               text NOT NULL CHECK (payload ~ '^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' AND length(payload) <= 1500000)
);
CREATE INDEX notes_user_seq     ON notes (user_id, seq);
CREATE INDEX notes_user_deleted ON notes (user_id, deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE tombstones (
  user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  entity   text NOT NULL CHECK (entity IN ('note', 'folder')),
  id       uuid NOT NULL,
  revision integer NOT NULL CHECK (revision >= 0),
  seq      bigint NOT NULL CHECK (seq > 0),
  PRIMARY KEY (user_id, entity, id)
);
CREATE INDEX tombstones_user_seq ON tombstones (user_id, seq);

CREATE TABLE devices (
  id           uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  platform     text NOT NULL DEFAULT 'web' CHECK (platform IN ('web', 'desktop', 'ios', 'android')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz
);
CREATE INDEX devices_user ON devices (user_id);

CREATE TABLE share_links (
  slug        text PRIMARY KEY CHECK (slug ~ '^[A-Za-z0-9_-]{22}$'),
  note_id     uuid NOT NULL UNIQUE REFERENCES notes(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_key text CHECK (wrapped_key IS NULL OR wrapped_key ~ '^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'),
  payload     text NOT NULL CHECK (payload ~ '^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' AND length(payload) <= 1500000),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX share_links_user ON share_links (user_id);

-- ── Sesión y abuso (se consultan antes de saber quién es la persona: sin RLS) ──
CREATE TABLE refresh_tokens (
  id         uuid PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  family_id  uuid NOT NULL,
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_family  ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires ON refresh_tokens (expires_at);
CREATE INDEX refresh_tokens_user    ON refresh_tokens (user_id);

CREATE TABLE verification_codes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     text NOT NULL CHECK (purpose IN ('verify-email', 'email-change', 'password-reset')),
  code_hash   bytea NOT NULL,
  attempts    integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX verification_codes_user    ON verification_codes (user_id, purpose);
CREATE INDEX verification_codes_expires ON verification_codes (expires_at);

CREATE TABLE rate_limits (
  key           text PRIMARY KEY,
  count         integer NOT NULL DEFAULT 0,
  window_start  timestamptz NOT NULL DEFAULT now(),
  blocked_until timestamptz
);
CREATE INDEX rate_limits_window ON rate_limits (window_start);

-- Registro de eventos sensibles. Sin contenido ni datos personales: la IP va como hash con sal diaria.
CREATE TABLE audit_log (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id uuid,
  event   text NOT NULL,
  ip_hash bytea,
  at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_user_at ON audit_log (user_id, at);

-- ── Seguridad por fila ────────────────────────────────────────────
ALTER TABLE folders     ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes       ENABLE ROW LEVEL SECURITY;
ALTER TABLE tombstones  ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices     ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_links ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_rows ON folders     USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
CREATE POLICY own_rows ON notes       USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
CREATE POLICY own_rows ON tombstones  USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
CREATE POLICY own_rows ON devices     USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
CREATE POLICY own_rows ON share_links USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());

-- Lectura pública de un enlace compartido: solo SELECT, y solo del slug fijado en app.public_slug.
CREATE POLICY public_read ON share_links FOR SELECT
  USING (slug = nullif(current_setting('app.public_slug', true), ''));

-- Siguiente número de secuencia de la cuenta actual (atómico; solo puede tocar su propia cuenta).
-- +goose StatementBegin
CREATE FUNCTION next_seq() RETURNS bigint
LANGUAGE sql VOLATILE
AS $$ UPDATE users SET account_seq = account_seq + 1 WHERE id = app_user_id() RETURNING account_seq $$;
-- +goose StatementEnd

-- ── Privilegios mínimos de la API ─────────────────────────────────
GRANT USAGE ON SCHEMA public TO apunte_app;
GRANT SELECT, INSERT, UPDATE ON users TO apunte_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON folders, notes, tombstones, devices, share_links,
  refresh_tokens, verification_codes, rate_limits TO apunte_app;
GRANT INSERT ON audit_log TO apunte_app;
GRANT EXECUTE ON FUNCTION app_user_id(), next_seq() TO apunte_app;

-- +goose Down
DROP FUNCTION IF EXISTS next_seq();
DROP TABLE IF EXISTS audit_log, rate_limits, verification_codes, refresh_tokens, share_links,
  devices, tombstones, notes, folders, users;
DROP FUNCTION IF EXISTS app_user_id();
