-- +goose Up

-- Verificación en dos pasos (TOTP + códigos de respaldo). La fuente única de verdad de «MFA activo»
-- es `user_totp.enabled_at IS NOT NULL`; no se añaden columnas a `users`.
CREATE TABLE user_totp (
  user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc text NOT NULL CHECK (secret_enc ~ '^t1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' AND length(secret_enc) <= 256),
  enabled_at timestamptz,                       -- NULL = pendiente de confirmar
  last_step  bigint NOT NULL DEFAULT 0,          -- último paso TOTP aceptado (anti-reutilización)
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mfa_recovery_codes (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  bytea NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, code_hash)
);
CREATE INDEX mfa_recovery_codes_user ON mfa_recovery_codes (user_id);

-- Con RLS: en el segundo paso ya se conoce la cuenta (va en el ticket), así que se usa
-- WithoutUser + SetUser, igual que VerifyEmail.
ALTER TABLE user_totp          ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_recovery_codes ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_rows ON user_totp          USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
CREATE POLICY own_rows ON mfa_recovery_codes USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());

CREATE POLICY maintenance ON user_totp          TO apunte_maint USING (true) WITH CHECK (true);
CREATE POLICY maintenance ON mfa_recovery_codes TO apunte_maint USING (true) WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_totp, mfa_recovery_codes TO apunte_app;
GRANT SELECT, DELETE ON user_totp, mfa_recovery_codes TO apunte_maint;

-- Purga: nada propio; las filas se van con la cuenta (ON DELETE CASCADE). Documentado en docs/operations.md.

-- +goose Down
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS user_totp;
