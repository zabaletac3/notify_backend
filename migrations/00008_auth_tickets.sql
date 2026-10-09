-- +goose Up

-- Tickets de un solo uso para pasos intermedios de autenticación (segundo factor MFA, estados y
-- resultados de Google). Este backend no usa Redis: los límites de intentos ya viven en PostgreSQL
-- (`rate_limits`), así que el «challenge en Redis» se traduce a esta tabla.
--
-- Sin RLS: se consultan antes de saber quién es la persona, igual que `refresh_tokens` y
-- `verification_codes`.
CREATE TABLE auth_tickets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  purpose     text NOT NULL CHECK (purpose IN
                ('mfa-login', 'google-state', 'google-result', 'google-link', 'google-signup')),
  token_hash  bytea NOT NULL UNIQUE,
  user_id     uuid REFERENCES users(id) ON DELETE CASCADE,   -- NULL mientras no haya cuenta
  payload     jsonb NOT NULL DEFAULT '{}',
  attempts    integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX auth_tickets_expires ON auth_tickets (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON auth_tickets TO apunte_app;
GRANT SELECT, DELETE ON auth_tickets TO apunte_maint;

-- +goose Down
DROP TABLE IF EXISTS auth_tickets;
