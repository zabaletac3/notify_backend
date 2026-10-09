-- +goose Up

-- Identidades externas (hoy, solo Google). Vinculan por `subject` (el `sub` de Google), nunca por
-- correo (G4). Sin RLS: se consultan antes de saber quién es la persona, igual que `refresh_tokens`
-- y `verification_codes`.
CREATE TABLE user_identities (
  provider   text NOT NULL CHECK (provider IN ('google')),
  subject    text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email      text NOT NULL,             -- correo de Google al vincular (informativo)
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, subject),
  UNIQUE (user_id, provider)
);
CREATE INDEX user_identities_user ON user_identities (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_identities TO apunte_app;
GRANT SELECT, DELETE ON user_identities TO apunte_maint;

-- Purga: se borra con la cuenta (ON DELETE CASCADE); sin plazo propio.

-- +goose Down
DROP TABLE IF EXISTS user_identities;
