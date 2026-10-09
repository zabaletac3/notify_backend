-- +goose Up

-- Dispositivos de confianza (T3): el servidor guarda la clave maestra cifrada con una clave propia del
-- navegador (`a1.<iv>.<ct>`, datos asociados `apunte/v1/mk/<userId>/trusted/<trustId>`). Ninguna mitad
-- sirve sola. El `id` lo genera el cliente (UUID v7); con RLS como `devices`.
CREATE TABLE trusted_devices (
  id                 uuid PRIMARY KEY,
  user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  platform           text NOT NULL DEFAULT 'web' CHECK (platform IN ('linux', 'windows', 'android', 'web')),
  wrapped_master_key text NOT NULL CHECK (wrapped_master_key ~ '^a1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
                                          AND length(wrapped_master_key) <= 512),
  created_at         timestamptz NOT NULL DEFAULT now(),
  last_used_at       timestamptz NOT NULL DEFAULT now(),
  revoked_at         timestamptz
);
CREATE INDEX trusted_devices_user ON trusted_devices (user_id);

ALTER TABLE trusted_devices ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_rows ON trusted_devices USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
CREATE POLICY maintenance ON trusted_devices TO apunte_maint USING (true) WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE, DELETE ON trusted_devices TO apunte_app;
GRANT SELECT, DELETE ON trusted_devices TO apunte_maint;

-- Purga (S6): revocados hace más de 30 días y no usados en 180 días. Documentado en docs/operations.md.

-- +goose Down
DROP TABLE IF EXISTS trusted_devices;
