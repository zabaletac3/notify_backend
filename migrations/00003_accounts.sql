-- +goose Up
ALTER TABLE users ADD COLUMN full_name text NOT NULL DEFAULT '' CHECK (length(full_name) <= 80);
ALTER TABLE users ALTER COLUMN full_name DROP DEFAULT;
ALTER TABLE users ADD COLUMN accepted_terms_at timestamptz;
ALTER TABLE users ADD COLUMN keys_version integer NOT NULL DEFAULT 1 CHECK (keys_version >= 1);

-- Las plataformas del contrato (DevicePlatform).
ALTER TABLE devices DROP CONSTRAINT devices_platform_check;
ALTER TABLE devices ADD CONSTRAINT devices_platform_check CHECK (platform IN ('linux', 'windows', 'android', 'web'));

-- Un código vigente por cuenta y finalidad.
CREATE UNIQUE INDEX verification_codes_active ON verification_codes (user_id, purpose) WHERE consumed_at IS NULL;

-- +goose Down
DROP INDEX verification_codes_active;
ALTER TABLE devices DROP CONSTRAINT devices_platform_check;
ALTER TABLE devices ADD CONSTRAINT devices_platform_check CHECK (platform IN ('web', 'desktop', 'ios', 'android'));
ALTER TABLE users DROP COLUMN keys_version, DROP COLUMN accepted_terms_at, DROP COLUMN full_name;
