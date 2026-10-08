-- +goose Up
-- Rol de mantenimiento (purga diaria): grupo sin login; el rol con login se crea al desplegar
-- (deploy/db-roles.sql). Las políticas de RLS le dan acceso a todas las cuentas; la API no lo usa.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_maint') THEN
    CREATE ROLE apunte_maint NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$$;
-- +goose StatementEnd

-- Las lápidas necesitan fecha para poder purgarlas a los 90 días.
ALTER TABLE tombstones ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX tombstones_created ON tombstones (created_at);

CREATE POLICY maintenance ON notes       TO apunte_maint USING (true) WITH CHECK (true);
CREATE POLICY maintenance ON folders     TO apunte_maint USING (true) WITH CHECK (true);
CREATE POLICY maintenance ON tombstones  TO apunte_maint USING (true) WITH CHECK (true);
CREATE POLICY maintenance ON devices     TO apunte_maint USING (true) WITH CHECK (true);
CREATE POLICY maintenance ON share_links TO apunte_maint USING (true) WITH CHECK (true);

GRANT USAGE ON SCHEMA public TO apunte_maint;
GRANT SELECT, DELETE ON notes, folders, devices, share_links, refresh_tokens, verification_codes, rate_limits TO apunte_maint;
GRANT SELECT, INSERT, UPDATE, DELETE ON tombstones TO apunte_maint;
GRANT SELECT, DELETE ON audit_log, users TO apunte_maint;
GRANT UPDATE (account_seq) ON users TO apunte_maint;

-- +goose Down
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM apunte_maint;
DROP POLICY maintenance ON share_links;
DROP POLICY maintenance ON devices;
DROP POLICY maintenance ON tombstones;
DROP POLICY maintenance ON folders;
DROP POLICY maintenance ON notes;
DROP INDEX tombstones_created;
ALTER TABLE tombstones DROP COLUMN created_at;
