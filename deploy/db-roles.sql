-- Roles de PostgreSQL de Apunte. Se ejecuta UNA vez por base de datos, como administrador,
-- antes de la primera migración. Cambia las contraseñas (openssl rand -base64 32).
--
--   apunte_owner  dueño del esquema: solo lo usa `cmd/migrate` (MIGRATE_DATABASE_URL).
--   apunte_api    lo usa la API (DATABASE_URL): sin DDL, sujeto a RLS, miembro de apunte_app.
--   apunte_purge  lo usa `cmd/purge` (PURGE_DATABASE_URL): miembro de apunte_maint (borra lo caducado en todas las cuentas).
--   apunte_backup lo usa deploy/backup.sh: solo lectura de todo, con BYPASSRLS (pg_dump necesita ver todas las filas).
--
-- La migración 00001 crea el rol de grupo apunte_app (NOLOGIN) si no existe.
CREATE ROLE apunte_owner LOGIN PASSWORD 'CAMBIAR' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE apunte_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE apunte_api LOGIN PASSWORD 'CAMBIAR' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS IN ROLE apunte_app;

CREATE ROLE apunte_maint NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE apunte_purge LOGIN PASSWORD 'CAMBIAR' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS IN ROLE apunte_maint;
CREATE ROLE apunte_backup LOGIN PASSWORD 'CAMBIAR' NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;
GRANT pg_read_all_data TO apunte_backup;

-- \c apunte   (conéctate a la base y continúa)
-- REVOKE ALL ON DATABASE apunte FROM PUBLIC;
-- GRANT CONNECT ON DATABASE apunte TO apunte_owner, apunte_api, apunte_purge, apunte_backup;
-- ALTER SCHEMA public OWNER TO apunte_owner;
-- REVOKE CREATE ON SCHEMA public FROM PUBLIC;
