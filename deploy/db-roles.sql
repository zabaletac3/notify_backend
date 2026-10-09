-- Roles de PostgreSQL de AxoNote. Se ejecuta UNA vez por base de datos, como administrador, antes de la
-- primera migración, con las contraseñas como variables de psql (lo hace deploy/init-db.sh):
--
--   psql -v ON_ERROR_STOP=1 -v owner_pw=… -v api_pw=… -v purge_pw=… -v backup_pw=… -v dbname=apunte -f db-roles.sql
--
--   apunte_owner  dueño del esquema: solo lo usa `cmd/migrate` (MIGRATE_DATABASE_URL).
--   apunte_api    lo usa la API (DATABASE_URL): sin DDL, sujeto a RLS, miembro de apunte_app.
--   apunte_purge  lo usa `cmd/purge` (PURGE_DATABASE_URL): miembro de apunte_maint (borra lo caducado).
--   apunte_backup lo usa deploy/backup.sh: solo lectura de todo, con BYPASSRLS (pg_dump necesita ver todas las filas).
--
-- Los roles de grupo (apunte_app, apunte_maint) también los crean las migraciones si no existen.

-- Cada rol se crea solo si falta (repetir el script no falla) y las contraseñas se fijan siempre (rotación).
SELECT 'CREATE ROLE apunte_app   NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_app') \gexec
SELECT 'CREATE ROLE apunte_maint NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_maint') \gexec
SELECT 'CREATE ROLE apunte_owner  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_owner') \gexec
SELECT 'CREATE ROLE apunte_api    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_api') \gexec
SELECT 'CREATE ROLE apunte_purge  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_purge') \gexec
SELECT 'CREATE ROLE apunte_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS'   WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apunte_backup') \gexec

SELECT format('ALTER ROLE apunte_owner  PASSWORD %L', :'owner_pw')  \gexec
SELECT format('ALTER ROLE apunte_api    PASSWORD %L', :'api_pw')    \gexec
SELECT format('ALTER ROLE apunte_purge  PASSWORD %L', :'purge_pw')  \gexec
SELECT format('ALTER ROLE apunte_backup PASSWORD %L', :'backup_pw') \gexec

GRANT apunte_app   TO apunte_api;
GRANT apunte_maint TO apunte_purge;
GRANT pg_read_all_data TO apunte_backup;

REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO apunte_owner, apunte_api, apunte_purge, apunte_backup;
ALTER SCHEMA public OWNER TO apunte_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO apunte_owner;
