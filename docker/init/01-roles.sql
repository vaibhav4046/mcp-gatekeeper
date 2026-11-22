-- Least-privilege role the gatekeeper connects as in docker-compose.
-- It can read and write the business tables and nothing else: no access to system_secrets or
-- audit_logs, no DDL, not a superuser. Table grants are applied by 02-schema.sql.
-- The password is for local development only.
CREATE ROLE gatekeeper_app LOGIN PASSWORD 'gatekeeper_app' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE gatekeeper TO gatekeeper_app;
GRANT USAGE ON SCHEMA public TO gatekeeper_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
