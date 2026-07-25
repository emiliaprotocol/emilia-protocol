-- SPDX-License-Identifier: Apache-2.0
-- Cluster-scoped roles used by the consequence actuator.
--
-- Supabase applies custom roles separately from schema migrations. Keep these
-- roles NOLOGIN and grant them only to deployment-provisioned database logins.

DO $roles$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'consequence_actuator_store_owner'
  ) THEN
    CREATE ROLE consequence_actuator_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'consequence_actuator_executor'
  ) THEN
    CREATE ROLE consequence_actuator_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

ALTER ROLE consequence_actuator_store_owner NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE consequence_actuator_executor NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
