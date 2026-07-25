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
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'rollout_attempt_store_owner'
  ) THEN
    CREATE ROLE rollout_attempt_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'rollout_attempt_executor'
  ) THEN
    CREATE ROLE rollout_attempt_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

ALTER ROLE consequence_actuator_store_owner NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE consequence_actuator_executor NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE rollout_attempt_store_owner NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE rollout_attempt_executor NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

DO $rollout_role_separation$
BEGIN
  IF pg_catalog.pg_has_role(
      'rollout_attempt_executor',
      'rollout_attempt_store_owner',
      'MEMBER'
    )
    OR pg_catalog.pg_has_role(
      'rollout_attempt_store_owner',
      'rollout_attempt_executor',
      'MEMBER'
    )
  THEN
    RAISE EXCEPTION
      'rollout attempt owner and executor roles must be membership-disjoint'
      USING ERRCODE = '42501';
  END IF;
END
$rollout_role_separation$;
