-- SPDX-License-Identifier: Apache-2.0
-- Cluster-scoped roles used by the consequence actuator.
--
-- Supabase applies custom roles separately from schema migrations. Keep these
-- Owner roles are NOLOGIN and membership-free. Grant only the executor roles
-- to deployment-provisioned, tenant-bound database logins.

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

DO $actuator_role_separation$
BEGIN
  IF EXISTS (
    WITH RECURSIVE
    executor_members(role_oid) AS (
      SELECT oid
      FROM pg_catalog.pg_roles
      WHERE rolname = 'consequence_actuator_executor'
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN executor_members AS inherited
        ON membership.roleid = inherited.role_oid
      WHERE membership.inherit_option OR membership.set_option
    ),
    owner_members(role_oid) AS (
      SELECT oid
      FROM pg_catalog.pg_roles
      WHERE rolname = 'consequence_actuator_store_owner'
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN owner_members AS inherited
        ON membership.roleid = inherited.role_oid
      WHERE membership.inherit_option OR membership.set_option
    )
    SELECT 1
    FROM executor_members
    JOIN pg_catalog.pg_roles AS candidate
      ON candidate.oid = executor_members.role_oid
    WHERE executor_members.role_oid IN (
        SELECT owner_members.role_oid FROM owner_members
      )
      OR candidate.rolsuper
      OR candidate.rolcreatedb
      OR candidate.rolcreaterole
      OR candidate.rolreplication
      OR candidate.rolbypassrls
      OR candidate.rolname IN ('anon', 'authenticated', 'service_role')
      OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS inherited_role
        WHERE (
            pg_catalog.pg_has_role(
              executor_members.role_oid,
              inherited_role.oid,
              'USAGE'
            )
            OR pg_catalog.pg_has_role(
              executor_members.role_oid,
              inherited_role.oid,
              'SET'
            )
          )
          AND (
            inherited_role.rolsuper
            OR inherited_role.rolcreatedb
            OR inherited_role.rolcreaterole
            OR inherited_role.rolreplication
            OR inherited_role.rolbypassrls
            OR inherited_role.rolname IN (
              'consequence_actuator_store_owner',
              'anon',
              'authenticated',
              'service_role'
            )
          )
      )
    UNION ALL
    SELECT 1
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid IN (membership.roleid, membership.member)
    WHERE owner_role.rolname = 'consequence_actuator_store_owner'
      AND (membership.inherit_option OR membership.set_option)
  )
  THEN
    RAISE EXCEPTION
      'consequence actuator owner and executor memberships must be least-privilege and disjoint'
      USING ERRCODE = '42501';
  END IF;
END
$actuator_role_separation$;

DO $rollout_role_separation$
BEGIN
  IF EXISTS (
    WITH RECURSIVE
    executor_members(role_oid) AS (
      SELECT oid
      FROM pg_catalog.pg_roles
      WHERE rolname = 'rollout_attempt_executor'
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN executor_members AS inherited
        ON membership.roleid = inherited.role_oid
      WHERE membership.inherit_option OR membership.set_option
    ),
    owner_members(role_oid) AS (
      SELECT oid
      FROM pg_catalog.pg_roles
      WHERE rolname = 'rollout_attempt_store_owner'
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN owner_members AS inherited
        ON membership.roleid = inherited.role_oid
      WHERE membership.inherit_option OR membership.set_option
    )
    SELECT 1
    FROM executor_members
    JOIN pg_catalog.pg_roles AS candidate
      ON candidate.oid = executor_members.role_oid
    WHERE executor_members.role_oid IN (
        SELECT owner_members.role_oid FROM owner_members
      )
      OR candidate.rolsuper
      OR candidate.rolcreatedb
      OR candidate.rolcreaterole
      OR candidate.rolreplication
      OR candidate.rolbypassrls
      OR candidate.rolname IN ('anon', 'authenticated', 'service_role')
      OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS inherited_role
        WHERE (
            pg_catalog.pg_has_role(
              executor_members.role_oid,
              inherited_role.oid,
              'USAGE'
            )
            OR pg_catalog.pg_has_role(
              executor_members.role_oid,
              inherited_role.oid,
              'SET'
            )
          )
          AND (
            inherited_role.rolsuper
            OR inherited_role.rolcreatedb
            OR inherited_role.rolcreaterole
            OR inherited_role.rolreplication
            OR inherited_role.rolbypassrls
            OR inherited_role.rolname IN (
              'rollout_attempt_store_owner',
              'anon',
              'authenticated',
              'service_role'
            )
          )
      )
    UNION ALL
    SELECT 1
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid IN (membership.roleid, membership.member)
    WHERE owner_role.rolname = 'rollout_attempt_store_owner'
      AND (membership.inherit_option OR membership.set_option)
  )
  THEN
    RAISE EXCEPTION
      'rollout attempt owner and executor roles must be membership-disjoint'
      USING ERRCODE = '42501';
  END IF;
END
$rollout_role_separation$;
