// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const migration = readFileSync(
  new URL(
    "../supabase/migrations/20260725160000_rollout_attempt_store.sql",
    import.meta.url,
  ),
  "utf8",
);
const suite =
  process.env.INTEGRATION_POSTGRES === "1"
    ? describe.sequential
    : describe.skip;

const OWNER_ROLE = "rollout_attempt_store_owner";
const EXECUTOR_ROLE = "rollout_attempt_executor";
const CLEAN_LOGIN = "rollout_attempt_clean_test_login";
const OWNER_LOGIN = "rollout_attempt_owner_test_login";
const OWNER_BRIDGE = "rollout_attempt_owner_test_bridge";
const OWNER_POLLUTION_LOGIN = "rollout_attempt_owner_pollution_login";
const BYPASS_LOGIN = "rollout_attempt_bypass_test_login";
const BYPASS_BRIDGE = "rollout_attempt_bypass_test_bridge";
const LOGIN_PASSWORD = "ep-role-graph-test-password";
const TEST_ROLES = [
  CLEAN_LOGIN,
  OWNER_LOGIN,
  OWNER_POLLUTION_LOGIN,
  BYPASS_LOGIN,
  OWNER_BRIDGE,
  BYPASS_BRIDGE,
  EXECUTOR_ROLE,
  OWNER_ROLE,
];

const connection = {
  host: process.env.PGHOST ?? "localhost",
  port: Number.parseInt(process.env.PGPORT ?? "5433", 10),
  database: process.env.PGDATABASE ?? "ep_test",
  user: process.env.PGUSER ?? "ep_test",
  password: process.env.PGPASSWORD ?? "ep_test",
};

let admin: pg.Pool;
let cleanupAllowed = false;

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function cleanupRoleGraph(): Promise<void> {
  await admin.query(
    `SELECT pg_catalog.pg_terminate_backend(pid)
     FROM pg_catalog.pg_stat_activity
     WHERE usename = ANY($1::text[])
       AND pid <> pg_catalog.pg_backend_pid()`,
    [[CLEAN_LOGIN, OWNER_LOGIN, BYPASS_LOGIN]],
  );
  await admin.query("DROP SCHEMA IF EXISTS rollout_attempt_private CASCADE");

  for (const role of TEST_ROLES) {
    const exists = await admin.query<{ exists: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1
       ) AS exists`,
      [role],
    );
    if (!exists.rows[0].exists) continue;
    await admin.query(`DROP OWNED BY ${identifier(role)} CASCADE`);
    await admin.query(`DROP ROLE ${identifier(role)}`);
  }
}

async function createLogin(role: string): Promise<void> {
  await admin.query(`
    CREATE ROLE ${identifier(role)}
      LOGIN PASSWORD '${LOGIN_PASSWORD}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  `);
}

async function callAs(
  role: string,
  operation: string,
  payload: unknown,
): Promise<Record<string, unknown>> {
  const client = new pg.Client({
    ...connection,
    user: role,
    password: LOGIN_PASSWORD,
  });
  await client.connect();
  try {
    const result = await client.query<{ response: Record<string, unknown> }>(
      `SELECT rollout_attempt_private.apply_operation($1, $2) AS response`,
      [operation, JSON.stringify(payload)],
    );
    return result.rows[0].response;
  } finally {
    await client.end();
  }
}

function validClaim(): Record<string, string> {
  const authorizationId = "authorization:test";
  const rolloutNonce = "role_graph_nonce_000001";
  const requestSha256 = "1".repeat(64);
  const preResourceVersion = "resource-version-1";
  const canonicalKey = JSON.stringify({
    authorization_id: authorizationId,
    pre_resource_version: preResourceVersion,
    request_sha256: requestSha256,
    rollout_nonce: rolloutNonce,
  });
  const claimSha256 = createHash("sha256")
    .update("EMILIA-DEPLOYMENT-ATTEMPT-CLAIM-V1")
    .update(Buffer.from([0]))
    .update(canonicalKey)
    .digest("hex");

  return {
    schema: "emilia-deployment-attempt-claim.v1",
    claim_sha256: claimSha256,
    authorization_id: authorizationId,
    rollout_nonce: rolloutNonce,
    request_sha256: requestSha256,
    pre_resource_version: preResourceVersion,
    project_id: "test-project",
    region: "us-central1",
    release_id: "release-1",
    transition: "apply-decision-1",
    service: "decision",
    config_sha256: "2".repeat(64),
    deployer_principal:
      "serviceAccount:deployer@test-project.iam.gserviceaccount.com",
    workflow_ref:
      "emiliaprotocol/emilia-protocol/.github/workflows/consequence-control-deploy.yml@refs/heads/main",
    workflow_sha: "3".repeat(40),
    wif_provider:
      "projects/123/locations/global/workloadIdentityPools/test-pool/providers/test-provider",
  };
}

suite("rollout-attempt dirty role graph on PostgreSQL 17", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ ...connection, max: 4 });
    const environment = await admin.query<{
      database: string;
      server_version_num: string;
      is_superuser: boolean;
    }>(`
      SELECT
        pg_catalog.current_database() AS database,
        pg_catalog.current_setting('server_version_num') AS server_version_num,
        current_setting('is_superuser')::boolean AS is_superuser
    `);
    expect(environment.rows[0].database).toBe(connection.database);
    expect(
      Number.parseInt(environment.rows[0].server_version_num, 10),
    ).toBeGreaterThanOrEqual(170000);
    expect(
      Number.parseInt(environment.rows[0].server_version_num, 10),
    ).toBeLessThan(180000);
    expect(environment.rows[0].is_superuser).toBe(true);
    cleanupAllowed = true;

    await cleanupRoleGraph();
    await admin.query(`
      CREATE SCHEMA IF NOT EXISTS extensions;
      CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
      DO $$ BEGIN
        CREATE ROLE anon NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL;
      END $$;
      DO $$ BEGIN
        CREATE ROLE authenticated NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL;
      END $$;
      DO $$ BEGIN
        CREATE ROLE service_role NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL;
      END $$;
    `);
  });

  afterAll(async () => {
    if (!admin) return;
    try {
      if (cleanupAllowed) await cleanupRoleGraph();
    } finally {
      await admin.end();
    }
  });

  it("rejects owner-to-executor membership pollution during migration", async () => {
    await admin.query(`
      CREATE ROLE ${identifier(OWNER_ROLE)} NOLOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
      CREATE ROLE ${identifier(EXECUTOR_ROLE)} NOLOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
      GRANT ${identifier(OWNER_ROLE)} TO ${identifier(EXECUTOR_ROLE)}
        WITH INHERIT TRUE;
    `);

    try {
      await expect(admin.query(migration)).rejects.toMatchObject({
        code: "42501",
        message:
          "rollout attempt owner and executor roles must be membership-disjoint",
      });
    } finally {
      await admin.query(
        `REVOKE ${identifier(OWNER_ROLE)} FROM ${identifier(EXECUTOR_ROLE)}`,
      );
    }
  });

  it("rejects an arbitrary login inheriting the owner during migration", async () => {
    await createLogin(OWNER_POLLUTION_LOGIN);
    await admin.query(
      `GRANT ${identifier(OWNER_ROLE)} TO ${identifier(OWNER_POLLUTION_LOGIN)}
        WITH INHERIT TRUE`,
    );

    try {
      await expect(admin.query(migration)).rejects.toMatchObject({
        code: "42501",
        message:
          "rollout attempt owner and executor roles must be membership-disjoint",
      });
    } finally {
      await admin.query(
        `REVOKE ${identifier(OWNER_ROLE)} FROM ${identifier(OWNER_POLLUTION_LOGIN)}`,
      );
    }
  });

  it("rejects a BYPASSRLS-contaminated executor graph during migration", async () => {
    await createLogin(BYPASS_LOGIN);
    await admin.query(`
      CREATE ROLE ${identifier(BYPASS_BRIDGE)} NOLOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
      GRANT ${identifier(BYPASS_BRIDGE)} TO ${identifier(BYPASS_LOGIN)}
        WITH INHERIT TRUE;
      GRANT ${identifier(EXECUTOR_ROLE)} TO ${identifier(BYPASS_LOGIN)}
        WITH INHERIT TRUE;
    `);

    try {
      await expect(admin.query(migration)).rejects.toMatchObject({
        code: "42501",
        message:
          "rollout attempt owner and executor roles must be membership-disjoint",
      });
    } finally {
      await admin.query(`
        REVOKE ${identifier(BYPASS_BRIDGE)} FROM ${identifier(BYPASS_LOGIN)};
        REVOKE ${identifier(EXECUTOR_ROLE)} FROM ${identifier(BYPASS_LOGIN)};
      `);
    }
  });

  it("installs after the role graph is clean", async () => {
    await admin.query(migration);
    const installed = await admin.query<{
      owner: string;
      executor_can_login: boolean;
    }>(`
      SELECT
        pg_catalog.pg_get_userbyid(nspowner) AS owner,
        executor.rolcanlogin AS executor_can_login
      FROM pg_catalog.pg_namespace
      CROSS JOIN pg_catalog.pg_roles AS executor
      WHERE nspname = 'rollout_attempt_private'
        AND executor.rolname = '${EXECUTOR_ROLE}'
    `);
    expect(installed.rows).toEqual([
      {
        owner: OWNER_ROLE,
        executor_can_login: false,
      },
    ]);
  });

  it("publishes qualified bare names and exact identity signatures", async () => {
    const snapshot = await admin.query<{ functions: string[] }>(`
      SELECT public.gov_schema_reconcile_introspect() -> 'functions'
        AS functions
    `);

    expect(snapshot.rows[0].functions).toEqual(expect.arrayContaining([
      "rollout_attempt_private.apply_operation",
      "rollout_attempt_private.apply_operation(text,text)",
    ]));
  });

  it("publishes catalog-derived rollout table, function, and role assertions", async () => {
    const assertions = await admin.query<{ assertion: string }>(`
      SELECT assertion
      FROM public.gov_consequence_control_security_assertions()
        AS security_assertions(assertion)
      WHERE assertion LIKE 'contract:%rollout%'
      ORDER BY assertion
    `);

    expect(assertions.rows.map(({ assertion }) => assertion)).toEqual([
      "contract:function:rollout_attempt_private.apply_operation(text,text):owner-definer-empty-search-path-executor-only",
      "contract:roles:rollout-attempt:least-privilege-membership-disjoint",
      "contract:table:rollout_attempt_private.claims:owner-force-rls-owner-only-acl",
      "contract:table:rollout_attempt_private.terminals:owner-force-rls-owner-only-acl",
      "contract:trigger:rollout_attempt_private.claims.rollout_attempt_claims_no_truncate:exact-before-truncate-statement-append-only",
      "contract:trigger:rollout_attempt_private.claims.rollout_attempt_claims_no_update_delete:exact-before-update-delete-row-append-only",
      "contract:trigger:rollout_attempt_private.terminals.rollout_attempt_terminals_no_truncate:exact-before-truncate-statement-append-only",
      "contract:trigger:rollout_attempt_private.terminals.rollout_attempt_terminals_no_update_delete:exact-before-update-delete-row-append-only",
    ]);
  });

  it("removes the live contract token when any rollout append-only trigger is dropped", async () => {
    const expected = [
      [
        "rollout_attempt_private",
        "claims",
        "rollout_attempt_claims_no_update_delete",
        "contract:trigger:rollout_attempt_private.claims.rollout_attempt_claims_no_update_delete:exact-before-update-delete-row-append-only",
      ],
      [
        "rollout_attempt_private",
        "claims",
        "rollout_attempt_claims_no_truncate",
        "contract:trigger:rollout_attempt_private.claims.rollout_attempt_claims_no_truncate:exact-before-truncate-statement-append-only",
      ],
      [
        "rollout_attempt_private",
        "terminals",
        "rollout_attempt_terminals_no_update_delete",
        "contract:trigger:rollout_attempt_private.terminals.rollout_attempt_terminals_no_update_delete:exact-before-update-delete-row-append-only",
      ],
      [
        "rollout_attempt_private",
        "terminals",
        "rollout_attempt_terminals_no_truncate",
        "contract:trigger:rollout_attempt_private.terminals.rollout_attempt_terminals_no_truncate:exact-before-truncate-statement-append-only",
      ],
    ] as const;

    for (const [schemaName, tableName, triggerName, token] of expected) {
      const definition = await admin.query<{ definition: string }>(`
        SELECT pg_catalog.pg_get_triggerdef(trigger.oid, TRUE) AS definition
        FROM pg_catalog.pg_trigger AS trigger
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = trigger.tgrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = $1
          AND relation.relname = $2
          AND trigger.tgname = $3
          AND NOT trigger.tgisinternal
      `, [schemaName, tableName, triggerName]);
      expect(definition.rows).toHaveLength(1);

      await admin.query(
        `DROP TRIGGER ${identifier(triggerName)} ON ${identifier(schemaName)}.${identifier(tableName)}`,
      );
      const missing = await admin.query<{ present: boolean }>(`
        SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
          ? $1 AS present
      `, [token]);
      expect(missing.rows).toEqual([{ present: false }]);

      await admin.query(definition.rows[0].definition);
      const restored = await admin.query<{ present: boolean }>(`
        SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
          ? $1 AS present
      `, [token]);
      expect(restored.rows).toEqual([{ present: true }]);
    }
  });

  it("requires the exact rollout rejection-function definition and SECURITY DEFINER posture", async () => {
    const signature = "rollout_attempt_private.reject_append_only_mutation()";
    const original = await admin.query<{ definition: string }>(`
      SELECT pg_catalog.pg_get_functiondef($1::regprocedure) AS definition
    `, [signature]);
    const triggerTokenCount = async (): Promise<number> => admin.query<{
      count: number;
    }>(`
      SELECT count(*)::integer AS count
      FROM pg_catalog.jsonb_array_elements_text(
        public.gov_schema_reconcile_introspect() -> 'functions'
      ) AS value(token)
      WHERE token LIKE 'contract:trigger:rollout_attempt_private.%'
    `).then(({ rows }) => rows[0].count);

    expect(await triggerTokenCount()).toBe(4);
    await admin.query(`ALTER FUNCTION ${signature} SECURITY INVOKER`);
    expect(await triggerTokenCount()).toBe(0);
    await admin.query(`ALTER FUNCTION ${signature} SECURITY DEFINER`);
    expect(await triggerTokenCount()).toBe(4);

    await admin.query(`
      CREATE OR REPLACE FUNCTION ${signature}
      RETURNS TRIGGER
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = ''
      AS $mutated$
      BEGIN
        RAISE EXCEPTION 'mutated rejection body' USING ERRCODE = '55000';
      END
      $mutated$
    `);
    expect(await triggerTokenCount()).toBe(0);
    await admin.query(original.rows[0].definition);
    expect(await triggerTokenCount()).toBe(4);
  });

  it("allows a clean executor login to claim an attempt", async () => {
    await createLogin(CLEAN_LOGIN);
    await admin.query(
      `GRANT ${identifier(EXECUTOR_ROLE)} TO ${identifier(CLEAN_LOGIN)}
        WITH INHERIT TRUE`,
    );

    const claim = validClaim();
    await expect(callAs(CLEAN_LOGIN, "claim", claim)).resolves.toMatchObject({
      operation: "claim",
      status: "claimed",
      claim_sha256: claim.claim_sha256,
    });
  });

  it("detects an arbitrary owner member after reproducing direct private-table access", async () => {
    await admin.query(
      `GRANT ${identifier(OWNER_ROLE)} TO ${identifier(OWNER_POLLUTION_LOGIN)}
        WITH INHERIT TRUE`,
    );
    try {
      const client = new pg.Client({
        ...connection,
        user: OWNER_POLLUTION_LOGIN,
        password: LOGIN_PASSWORD,
      });
      await client.connect();
      try {
        const exposed = await client.query<{ count: string }>(
          "SELECT count(*)::text AS count FROM rollout_attempt_private.claims",
        );
        expect(Number.parseInt(exposed.rows[0].count, 10)).toBeGreaterThan(0);
      } finally {
        await client.end();
      }

      const assertion = await admin.query<{ present: boolean }>(`
        SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
          ? 'contract:roles:rollout-attempt:least-privilege-membership-disjoint'
          AS present
      `);
      expect(assertion.rows).toEqual([{ present: false }]);
    } finally {
      await admin.query(
        `REVOKE ${identifier(OWNER_ROLE)} FROM ${identifier(OWNER_POLLUTION_LOGIN)}`,
      );
    }

    const restored = await admin.query<{ present: boolean }>(`
      SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
        ? 'contract:roles:rollout-attempt:least-privilege-membership-disjoint'
        AS present
    `);
    expect(restored.rows).toEqual([{ present: true }]);
  });

  it("recovers exact claim and terminal acknowledgements without accepting conflicts", async () => {
    const claim = validClaim();
    await expect(callAs(CLEAN_LOGIN, "claim", claim)).resolves.toMatchObject({
      operation: "claim",
      status: "recovered",
      claim_sha256: claim.claim_sha256,
      final_resource_version: null,
    });

    const terminal = {
      schema: "emilia-deployment-attempt-store-operation.v1",
      operation: "complete",
      claim,
      outcome: "applied",
      final_resource_version: "resource-version-2",
    };
    await expect(
      callAs(CLEAN_LOGIN, "complete", terminal),
    ).resolves.toMatchObject({
      operation: "complete",
      status: "completed",
      final_resource_version: "resource-version-2",
    });
    await expect(
      callAs(CLEAN_LOGIN, "complete", terminal),
    ).resolves.toMatchObject({
      operation: "complete",
      status: "completed",
      final_resource_version: "resource-version-2",
    });
    await expect(callAs(CLEAN_LOGIN, "claim", claim)).resolves.toMatchObject({
      operation: "claim",
      status: "completed",
      final_resource_version: "resource-version-2",
    });

    await expect(callAs(CLEAN_LOGIN, "reconcile", {
      ...terminal,
      operation: "reconcile",
      outcome: "not-applied",
    })).rejects.toMatchObject({
      code: "55000",
      message:
        "attempt is unclaimed, terminal conflict, or claim binding mismatched",
    });
  });

  it("rejects an executor login with transitive owner membership", async () => {
    await createLogin(OWNER_LOGIN);
    await admin.query(`
      CREATE ROLE ${identifier(OWNER_BRIDGE)} NOLOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
      GRANT ${identifier(OWNER_ROLE)} TO ${identifier(OWNER_BRIDGE)}
        WITH INHERIT TRUE;
      GRANT ${identifier(OWNER_BRIDGE)} TO ${identifier(OWNER_LOGIN)}
        WITH INHERIT TRUE;
      GRANT ${identifier(EXECUTOR_ROLE)} TO ${identifier(OWNER_LOGIN)}
        WITH INHERIT TRUE;
    `);

    try {
      const assertion = await admin.query<{ present: boolean }>(`
        SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
          ? 'contract:roles:rollout-attempt:least-privilege-membership-disjoint'
          AS present
      `);
      expect(assertion.rows).toEqual([{ present: false }]);
      await expect(
        callAs(OWNER_LOGIN, "claim", validClaim()),
      ).rejects.toMatchObject({
        code: "42501",
        message: "dedicated least-privilege rollout attempt executor is required",
      });
    } finally {
      await admin.query(`
        REVOKE ${identifier(OWNER_ROLE)} FROM ${identifier(OWNER_BRIDGE)};
        REVOKE ${identifier(OWNER_BRIDGE)} FROM ${identifier(OWNER_LOGIN)};
        REVOKE ${identifier(EXECUTOR_ROLE)} FROM ${identifier(OWNER_LOGIN)};
      `);
    }

    const restored = await admin.query<{ present: boolean }>(`
      SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
        ? 'contract:roles:rollout-attempt:least-privilege-membership-disjoint'
        AS present
    `);
    expect(restored.rows).toEqual([{ present: true }]);
  });

  it("rejects an executor login inheriting BYPASSRLS", async () => {
    await admin.query(`
      GRANT ${identifier(BYPASS_BRIDGE)} TO ${identifier(BYPASS_LOGIN)}
        WITH INHERIT TRUE;
      GRANT ${identifier(EXECUTOR_ROLE)} TO ${identifier(BYPASS_LOGIN)}
        WITH INHERIT TRUE;
    `);

    try {
      const assertion = await admin.query<{ present: boolean }>(`
        SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
          ? 'contract:roles:rollout-attempt:least-privilege-membership-disjoint'
          AS present
      `);
      expect(assertion.rows).toEqual([{ present: false }]);
      await expect(
        callAs(BYPASS_LOGIN, "claim", validClaim()),
      ).rejects.toMatchObject({
        code: "42501",
        message: "dedicated least-privilege rollout attempt executor is required",
      });
    } finally {
      await admin.query(`
        REVOKE ${identifier(BYPASS_BRIDGE)} FROM ${identifier(BYPASS_LOGIN)};
        REVOKE ${identifier(EXECUTOR_ROLE)} FROM ${identifier(BYPASS_LOGIN)};
      `);
    }

    const restored = await admin.query<{ present: boolean }>(`
      SELECT (public.gov_schema_reconcile_introspect() -> 'functions')
        ? 'contract:roles:rollout-attempt:least-privilege-membership-disjoint'
        AS present
    `);
    expect(restored.rows).toEqual([{ present: true }]);
  });
});
