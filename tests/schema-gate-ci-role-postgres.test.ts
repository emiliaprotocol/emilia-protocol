// SPDX-License-Identifier: Apache-2.0
//
// Proves the schema CI role's authority by execution: the migration and the
// runbook's login provisioning run in a disposable database, a real
// password-authenticated connection logs in as the login, runs the query CI
// runs, and every read, write, create and escalation attempt is refused.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

function read(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function extract(source: string, pattern: RegExp, label: string): string {
  const match = source.match(pattern);
  if (!match) throw new Error(`could not extract ${label}`);
  return match[0];
}

const migration = read('supabase/migrations/20260926035734_schema_gate_ci_role.sql');
const runbook = read('docs/operations/SCHEMA-GATE-CI.md');
// The live definitions the gate calls, not stand-ins.
const contractFunction = extract(
  read('supabase/migrations/20260725210000_schema_contract_identity_arguments.sql'),
  /CREATE OR REPLACE FUNCTION public\.gov_schema_contract_introspect\(\)[\s\S]+?\n\$\$;/,
  'contract introspection function',
);
const reconcileFunction = extract(
  read('supabase/migrations/20260728210700_open_exposure_ledger.sql'),
  /CREATE OR REPLACE FUNCTION public\.gov_schema_reconcile_introspect\(\)[\s\S]+?\n\$reconcile\$;/,
  'reconcile introspection function',
);
// The exact statement the schema-security job sends.
const ciQuery = extract(
  read('scripts/_schema-introspect.mts'),
  /select\s+public\.gov_schema_contract_introspect\(\) as snap,\s+public\.gov_schema_reconcile_introspect\(\) as reconcile/i,
  'CI introspection query',
);

function runbookSql(name: string): string {
  for (const [, block] of runbook.matchAll(/```sql\n([\s\S]*?)```/g)) {
    if (block.startsWith(`-- runbook: ${name}\n`)) return block;
  }
  throw new Error(`runbook has no sql block named ${name}`);
}

const GROUP = 'schema_gate_ci';
const LOGIN = 'schema_gate_ci_gha';
const PRIVILEGED = 'schema_gate_ci_test_privileged';
const suffix = randomBytes(6).toString('hex');
const DATABASE = `schema_gate_ci_${suffix}_test`;
const password = randomBytes(24).toString('hex');
const secret = `row-secret-${randomBytes(12).toString('hex')}`;

const server = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};
const adminDatabase = process.env.PGDATABASE ?? 'ep_test';

const suite = process.env.INTEGRATION_POSTGRES === '1' ? describe : describe.skip;

let cluster: pg.Client;
let admin: pg.Client;
let login: pg.Client;
let databaseCreated = false;
let rolesCreated = false;

async function sqlState(client: pg.Client, statement: string): Promise<string> {
  try {
    await client.query(statement);
  } catch (error) {
    return String((error as { code?: string }).code);
  }
  return 'succeeded';
}

async function refusal(client: pg.Client, statement: string): Promise<string> {
  try {
    await client.query(statement);
  } catch (error) {
    return String((error as Error).message);
  }
  return 'succeeded';
}

async function dropRoles(): Promise<void> {
  for (const role of [LOGIN, GROUP, PRIVILEGED]) {
    const found = await cluster.query('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1', [role]);
    if (found.rowCount) await cluster.query(`DROP ROLE ${role}`);
  }
}

suite('schema CI role, executed against PostgreSQL', () => {
  beforeAll(async () => {
    cluster = new pg.Client({ ...server, database: adminDatabase });
    await cluster.connect();
    const occupied = await cluster.query(
      'SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])',
      [[GROUP, LOGIN, PRIVILEGED]],
    );
    if (occupied.rowCount) {
      throw new Error(`refusing to reuse existing roles: ${occupied.rows.map((row) => row.rolname).join(', ')}`);
    }
    await cluster.query(`CREATE DATABASE ${DATABASE}`);
    databaseCreated = true;
    rolesCreated = true;

    admin = new pg.Client({ ...server, database: DATABASE });
    await admin.connect();
    await admin.query(`
      CREATE ROLE ${PRIVILEGED} NOLOGIN;
      CREATE TABLE public.schema_gate_app_rows (id integer PRIMARY KEY, secret text NOT NULL);
      INSERT INTO public.schema_gate_app_rows VALUES (1, '${secret}');
      GRANT ALL ON public.schema_gate_app_rows TO ${PRIVILEGED};
      CREATE SEQUENCE public.schema_gate_app_sequence;

      -- The live reconcile function calls these; the login must not.
      CREATE FUNCTION public.gov_consequence_control_security_assertions()
        RETURNS SETOF text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
        AS $$ SELECT 'consequence-control-assertions-ran'::text $$;
      CREATE FUNCTION public.gov_open_exposure_security_assertions()
        RETURNS SETOF text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
        AS $$ SELECT 'open-exposure-assertions-ran'::text $$;
      REVOKE ALL ON FUNCTION public.gov_consequence_control_security_assertions() FROM PUBLIC;
      REVOKE ALL ON FUNCTION public.gov_open_exposure_security_assertions() FROM PUBLIC;

      ${contractFunction}
      ${reconcileFunction}
      REVOKE ALL ON FUNCTION public.gov_schema_contract_introspect() FROM PUBLIC;
      REVOKE ALL ON FUNCTION public.gov_schema_reconcile_introspect() FROM PUBLIC;

      -- PostgreSQL's default: a new function is executable by PUBLIC.
      CREATE FUNCTION public.schema_gate_public_definer_probe()
        RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
        AS $$ SELECT secret FROM public.schema_gate_app_rows WHERE id = 1 $$;
    `);

    await admin.query(migration);
    await admin.query(migration);
    await admin.query(runbookSql('provision login'));
    await admin.query(`ALTER ROLE ${LOGIN} PASSWORD '${password}'`);
    // A repeated run after the login exists must still pass.
    await admin.query(migration);

    login = new pg.Client({ ...server, database: DATABASE, user: LOGIN, password });
    await login.connect();
  });

  afterAll(async () => {
    await login?.end().catch(() => undefined);
    await admin?.end().catch(() => undefined);
    if (cluster) {
      try {
        if (databaseCreated) await cluster.query(`DROP DATABASE IF EXISTS ${DATABASE} WITH (FORCE)`);
        if (rolesCreated) await dropRoles();
      } finally {
        await cluster.end();
      }
    }
  });

  it('authenticates as the login with no elevated attribute', async () => {
    const identity = await login.query(`
      SELECT current_user, session_user, rolsuper, rolcreatedb, rolcreaterole,
        rolreplication, rolbypassrls
      FROM pg_catalog.pg_roles WHERE rolname = current_user
    `);
    expect(identity.rows[0]).toEqual({
      current_user: LOGIN,
      session_user: LOGIN,
      rolsuper: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolreplication: false,
      rolbypassrls: false,
    });
  });

  it('runs the exact CI introspection query and receives metadata, not rows', async () => {
    const result = await login.query(ciQuery);
    const { snap, reconcile } = result.rows[0];
    expect(snap.tables).toContain('schema_gate_app_rows');
    expect(snap.columns).toContainEqual({
      t: 'schema_gate_app_rows', c: 'secret', type: 'text', nullable: 'NO',
    });
    expect(reconcile.tables).toContain('schema_gate_app_rows');
    expect(reconcile.functions).toEqual(expect.arrayContaining([
      'consequence-control-assertions-ran',
      'open-exposure-assertions-ran',
    ]));
    expect(JSON.stringify(result.rows)).not.toContain(secret);
  });

  it('refuses every direct read and write of application data', async () => {
    const statements = [
      'SELECT secret FROM public.schema_gate_app_rows',
      "INSERT INTO public.schema_gate_app_rows VALUES (2, 'x')",
      "UPDATE public.schema_gate_app_rows SET secret = 'x'",
      'DELETE FROM public.schema_gate_app_rows',
      'TRUNCATE public.schema_gate_app_rows',
      "SELECT nextval('public.schema_gate_app_sequence')",
      'SELECT public.gov_consequence_control_security_assertions()',
      'SELECT public.gov_open_exposure_security_assertions()',
    ];
    for (const statement of statements) {
      expect([statement, await sqlState(login, statement)]).toEqual([statement, '42501']);
    }
  });

  it('refuses to create, alter, drop or grant', async () => {
    const statements = [
      'CREATE TABLE public.schema_gate_created (id integer)',
      'CREATE VIEW public.schema_gate_view AS SELECT 1 AS one',
      'CREATE FUNCTION public.schema_gate_created() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$',
      'CREATE SCHEMA schema_gate_created',
      'ALTER TABLE public.schema_gate_app_rows ADD COLUMN extra integer',
      'DROP TABLE public.schema_gate_app_rows',
      `GRANT SELECT ON public.schema_gate_app_rows TO ${LOGIN}`,
      'CREATE ROLE schema_gate_created',
      'CREATE DATABASE schema_gate_created',
    ];
    for (const statement of statements) {
      expect([statement, await sqlState(login, statement)]).toEqual([statement, '42501']);
    }
  });

  it('cannot escalate to any role outside its group', async () => {
    const statements = [
      `SET ROLE ${PRIVILEGED}`,
      `SET ROLE ${server.user}`,
      `SET SESSION AUTHORIZATION ${server.user}`,
      `ALTER ROLE ${LOGIN} BYPASSRLS`,
      `ALTER ROLE ${LOGIN} SUPERUSER`,
      `ALTER ROLE ${GROUP} LOGIN`,
      `GRANT ${PRIVILEGED} TO ${LOGIN}`,
      `GRANT ${GROUP} TO ${PRIVILEGED}`,
    ];
    for (const statement of statements) {
      expect([statement, await sqlState(login, statement)]).toEqual([statement, '42501']);
    }
    // Its own group is reachable and still reads no rows.
    await login.query(`SET ROLE ${GROUP}`);
    expect(await sqlState(login, 'SELECT secret FROM public.schema_gate_app_rows')).toBe('42501');
    await login.query('RESET ROLE');
  });

  it('inherits PUBLIC function grants, and the runbook audit lists and clears them', async () => {
    const audit = runbookSql('audit functions');
    // The caveat is real: a PUBLIC-executable definer function returns rows.
    const leaked = await login.query('SELECT public.schema_gate_public_definer_probe() AS value');
    expect(leaked.rows[0].value).toBe(secret);
    const before = await admin.query(audit);
    expect(before.rows.filter((row) => row.security_definer)).toEqual([
      expect.objectContaining({ proname: 'gov_schema_contract_introspect', via_public: false }),
      expect.objectContaining({ proname: 'gov_schema_reconcile_introspect', via_public: false }),
      expect.objectContaining({ proname: 'schema_gate_public_definer_probe', via_public: true }),
    ]);

    await admin.query('REVOKE EXECUTE ON FUNCTION public.schema_gate_public_definer_probe() FROM PUBLIC');
    expect(await sqlState(login, 'SELECT public.schema_gate_public_definer_probe()')).toBe('42501');
    const after = await admin.query(audit);
    expect(after.rows.map((row) => [row.proname, row.security_definer, row.via_public])).toEqual([
      ['gov_schema_contract_introspect', true, false],
      ['gov_schema_reconcile_introspect', true, false],
    ]);
  });

  it('passes every other runbook audit on a stock database', async () => {
    expect((await admin.query(runbookSql('audit role attributes'))).rows).toEqual([
      {
        rolname: GROUP, rolcanlogin: false, rolinherit: true, rolsuper: false,
        rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false,
      },
      {
        rolname: LOGIN, rolcanlogin: true, rolinherit: true, rolsuper: false,
        rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false,
      },
    ]);
    expect((await admin.query(runbookSql('audit reachable roles'))).rows).toEqual([{ rolname: GROUP }]);
    expect((await admin.query(runbookSql('audit database privileges'))).rows).toEqual([
      { can_create: false, can_connect: true, can_temporary: true },
    ]);
    expect((await admin.query(runbookSql('audit schemas'))).rows).toEqual([
      { nspname: 'public', can_use: true, can_create: false },
    ]);
    expect((await admin.query(runbookSql('audit relations'))).rows).toEqual([]);
  });

  it('refuses, with a reason, to repurpose a role that has drifted', async () => {
    const drifts: Array<[string, string, string]> = [
      [`ALTER ROLE ${GROUP} LOGIN`, `ALTER ROLE ${GROUP} NOLOGIN`, 'can log in or holds an elevated attribute'],
      [`ALTER ROLE ${GROUP} BYPASSRLS`, `ALTER ROLE ${GROUP} NOBYPASSRLS`, 'can log in or holds an elevated attribute'],
      [`GRANT ${PRIVILEGED} TO ${GROUP}`, `REVOKE ${PRIVILEGED} FROM ${GROUP}`, 'is a member of another role'],
      [`GRANT SELECT ON public.schema_gate_app_rows TO ${GROUP}`, `REVOKE SELECT ON public.schema_gate_app_rows FROM ${GROUP}`, 'outside its schema-introspection contract'],
      [`GRANT SELECT (secret) ON public.schema_gate_app_rows TO ${GROUP}`, `REVOKE SELECT (secret) ON public.schema_gate_app_rows FROM ${GROUP}`, 'outside its schema-introspection contract'],
      [`GRANT USAGE ON SEQUENCE public.schema_gate_app_sequence TO ${GROUP}`, `REVOKE USAGE ON SEQUENCE public.schema_gate_app_sequence FROM ${GROUP}`, 'outside its schema-introspection contract'],
      [`GRANT CREATE ON DATABASE ${DATABASE} TO ${GROUP}`, `REVOKE CREATE ON DATABASE ${DATABASE} FROM ${GROUP}`, 'outside its schema-introspection contract'],
      [`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO ${GROUP}`, `ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM ${GROUP}`, 'outside its schema-introspection contract'],
      [`GRANT EXECUTE ON FUNCTION public.schema_gate_public_definer_probe() TO ${GROUP}`, `REVOKE EXECUTE ON FUNCTION public.schema_gate_public_definer_probe() FROM ${GROUP}`, 'outside its schema-introspection contract'],
      [`CREATE POLICY schema_gate_policy ON public.schema_gate_app_rows TO ${GROUP} USING (true)`, 'DROP POLICY schema_gate_policy ON public.schema_gate_app_rows', 'outside its schema-introspection contract'],
      [`ALTER TABLE public.schema_gate_app_rows OWNER TO ${GROUP}`, `ALTER TABLE public.schema_gate_app_rows OWNER TO ${server.user}`, 'outside its schema-introspection contract'],
      [`GRANT CREATE ON SCHEMA public TO ${GROUP}`, `REVOKE CREATE ON SCHEMA public FROM ${GROUP}`, 'more than USAGE on schema public'],
      [`GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect() TO ${GROUP} WITH GRANT OPTION`, `REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION public.gov_schema_contract_introspect() FROM ${GROUP}`, 'EXECUTE on the introspection functions'],
    ];
    for (const [drift, restore, reason] of drifts) {
      await admin.query(drift);
      try {
        const message = await refusal(admin, migration);
        expect([drift, message]).toEqual([drift, expect.stringContaining(`schema_gate_ci refused: `)]);
        expect([drift, message]).toEqual([drift, expect.stringContaining(reason)]);
      } finally {
        await admin.query(restore);
      }
    }
    // Restored to its contract, the migration runs again.
    await admin.query(migration);
  });
});
