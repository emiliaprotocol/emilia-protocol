// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const legacy = readFileSync(
  new URL('../supabase/migrations/033_authority_registry.sql', import.meta.url),
  'utf8',
);
const repair = readFileSync(
  new URL(
    '../supabase/migrations/20260629224357_authority_subject_columns_replay_repair.sql',
    import.meta.url,
  ),
  'utf8',
);
const successor = readFileSync(
  new URL('../supabase/migrations/20260629224358_create_authorities_table.sql', import.meta.url),
  'utf8',
);
const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;
const DATABASE = 'ep_authority_fresh_replay_test';
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};

let admin: pg.Client;
let database: pg.Pool;

suite('authority schema fresh replay on PostgreSQL 17', () => {
  beforeAll(async () => {
    admin = new pg.Client({ ...baseConnection, database: process.env.PGDATABASE ?? 'ep_test' });
    await admin.connect();
    await admin.query(
      `SELECT pg_catalog.pg_terminate_backend(pid)
       FROM pg_catalog.pg_stat_activity
       WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()`,
      [DATABASE],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${DATABASE}`);
    await admin.query(`CREATE DATABASE ${DATABASE}`);
    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 2 });
    await database.query(`
      DO $$ BEGIN CREATE ROLE service_role NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    `);
    await database.query(legacy);
    await database.query(repair);
    await database.query(successor);
  });

  afterAll(async () => {
    if (database) await database.end();
    if (admin) {
      await admin.query(
        `SELECT pg_catalog.pg_terminate_backend(pid)
         FROM pg_catalog.pg_stat_activity
         WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()`,
        [DATABASE],
      );
      await admin.query(`DROP DATABASE IF EXISTS ${DATABASE}`);
      await admin.end();
    }
  });

  it('replays through the successor and permits the expanded authority roles', async () => {
    const columns = await database.query<{ column_name: string }>(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'authorities'
        AND column_name = ANY($1::text[])
      ORDER BY column_name
    `, [['assurance_class', 'organization_id', 'subject_ref', 'subject_type']]);
    expect(columns.rows.map(({ column_name }) => column_name)).toEqual([
      'assurance_class',
      'organization_id',
      'subject_ref',
      'subject_type',
    ]);

    await expect(database.query(`
      INSERT INTO public.authorities (
        key_id, public_key, role, organization_id, subject_type, subject_ref
      ) VALUES (
        'key:fresh-replay', 'public-key', 'policy_admin',
        'org:1', 'human_approver', 'approver:1'
      )
    `)).resolves.toBeDefined();
  });
});
