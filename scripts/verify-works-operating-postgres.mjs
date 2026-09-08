// SPDX-License-Identifier: Apache-2.0
// Real PostgreSQL integration checks. This script only accepts a local Unix
// socket and creates a new, isolated database; it never targets a deployment.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';

const socket = process.env.WORKS_TEST_PG_SOCKET;
if (!socket?.startsWith('/private/tmp/emilia-marketplace-pg.')) {
  throw new Error('Set WORKS_TEST_PG_SOCKET to the isolated local PostgreSQL socket.');
}
const connection = { host: socket, port: Number(process.env.WORKS_TEST_PG_PORT || 55479), user: 'postgres' };
const database = `works_check_${randomBytes(8).toString('hex')}`;
const admin = new pg.Client({ ...connection, database: 'postgres' });
await admin.connect();
await admin.query(`CREATE DATABASE ${database} TEMPLATE template0 ENCODING 'UTF8'`);
await admin.end();
const pool = new pg.Pool({ ...connection, database, max: 12 });
let checks = 0;
const check = async (name, fn) => { await fn(); checks += 1; process.stdout.write(`PASS ${name}\n`); };
const digest = (prefix = 'hmac-sha256') => `${prefix}:${randomBytes(32).toString('hex')}`;
const sqlFile = async (path) => pool.query(await readFile(new URL(`../${path}`, import.meta.url), 'utf8'));

try {
  await pool.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role; END IF;
    END $$;
    CREATE SCHEMA extensions;
    CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
    GRANT USAGE ON SCHEMA public, extensions TO anon, authenticated, service_role;
    CREATE TABLE public.entities (
      id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
      entity_id text UNIQUE NOT NULL,
      owner_id text NOT NULL,
      display_name text NOT NULL,
      entity_type text NOT NULL CHECK (entity_type IN ('agent', 'merchant', 'service_provider')),
      description text NOT NULL,
      capabilities jsonb NOT NULL DEFAULT '[]',
      verified boolean NOT NULL DEFAULT false,
      status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
      organization_id text,
      is_operator boolean NOT NULL DEFAULT false,
      api_key_hash text NOT NULL
    );
    GRANT SELECT, INSERT ON public.entities TO service_role;
  `);
  await sqlFile('supabase/migrations/20260809063111_works_records.sql');
  await sqlFile('supabase/migrations/20260907235809_works_accounts.sql');
  await check('account migration applies to the legacy non-null hash schema', async () => {
    const { rows } = await pool.query("SELECT count(*)::int n FROM information_schema.tables WHERE table_name LIKE 'works_account%'");
    assert.equal(rows[0].n, 3);
  });

  async function begin(email = digest(), name = 'Test Buyer', client = digest()) {
    const challenge = { id: randomUUID(), email, code: digest(), client };
    await pool.query('SELECT public.begin_works_account_email_challenge($1,$2,$3,$4,$5,$6,$7,$8)',
      [challenge.id, email, client, challenge.code, 'signup', name, true, false]);
    await pool.query('SELECT public.mark_works_account_email_delivery($1,$2,true)', [challenge.id, challenge.code]);
    return challenge;
  }
  async function exchange(challenge, code = challenge.code) {
    const session = digest('sha256');
    const { rows } = await pool.query('SELECT public.exchange_works_account_email_challenge($1,$2,$3,$4,$5) result',
      [challenge.id, challenge.email, code, session, new Date(Date.now() + 86_400_000).toISOString()]);
    return { ...rows[0].result, session };
  }
  let buyer;
  let builder;
  await check('verified signup creates only a private inactive principal, not a protocol credential', async () => {
    buyer = await exchange(await begin());
    builder = await exchange(await begin(digest(), 'Test Builder'));
    assert.equal(buyer.status, 'AUTHENTICATED');
    assert.equal(builder.status, 'AUTHENTICATED');
    const { rows: [entity] } = await pool.query('SELECT * FROM entities WHERE id=$1', [buyer.owner_entity_id]);
    assert.equal(entity.status, 'inactive');
    assert.equal(entity.verified, false);
    assert.equal(entity.is_operator, false);
    assert.match(entity.organization_id, /^@org:works-account:/);
    assert.match(entity.api_key_hash, /^sha256:[a-f0-9]{64}$/);
  });
  await check('one code yields one session even under concurrent exchanges', async () => {
    const challenge = await begin();
    const results = await Promise.all(Array.from({ length: 6 }, () => exchange(challenge)));
    assert.equal(results.filter((result) => result.status === 'AUTHENTICATED').length, 1);
  });
  await check('two verified signup challenges for one email converge on one account', async () => {
    const email = digest();
    const challenges = await Promise.all([begin(email), begin(email)]);
    const results = await Promise.all(challenges.map((challenge) => exchange(challenge)));
    assert.ok(results.every((result) => result.status === 'AUTHENTICATED'));
    assert.equal(new Set(results.map((result) => result.account_id)).size, 1);
  });
  await check('five wrong codes consume the challenge, including under concurrency', async () => {
    const challenge = await begin();
    await Promise.all(Array.from({ length: 6 }, () => exchange(challenge, digest())));
    assert.equal((await exchange(challenge)).status, 'INVALID');
    const { rows: [row] } = await pool.query('SELECT attempt_count,consumed_at FROM works_account_email_challenges WHERE challenge_id=$1', [challenge.id]);
    assert.equal(row.attempt_count, 5);
    assert.ok(row.consumed_at);
  });
  await check('expiry, disabled accounts and revocation deny session access', async () => {
    const { rows: [row] } = await pool.query('SELECT read_works_account_session($1) actor', [buyer.session]);
    assert.equal(row.actor.owner_entity_id, buyer.owner_entity_id);
    await pool.query("UPDATE works_accounts SET status='DISABLED' WHERE account_id=$1", [buyer.account_id]);
    assert.equal((await pool.query('SELECT read_works_account_session($1) actor', [buyer.session])).rows[0].actor, null);
    await pool.query("UPDATE works_accounts SET status='ACTIVE' WHERE account_id=$1", [buyer.account_id]);
    await pool.query('SELECT revoke_works_account_session($1)', [buyer.session]);
    assert.equal((await pool.query('SELECT read_works_account_session($1) actor', [buyer.session])).rows[0].actor, null);
    const challenge = await begin();
    await pool.query("UPDATE works_account_email_challenges SET requested_at=now()-interval '20 minutes',expires_at=now()-interval '10 minutes' WHERE challenge_id=$1", [challenge.id]);
    assert.equal((await exchange(challenge)).status, 'INVALID');
  });
  await check('durable email rate counter allows at most five simultaneous challenges', async () => {
    const email = digest();
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => begin(email)));
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 5);
    for (const result of results) if (result.status === 'rejected') assert.equal(result.reason.code, 'WA001');
  });
  await check('anonymous and authenticated roles cannot read accounts or execute their RPCs', async () => {
    for (const role of ['anon', 'authenticated']) {
      const { rows: [row] } = await pool.query(`SELECT has_table_privilege($1,'works_accounts','SELECT') readable,
        has_function_privilege($1,'public.read_works_account_session(text)','EXECUTE') executable`, [role]);
      assert.equal(row.readable, false);
      assert.equal(row.executable, false);
    }
  });
  if (process.env.WORKS_TEST_ACCOUNTS_ONLY !== '1') {
    await sqlFile('supabase/migrations/20260907235858_works_workflow.sql');
    const outsider = await exchange(await begin(digest(), 'Other Builder'));
    const key = () => `check-${randomUUID()}`;
    async function insert(collection, id, owner, record) {
      await pool.query(`INSERT INTO works_records(collection,record_id,owner_entity_id,visibility,record)
        VALUES($1,$2,$3,$4,$5)`, [collection, id, owner, record.visibility || 'public', JSON.stringify({ ...record, example: false })]);
    }
    async function job(id) {
      await insert('opportunities', id, buyer.owner_entity_id, {
        opportunity_id: id, kind: 'problem', title: 'Prepare refund recommendations',
        description: 'Review the supplied sample orders. Do not move funds.', posted_by: 'Test Buyer',
        contact_route: 'https://example.com/buyer', claims: [],
      });
    }
    async function proposal(id, jobId, actor = builder, builderId = 'builder-one') {
      await insert('submissions', id, actor.owner_entity_id, {
        submission_id: id, opportunity_id: jobId, builder_id: builderId, visibility: 'private',
        proposal: 'Deliver a recommendation file for buyer review.',
      });
    }
    async function select(proposalId, revision = 0, idem = key(), actor = buyer, scope = 'Prepare recommendations. No authority to issue refunds.') {
      return (await pool.query('SELECT select_works_proposal($1,$2,$3,$4,$5,$6,$7) result',
        [actor.owner_entity_id, proposalId, revision, idem, scope, JSON.stringify(['Each recommendation cites the supplied order.']), 'Payment agreed directly.'])).rows[0].result;
    }
    async function command(assignment, cmd, actor, payload = {}, idem = key()) {
      return (await pool.query('SELECT command_works_assignment($1,$2,$3,$4,$5,$6) result',
        [actor.owner_entity_id, assignment.assignment_id, cmd, assignment.revision, idem, JSON.stringify(payload)])).rows[0].result;
    }
    async function recordCommand(id, cmd, rev, actor = buyer, idem = key()) {
      return (await pool.query('SELECT command_works_record($1,$2,$3,$4,$5) result',
        [actor.owner_entity_id, cmd, id, rev, idem])).rows[0].result;
    }
    const codeIs = (...codes) => (error) => codes.includes(error.code);
    const workspace = async (actor) => (await pool.query('SELECT read_works_workspace($1) result', [actor.owner_entity_id])).rows[0].result;
    await insert('builders', 'builder-one', builder.owner_entity_id, { builder_id: 'builder-one', name: 'Test Builder', contact_route: 'https://example.com/builder' });
    await insert('builders', 'builder-two', outsider.owner_entity_id, { builder_id: 'builder-two', name: 'Other Builder', contact_route: 'https://example.com/other' });
    await insert('listings', 'agent-one', builder.owner_entity_id, {
      listing_id: 'agent-one', builder_id: 'builder-one', kind: 'agent', name: 'Refund analyst',
      summary: 'Prepares refund recommendations.', supported_tasks: ['Refund review'], interfaces: ['MCP'],
      operating_constraints: ['No fund movement'], status: 'active',
    });
    await job('job-one');
    await proposal('proposal-one', 'job-one');
    await proposal('proposal-two', 'job-one', outsider, 'builder-two');
    await check('private proposals and notifications appear only in their owners workspaces', async () => {
      const buyerView = await workspace(buyer);
      const builderView = await workspace(builder);
      const otherView = await workspace(outsider);
      assert.equal(buyerView.received_proposals.length, 2);
      assert.equal(buyerView.notifications.filter(item => item.kind === 'proposal_received').length, 2);
      assert.equal(builderView.submitted_proposals.length, 1);
      assert.equal(builderView.received_proposals.length, 0);
      assert.equal(otherView.submitted_proposals.length, 1);
      assert.ok(!JSON.stringify(builderView).includes('proposal-two'));
      assert.ok(!JSON.stringify(buyerView).includes('owner_entity_id'));
    });
    await check('notification reads require the recipient and replay one exact revision change', async () => {
      const notification = (await workspace(buyer)).notifications[0];
      const idem = key();
      const mark = async (actor, revision, requestKey) => (await pool.query('SELECT mark_works_notification_read($1,$2,$3,$4) result',
        [actor.owner_entity_id, notification.notification_id, revision, requestKey])).rows[0].result;
      await assert.rejects(mark(builder, 0, key()), codeIs('EW404'));
      const result = await mark(buyer, 0, idem);
      assert.equal(result.resource.revision, 1);
      assert.ok(result.resource.read_at);
      assert.deepEqual((await mark(buyer, 0, idem)).resource, result.resource);
      await assert.rejects(mark(buyer, 0, key()), codeIs('EWREV'));
      assert.equal((await workspace(buyer)).notifications.find(item => item.notification_id === notification.notification_id).revision, 1);
    });
    let selected;
    const selectionKey = key();
    await check('selecting a proposal freezes the agreement, records one event, and does not grant execution', async () => {
      selected = await select('proposal-one', 0, selectionKey);
      assert.equal(selected.resource.state, 'proposed');
      assert.equal(selected.resource.history.length, 1);
      assert.equal(selected.resource.history[0].revision, 0);
      assert.equal(selected.resource.frozen.job.opportunity_id, 'job-one');
      const { rows: [event] } = await pool.query('SELECT evidence FROM works_assignment_events WHERE assignment_id=$1', [selected.resource.assignment_id]);
      assert.equal(event.evidence.execution_authority_granted, false);
    });
    await check('same command retry replays the original result; changed scope with same key is refused', async () => {
      const retry = await select('proposal-one', 0, selectionKey);
      assert.equal(retry.replayed, true);
      assert.deepEqual(retry.resource, selected.resource);
      await assert.rejects(select('proposal-one', 0, selectionKey, buyer, 'Different scope'), codeIs('EWIDM'));
      assert.equal((await pool.query('SELECT count(*)::int n FROM works_assignments')).rows[0].n, 1);
    });
    await check('one job cannot be awarded twice, and an assigned job refuses new proposals', async () => {
      await assert.rejects(select('proposal-two'), codeIs('EWREV', 'EWTRN'));
      await assert.rejects(proposal('proposal-late', 'job-one'), codeIs('EWTRN'));
    });
    await check('builder confirmation and buyer completion cannot be forged by the other party', async () => {
      await assert.rejects(command(selected.resource, 'builder_confirm', buyer), codeIs('EW403'));
      await assert.rejects(command(selected.resource, 'builder_confirm', outsider), codeIs('EW404'));
      await assert.rejects(command(selected.resource, 'accept_completion', builder), codeIs('EW403'));
      await assert.rejects(command(selected.resource, 'accept_completion', buyer), codeIs('EWTRN'));
    });
    let assignment = selected.resource;
    await check('confirm, deliver, request changes, redeliver and buyer acceptance preserve the full history', async () => {
      assignment = (await command(assignment, 'builder_confirm', builder)).resource;
      await assert.rejects(command(assignment, 'submit_delivery', builder, { delivery_url: null, summary: null }), codeIs('22023'));
      assignment = (await command(assignment, 'submit_delivery', builder, { delivery_url: 'https://example.com/delivery-v1', summary: 'First recommendations.' })).resource;
      assert.equal(assignment.state, 'delivery_submitted');
      assert.equal(assignment.outcome, null);
      await assert.rejects(command(assignment, 'request_changes', buyer, { summary: null }), codeIs('22023'));
      await assert.rejects(command(assignment, 'cancel', buyer, { reason: null }), codeIs('22023'));
      assignment = (await command(assignment, 'request_changes', buyer, { summary: 'Include the order ID for the third row.' })).resource;
      assignment = (await command(assignment, 'submit_delivery', builder, { delivery_url: 'https://example.com/delivery-v2', summary: 'Order IDs included.' })).resource;
      assignment = (await command(assignment, 'accept_completion', buyer, { summary: 'Reviewed against the agreed criteria.' })).resource;
      assert.equal(assignment.state, 'completed');
      assert.equal(assignment.revision, 5);
      assert.equal(assignment.history.length, 6);
      assert.deepEqual(assignment.history.map(event => event.revision), [0, 1, 2, 3, 4, 5]);
      assert.equal(assignment.history[3].summary, 'Include the order ID for the third row.');
      assert.equal(assignment.history[2].delivery.url, 'https://example.com/delivery-v1');
      assert.equal(assignment.delivery.url, 'https://example.com/delivery-v2');
      assert.ok(assignment.outcome.accepted_at);
      assert.equal((await workspace(buyer)).jobs[0].workflow.state, 'closed');
      await assert.rejects(command(assignment, 'cancel', buyer, { reason: 'Too late' }), codeIs('EWTRN'));
    });
    await check('frozen agreement and recorded events cannot be edited after selection', async () => {
      await assert.rejects(pool.query("UPDATE works_assignments SET scope='Changed scope' WHERE assignment_id=$1", [assignment.assignment_id]));
      await assert.rejects(pool.query("UPDATE works_assignment_events SET evidence='{}' WHERE assignment_id=$1", [assignment.assignment_id]));
      await assert.rejects(pool.query('DELETE FROM works_assignment_events WHERE assignment_id=$1', [assignment.assignment_id]));
      await pool.query("UPDATE works_records SET record=jsonb_set(record,'{description}','\"Edited current brief\"') WHERE collection='opportunities' AND record_id='job-one'");
      const current = (await pool.query('SELECT read_works_assignment($1,$2) result', [buyer.owner_entity_id, assignment.assignment_id])).rows[0].result;
      assert.equal(current.assignment.frozen.job.description, 'Review the supplied sample orders. Do not move funds.');
    });
    await check('concurrent selection of two proposals produces exactly one active assignment', async () => {
      await job('job-race');
      await proposal('proposal-race-one', 'job-race');
      await proposal('proposal-race-two', 'job-race', outsider, 'builder-two');
      const results = await Promise.allSettled([select('proposal-race-one'), select('proposal-race-two')]);
      assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
      assert.equal((await pool.query("SELECT count(*)::int n FROM works_assignments WHERE opportunity_id='job-race'")).rows[0].n, 1);
    });
    await check('closing a job fences new submissions and reopening requires the new revision', async () => {
      await job('job-closed');
      await recordCommand('job-closed', 'close_job', 0);
      await assert.rejects(proposal('proposal-closed', 'job-closed'), codeIs('EWTRN'));
      await assert.rejects(recordCommand('job-closed', 'reopen_job', 0), codeIs('EWREV'));
      await recordCommand('job-closed', 'reopen_job', 1);
      await proposal('proposal-reopened', 'job-closed');
    });
    await check('cancellation records the reason and releases the job without pretending work completed', async () => {
      const cancelled = (await select('proposal-reopened', 2)).resource;
      const result = (await command(cancelled, 'cancel', builder, { reason: 'The required source data is unavailable.' })).resource;
      assert.equal(result.state, 'cancelled');
      assert.equal(result.outcome, null);
      assert.equal(result.history[1].reason, 'The required source data is unavailable.');
      const jobs = (await workspace(buyer)).jobs;
      assert.equal(jobs.find(item => item.record.opportunity_id === 'job-closed').workflow.state, 'open');
    });
    await check('pause and archive controls update discovery status, with no generic PATCH bypass', async () => {
      await recordCommand('agent-one', 'pause_listing', 0, builder);
      assert.equal((await pool.query("SELECT record->>'status' state FROM works_records WHERE collection='listings' AND record_id='agent-one'")).rows[0].state, 'paused');
      await assert.rejects(pool.query("UPDATE works_records SET record=jsonb_set(record,'{status}','\"active\"') WHERE collection='listings' AND record_id='agent-one'"), codeIs('EWTRN'));
      await recordCommand('agent-one', 'archive_listing', 1, builder);
      await recordCommand('agent-one', 'reactivate_listing', 2, builder);
    });
    await check('workflow tables and actor-taking RPCs remain inaccessible to untrusted database clients', async () => {
      for (const role of ['anon', 'authenticated']) {
        const { rows: [row] } = await pool.query(`SELECT has_table_privilege($1,'works_assignments','SELECT') readable,
          has_function_privilege($1,'public.read_works_workspace(uuid)','EXECUTE') executable`, [role]);
        assert.equal(row.readable, false); assert.equal(row.executable, false);
      }
      const client = await pool.connect();
      try {
        await client.query('SET ROLE service_role');
        assert.ok((await client.query('SELECT read_works_workspace($1) result', [buyer.owner_entity_id])).rows[0].result);
        await assert.rejects(client.query('SELECT * FROM works_assignments'), codeIs('42501'));
      } finally { await client.query('RESET ROLE'); client.release(); }
    });
  }
  process.stdout.write(`${checks} PostgreSQL checks passed. Isolated database: ${database}\n`);
} finally {
  await pool.end();
}
