// SPDX-License-Identifier: Apache-2.0
/**
 * Durable Stripe refund connector against a real PostgreSQL attempt store.
 * The schema is the package's exported PROPOSAL_TO_EFFECT_POSTGRES_DDL only
 * (no lookup_attempt migration), installed under a non-login owner, with
 * separate executor and recovery login roles. Stripe is a recording fake.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { createEg1Harness, createGate } from '../index.js';
import { PROPOSAL_TO_EFFECT_POSTGRES_DDL } from '../proposal-to-effect-postgres.js';
import {
  createStripeDurableRefundManifest,
  createStripeRefundDurableConnector,
  createStripeRefundDurableStore,
  guardStripeRefundDurable,
  reconcileStripeRefundDurable,
} from './stripe-refund-durable.js';

const url = process.env.ADMISSION_STORE_POSTGRES_TEST_URL;
const ACCOUNT = 'acct_1LivePostgres';
const TENANT = 'tenant:finance';
const ENV = 'test';
const JOB = Object.freeze({ payment_intent: 'pi_live_pg', amount: 5000, operation_id: 'refund:live-pg:01' });
const APPROVED = Object.freeze({
  action_type: 'stripe.refund.create', tenant_id: TENANT, environment: ENV,
  provider_account_id: ACCOUNT, ...JOB,
});
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const LEASE_SECONDS = 1;
const staleWait = () => sleep(LEASE_SECONDS * 1000 + 300);

function fakeStripe() {
  const refunds = [];
  const creates = [];
  const hooks = {};
  return {
    refunds_created: refunds, creates, hooks,
    accounts: { async retrieve() { if (hooks.retrieve) return hooks.retrieve(); return { id: ACCOUNT }; } },
    refunds: {
      async create(params, options) {
        creates.push({ params, options });
        const refund = {
          id: `re_live_${refunds.length + 1}`, payment_intent: params.payment_intent,
          amount: params.amount, metadata: params.metadata,
          created: Math.floor(Date.now() / 1000), status: 'pending',
        };
        refunds.push(refund);
        if (hooks.afterAccept) await hooks.afterAccept(refund);
        return structuredClone(refund);
      },
      async list({ payment_intent }) {
        return { data: refunds.filter((refund) => refund.payment_intent === payment_intent), has_more: false };
      },
    },
  };
}

test('durable Stripe refund connector on real PostgreSQL: one provider entry, crash-safe recovery on the exported DDL', {
  skip: url ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async (t) => {
  const { default: pg } = await import('pg');
  const suffix = crypto.randomBytes(6).toString('hex');
  const database = `ep_pte_stripe_${suffix}`;
  const owner = `ep_pte_owner_${suffix}`;
  const executor = `ep_pte_exec_${suffix}`;
  const recovery = `ep_pte_recov_${suffix}`;
  const execPassword = crypto.randomBytes(18).toString('base64url');
  const recovPassword = crypto.randomBytes(18).toString('base64url');
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  const pools = [];
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    await admin.query(`DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'proposal_to_effect_executor') THEN
        CREATE ROLE proposal_to_effect_executor NOLOGIN; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'proposal_to_effect_recovery') THEN
        CREATE ROLE proposal_to_effect_recovery NOLOGIN; END IF;
    END $$`);
    await admin.query(`CREATE ROLE ${owner} NOLOGIN`);
    await admin.query(`CREATE ROLE ${executor} LOGIN PASSWORD '${execPassword}'`);
    await admin.query(`CREATE ROLE ${recovery} LOGIN PASSWORD '${recovPassword}'`);
    await admin.query(`GRANT proposal_to_effect_executor TO ${executor}`);
    await admin.query(`GRANT proposal_to_effect_recovery TO ${recovery}`);

    const target = new URL(url);
    target.pathname = `/${database}`;
    const installer = new pg.Client({ connectionString: target.toString() });
    await installer.connect();
    try {
      await installer.query(`GRANT CREATE ON DATABASE ${database} TO ${owner}`);
      await installer.query(`SET ROLE ${owner}`);
      await installer.query(PROPOSAL_TO_EFFECT_POSTGRES_DDL);
      await installer.query(`INSERT INTO proposal_to_effect_private.tenant_principals
        (principal_name, tenant_id, can_execute, can_recover)
        VALUES ($1, $3, true, false), ($2, $3, false, true)`, [executor, recovery, TENANT]);
      await installer.query('RESET ROLE');
      const lookup = await installer.query(`SELECT count(*)::int AS n FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'proposal_to_effect_private' AND p.proname = 'lookup_attempt'`);
      assert.equal(lookup.rows[0].n, 0, 'exported DDL must be exercised without lookup_attempt');
    } finally {
      await installer.end();
    }

    const loginUrl = (user, password) => {
      const value = new URL(target.toString());
      value.username = user;
      value.password = password;
      return value.toString();
    };
    const execPool = new pg.Pool({ connectionString: loginUrl(executor, execPassword), max: 16 });
    const recovPool = new pg.Pool({ connectionString: loginUrl(recovery, recovPassword), max: 4 });
    pools.push(execPool, recovPool);
    const withTarget = async (work) => {
      const client = new pg.Client({ connectionString: target.toString() });
      await client.connect();
      try {
        return await work(client);
      } finally {
        await client.end();
      }
    };
    const rows = () => withTarget(async (client) => {
      const attempts = await client.query(`SELECT state, owner_generation::int AS generation,
        evidence_digest IS NOT NULL AS has_evidence FROM proposal_to_effect_private.consequence_attempts`);
      const evidence = await client.query('SELECT evidence_id FROM proposal_to_effect_private.provider_evidence');
      return { attempts: attempts.rows, evidence: evidence.rows.map((row) => row.evidence_id) };
    });
    // TRUNCATE does not fire the row-level immutability triggers; test reset only.
    const reset = () => withTarget((client) => client.query(
      'TRUNCATE proposal_to_effect_private.provider_evidence, proposal_to_effect_private.consequence_attempts'));
    const makeExecutor = async (stripe, { harness = createEg1Harness({ action: APPROVED }), environment = ENV } = {}) => {
      const gate = createGate({
        manifest: createStripeDurableRefundManifest(), trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId, allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true,
      });
      const store = createStripeRefundDurableStore({
        pool: execPool, recovery_pool: recovPool, owner_hmac_sha256_key: new Uint8Array(32).fill(7),
        tenant_id: TENANT, provider_account_id: ACCOUNT, environment,
        lease_seconds: LEASE_SECONDS, authorize_recovery: () => true,
      });
      const connector = await createStripeRefundDurableConnector({
        stripe, gate, store, tenant_id: TENANT, environment,
        metadata_hmac_sha256_key: new Uint8Array(32).fill(9), resolve_operation: () => JOB,
      });
      return {
        harness,
        guard: (receipt = harness.mint({ outcome: 'allow_with_signoff' })) =>
          guardStripeRefundDurable(connector, { operation_reference: 'refund-job-live', receipt }),
        reconcile: () => reconcileStripeRefundDurable(connector, 'refund-job-live'),
      };
    };

    await t.test('concurrent fresh approvals across executors make exactly one refunds.create', async () => {
      await reset();
      const stripe = fakeStripe();
      const executors = await Promise.all(Array.from({ length: 8 }, () => makeExecutor(stripe)));
      const results = await Promise.all(executors.map((value) => value.guard()));
      assert.equal(results.filter((result) => result.state === 'COMMITTED').length, 1);
      assert.equal(results.filter((result) => result.reason === 'operation_already_reserved').length, 7);
      assert.equal(stripe.creates.length, 1);
      assert.deepEqual(await rows(), {
        attempts: [{ state: 'COMMITTED', generation: 0, has_evidence: true }], evidence: ['re_live_1'],
      });
    });

    await t.test('lost response: fresh approval never re-enters Stripe; stale recovery commits from the matching refund', async () => {
      await reset();
      const stripe = fakeStripe();
      stripe.hooks.afterAccept = async () => { throw new Error('response lost after Stripe accepted'); };
      const first = await makeExecutor(stripe);
      assert.equal((await first.guard()).reason, 'stripe_refund_outcome_unknown');
      delete stripe.hooks.afterAccept;
      const restarted = await makeExecutor(stripe);
      assert.equal((await restarted.guard()).reason, 'operation_already_reserved');
      await staleWait();
      assert.deepEqual(await restarted.reconcile(), { ok: true, state: 'COMMITTED', refund_id: 're_live_1' });
      assert.equal((await restarted.reconcile()).reason, 'previously_verified');
      assert.equal((await restarted.guard()).reason, 'operation_already_reserved');
      assert.equal(stripe.creates.length, 1);
      assert.deepEqual(await rows(), {
        attempts: [{ state: 'COMMITTED', generation: 1, has_evidence: true }], evidence: ['re_live_1'],
      });
    });

    await t.test('an owner that stalls inside Stripe is recovered without a second call and cannot commit late', async () => {
      await reset();
      const stripe = fakeStripe();
      let release;
      stripe.hooks.afterAccept = () => new Promise((resolve) => { release = resolve; });
      const stalled = await makeExecutor(stripe);
      const inflight = stalled.guard();
      await staleWait();
      delete stripe.hooks.afterAccept;
      const recoverer = await makeExecutor(stripe);
      assert.deepEqual(await recoverer.reconcile(), { ok: true, state: 'COMMITTED', refund_id: 're_live_1' });
      release();
      assert.equal((await inflight).reason, 'attempt_freeze_failed');
      assert.equal(stripe.creates.length, 1);
    });

    await t.test('an owner lost before provider entry recovers as indeterminate, never as retryable', async () => {
      await reset();
      const stripe = fakeStripe();
      let probes = 0;
      let release;
      stripe.hooks.retrieve = async () => {
        probes += 1;
        // Probe 3 is the in-callback probe after the row is INVOKING.
        if (probes === 3) await new Promise((resolve) => { release = resolve; });
        return { id: probes === 3 ? 'acct_1Switched' : ACCOUNT };
      };
      const lost = await makeExecutor(stripe);
      const inflight = lost.guard();
      await staleWait();
      delete stripe.hooks.retrieve;
      const recoverer = await makeExecutor(stripe);
      assert.deepEqual(await recoverer.reconcile(),
        { ok: false, state: 'INDETERMINATE', reason: 'provider_effect_unproven' });
      assert.equal((await recoverer.guard()).reason, 'operation_already_reserved');
      release();
      assert.equal((await inflight).state, 'INDETERMINATE');
      assert.equal(stripe.creates.length, 0);
      assert.deepEqual((await rows()).attempts, [{ state: 'INDETERMINATE', generation: 1, has_evidence: false }]);
    });

    await t.test('one approval is refused under a second environment namespace', async () => {
      await reset();
      const stripe = fakeStripe();
      const home = await makeExecutor(stripe);
      const receipt = home.harness.mint({ outcome: 'allow_with_signoff' });
      const other = await makeExecutor(stripe, { harness: home.harness, environment: 'test-2' });
      assert.equal((await other.guard(receipt)).state, 'REFUSED');
      assert.equal((await home.guard(receipt)).state, 'COMMITTED');
      assert.equal(stripe.creates.length, 1);
    });
  } finally {
    for (const pool of pools) await pool.end().catch(() => {});
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`).catch(() => {});
    for (const role of [executor, recovery, owner]) {
      await admin.query(`DROP ROLE IF EXISTS ${role}`).catch(() => {});
    }
    await admin.end();
  }
});
