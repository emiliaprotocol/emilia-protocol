// SPDX-License-Identifier: Apache-2.0
//
// Legacy @emilia-protocol/mcp-guard boundary tests. This package is an
// experimental reference wrapper, but adopters may copy it, so attacker-supplied
// tool args must not downgrade trusted server policy.

import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  classifyToolCall,
  bindToolAction,
  createPostgresProvenanceLedgerStore,
  demandReceipt,
  PROVENANCE_POSTGRES_SQL,
  ProvenanceLedger,
  withMcpGuard as createMcpGuard,
} from '../packages/mcp-guard/index.js';

const withMcpGuard = (handler: (...args: any[]) => any, options: any = {}) =>
  createMcpGuard(handler, { allowEphemeralLedger: true, ...options });

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

function mint(action, { outcome = 'allow_with_signoff', quorum = null } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_mcp_guard_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:mcp-guard-redteam',
    created_at: new Date().toISOString(),
    claim: {
      action_type: action,
      outcome,
      approver: 'ep:approver:mcp-guard',
      ...(quorum ? { quorum } : {}),
    },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
}

function fixtureAssurance(doc) {
  const claim = doc?.payload?.claim || {};
  if (claim.outcome === 'allow_with_signoff') return { ok: true, tier: 'class_a', reason: 'fixture_assurance_verified' };
  return { ok: true, tier: 'software', reason: 'fixture_assurance_verified' };
}

describe('@emilia-protocol/mcp-guard boundary hardening', () => {
  const bound = (tool, args, family) => bindToolAction(tool, args, family);

  it('reloads and verifies a durable provenance head after process restart', async () => {
    const persisted: any[] = [];
    const store = {
      durable: true as const,
      async load() { return structuredClone(persisted); },
      async append({ expectedSequence, expectedPreviousHash, entry }) {
        if (expectedSequence !== persisted.length
          || expectedPreviousHash !== (persisted.at(-1)?.entry_hash ?? '')) {
          return { ok: false as const, reason: 'head_conflict' as const };
        }
        persisted.push(structuredClone(entry));
        return { ok: true as const };
      },
    };
    const ledger = await ProvenanceLedger.open({ store });
    await ledger.append({
      tool: 'deploy',
      action: 'deploy.production',
      actionDigest: 'sha256:first',
      receiptRef: { receipt_id: 'receipt:first', receipt_hash: 'sha256:receipt' },
      verified: {
        outcome: 'allow_with_signoff',
        subject: 'agent:test',
        signer: 'approver:test',
      },
    });

    const restarted = await ProvenanceLedger.open({ store });
    expect(restarted.durable).toBe(true);
    expect(restarted.verifyChain()).toEqual({ ok: true, length: 1 });
    expect(restarted.headHash).toBe(persisted[0].entry_hash);
    expect(() => (restarted.entries as any[]).push({ attacker: true })).toThrow();
    expect(restarted.verifyChain()).toEqual({ ok: true, length: 1 });
  });

  it('refuses a corrupt durable provenance chain at startup', async () => {
    const store = {
      durable: true as const,
      async load() {
        return [{
          '@version': 'EP-PROVENANCE-ENTRY-v1',
          sequence: 0,
          at: new Date().toISOString(),
          tool: 'deploy',
          action: 'deploy.production',
          action_digest: 'sha256:first',
          receipt_ref: {},
          verified: null,
          agent_claim: null,
          liability: null,
          prev_entry_hash: null,
          entry_hash: 'sha256:tampered',
        }];
      },
      async append() { return { ok: true as const }; },
    };
    await expect(ProvenanceLedger.open({ store })).rejects.toThrow(/durable provenance chain/i);
  });

  it('requires explicit ephemeral mode when no durable provenance ledger is supplied', () => {
    expect(() => createMcpGuard(async () => ({ ok: true }))).toThrow(/durable provenance ledger/i);
  });

  it('ships an atomic append-only PostgreSQL provenance store contract', () => {
    const sql = readFileSync(
      new URL('../packages/mcp-guard/sql/provenance-ledger-v1.sql', import.meta.url),
      'utf8',
    );
    expect(sql).toMatch(/FOR UPDATE/);
    expect(sql).toMatch(/head_conflict/);
    expect(sql).toMatch(/append-only/);
    expect(sql).toMatch(/singleton boolean PRIMARY KEY DEFAULT true CHECK \(singleton\)/);
    expect(sql).toMatch(/provenance authority domain mismatch/);
    expect(sql).toMatch(/ep_mcp_provenance_binding_permanent/);
    expect(sql).toMatch(/REVOKE ALL ON TABLE public\.ep_mcp_provenance_entries FROM PUBLIC/);
    expect(sql).toMatch(/REVOKE ALL ON FUNCTION public\.ep_mcp_provenance_append/);
  });

  it('binds the PostgreSQL provenance adapter to one tenant and ledger', async () => {
    const calls: Array<{ text: string; params: readonly unknown[] }> = [];
    const store = createPostgresProvenanceLedgerStore({
      tenantId: 'tenant:alpha',
      ledgerId: 'ledger:production',
      query: async (text, params) => {
        calls.push({ text, params });
        return {
          rowCount: 1,
          rows: [{
            result: text === PROVENANCE_POSTGRES_SQL.load
              ? { ok: true, entries: [], head_sequence: -1, head_hash: '' }
              : { ok: true },
          }],
        };
      },
    });
    const ledger = await ProvenanceLedger.open({ store });
    await ledger.append({
      tool: 'deploy',
      action: 'deploy.production',
      actionDigest: 'sha256:first',
      receiptRef: { receipt_id: 'receipt:first', receipt_hash: 'sha256:receipt' },
      verified: {
        outcome: 'allow_with_signoff',
        subject: 'agent:test',
        signer: 'approver:test',
      },
    });
    expect(calls[0]).toEqual({
      text: PROVENANCE_POSTGRES_SQL.load,
      params: ['tenant:alpha', 'ledger:production'],
    });
    expect(calls[1].text).toBe(PROVENANCE_POSTGRES_SQL.append);
    expect(calls[1].params.slice(0, 4)).toEqual([
      'tenant:alpha', 'ledger:production', 0, '',
    ]);
  });

  it('does not invoke the protected tool when durable provenance append fails', async () => {
    const ledger = await ProvenanceLedger.open({
      store: {
        durable: true,
        async load() { return []; },
        async append() { throw new Error('provenance database unavailable'); },
      },
    });
    let ran = false;
    const guarded = createMcpGuard(async () => {
      ran = true;
      return { deleted: true };
    }, {
      ledger,
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
    });
    const receipt = mint(bound('delete_repo', {}, 'github.repo.delete'));
    await expect(guarded('delete_repo', { __ep: { receipt } }))
      .rejects.toThrow('provenance database unavailable');
    expect(ran).toBe(false);
  });

  it.skipIf(!process.env.MCP_PROVENANCE_POSTGRES_TEST_URL)(
    'persists and reloads provenance through a real PostgreSQL restart boundary',
    async () => {
      const { Pool } = await import('pg');
      const pool = new Pool({
        connectionString: process.env.MCP_PROVENANCE_POSTGRES_TEST_URL,
        max: 4,
      });
      try {
        const sql = readFileSync(
          new URL('../packages/mcp-guard/sql/provenance-ledger-v1.sql', import.meta.url),
          'utf8',
        );
        await pool.query(sql);
        await pool.query(
          'SELECT public.ep_mcp_provenance_bind($1::text, $2::text)',
          ['tenant:integration', 'ledger:restart'],
        );
        await expect(pool.query(
          'SELECT public.ep_mcp_provenance_load($1::text, $2::text)',
          ['tenant:other', 'ledger:restart'],
        )).rejects.toThrow(/authority domain mismatch/);
        const store = createPostgresProvenanceLedgerStore({
          tenantId: 'tenant:integration',
          ledgerId: 'ledger:restart',
          query: (text, params) => pool.query(text, [...params]) as any,
        });
        const firstProcess = await ProvenanceLedger.open({ store });
        await firstProcess.append({
          tool: 'deploy',
          action: 'deploy.production',
          actionDigest: 'sha256:first',
          receiptRef: { receipt_id: 'receipt:first', receipt_hash: 'sha256:receipt' },
          verified: {
            outcome: 'allow_with_signoff',
            subject: 'agent:test',
            signer: 'approver:test',
          },
        });

        const restartedProcess = await ProvenanceLedger.open({ store });
        expect(restartedProcess.verifyChain()).toEqual({ ok: true, length: 1 });
        await expect(pool.query(
          "UPDATE public.ep_mcp_provenance_entries SET entry_json = '{}'::jsonb",
        )).rejects.toThrow(/append-only/);

        const concurrentA = await ProvenanceLedger.open({ store });
        const concurrentB = await ProvenanceLedger.open({ store });
        const nextEntry = {
          tool: 'release',
          action: 'payment.release',
          actionDigest: 'sha256:second',
          receiptRef: { receipt_id: 'receipt:second', receipt_hash: 'sha256:receipt2' },
          verified: {
            outcome: 'allow_with_signoff',
            subject: 'agent:test',
            signer: 'approver:test',
          },
        };
        const raced = await Promise.allSettled([
          concurrentA.append(nextEntry),
          concurrentB.append(nextEntry),
        ]);
        expect(raced.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
        expect(raced.filter((result) => result.status === 'rejected')).toHaveLength(1);
        const finalProcess = await ProvenanceLedger.open({ store });
        expect(finalProcess.verifyChain()).toEqual({ ok: true, length: 2 });
      } finally {
        await pool.end();
      }
    },
  );

  it('does not let attacker-controlled __ep.irreversible=false downgrade trusted policy', () => {
    expect(classifyToolCall('delete_repo', { __ep: { irreversible: false } }, {
      annotations: { delete_repo: { irreversible: true } },
    })).toEqual({ irreversible: true, reason: 'annotation' });

    expect(classifyToolCall('delete_repo', { __ep: { irreversible: false } }, {
      policy: () => true,
    })).toEqual({ irreversible: true, reason: 'policy_fn' });

    expect(classifyToolCall('delete_repo', { __ep: { irreversible: false } }, {
      defaultIrreversible: true,
    })).toEqual({ irreversible: true, reason: 'default' });
  });

  it('retains no attacker-keyed per-action gate cache', () => {
    const source = readFileSync(
      new URL('../packages/mcp-guard/src/index.ts', import.meta.url),
      'utf8',
    );
    expect(source).not.toMatch(/const\s+gates\s*=\s*new\s+Map/);
    expect(source).not.toMatch(/gates\.(?:has|set|get)\s*\(/);
  });

  it('still allows per-call metadata to escalate a call to irreversible', () => {
    expect(classifyToolCall('read_status', { __ep: { irreversible: true } }, {
      annotations: { read_status: { readOnlyHint: true } },
    })).toEqual({ irreversible: true, reason: 'per_call_override' });
  });

  it('gates an unclassified tool by default and only passes explicit read-only tools', () => {
    expect(classifyToolCall('new_tool', {})).toEqual({ irreversible: true, reason: 'default' });
    expect(classifyToolCall('read_status', {}, {
      annotations: { read_status: { irreversible: false } },
    })).toEqual({ irreversible: false, reason: 'annotation' });
    expect(classifyToolCall('read_status', {}, {
      annotations: { read_status: { readOnlyHint: true } },
    })).toEqual({ irreversible: true, reason: 'default' });
    expect(classifyToolCall('read_status', {}, {
      annotations: { read_status: { readOnlyHint: true } },
      trustReadOnlyHints: true,
    })).toEqual({ irreversible: false, reason: 'trusted_readOnlyHint' });
  });

  it('untrusted registry annotations cannot downgrade local policy or replace action binding', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => { ran = true; }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      getAnnotations: () => ({
        irreversible: false,
        readOnlyHint: true,
        action: 'harmless.read',
      }),
    });
    const result = await guarded('delete_repo', { repo: 'prod' });
    expect(result.ep_refused).toBe(true);
    expect(result.required.action).toMatch(/^github\.repo\.delete:sha256:/);
    expect(ran).toBe(false);
  });

  it('a remote readOnlyHint cannot outrank the operator policy function, even with trustReadOnlyHints on', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => { ran = true; }, {
      trustReadOnlyHints: true,
      policy: (name: string) => /^delete_/.test(name),
      getAnnotations: () => ({ readOnlyHint: true }),
    });
    const result = await guarded('delete_all_prod_data', { confirm: true });
    expect(result.ep_refused).toBe(true);
    expect(ran).toBe(false);
  });

  it('a remote readOnlyHint cannot downgrade a locally named action family that omits irreversible', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => { ran = true; }, {
      trustReadOnlyHints: true,
      annotations: { delete_all_prod_data: { action: 'prod.data.delete' } },
      getAnnotations: () => ({ readOnlyHint: true }),
    });
    const result = await guarded('delete_all_prod_data', { confirm: true });
    expect(result.ep_refused).toBe(true);
    expect(ran).toBe(false);
  });

  it('a locally authored readOnlyHint still downgrades when the operator opts in', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => { ran = true; }, {
      trustReadOnlyHints: true,
      annotations: { list_items: { readOnlyHint: true } },
    });
    await guarded('list_items', {});
    expect(ran).toBe(true);
  });

  it('withMcpGuard refuses an unknown tool instead of silently executing it', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => {
      ran = true;
      return { ran: true };
    });

    const res = await guarded('newly_installed_tool', { target: 'prod' });
    expect(res.ep_refused).toBe(true);
    expect(res.stage).toBe('consent');
    expect(ran).toBe(false);
  });

  it('withMcpGuard fail-closes instead of running a destructive tool when args try to downgrade it', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => {
      ran = true;
      return { deleted: true };
    }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
    });

    const res = await guarded('delete_repo', { repo: 'prod', __ep: { irreversible: false } });
    expect(res.ep_refused).toBe(true);
    expect(ran).toBe(false);
  });

  it('demandReceipt refuses software receipts when Class-A is required', () => {
    const action = 'github.repo.delete';
    const software = mint(action, { outcome: 'allow' });
    const refused = demandReceipt({
      action,
      args: { __ep: { receipt: software } },
      verifyOpts: { allowInlineKey: true, assuranceClass: 'class_a', verifyAssurance: fixtureAssurance },
    });
    expect(refused.ok).toBe(false);
    expect(refused.refusal.rejected.reason).toBe('assurance_too_low');

    const classA = demandReceipt({
      action,
      args: { __ep: { receipt: mint(action) } },
      verifyOpts: { allowInlineKey: true, assuranceClass: 'class_a', verifyAssurance: fixtureAssurance },
    });
    expect(classA.ok).toBe(true);
  });

  it('refuses duplicate-key receipt JSON carried as base64', () => {
    const action = 'github.repo.delete';
    const receipt = mint(action);
    const raw = `{"@version":"EP-RECEIPT-v0",${JSON.stringify(receipt).slice(1)}`;
    const result = demandReceipt({
      action,
      args: { __ep: { receipt_b64: Buffer.from(raw).toString('base64') } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
    });
    expect(result.ok).toBe(false);
    expect(result.refusal.detail).toMatch(/No EMILIA receipt presented/);
  });

  it('withMcpGuard refuses a presented low-tier receipt and does not execute the handler', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => {
      ran = true;
      return { deleted: true };
    }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
    });

    const res = await guarded('delete_repo', {
      repo: 'prod',
      __ep: { receipt: mint(bound('delete_repo', { repo: 'prod' }, 'github.repo.delete'), { outcome: 'allow' }) },
    });
    expect(res.ep_refused).toBe(true);
    expect(res.rejected.reason).toBe('assurance_too_low');
    expect(ran).toBe(false);
  });

  it('withMcpGuard refuses an issued receipt that self-verifies but misses required assurance', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => {
      ran = true;
      return { deleted: true };
    }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      verifyOpts: { allowInlineKey: true },
      requestConsent: async () => ({ approved: true }),
      requestClassASignoff: async () => ({ approved: true }),
      issueReceipt: async ({ action }) => ({ receipt: mint(action, { outcome: 'allow' }) }),
    });

    const res = await guarded('delete_repo', { repo: 'prod' });
    expect(res.ep_refused).toBe(true);
    expect(res.stage).toBe('issue');
    expect(res.rejected.reason).toBe('assurance_proof_required');
    expect(ran).toBe(false);
  });

  it('withMcpGuard consumes a presented receipt exactly once', async () => {
    let runs = 0;
    const guarded = withMcpGuard(async () => {
      runs += 1;
      return { deleted: true };
    }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
    });
    const receipt = mint(bound('delete_repo', {}, 'github.repo.delete'));
    const first = await guarded('delete_repo', { __ep: { receipt } });
    expect(first.deleted).toBe(true);
    const replay = await guarded('delete_repo', { __ep: { receipt } });
    expect(replay.ep_refused).toBe(true);
    expect(replay.rejected.reason).toBe('replay_refused');
    expect(runs).toBe(1);
  });

  it('concurrent presentation admits one irreversible effect', async () => {
    let runs = 0;
    let release;
    const guarded = withMcpGuard(async () => {
      runs += 1;
      await new Promise((resolve) => { release = resolve; });
      return { ran: true };
    }, {
      annotations: { deploy: { irreversible: true, action: 'deploy.production' } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
    });
    const receipt = mint(bound('deploy', {}, 'deploy.production'));
    const first = guarded('deploy', { __ep: { receipt } });
    while (!release) await new Promise((resolve) => setTimeout(resolve, 0));
    const second = await guarded('deploy', { __ep: { receipt } });
    expect(second.ep_refused).toBe(true);
    expect(second.rejected.reason).toBe('replay_refused');
    release();
    await first;
    expect(runs).toBe(1);
  });

  it('an indeterminate handler failure burns the receipt', async () => {
    let runs = 0;
    const guarded = withMcpGuard(async () => {
      runs += 1;
      throw new Error('downstream response lost');
    }, {
      annotations: { wire: { irreversible: true, action: 'payment.release' } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
    });
    const receipt = mint(bound('wire', {}, 'payment.release'));
    await expect(guarded('wire', { __ep: { receipt } })).rejects.toThrow('downstream response lost');
    const retry = await guarded('wire', { __ep: { receipt } });
    expect(retry.rejected.reason).toBe('replay_refused');
    expect(runs).toBe(1);
  });

  it('a freshly issued receipt is consumed before it can re-enter the presented path', async () => {
    let runs = 0;
    const issued = mint(bound('delete_repo', { repo: 'prod' }, 'github.repo.delete'));
    const guarded = withMcpGuard(async () => {
      runs += 1;
      return { deleted: true };
    }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
      requestConsent: async () => ({ approved: true }),
      requestClassASignoff: async () => ({ approved: true }),
      issueReceipt: async () => ({ receipt: issued }),
    });
    await guarded('delete_repo', { repo: 'prod' });
    const replay = await guarded('delete_repo', { repo: 'prod', __ep: { receipt: issued } });
    expect(replay.rejected.reason).toBe('replay_refused');
    expect(runs).toBe(1);
  });

  it('adapter approval must be the boolean true', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => { ran = true; }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      requestConsent: async () => ({ approved: 1 }),
    });
    const result = await guarded('delete_repo', {});
    expect(result.stage).toBe('consent');
    expect(ran).toBe(false);
  });

  it('binds amount and destination into the enforced action, not only provenance', async () => {
    let runs = 0;
    const guarded = withMcpGuard(async () => { runs += 1; }, {
      annotations: { wire: { irreversible: true, action: 'payment.release' } },
      verifyOpts: { allowInlineKey: true, verifyAssurance: fixtureAssurance },
    });
    const approvedArgs = { amount: '10.00', currency: 'USD', destination: 'acct:vendor' };
    const receipt = mint(bound('wire', approvedArgs, 'payment.release'));
    const substituted = await guarded('wire', {
      ...approvedArgs,
      amount: '1000000.00',
      __ep: { receipt },
    });
    expect(substituted.ep_refused).toBe(true);
    expect(substituted.rejected.reason).toBe('action_mismatch');
    expect(runs).toBe(0);
  });

  it('refuses values outside the cross-language canonical profile before execution', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => { ran = true; }, {
      annotations: { wire: { irreversible: true, action: 'payment.release' } },
    });
    const unsafe = await guarded('wire', { amount: 9007199254740992 });
    expect(unsafe.stage).toBe('bind');
    expect(unsafe.rejected.reason).toBe('action_binding_invalid');
    expect(ran).toBe(false);

    const nonFinite = await guarded('wire', { amount: Number.NaN });
    expect(nonFinite.stage).toBe('bind');
    expect(nonFinite.rejected.reason).toBe('action_binding_invalid');
    expect(ran).toBe(false);
  });
});
