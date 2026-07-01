// SPDX-License-Identifier: Apache-2.0
//
// Legacy @emilia-protocol/mcp-guard boundary tests. This package is an
// experimental reference wrapper, but adopters may copy it, so attacker-supplied
// tool args must not downgrade trusted server policy.

import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import {
  classifyToolCall,
  demandReceipt,
  withMcpGuard,
} from '../packages/mcp-guard/index.js';

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

describe('@emilia-protocol/mcp-guard boundary hardening', () => {
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

  it('still allows per-call metadata to escalate a call to irreversible', () => {
    expect(classifyToolCall('read_status', { __ep: { irreversible: true } }, {
      annotations: { read_status: { readOnlyHint: true } },
    })).toEqual({ irreversible: true, reason: 'per_call_override' });
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
      verifyOpts: { allowInlineKey: true, assuranceClass: 'class_a' },
    });
    expect(refused.ok).toBe(false);
    expect(refused.refusal.rejected.reason).toBe('assurance_too_low');

    const classA = demandReceipt({
      action,
      args: { __ep: { receipt: mint(action) } },
      verifyOpts: { allowInlineKey: true, assuranceClass: 'class_a' },
    });
    expect(classA.ok).toBe(true);
  });

  it('withMcpGuard refuses a presented low-tier receipt and does not execute the handler', async () => {
    let ran = false;
    const guarded = withMcpGuard(async () => {
      ran = true;
      return { deleted: true };
    }, {
      annotations: { delete_repo: { irreversible: true, action: 'github.repo.delete' } },
      verifyOpts: { allowInlineKey: true },
    });

    const res = await guarded('delete_repo', {
      repo: 'prod',
      __ep: { receipt: mint('github.repo.delete', { outcome: 'allow' }) },
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
      issueReceipt: async () => ({ receipt: mint('github.repo.delete', { outcome: 'allow' }) }),
    });

    const res = await guarded('delete_repo', { repo: 'prod' });
    expect(res.ep_refused).toBe(true);
    expect(res.stage).toBe('issue');
    expect(res.rejected.reason).toBe('assurance_too_low');
    expect(ran).toBe(false);
  });
});
