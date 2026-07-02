// SPDX-License-Identifier: Apache-2.0
//
// The dependency-free copy-in gate (packages/require-receipt/dist/emilia-gate.mjs)
// must (a) import nothing but node: builtins and (b) pass EMILIA RR-1 — the same
// four behaviors as the published package, since it is generated from the same source.

import { test, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  makeReceiptGate,
  receiptRequiredConformance,
} from '../packages/require-receipt/dist/emilia-gate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dropInPath = join(here, '..', 'packages', 'require-receipt', 'dist', 'emilia-gate.mjs');

// Canonical JSON (matches the EP verifier in the drop-in).
const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

function mint(actionType, { outcome = 'allow_with_signoff', quorum = null } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: {
      action_type: actionType,
      outcome,
      approver: 'jane@yourco.example',
      ...(quorum ? { quorum } : {}),
    },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
}

function fixtureAssurance(doc) {
  const claim = doc?.payload?.claim || {};
  const q = claim.quorum || {};
  const signers = Array.isArray(q.signers) ? q.signers : [];
  const threshold = Number(q.threshold ?? q.m ?? 0);
  if (threshold >= 2 && new Set(signers).size >= threshold) {
    return { ok: true, tier: 'quorum', reason: 'fixture_assurance_verified' };
  }
  if (claim.outcome === 'allow_with_signoff') return { ok: true, tier: 'class_a', reason: 'fixture_assurance_verified' };
  return { ok: true, tier: 'software', reason: 'fixture_assurance_verified' };
}

test('drop-in imports only node: builtins (genuinely dependency-free)', () => {
  const src = readFileSync(dropInPath, 'utf8');
  const specifiers = [...src.matchAll(/^\s*(?:import|export)\b[^\n]*\bfrom\s+['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  const nonNode = specifiers.filter((s) => !s.startsWith('node:'));
  expect(nonNode).toEqual([]);
});

test('drop-in passes EMILIA RR-1 (challenge / runs / replay-refused / forged-refused)', async () => {
  const ACTION = 'db.records.delete';
  const gate = makeReceiptGate({ action: ACTION, allowInlineKey: true, maxAgeSec: 900 });

  const dispatch = async (_tool, _args, receipt) => {
    const r = await gate.run(receipt, {}, async () => 'done');
    return r.ok ? { status: 200, body: r } : { status: r.status, body: r.body };
  };

  const report = await receiptRequiredConformance({
    dispatch,
    tool: 'delete_user',
    action: ACTION,
    issueReceipt: (action) => mint(action),
  });

  expect(report.checks.challenge_on_missing).toBe(true);
  expect(report.checks.runs_on_valid).toBe(true);
  expect(report.checks.replay_refused).toBe(true);
  expect(report.checks.forged_refused).toBe(true);
  expect(report.passed).toBe(true);
  expect(report.level).toBe('RR-1');
});

test('drop-in enforces assuranceClass, including quorum', async () => {
  const gate = makeReceiptGate({ action: 'deploy.production', assuranceClass: 'quorum', allowInlineKey: true });

  const software = await gate.run(mint('deploy.production', { outcome: 'allow' }), {}, async () => 'should-not-run');
  expect(software.ok).toBe(false);
  expect(software.body.rejected.reason).toBe('assurance_proof_required');

  const classA = await gate.run(mint('deploy.production'), {}, async () => 'should-not-run');
  expect(classA.ok).toBe(false);
  expect(classA.body.rejected.reason).toBe('assurance_proof_required');

  const verifiedGate = makeReceiptGate({
    action: 'deploy.production',
    assuranceClass: 'quorum',
    allowInlineKey: true,
    verifyAssurance: fixtureAssurance,
  });
  const quorum = await verifiedGate.run(mint('deploy.production', {
    quorum: { threshold: 2, signers: ['ep:approver:a', 'ep:approver:b'] },
  }), {}, async () => 'deployed');
  expect(quorum.ok).toBe(true);
  expect(quorum.result).toBe('deployed');
});
