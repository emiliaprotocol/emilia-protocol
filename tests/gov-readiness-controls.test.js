// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import {
  buildSecurityEvent,
  canonicalize,
  verifySecurityEventChain,
} from '../lib/security-events.js';
import {
  assertProductionKeyCustody,
  createExternalCustodySigner,
} from '../lib/key-custody.js';
import {
  productionReceiptVerifierOptions,
  verifyReceiptForProduction,
} from '../lib/gov-receipt-verifier.js';
import { resolveAuthorizedOrg } from '../lib/tenant-binding.js';
import { runKeyCompromiseDrill } from '../scripts/drills/key-compromise-drill.mjs';

function signedReceipt({ action = 'payment.release', outcome = 'allow' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const payload = {
    receipt_id: 'rcpt_gov_test',
    subject: 'ep:subject:test',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome },
  };
  const signature = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
  const publicKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    publicKeyB64u,
    doc: {
      '@version': 'EP-RECEIPT-v1',
      payload,
      public_key: publicKeyB64u,
      signature: { algorithm: 'Ed25519', value: signature },
    },
  };
}

describe('government readiness controls', () => {
  it('production receipt verifier pins keys and refuses inline-only trust', () => {
    const { doc, publicKeyB64u } = signedReceipt();

    const opts = productionReceiptVerifierOptions({
      action: 'payment.release',
      config: { trustedIssuerKeys: [], govStrict: true },
    });
    expect(opts.allowInlineKey).toBe(false);
    expect(opts.trustedKeys).toEqual([]);

    const rejected = verifyReceiptForProduction(doc, {
      action: 'payment.release',
      config: { trustedIssuerKeys: [], govStrict: true },
    });
    expect(rejected.ok).toBe(false);
    expect(rejected.reason).toBe('no_trusted_keys_configured');

    const accepted = verifyReceiptForProduction(doc, {
      action: 'payment.release',
      config: { trustedIssuerKeys: [publicKeyB64u], govStrict: true },
    });
    expect(accepted.ok).toBe(true);
  });

  it('security events redact secrets and detect hash-chain tampering', () => {
    const first = buildSecurityEvent({
      eventType: 'receipt.challenge',
      tenantId: 'org_1',
      payload: { authorization: 'Bearer secret', nested: { api_key: 'ep_live_bad' }, action: 'delete' },
      createdAt: '2026-06-28T00:00:00.000Z',
    });
    expect(first.payload_json.authorization).toBe('[redacted]');
    expect(first.payload_json.nested.api_key).toBe('[redacted]');

    const second = buildSecurityEvent({
      eventType: 'receipt.consume',
      tenantId: 'org_1',
      previousHash: first.event_hash,
      payload: { receipt_id: 'tr_1' },
      createdAt: '2026-06-28T00:01:00.000Z',
    });
    expect(verifySecurityEventChain([first, second]).ok).toBe(true);

    const tampered = { ...second, payload_json: { receipt_id: 'tr_2' } };
    const report = verifySecurityEventChain([first, tampered]);
    expect(report.ok).toBe(false);
    expect(report.errors.join(' ')).toContain('payload_hash mismatch');
  });

  it('key custody fails closed for local keys in government mode', async () => {
    const denied = assertProductionKeyCustody({ mode: 'local-dev', govStrict: true, isProduction: false });
    expect(denied.ok).toBe(false);
    expect(denied.reason).toBe('local_key_custody_forbidden');

    const signer = createExternalCustodySigner({
      mode: 'kms',
      keyId: 'kms://gov/test-key',
      sign: async (bytes, context) => `${context.keyId}:${bytes.toString('hex')}`,
    });
    await expect(signer.sign(Buffer.from('ok'))).resolves.toBe('kms://gov/test-key:6f6b');
  });

  it('tenant binding rejects body organization mismatch and unbound gov writes', () => {
    const auth = { entity: { entity_id: 'ent_1', organization_id: 'org_a' } };
    expect(resolveAuthorizedOrg(auth, 'org_b', { requireBound: true }).error.code).toBe('organization_mismatch');
    expect(resolveAuthorizedOrg({ entity: { entity_id: 'ent_2' } }, 'org_a', { requireBound: true }).error.code).toBe('entity_not_org_bound');
    expect(resolveAuthorizedOrg(auth, 'org_a', { requireBound: true }).organizationId).toBe('org_a');
  });

  it('key compromise drill proves old authorization is refused after revocation', () => {
    const result = runKeyCompromiseDrill();
    expect(result.before_revocation_seen).toBe(false);
    expect(result.revocation_statement_valid).toBe(true);
    expect(result.after_revocation_seen).toBe(true);
    expect(result.accepted_after_revocation).toBe(false);
  });

  it('static government readiness gate passes', () => {
    const root = resolve(import.meta.dirname, '..');
    const out = execFileSync('node', ['scripts/gov-readiness-check.mjs'], {
      cwd: root,
      encoding: 'utf8',
    });
    expect(out).toContain('PASSED');
  });
});
