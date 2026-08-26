// SPDX-License-Identifier: Apache-2.0
//
// EP-RECEIPT-HYBRID-v1 evidence receipts (lib/guard-evidence-receipt.ts), plus
// the regression that matters most: adding a hybrid path must not change one
// byte of what signEvidenceReceipt() already signs.
//
// The regression independently recomputes the canonical payload bytes here
// rather than reusing the module's canonicalize(), so a refactor that quietly
// changed the signed material cannot pass by agreeing with itself.
//
// The PQ leg runs for real. These tests FAIL LOUDLY if @noble/post-quantum is
// missing rather than silently skipping, so a green run means ML-DSA-65
// actually signed and verified.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';

import { verifyReceipt } from '../packages/verify/index.js';
import { verifyHybridReceipt, HYBRID_RECEIPT_REASONS } from '../packages/verify/receipt-hybrid.js';
import {
  signEvidenceReceipt,
  signEvidenceReceiptHybrid,
  _resetForTesting,
} from '../lib/guard-evidence-receipt.js';
import {
  clearCustodySigner,
  createHybridCustodySigner,
  createLocalDevSigner,
  createPqCustodySigner,
  registerCustodySigner,
} from '../lib/key-custody.js';

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

/** INDEPENDENT canonicalizer — deliberately not the module's own. */
function independentCanonicalize(value: any): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `[${value.map(independentCanonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map((k) => `${JSON.stringify(k)}:${independentCanonicalize(value[k])}`)
      .join(',')}}`;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('outside the EP canonicalization profile');
    return String(value);
  }
  return JSON.stringify(value);
}

const ISSUED_AT = '2026-08-17T12:00:00.000Z';

const CANONICAL_ACTION = Object.freeze({
  organization_id: 'org_1',
  actor_id: 'user_1',
  action_type: 'vendor_bank_account_change',
  target_resource_id: 'vendor:V1',
  policy_id: 'p1',
  nonce: 'nonce_1',
});

const BASE = Object.freeze({
  action_type: 'vendor_bank_account_change',
  decision: 'allow_with_signoff',
  enforcement_mode: 'enforce',
  policy_id: 'p1',
  policy_hash: 'sha256:ccc',
  action_hash: 'sha256:ddd',
  before_state_hash: 'sha256:aaa',
  after_state_hash: 'sha256:bbb',
  signoff_required: true,
  expires_at: '2026-08-18T00:00:00Z',
  receipt_status: 'pending_signoff',
  canonical_action: CANONICAL_ACTION,
});

const APPROVED = Object.freeze({
  actor_id: 'ep:approver:cfo',
  created_at: ISSUED_AT,
  after_state: { key_class: 'A', decided_at: ISSUED_AT },
});

const ARGS = Object.freeze({
  receiptId: 'rcpt_hybrid_1',
  base: BASE,
  approved: APPROVED,
  rejected: null,
  consumed: null,
  issuedAt: ISSUED_AT,
});

// A dev Ed25519 seed so the classical leg is deterministic across the suite.
const ED_SEED = Buffer.alloc(32, 7).toString('base64');
const ORIG_KEY = process.env.EP_COMMIT_SIGNING_KEY;
const ORIG_NODE_ENV = process.env.NODE_ENV;

const pq = ml_dsa65.keygen(new Uint8Array(crypto.createHash('sha256').update('guard-evidence-hybrid/seed').digest()));
const pqPublicRawB64u = Buffer.from(pq.publicKey).toString('base64url');

function registerHybrid({ pqSigner }: { pqSigner?: any } = {}) {
  const classical = createLocalDevSigner({ keyId: 'ep-signing-key-1', seedB64: ED_SEED });
  const pqLeg = pqSigner ?? createPqCustodySigner({
    keyId: 'ep-signing-key-pq-1',
    getPublicKey: () => pqPublicRawB64u,
    sign: async (bytes: Buffer) =>
      Buffer.from(ml_dsa65.sign(new Uint8Array(bytes), pq.secretKey)).toString('base64url'),
  });
  return registerCustodySigner(createHybridCustodySigner({ classical, pq: pqLeg }));
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime('2026-08-17T12:01:00.000Z');
  process.env.EP_COMMIT_SIGNING_KEY = ED_SEED;
  process.env.NODE_ENV = 'test';
  _resetForTesting();
  clearCustodySigner();
});

afterEach(() => {
  vi.useRealTimers();
  clearCustodySigner();
  _resetForTesting();
  if (ORIG_KEY === undefined) delete process.env.EP_COMMIT_SIGNING_KEY;
  else process.env.EP_COMMIT_SIGNING_KEY = ORIG_KEY;
  if (ORIG_NODE_ENV === undefined) delete (process.env as any).NODE_ENV;
  else process.env.NODE_ENV = ORIG_NODE_ENV;
});

describe('EP-RECEIPT-v1 evidence issuance is byte-identical', () => {
  it('signs exactly the bytes it signed before, verified over an INDEPENDENT recomputation', () => {
    const signed = signEvidenceReceipt({ ...ARGS });
    expect(signed).not.toBeNull();
    const { document, public_key } = signed!;

    expect(document['@version']).toBe('EP-RECEIPT-v1');
    expect(Object.keys(document).sort()).toEqual(['@version', 'metadata', 'payload', 'signature']);
    expect(document.signature.algorithm).toBe('Ed25519');
    expect(document.signature.key_class).toBe('C');
    expect(document.signature.key_id).toBe('ep-signing-key-1');

    const key = crypto.createPublicKey({
      key: Buffer.from(public_key, 'base64url'), format: 'der', type: 'spki',
    });
    const bytes = Buffer.from(independentCanonicalize(document.payload), 'utf8');
    expect(crypto.verify(null, bytes, key, Buffer.from(document.signature.value, 'base64url'))).toBe(true);

    // And under the published offline verifier, which is what a relying party runs.
    expect(verifyReceipt(document, public_key).valid).toBe(true);
  });

  it('binds the exact canonical action, decision, and approval facts', () => {
    const { document } = signEvidenceReceipt({ ...ARGS })!;
    expect(document.payload.claim.canonical_action).toEqual(CANONICAL_ACTION);
    expect(document.payload.claim.action_hash).toBe('sha256:ddd');
    expect(document.payload.authorization.status).toBe('approved_pending_consume');
    expect(document.payload.authorization.approver_id).toBe('ep:approver:cfo');
    expect(document.payload.authorization.approver_key_class).toBe('A');
  });

  it('keeps every honesty gate: a pending, denied, or action-less receipt is never signed', () => {
    expect(signEvidenceReceipt({ ...ARGS, approved: null })).toBeNull();
    expect(signEvidenceReceipt({ ...ARGS, rejected: { actor_id: 'x' } })).toBeNull();
    expect(signEvidenceReceipt({ ...ARGS, base: { ...BASE, canonical_action: undefined } })).toBeNull();
    expect(signEvidenceReceipt({ ...ARGS, base: null as any })).toBeNull();
  });

  it('a registered hybrid signer does NOT change the classical document', () => {
    const before = signEvidenceReceipt({ ...ARGS })!;
    registerHybrid();
    const after = signEvidenceReceipt({ ...ARGS })!;
    expect(independentCanonicalize(after.document)).toBe(independentCanonicalize(before.document));
    expect(after.public_key).toBe(before.public_key);
  });
});

describe('EP-RECEIPT-HYBRID-v1 evidence issuance', () => {
  it('mints a hybrid document that verifies under the published hybrid verifier', async () => {
    registerHybrid();
    const result = await signEvidenceReceiptHybrid({ ...ARGS });
    expect(result).not.toBeNull();
    const { document, verification_keys } = result!;

    expect(document['@version']).toBe('EP-RECEIPT-HYBRID-v1');
    expect(document.profile).toEqual({
      id: 'EP-RECEIPT-HYBRID-v1',
      required_algorithms: ['Ed25519', 'ML-DSA-65'],
    });
    expect(document.signatures.map((s) => s.alg)).toEqual(['Ed25519', 'ML-DSA-65']);
    expect(verification_keys.mldsaPublicKey).toBe(pqPublicRawB64u);

    const verdict = await verifyHybridReceipt(document, verification_keys);
    expect(verdict.reason).toBeNull();
    expect(verdict.verified).toBe(true);
    expect(verdict.set_result!.results.map((r) => [r.alg, r.verified]))
      .toEqual([['Ed25519', true], ['ML-DSA-65', true]]);
  });

  it('signs the SAME payload as the classical path, under different bytes', async () => {
    registerHybrid();
    const classical = signEvidenceReceipt({ ...ARGS })!;
    const hybrid = (await signEvidenceReceiptHybrid({ ...ARGS }))!;
    expect(independentCanonicalize(hybrid.document.payload))
      .toBe(independentCanonicalize(classical.document.payload));
  });

  it('V1 REFUSES HYBRID: the unchanged verifier refuses on the version marker without crashing', async () => {
    registerHybrid();
    const { document, verification_keys } = (await signEvidenceReceiptHybrid({ ...ARGS }))!;
    const verdict = verifyReceipt(document, verification_keys.ed25519PublicKey);
    expect(verdict.valid).toBe(false);
    expect(verdict.error).toBe('Unsupported version: EP-RECEIPT-HYBRID-v1');
    expect(verdict.checks.signature).toBe(false);
  });

  it('STRIPPED LEG: dropping the ML-DSA signature is refused', async () => {
    registerHybrid();
    const { document, verification_keys } = (await signEvidenceReceiptHybrid({ ...ARGS }))!;
    const stripped = JSON.parse(JSON.stringify(document));
    stripped.signatures = stripped.signatures.filter((s: any) => s.alg === 'Ed25519');
    const verdict = await verifyHybridReceipt(stripped, verification_keys);
    expect(verdict.verified).toBe(false);
    expect(verdict.reason).toBe(HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING);
  });

  it('NARROWED SET: dropping the leg and narrowing required_algorithms is refused', async () => {
    registerHybrid();
    const { document, verification_keys } = (await signEvidenceReceiptHybrid({ ...ARGS }))!;
    const narrowed = JSON.parse(JSON.stringify(document));
    narrowed.signatures = narrowed.signatures.filter((s: any) => s.alg === 'Ed25519');
    narrowed.profile.required_algorithms = ['Ed25519'];
    const verdict = await verifyHybridReceipt(narrowed, verification_keys);
    expect(verdict.reason).toBe(HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH);
  });

  it('TAMPERED PAYLOAD: an altered approver breaks both legs', async () => {
    registerHybrid();
    const { document, verification_keys } = (await signEvidenceReceiptHybrid({ ...ARGS }))!;
    const tampered = JSON.parse(JSON.stringify(document));
    tampered.payload.authorization.approver_id = 'ep:approver:attacker';
    const verdict = await verifyHybridReceipt(tampered, verification_keys);
    expect(verdict.verified).toBe(false);
    expect(verdict.set_result!.results.every((r) => r.verified === false)).toBe(true);
  });

  it('METADATA is unsigned, exactly as in the v1 envelope', async () => {
    registerHybrid();
    const { document, verification_keys } = (await signEvidenceReceiptHybrid({ ...ARGS }))!;
    expect(document.metadata).toEqual({
      operator: 'ep_operator_emilia_primary',
      issued_at: ISSUED_AT,
    });
    const edited = JSON.parse(JSON.stringify(document));
    edited.metadata.operator = 'attacker';
    expect((await verifyHybridReceipt(edited, verification_keys)).verified).toBe(true);
  });
});

describe('EP-RECEIPT-HYBRID-v1 evidence REFUSALS', () => {
  it('returns null when no dual-signer is registered — never a downgraded single-leg document', async () => {
    expect(await signEvidenceReceiptHybrid({ ...ARGS })).toBeNull();
  });

  it('returns null when only a classical signer is registered', async () => {
    registerCustodySigner(createLocalDevSigner({ keyId: 'ep-signing-key-1', seedB64: ED_SEED }));
    expect(await signEvidenceReceiptHybrid({ ...ARGS })).toBeNull();
  });

  it('applies the SAME honesty gates as the classical path', async () => {
    registerHybrid();
    expect(await signEvidenceReceiptHybrid({ ...ARGS, approved: null })).toBeNull();
    expect(await signEvidenceReceiptHybrid({ ...ARGS, rejected: { actor_id: 'x' } })).toBeNull();
    expect(await signEvidenceReceiptHybrid({
      ...ARGS, base: { ...BASE, canonical_action: undefined },
    })).toBeNull();
  });

  it('returns null when the PQ half cannot be published — an unpinnable receipt is worse than none', async () => {
    registerHybrid({
      pqSigner: createPqCustodySigner({
        keyId: 'ep-signing-key-pq-1',
        // No getPublicKey: a relying party could not be told what to pin.
        sign: async (bytes: Buffer) =>
          Buffer.from(ml_dsa65.sign(new Uint8Array(bytes), pq.secretKey)).toString('base64url'),
      }),
    });
    expect(await signEvidenceReceiptHybrid({ ...ARGS })).toBeNull();
  });

  it('NO PQ BACKEND: a throwing PQ signer yields null, never a classical-only document', async () => {
    registerHybrid({
      pqSigner: createPqCustodySigner({
        keyId: 'ep-signing-key-pq-1',
        getPublicKey: () => pqPublicRawB64u,
        sign: async () => { throw new Error('pq_backend_unavailable'); },
      }),
    });
    expect(await signEvidenceReceiptHybrid({ ...ARGS })).toBeNull();
  });

  it('a PQ signer returning a wrong-length signature is refused at the custody seam', async () => {
    registerHybrid({
      pqSigner: createPqCustodySigner({
        keyId: 'ep-signing-key-pq-1',
        getPublicKey: () => pqPublicRawB64u,
        sign: async () => Buffer.alloc(64).toString('base64url'),
      }),
    });
    expect(await signEvidenceReceiptHybrid({ ...ARGS })).toBeNull();
  });
});
