// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for lib/guard-evidence-receipt.js — the builder that turns a
// GovGuard/FinGuard receipt's audit log into a signed, offline-verifiable
// EP-RECEIPT-v1 document. The headline assertion is the ROUND-TRIP: what this
// module signs, @emilia-protocol/verify accepts — and tamper breaks it.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import { verifyReceipt } from '../packages/verify/index.js';
import {
  signEvidenceReceipt,
  resolveReceiptStatus,
  getEvidenceSigningKeypair,
  canonicalize,
  _resetForTesting,
} from '../lib/guard-evidence-receipt.js';

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const ORIG_KEY = process.env.EP_COMMIT_SIGNING_KEY;
const ORIG_NODE_ENV = process.env.NODE_ENV;

function canonicalAction(overrides = {}) {
  return {
    organization_id: 'org_1',
    actor_id: 'user_1',
    action_type: 'vendor_bank_account_change',
    target_resource_id: 'vendor:V1',
    before_state_hash: 'sha256:aaa',
    after_state_hash: 'sha256:bbb',
    policy_id: 'p1',
    policy_hash: 'sha256:ccc',
    nonce: 'nonce_1',
    expires_at: '2026-04-27T00:00:00Z',
    requested_at: '2026-04-26T00:00:00Z',
    ...overrides,
  };
}

function createdState(overrides = {}) {
  return {
    organization_id: 'org_1',
    action_type: 'vendor_bank_account_change',
    decision: 'allow_with_signoff',
    enforcement_mode: 'enforce',
    policy_id: 'p1',
    policy_hash: 'sha256:ccc',
    action_hash: 'sha256:ddd',
    before_state_hash: 'sha256:aaa',
    after_state_hash: 'sha256:bbb',
    signoff_required: true,
    expires_at: '2026-04-27T00:00:00Z',
    receipt_status: 'pending_signoff',
    canonical_action: canonicalAction(),
    ...overrides,
  };
}

const approvedEvent = {
  event_type: 'guard.signoff.approved',
  actor_id: 'approver_jane',
  created_at: '2026-04-26T00:01:00Z',
  after_state: { signoff_id: 'sig_1', approver_id: 'approver_jane', decided_at: '2026-04-26T00:01:00Z', key_class: 'C' },
};
const consumedEvent = {
  event_type: 'guard.trust_receipt.consumed',
  after_state: { consumed_at: '2026-04-26T00:02:00Z', consumed_by_system: 'svc', execution_reference_id: 'exec_1' },
  created_at: '2026-04-26T00:02:00Z',
};

beforeEach(() => {
  _resetForTesting();
  // Stable, known seed so the round-trip is deterministic.
  process.env.EP_COMMIT_SIGNING_KEY = crypto.randomBytes(32).toString('base64');
  process.env.NODE_ENV = 'test';
});

afterEach(() => {
  if (ORIG_KEY === undefined) delete process.env.EP_COMMIT_SIGNING_KEY;
  else process.env.EP_COMMIT_SIGNING_KEY = ORIG_KEY;
  process.env.NODE_ENV = ORIG_NODE_ENV;
  _resetForTesting();
});

describe('canonicalize', () => {
  it('sorts keys recursively and is byte-identical to the verifier', () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
    expect(canonicalize(null)).toBe('null');
  });
});

describe('resolveReceiptStatus', () => {
  it('consumed wins', () => {
    expect(resolveReceiptStatus(createdState(), { consumed: consumedEvent })).toBe('consumed');
  });
  it('approved (no consume) → approved_pending_consume', () => {
    expect(resolveReceiptStatus(createdState(), { approved: approvedEvent })).toBe('approved_pending_consume');
  });
  it('rejected → rejected', () => {
    expect(resolveReceiptStatus(createdState(), { rejected: {} })).toBe('rejected');
  });
  it('no-signoff non-deny decision → approved_pending_consume', () => {
    expect(resolveReceiptStatus(createdState({ signoff_required: false, decision: 'allow' }), {})).toBe('approved_pending_consume');
  });
  it('deny → denied', () => {
    expect(resolveReceiptStatus(createdState({ signoff_required: false, decision: 'deny' }), {})).toBe('denied');
  });
  it('pending falls through to receipt_status', () => {
    expect(resolveReceiptStatus(createdState(), {})).toBe('pending_signoff');
  });
});

describe('signEvidenceReceipt — honesty gate (returns null, fabricates nothing)', () => {
  const args = (over = {}) => ({ receiptId: 'tr_1', base: createdState(), approved: null, rejected: null, consumed: null, issuedAt: '2026-04-26T00:00:00Z', ...over });

  it('null base → null', () => {
    expect(signEvidenceReceipt({ ...args(), base: null })).toBeNull();
  });
  it('pending (no approval/consume) → null', () => {
    expect(signEvidenceReceipt(args())).toBeNull();
  });
  it('rejected → null', () => {
    expect(signEvidenceReceipt(args({ rejected: {} }))).toBeNull();
  });
  it('denied → null', () => {
    expect(signEvidenceReceipt(args({ base: createdState({ signoff_required: false, decision: 'deny' }) }))).toBeNull();
  });
  it('approved but missing canonical_action → null (no re-describing)', () => {
    const base = createdState();
    delete base.canonical_action;
    expect(signEvidenceReceipt(args({ base, approved: approvedEvent }))).toBeNull();
  });
});

describe('signEvidenceReceipt — signs + round-trip verifies under packages/verify', () => {
  it('approved+consumed receipt verifies offline', () => {
    const out = signEvidenceReceipt({
      receiptId: 'tr_1',
      base: createdState(),
      approved: approvedEvent,
      rejected: null,
      consumed: consumedEvent,
      issuedAt: '2026-04-26T00:00:00Z',
    });
    expect(out).not.toBeNull();
    expect(out.document['@version']).toBe('EP-RECEIPT-v1');
    expect(out.document.signature.key_class).toBe('C');
    expect(out.document.payload.authorization.status).toBe('consumed');
    expect(out.document.payload.authorization.approver_id).toBe('approver_jane');

    const result = verifyReceipt(out.document, out.public_key);
    expect(result.valid).toBe(true);
    expect(result.checks.signature).toBe(true);
  });

  it('approved-pending-consume receipt verifies offline', () => {
    const out = signEvidenceReceipt({
      receiptId: 'tr_2',
      base: createdState(),
      approved: approvedEvent,
      rejected: null,
      consumed: null,
      issuedAt: '2026-04-26T00:00:00Z',
    });
    expect(out).not.toBeNull();
    expect(out.document.payload.authorization.status).toBe('approved_pending_consume');
    expect(verifyReceipt(out.document, out.public_key).valid).toBe(true);
  });

  it('tampering any nested field breaks the signature', () => {
    const out = signEvidenceReceipt({
      receiptId: 'tr_3', base: createdState(), approved: approvedEvent, rejected: null, consumed: consumedEvent, issuedAt: '2026-04-26T00:00:00Z',
    });
    const tampered = JSON.parse(JSON.stringify(out.document));
    tampered.payload.claim.canonical_action.before_state_hash = 'sha256:evil';
    expect(verifyReceipt(tampered, out.public_key).valid).toBe(false);
  });

  it('wrong public key fails verification', () => {
    const out = signEvidenceReceipt({
      receiptId: 'tr_4', base: createdState(), approved: approvedEvent, rejected: null, consumed: consumedEvent, issuedAt: '2026-04-26T00:00:00Z',
    });
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const otherKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    expect(verifyReceipt(out.document, otherKey).valid).toBe(false);
  });
});

describe('getEvidenceSigningKeypair', () => {
  it('throws on a non-32-byte seed', () => {
    _resetForTesting();
    process.env.EP_COMMIT_SIGNING_KEY = Buffer.from('too short').toString('base64');
    expect(() => getEvidenceSigningKeypair()).toThrow(/32-byte/);
  });

  it('caches the keypair across calls', () => {
    const a = getEvidenceSigningKeypair();
    const b = getEvidenceSigningKeypair();
    expect(a).toBe(b);
  });

  it('returns null in production when no signing key is configured (fail closed)', () => {
    _resetForTesting();
    delete process.env.EP_COMMIT_SIGNING_KEY;
    process.env.NODE_ENV = 'production';
    expect(getEvidenceSigningKeypair()).toBeNull();
  });

  it('generates an ephemeral key in dev/test when none configured (round-trip still works)', () => {
    _resetForTesting();
    delete process.env.EP_COMMIT_SIGNING_KEY;
    process.env.NODE_ENV = 'test';
    const kp = getEvidenceSigningKeypair();
    expect(kp).not.toBeNull();
    expect(typeof kp.publicKeySpkiB64u).toBe('string');
  });
});
