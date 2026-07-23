/**
 * PIP-006 Federation — two-operator cross-redemption conformance harness.
 *
 * This is the executable form of PIP-006 acceptance gate #1: a second,
 * independent operator (Operator B) verifies a receipt issued by Operator A
 * using ONLY A's published discovery surfaces — no shared key material, no
 * shared database, no trust in A's policy.
 *
 * Operator A and Operator B are independent Ed25519 identities generated here.
 * A issues a genuine EP-RECEIPT-v1 (real signature over the canonical payload);
 * B resolves A's key from A's ep-keys.json and verifies. The negative cases
 * prove the contract is sound: tampering, wrong-operator keys, and revocation
 * are all rejected, while a pre-rotation receipt still verifies against A's
 * advertised historical key.
 *
 * Run: node --test federation.test.ts   (or: npm test, from packages/verify/)
 *
 * @license Apache-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  resolveOperatorKeys,
  verifyFederatedReceiptOffline,
  verifyFederatedReceipt,
  _internals,
} from './federation.js';

// ── Canonicalization (must match packages/verify/index.js canonicalize) ──────
// Operator A signs canonical bytes; the verifier re-derives them identically.
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

// ── Operator helpers ─────────────────────────────────────────────────────────

/** Create an independent EP operator identity (an Ed25519 signing key). */
function makeOperator(operatorId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return { operatorId, publicKey, privateKey, publicKeyB64u };
}

const KEY_DISCOVERY = (op) => `https://${op.operatorId}.example/.well-known/ep-keys.json`;

// A key-SOURCE pin for an operator: the object-map form of trustedIssuers that
// binds the signer's expected key_discovery origin (required online to honor a
// receipt-supplied key_discovery — a bare-id pin cannot authenticate the key
// origin). Optionally pins the public key too.
const pinFor = (op, { pinKey = false } = {}) => ({
  [op.operatorId]: {
    key_discovery: KEY_DISCOVERY(op),
    ...(pinKey ? { publicKey: op.publicKeyB64u } : {}),
  },
});

// Relying-party status policy. The network response is not trusted by itself;
// this verifier is the configured trust boundary for authentication, exact
// target binding, and freshness.
const verifyFreshStatus = async (status, { receiptId }) => ({
  authenticated: true,
  target_bound: status?.receipt_id === receiptId,
  fresh: true,
  revoked: status?.revoked,
});

const TEST_PUBLIC_ADDRESS = '93.184.216.34';

// Explicit online trust boundary used by tests. Production implementations
// resolve every A/AAAA record, then connect directly to one approved address
// while preserving the URL hostname for TLS SNI and the Host header.
const testNetworkFor = (
  fetchImpl,
  {
    resolveAddresses = async () => [TEST_PUBLIC_ADDRESS],
    connectedAddress = null,
  } = {},
) => ({
  networkBoundary: {
    resolveAddresses,
    async fetchPinned(url, init, context) {
      const response = await fetchImpl(url, init, context);
      return {
        response,
        connectedAddress: connectedAddress || context.approvedAddresses[0],
      };
    },
  },
});

/** Operator issues a genuine EP-RECEIPT-v1 over `payload`, signed with `signingKey`. */
function issueReceipt(op, payload, { signingKey } = {}) {
  const priv = signingKey || op.privateKey;
  const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), priv);
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      signer: op.operatorId,
      key_discovery: KEY_DISCOVERY(op),
      algorithm: 'Ed25519',
      value: sig.toString('base64url'),
    },
  };
}

/** Build an operator's ep-keys.json discovery document. */
function discoveryDoc(op, { historical = [] } = {}) {
  const doc = {
    version: '1.0',
    operator_id: op.operatorId,
    keys: { [op.operatorId]: { public_key: op.publicKeyB64u, algorithm: 'Ed25519' } },
  };
  if (historical.length) {
    doc.historical_keys = {
      [op.operatorId]: historical.map((h) => ({
        public_key: h.publicKeyB64u,
        algorithm: 'Ed25519',
        retired_at: h.retired_at || '2026-01-01T00:00:00Z',
      })),
    };
  }
  return doc;
}

const samplePayload = (receiptId) => ({
  receipt_id: receiptId,
  '@version': 'EP-RECEIPT-v1',
  entity_id: 'ep_entity_acme_agent',
  action: { type: 'fin/payment-release', amount: 82000, currency: 'USD' },
  context: { risk_signals: ['large_amount'], change: { after_bank_hash: 'abc123' } },
  issued_at: '2026-06-11T12:00:00Z',
});

// ── 1. Happy path: cross-operator redemption ─────────────────────────────────

test('Operator B accepts a valid receipt issued by a PINNED Operator A', () => {
  const A = makeOperator('ep_operator_a');
  const B = makeOperator('ep_operator_b'); // B is independent; never sees A's private key
  void B;

  const receipt = issueReceipt(A, samplePayload('ep_receipt_001'));
  // B has pinned A out-of-band as a trusted federation issuer.
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A), {
    trustedIssuers: ['ep_operator_a'],
  });

  assert.equal(result.accepted, true, 'a valid, pinned cross-operator receipt must be accepted');
  assert.equal(result.verified, true);
  assert.equal(result.trusted, true);
  assert.equal(result.revoked, false);
  assert.equal(result.signer, 'ep_operator_a');
  assert.equal(result.keyMatched, 'current');
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.not_revoked, true);
  assert.equal(result.checks.issuer_pinned, true);
});

// ── 2. Tamper rejection ──────────────────────────────────────────────────────

test('a tampered payload does not verify (no trust laundering)', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_002'));

  // Relying party flips the amount after issuance.
  receipt.payload.action.amount = 1; // was 82000

  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A));
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /does not verify/);
});

// ── 3. Wrong-operator key rejection ──────────────────────────────────────────

test('a receipt does not verify against a different operator\'s key', () => {
  const A = makeOperator('ep_operator_a');
  const Imposter = makeOperator('ep_operator_a'); // same id, different key

  const receipt = issueReceipt(A, samplePayload('ep_receipt_003'));
  // B is handed the imposter's discovery doc (same operator_id, wrong key).
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(Imposter));

  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
});

test('expectedSigner mismatch is rejected before key resolution', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_003b'));
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A), {
    expectedSigner: 'ep_operator_somebody_else',
  });
  assert.equal(result.verified, false);
  assert.match(result.error || '', /Signer mismatch/);
});

// ── 4. Key rotation: historical key still verifies an old receipt ─────────────

test('a pre-rotation receipt verifies against an advertised historical key', () => {
  // A signs with an OLD key, then rotates. A's discovery doc advertises the new
  // key as current and the old key as historical. The old receipt must remain
  // verifiable (PIP-006 §Security considerations → Key rotation).
  const oldKeyPair = crypto.generateKeyPairSync('ed25519');
  const oldOp = {
    operatorId: 'ep_operator_a',
    privateKey: oldKeyPair.privateKey,
    publicKeyB64u: oldKeyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const A = makeOperator('ep_operator_a'); // new (current) key

  const oldReceipt = issueReceipt(oldOp, samplePayload('ep_receipt_004'), { signingKey: oldKeyPair.privateKey });
  oldOp.retired_at = '2026-06-11T12:00:00Z';
  const doc = discoveryDoc(A, { historical: [oldOp] });

  const result = verifyFederatedReceiptOffline(oldReceipt, doc, { trustedIssuers: ['ep_operator_a'] });
  assert.equal(result.verified, true, 'pre-rotation receipt must verify against historical key');
  assert.equal(result.accepted, true);
  assert.equal(result.keyMatched, 'historical');
});

test('a historical key refuses receipts issued after retirement or without a valid bound issued_at', () => {
  const oldKeyPair = crypto.generateKeyPairSync('ed25519');
  const oldOp = {
    operatorId: 'ep_operator_a',
    privateKey: oldKeyPair.privateKey,
    publicKeyB64u: oldKeyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    retired_at: '2026-06-11T12:00:00Z',
  };
  const A = makeOperator('ep_operator_a');
  const doc = discoveryDoc(A, { historical: [oldOp] });
  const cases = [
    { name: 'missing issued_at', issuedAt: undefined },
    { name: 'malformed issued_at', issuedAt: 'not-a-timestamp' },
    { name: 'issued after retirement', issuedAt: '2026-06-11T12:00:00.000000001Z' },
  ];

  for (const item of cases) {
    const payload = samplePayload(`ep_receipt_historical_${item.name.replaceAll(' ', '_')}`);
    if (item.issuedAt === undefined) delete payload.issued_at;
    else payload.issued_at = item.issuedAt;
    const receipt = issueReceipt(oldOp, payload, { signingKey: oldKeyPair.privateKey });

    const result = verifyFederatedReceiptOffline(receipt, doc, {
      trustedIssuers: ['ep_operator_a'],
    });
    assert.equal(result.verified, false, item.name);
    assert.equal(result.accepted, false, item.name);
    assert.match(result.error || '', /historical key.*issued_at|retired_at/i, item.name);
  }
});

test('a historical key with missing or malformed retired_at fails closed', () => {
  const oldKeyPair = crypto.generateKeyPairSync('ed25519');
  const oldOp = {
    operatorId: 'ep_operator_a',
    privateKey: oldKeyPair.privateKey,
    publicKeyB64u: oldKeyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    retired_at: '2026-06-12T00:00:00Z',
  };
  const A = makeOperator('ep_operator_a');

  for (const retiredAt of [undefined, 'not-a-timestamp']) {
    const doc = discoveryDoc(A, { historical: [oldOp] });
    if (retiredAt === undefined) delete doc.historical_keys.ep_operator_a[0].retired_at;
    else doc.historical_keys.ep_operator_a[0].retired_at = retiredAt;
    const receipt = issueReceipt(oldOp, samplePayload(`ep_receipt_bad_retirement_${String(retiredAt)}`), {
      signingKey: oldKeyPair.privateKey,
    });

    const result = verifyFederatedReceiptOffline(receipt, doc, {
      trustedIssuers: ['ep_operator_a'],
    });
    assert.equal(result.verified, false);
    assert.equal(result.accepted, false);
    assert.match(result.error || '', /historical key.*retired_at/i);
  }
});

test('resolveOperatorKeys returns current before historical', () => {
  const oldKeyPair = crypto.generateKeyPairSync('ed25519');
  const oldOp = {
    operatorId: 'ep_operator_a',
    publicKeyB64u: oldKeyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const A = makeOperator('ep_operator_a');
  const keys = resolveOperatorKeys(discoveryDoc(A, { historical: [oldOp] }), 'ep_operator_a');
  assert.equal(keys.length, 2);
  assert.equal(keys[0].status, 'current');
  assert.equal(keys[1].status, 'historical');
});

// ── 5. Revocation ────────────────────────────────────────────────────────────

test('a revoked receipt verifies cryptographically but is not accepted', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_005'));

  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A), {
    revokedReceiptIds: new Set(['ep_receipt_005']),
    trustedIssuers: ['ep_operator_a'],
  });

  // The signature is still valid — revocation is a policy/dispute signal, not a
  // forgery. But the receipt must not be accepted as live evidence.
  assert.equal(result.verified, true);
  assert.equal(result.revoked, true);
  assert.equal(result.accepted, false);
  assert.equal(result.checks.not_revoked, false);
});

// ── 6. Malformed / non-federated receipts ────────────────────────────────────

test('a receipt without signature.signer is not a federated receipt', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_006'));
  delete receipt.signature.signer;

  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A));
  assert.equal(result.verified, false);
  assert.match(result.error || '', /missing signature\.signer/);
});

test('an operator that advertises no key for the signer is rejected', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_007'));
  const emptyDoc = { version: '1.0', operator_id: 'ep_operator_a', keys: {} };
  const result = verifyFederatedReceiptOffline(receipt, emptyDoc);
  assert.equal(result.verified, false);
  assert.match(result.error || '', /advertises no key/);
});

// ── 7. Online path with injected fetch (no real network) ─────────────────────

test('online verifyFederatedReceipt resolves keys + revocation through a pinned test transport', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_008'));
  const doc = discoveryDoc(A);

  // A fake transport that serves A's discovery doc and a not-revoked verdict.
  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) {
      return { ok: true, status: 200, json: async () => doc };
    }
    if (url.includes('/api/verify/')) {
      return { ok: true, status: 200, json: async () => ({ receipt_id: 'ep_receipt_008', revoked: false }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl),
    trustedIssuers: pinFor(A),
    statusVerifier: verifyFreshStatus,
  });
  assert.equal(result.verified, true);
  assert.equal(result.accepted, true);
  assert.equal(result.revocation_confirmed, true);
  assert.equal(result.fetched.keyDiscoveryUrl, KEY_DISCOVERY(A));
});

test('online path uses the discovery doc verify_url_template for revocation', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_008b'));
  // Operator hosts its verifier-of-record at a NON-standard path and advertises
  // it via verify_url_template (e.g. a serverless function prefix).
  const doc = { ...discoveryDoc(A), verify_url_template: 'https://op.example/fn/op/api/verify/{receipt_id}' };

  let revocationUrlHit = null;
  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
    if (url.includes('/fn/op/api/verify/')) {
      revocationUrlHit = url;
      return { ok: true, status: 200, json: async () => ({ receipt_id: 'ep_receipt_008b', revoked: false }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl),
    trustedIssuers: pinFor(A),
    statusVerifier: verifyFreshStatus,
  });
  assert.equal(result.accepted, true);
  assert.equal(result.revocation_confirmed, true);
  assert.equal(revocationUrlHit, 'https://op.example/fn/op/api/verify/ep_receipt_008b');
});

test('online path honors an operator revocation verdict', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_009'));
  const doc = discoveryDoc(A);

  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
    if (url.includes('/api/verify/')) {
      return { ok: true, status: 200, json: async () => ({ receipt_id: 'ep_receipt_009', revoked: true }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl),
    trustedIssuers: pinFor(A),
    statusVerifier: verifyFreshStatus,
  });
  assert.equal(result.verified, true);
  assert.equal(result.revoked, true);
  assert.equal(result.accepted, false);
});

test('online path fails closed when key discovery is unreachable', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_010'));
  const fetchImpl = async () => { throw new Error('network down'); };
  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl),
    trustedIssuers: pinFor(A),
  });
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /Failed to fetch operator key discovery/);
});

test('online path preserves signature verification but refuses acceptance when revocation is unavailable', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_011'));
  const doc = discoveryDoc(A);
  // Discovery succeeds; revocation endpoint is down.
  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
    throw new Error('revocation feed down');
  };
  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl),
    trustedIssuers: pinFor(A),
  });
  assert.equal(result.verified, true);
  assert.equal(result.accepted, false, 'unknown revocation state must not become live acceptance');
  assert.equal(result.revocation_confirmed, false);
  assert.equal(result.revocation_status, 'unavailable');
  assert.equal(result.checks.not_revoked, false);
  assert.match(result.error || '', /revocation status is unavailable/);
});

test('online path requires authenticated, target-bound, fresh status and an explicit revoked field', async () => {
  const A = makeOperator('ep_operator_a');
  const receiptId = 'ep_receipt_status_fail_closed';
  const receipt = issueReceipt(A, samplePayload(receiptId));
  const doc = discoveryDoc(A);

  const run = async (status, statusVerifier) => {
    const fetchImpl = async (url) => {
      if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
      if (url.includes('/api/verify/')) return { ok: true, status: 200, json: async () => status };
      return { ok: false, status: 404, json: async () => ({}) };
    };
    return verifyFederatedReceipt(receipt, {
      ...testNetworkFor(fetchImpl),
      trustedIssuers: pinFor(A),
      ...(statusVerifier ? { statusVerifier } : {}),
    });
  };

  const cases = [
    {
      name: 'successful JSON without a relying-party status verifier',
      status: { receipt_id: receiptId, revoked: false },
      statusVerifier: null,
    },
    {
      name: 'missing revoked field',
      status: { receipt_id: receiptId },
      statusVerifier: async () => ({ authenticated: true, target_bound: true, fresh: true, revoked: false }),
    },
    {
      name: 'malformed verifier result',
      status: { receipt_id: receiptId, revoked: false },
      statusVerifier: async () => ({ authenticated: true }),
    },
    {
      name: 'unauthenticated verifier result',
      status: { receipt_id: receiptId, revoked: false },
      statusVerifier: async () => ({ authenticated: false, target_bound: true, fresh: true, revoked: false }),
    },
    {
      name: 'response bound to another receipt',
      status: { receipt_id: 'ep_receipt_other', revoked: false },
      statusVerifier: async () => ({ authenticated: true, target_bound: true, fresh: true, revoked: false }),
    },
    {
      name: 'verifier cannot bind the target',
      status: { receipt_id: receiptId, revoked: false },
      statusVerifier: async () => ({ authenticated: true, target_bound: false, fresh: true, revoked: false }),
    },
    {
      name: 'stale verifier result',
      status: { receipt_id: receiptId, revoked: false },
      statusVerifier: async () => ({ authenticated: true, target_bound: true, fresh: false, revoked: false }),
    },
  ];

  for (const item of cases) {
    const result = await run(item.status, item.statusVerifier);
    assert.equal(result.verified, true, item.name);
    assert.equal(result.accepted, false, item.name);
    assert.equal(result.revocation_confirmed, false, item.name);
    assert.equal(result.checks.not_revoked, false, item.name);
  }
});

// ── 8. Trust-anchor injection — the DoD-audit finding ─────────────────────────
// The core attack: a receipt's signature.signer and signature.key_discovery are
// attacker-controlled. An attacker mints a receipt with THEIR OWN key and hosts
// a matching ep-keys.json at THEIR OWN URL. The signature is internally
// consistent (it "verifies"), but the relying party never pinned this signer,
// so it must NEVER be accepted. Trust must come from out-of-band pinning, never
// from fields the receipt carries.

test('OFFLINE: attacker-controlled signer + self-hosted key does NOT accept without a pin', () => {
  // "Attacker" is a fully valid, self-consistent operator identity the relying
  // party has never heard of — exactly what an attacker can always produce.
  const Attacker = makeOperator('ep_operator_attacker');
  const receipt = issueReceipt(Attacker, samplePayload('ep_receipt_atk_001'));
  // The attacker also supplies the discovery doc that matches their own key.
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(Attacker));

  assert.equal(result.verified, true, 'the signature is internally consistent, so it verifies');
  assert.equal(result.trusted, false, 'but the signer was never pinned by the relying party');
  assert.equal(result.accepted, false, 'so the receipt must NOT be accepted (fail closed)');
  assert.equal(result.checks.issuer_pinned, false);
  assert.match(result.error || '', /not pinned/);
});

test('OFFLINE: a pinned allowlist that does NOT include the attacker still refuses acceptance', () => {
  const Attacker = makeOperator('ep_operator_attacker');
  const receipt = issueReceipt(Attacker, samplePayload('ep_receipt_atk_002'));
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(Attacker), {
    trustedIssuers: ['ep_operator_a', 'ep_operator_b'], // attacker not on the list
  });
  assert.equal(result.verified, true);
  assert.equal(result.accepted, false);
});

test('OFFLINE: expectedSigner acts as a single-issuer pin (matching → accepted)', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_atk_003'));
  const ok = verifyFederatedReceiptOffline(receipt, discoveryDoc(A), { expectedSigner: 'ep_operator_a' });
  assert.equal(ok.accepted, true);
  assert.equal(ok.trusted, true);
});

test('ONLINE: unpinned receipt is refused BEFORE any fetch (no SSRF, no trust laundering)', async () => {
  const Attacker = makeOperator('ep_operator_attacker');
  const receipt = issueReceipt(Attacker, samplePayload('ep_receipt_atk_004'));
  let fetchCalled = false;
  const fetchImpl = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => discoveryDoc(Attacker) }; };

  // No trustedIssuers / expectedSigner supplied → the receipt's own
  // key_discovery URL must not be fetched at all.
  const result = await verifyFederatedReceipt(receipt, { fetchImpl });
  assert.equal(fetchCalled, false, 'must not fetch a receipt-supplied URL for an unpinned signer');
  assert.equal(result.accepted, false);
  assert.equal(result.verified, false);
  assert.match(result.error || '', /Refusing to fetch/);
});

test('ONLINE: even a "verifying" attacker receipt is not accepted when signer is not pinned', async () => {
  // Pin a DIFFERENT operator; the attacker's own key_discovery would verify its
  // signature, but the signer is not the pinned one, so acceptance fails closed.
  const Attacker = makeOperator('ep_operator_attacker');
  const receipt = issueReceipt(Attacker, samplePayload('ep_receipt_atk_005'));
  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => discoveryDoc(Attacker) };
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const result = await verifyFederatedReceipt(receipt, { fetchImpl, trustedIssuers: ['ep_operator_a'] });
  // Signer mismatch is caught before key resolution; either way, not accepted.
  assert.equal(result.accepted, false);
});

// ── 8b. Key-SOURCE laundering — the federation trust-laundering finding ───────
// The decisive attack the string-id pin missed: an attacker sets
// signature.signer to a PINNED operator id and points signature.key_discovery at
// a server THEY control, hosting an ep-keys.json that advertises the ATTACKER's
// key under the pinned id. The forged receipt then "verifies" against the
// attacker's key and — under an id-only pin — would be ACCEPTED (trusted, because
// the id is pinned). Pinning the id does not authenticate the key SOURCE. The fix
// binds the key source to the pinned signer and fails closed.

test('ONLINE-REGRESSION: pinned signer id + attacker-hosted key_discovery origin → accepted:false', async () => {
  // The relying party pins ep_operator_a's KEY SOURCE to A's real discovery
  // origin (https://ep_operator_a.example).
  const A = makeOperator('ep_operator_a');
  // Attacker forges a receipt under A's pinned id, signs it with THEIR OWN key,
  // and points key_discovery at their OWN server hosting a matching ep-keys.json.
  const Attacker = makeOperator('ep_operator_a'); // same id, attacker key
  const receipt = issueReceipt(Attacker, samplePayload('ep_receipt_launder_001'));
  receipt.signature.key_discovery = 'https://attacker.evil.example/.well-known/ep-keys.json';

  let fetchedUrl = null;
  const fetchImpl = async (url) => {
    fetchedUrl = url;
    // The attacker's server advertises the ATTACKER's key under the pinned id,
    // so the forged signature WOULD verify against it.
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => discoveryDoc(Attacker) };
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const result = await verifyFederatedReceipt(receipt, {
    fetchImpl,
    // Key-SOURCE pin: A's id bound to A's REAL discovery origin (+ real key).
    trustedIssuers: { ep_operator_a: { key_discovery: KEY_DISCOVERY(A), publicKey: A.publicKeyB64u } },
  });

  assert.equal(result.accepted, false, 'a receipt-redirected key source must NOT be accepted (fail closed)');
  assert.equal(result.verified, false, 'the attacker key is never fetched, so nothing verifies');
  assert.equal(fetchedUrl, null, 'the verifier must not fetch the attacker-hosted key_discovery at all');
  assert.match(result.error || '', /does not match the origin pinned/);
});

test('ONLINE-REGRESSION: bare-id pin refuses a receipt-supplied key_discovery (id pin cannot authenticate the key source)', async () => {
  // A bare-id pin no longer authorizes fetching a receipt-supplied key_discovery:
  // the id alone cannot say WHERE the key comes from. Fail closed.
  const Attacker = makeOperator('ep_operator_a');
  const receipt = issueReceipt(Attacker, samplePayload('ep_receipt_launder_002'));
  receipt.signature.key_discovery = 'https://attacker.evil.example/.well-known/ep-keys.json';

  let fetchCalled = false;
  const fetchImpl = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => discoveryDoc(Attacker) }; };

  const result = await verifyFederatedReceipt(receipt, { fetchImpl, trustedIssuers: ['ep_operator_a'] });
  assert.equal(fetchCalled, false, 'a bare-id pin must not fetch a receipt-supplied key_discovery');
  assert.equal(result.accepted, false);
  assert.equal(result.verified, false);
  assert.match(result.error || '', /does not bind a key source/);
});

test('OFFLINE-REGRESSION: a key-pinned signer refuses a laundered key advertised under the pinned id', () => {
  // Offline, the discovery doc is caller-supplied — but a relying party may still
  // pin the key. If a (compromised/attacker) doc advertises a different key under
  // the pinned id, the matched key is not the pinned key → refused.
  const A = makeOperator('ep_operator_a');
  const Attacker = makeOperator('ep_operator_a'); // same id, attacker key
  const receipt = issueReceipt(Attacker, samplePayload('ep_receipt_launder_003'));
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(Attacker), {
    trustedIssuers: { ep_operator_a: { publicKey: A.publicKeyB64u } }, // pin A's REAL key
  });
  assert.equal(result.verified, true, 'the attacker signature is internally consistent with the attacker doc');
  assert.equal(result.accepted, false, 'but the verified key is not the pinned key → fail closed');
  assert.match(result.error || '', /does not match the relying party's pinned key/);
});

test('ONLINE: a properly key-SOURCE-pinned same-origin redemption still ACCEPTS', async () => {
  // The legitimate case must stay green: signer pinned, key_discovery origin
  // bound to A's real origin, key pinned to A's real key.
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_launder_ok'));
  const doc = discoveryDoc(A);
  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
    if (url.includes('/api/verify/')) {
      return { ok: true, status: 200, json: async () => ({ receipt_id: 'ep_receipt_launder_ok', revoked: false }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl),
    trustedIssuers: pinFor(A, { pinKey: true }),
    statusVerifier: verifyFreshStatus,
  });
  assert.equal(result.verified, true);
  assert.equal(result.accepted, true);
  assert.equal(result.trusted, true);
});

// ── 9. SSRF guard on receipt-supplied fetch URLs ─────────────────────────────
// The receipt supplies the key_discovery URL. A pinned signer is necessary but
// not sufficient: the URL itself must be a safe public https target, or the
// fetch is an SSRF primitive against the verifier's network.

test('ONLINE: an injected plain fetch is not an SSRF-safe network boundary', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_plain_fetch'));
  const doc = discoveryDoc(A);
  let fetchCalled = false;
  const fetchImpl = async (url) => {
    fetchCalled = true;
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
    return {
      ok: true,
      status: 200,
      json: async () => ({ receipt_id: 'ep_receipt_plain_fetch', revoked: false }),
    };
  };

  const result = await verifyFederatedReceipt(receipt, {
    fetchImpl,
    trustedIssuers: pinFor(A),
    statusVerifier: verifyFreshStatus,
  });
  assert.equal(fetchCalled, false);
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /network boundary|plain fetch/i);
});

test('ONLINE: DNS aliases to loopback such as nip.io are blocked before fetch', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_nip_io'));
  let fetchCalled = false;
  const fetchImpl = async () => {
    fetchCalled = true;
    return { ok: true, status: 200, json: async () => discoveryDoc(A) };
  };
  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl, {
      resolveAddresses: async () => ['127.0.0.1'],
    }),
    keyDiscoveryUrl: 'https://127.0.0.1.nip.io/.well-known/ep-keys.json',
  });

  assert.equal(fetchCalled, false);
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /resolved address.*not public/i);
});

test('ONLINE: mixed public and private DNS answers fail closed before fetch', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_multi_address'));
  let fetchCalled = false;
  const fetchImpl = async () => {
    fetchCalled = true;
    return { ok: true, status: 200, json: async () => discoveryDoc(A) };
  };
  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl, {
      resolveAddresses: async () => [TEST_PUBLIC_ADDRESS, '10.0.0.8'],
    }),
    keyDiscoveryUrl: 'https://multi-address.example/.well-known/ep-keys.json',
  });

  assert.equal(fetchCalled, false);
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /resolved address.*not public/i);
});

test('ONLINE: pinned transport must attest a connection to an approved address', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_unapproved_connection'));
  const fetchImpl = async () => ({ ok: true, status: 200, json: async () => discoveryDoc(A) });
  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl, { connectedAddress: '93.184.216.35' }),
    trustedIssuers: pinFor(A),
  });

  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /connected address.*not approved/i);
});

const PRIVATE_KEY_DISCOVERY_URLS = [
  'http://ep_operator_a.example/.well-known/ep-keys.json',       // not https
  'https://169.254.169.254/.well-known/ep-keys.json',            // cloud metadata (link-local)
  'https://127.0.0.1/.well-known/ep-keys.json',                  // loopback
  'https://localhost/.well-known/ep-keys.json',                  // loopback name
  'https://10.0.0.5/.well-known/ep-keys.json',                   // RFC1918 private
  'https://192.168.1.1/.well-known/ep-keys.json',                // RFC1918 private
  'https://[::1]/.well-known/ep-keys.json',                      // IPv6 loopback
  'https://[fd00::1]/.well-known/ep-keys.json',                  // IPv6 unique-local
  'https://user:pass@op.example/.well-known/ep-keys.json',       // embedded credentials
  'https://metadata.google.internal/computeMetadata/v1/',        // GCP metadata host
];

// Cohort A — the SSRF guard proper. A caller-supplied keyDiscoveryUrl override
// is the relying party's own choice and skips the origin-binding gate, so it
// exercises assertSafeFetchUrl directly: an unsafe target is blocked, no request
// issued.
for (const badUrl of PRIVATE_KEY_DISCOVERY_URLS) {
  test(`ONLINE: SSRF attempt via caller override is blocked, no request issued — ${badUrl}`, async () => {
    const A = makeOperator('ep_operator_a');
    const receipt = issueReceipt(A, samplePayload('ep_receipt_ssrf'));

    let fetchCalled = false;
    const fetchImpl = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => discoveryDoc(A) }; };

    const result = await verifyFederatedReceipt(receipt, {
      fetchImpl,
      keyDiscoveryUrl: badUrl, // relying party's own (mis)configuration; still SSRF-guarded
    });

    assert.equal(fetchCalled, false, 'the server must not issue a request to a private/unsafe URL');
    assert.equal(result.accepted, false);
    assert.equal(result.verified, false);
    assert.match(result.error || '', /Blocked unsafe key_discovery URL/);
  });
}

// Cohort B — key-SOURCE binding is fail-closed. The relying party pins A's key
// source to A's real discovery origin. An attacker who sets a PINNED signer's
// receipt key_discovery to an internal/foreign target is refused at the origin
// gate BEFORE any request — the receipt origin does not match the pinned origin.
// (An unsafe same-origin target would then still hit the SSRF guard; here the
// point is that a receipt cannot redirect a pinned signer's key source at all.)
for (const badUrl of PRIVATE_KEY_DISCOVERY_URLS) {
  test(`ONLINE: pinned signer + receipt key_discovery pointed elsewhere is refused, no request — ${badUrl}`, async () => {
    const A = makeOperator('ep_operator_a');
    const receipt = issueReceipt(A, samplePayload('ep_receipt_ssrf_b'));
    // Attacker points a PINNED operator's key_discovery at an internal target.
    receipt.signature.key_discovery = badUrl;

    let fetchCalled = false;
    const fetchImpl = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => discoveryDoc(A) }; };

    const result = await verifyFederatedReceipt(receipt, {
      fetchImpl,
      trustedIssuers: pinFor(A), // signer + key SOURCE pinned to A's real origin
    });

    assert.equal(fetchCalled, false, 'the server must not issue a request to a receipt-redirected key source');
    assert.equal(result.accepted, false);
    assert.equal(result.verified, false);
    assert.match(result.error || '', /does not match the origin pinned|Blocked unsafe key_discovery URL/);
  });
}

test('assertSafeFetchUrl allows a normal public https URL and blocks private ones', () => {
  assert.equal(_internals.assertSafeFetchUrl('https://op.example/.well-known/ep-keys.json').ok, true);
  assert.equal(_internals.assertSafeFetchUrl('https://169.254.169.254/').ok, false);
  assert.equal(_internals.assertSafeFetchUrl('https://10.1.2.3/').ok, false);
  assert.equal(_internals.assertSafeFetchUrl('http://op.example/').ok, false);
  // IPv4-mapped IPv6 to a private address must also be blocked.
  assert.equal(_internals.assertSafeFetchUrl('https://[::ffff:127.0.0.1]/').ok, false);
});

test('ONLINE: a caller-supplied keyDiscoveryUrl override is still SSRF-guarded', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_ssrf_override'));
  let fetchCalled = false;
  const fetchImpl = async () => { fetchCalled = true; return { ok: true, status: 200, json: async () => discoveryDoc(A) }; };

  const result = await verifyFederatedReceipt(receipt, {
    fetchImpl,
    keyDiscoveryUrl: 'https://169.254.169.254/.well-known/ep-keys.json',
  });
  assert.equal(fetchCalled, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /Blocked unsafe key_discovery URL/);
});

test('ONLINE: redirect responses are refused (redirect:manual closes rebind-via-redirect)', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_redirect'));
  let redirectMode = null;
  const fetchImpl = async (_url, init) => {
    redirectMode = init.redirect;
    return { ok: false, status: 302, type: 'opaqueredirect', json: async () => ({}) };
  };
  const result = await verifyFederatedReceipt(receipt, {
    ...testNetworkFor(fetchImpl),
    trustedIssuers: pinFor(A),
  });
  assert.equal(redirectMode, 'manual');
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /Failed to fetch operator key discovery|redirect/);
});
