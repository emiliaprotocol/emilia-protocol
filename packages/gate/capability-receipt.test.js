// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize } from './execution-binding.js';
import {
  executeWithCapability,
  executeWithThreshold,
  reconcileCapabilityOperation,
  delegateCapabilityReceipt,
  createMemoryCapabilityStore,
  createPostgresCapabilityStore,
  CAPABILITY_SQL,
  mintCapabilityReceipt,
  reconstructCapabilitySecret,
  splitCapabilitySecret,
  verifyCapabilityReceipt,
  CAPABILITY_RECEIPT_VERSION,
  CAPABILITY_SCOPE_PROFILE,
  CAPABILITY_CAID_SCOPE_PROFILE,
  capabilityActionDigest,
  capabilityBaseReceiptDigest,
} from './capability-receipt.js';

const NOW = Date.parse('2026-07-18T22:00:00.000Z');

function baseReceipt({ privateKey, publicKey, receiptId = 'base_1' } = {}) {
  const payload = {
    receipt_id: receiptId,
    created_at: new Date(NOW - 1000).toISOString(),
    subject: 'operator@example.test',
    claim: { action_type: 'payment.release', outcome: 'allow' },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64url') },
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function issuer() {
  const keys = generateKeyPairSync('ed25519');
  return { ...keys, receipt: baseReceipt({ privateKey: keys.privateKey, publicKey: keys.publicKey }) };
}

function scopedAction(operation_id, overrides = {}) {
  return { amount: 1, currency: 'USD', operation_id, ...overrides };
}

const DEFAULT_SCOPE_ACTIONS = [
  scopedAction('op_1', { amount: 30, destination: 'acct_a' }),
  scopedAction('op_2', { amount: 60 }),
  scopedAction('op_3', { amount: 60 }),
  scopedAction('op_4', { amount: 10 }),
  scopedAction('bad_1'),
  scopedAction('bad_1', { currency: 'EUR' }),
  scopedAction('threshold_op_1', { amount: 25 }),
  scopedAction('envelope_collision_spend'),
];

function options(overrides = {}) {
  return {
    budget: { amount: 100, currency: 'USD' },
    expiry: NOW + 60_000,
    issuerPrivateKey: overrides.issuerPrivateKey,
    scope: {
      profile: CAPABILITY_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      action_digests: DEFAULT_SCOPE_ACTIONS.map(capabilityActionDigest),
    },
    ...overrides,
  };
}

test('capability metadata is issuer-signed and tamper-evident', () => {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
  const trusted = keys.receipt.public_key;
  assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: [trusted] }).ok, true);
  assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt).reason, 'capability_issuer_not_trusted');

  const tampered = structuredClone(minted.capabilityReceipt);
  tampered.capability.budget.amount = 1_000_000;
  assert.equal(verifyCapabilityReceipt(tampered, { trustedIssuerKeys: [trusted] }).ok, false);
  assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: ['wrong'] }).reason, 'capability_issuer_not_trusted');
});

test('capability issuer is separately pinned and signs the complete base-receipt digest', () => {
  const receiptIssuer = issuer();
  const capabilityIssuer = generateKeyPairSync('ed25519');
  const capabilityIssuerPublicKey = capabilityIssuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const minted = mintCapabilityReceipt(receiptIssuer.receipt, options({
    issuerPrivateKey: capabilityIssuer.privateKey,
  }));
  assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, {
    trustedIssuerKeys: [capabilityIssuerPublicKey],
  }).ok, true);

  const substituted = structuredClone(minted.capabilityReceipt);
  substituted.receipt.payload.subject = 'attacker@example.test';
  assert.equal(verifyCapabilityReceipt(substituted, {
    trustedIssuerKeys: [capabilityIssuerPublicKey],
  }).reason, 'capability_signature_invalid');
});

test('capability scope is mandatory, signed, exact, and operation-bound', async () => {
  const keys = issuer();
  assert.throws(
    () => mintCapabilityReceipt(keys.receipt, {
      issuerPrivateKey: keys.privateKey,
      budget: { amount: 10, currency: 'USD' },
      expiry: NOW + 60_000,
    }),
    /scope.profile/,
  );

  const allowed = scopedAction('scope-op', { amount: 10, destination: 'acct_allowed' });
  const minted = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    scope: {
      profile: CAPABILITY_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      action_digests: [capabilityActionDigest(allowed)],
    },
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(minted.capabilityReceipt), true);
  const common = {
    capabilityReceipt: minted.capabilityReceipt,
    secret: minted.secret,
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    executeAction: async () => assert.fail('out-of-scope effect must not run'),
    now: NOW,
  };
  const substituted = await executeWithCapability({
    ...common,
    operationId: 'scope-op',
    action: { ...allowed, destination: 'acct_attacker' },
  });
  assert.equal(substituted.reason, 'capability_action_out_of_scope');

  const relabelled = await executeWithCapability({
    ...common,
    operationId: 'scope-op-attacker',
    action: allowed,
  });
  assert.equal(relabelled.reason, 'capability_operation_binding_failed');
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 0);
});

test('CAID scope requires a pinned resolver and matches only an allowed CAID', async () => {
  const keys = issuer();
  const action = {
    action_type: 'science.bio.experiment.execute.1',
    operation_id: 'caid-op',
    amount: 5,
    currency: 'USD',
  };
  const caid = 'caid:1:science.bio.experiment.execute.1:jcs-sha256:AdzQBitumEFF9QO6nJ9YOexgCtOcHILorM5joy0-HzY';
  const minted = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    scope: {
      profile: CAPABILITY_CAID_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      caids: [caid],
    },
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(minted.capabilityReceipt), true);
  const common = {
    capabilityReceipt: minted.capabilityReceipt,
    secret: minted.secret,
    action,
    operationId: 'caid-op',
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    executeAction: async (_action, context) => context.caid,
    now: NOW,
  };
  assert.equal((await executeWithCapability(common)).reason, 'capability_caid_resolver_required');
  const result = await executeWithCapability({ ...common, resolveCaid: () => caid });
  assert.equal(result.ok, true);
  assert.equal(result.caid, caid);
  assert.equal(result.result, caid);
});

test('atomic capability spending enforces the budget and consumes indeterminate effects', async () => {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(minted.capabilityReceipt), true);
  const common = {
    capabilityReceipt: minted.capabilityReceipt,
    secret: minted.secret,
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    now: NOW,
  };

  const first = await executeWithCapability({
    ...common,
    operationId: 'op_1',
    action: scopedAction('op_1', { amount: 30, destination: 'acct_a' }),
    executeAction: async () => 'settled',
  });
  assert.equal(first.ok, true);
  assert.equal(first.result, 'settled');
  assert.equal(store.getOperation('op_1').action_digest, capabilityActionDigest(scopedAction('op_1', { amount: 30, destination: 'acct_a' })));
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 30);

  const [left, right] = await Promise.all([
    executeWithCapability({ ...common, operationId: 'op_2', action: scopedAction('op_2', { amount: 60 }), executeAction: async () => 'left' }),
    executeWithCapability({ ...common, operationId: 'op_3', action: scopedAction('op_3', { amount: 60 }), executeAction: async () => 'right' }),
  ]);
  assert.equal([left.ok, right.ok].filter(Boolean).length, 1);
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 90);

  const indeterminate = await executeWithCapability({
    ...common,
    operationId: 'op_4',
    action: scopedAction('op_4', { amount: 10 }),
    executeAction: async () => { throw new Error('provider response lost'); },
  });
  assert.equal(indeterminate.ok, false);
  assert.equal(indeterminate.reason, 'effect_indeterminate');
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 100);

  const evidenceDigest = `sha256:${'a'.repeat(64)}`;
  const reconcile = () => reconcileCapabilityOperation({
    store,
    capabilityId: minted.capabilityReceipt.capability.id,
    operationId: 'op_4',
    action: scopedAction('op_4', { amount: 10 }),
    evidence: { provider: 'test' },
    now: NOW + 1,
    verifyEvidence: (_evidence, context) => ({
      valid: true,
      outcome: 'executed',
      action_digest: context.action_digest,
      evidence_digest: evidenceDigest,
    }),
  });
  assert.deepEqual(await reconcile(), {
    ok: true,
    outcome: 'executed',
    action_digest: capabilityActionDigest(scopedAction('op_4', { amount: 10 })),
    evidence_digest: evidenceDigest,
    idempotent: false,
  });
  assert.equal((await reconcile()).idempotent, true);
  assert.equal(store.getOperation('op_4').reconciliation_outcome, 'executed');
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 100);
});

test('capability refuses invalid secret, currency, and unverified base authority', async () => {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
  const store = createMemoryCapabilityStore();
  store.registerCapability(minted.capabilityReceipt);
  const common = {
    capabilityReceipt: minted.capabilityReceipt,
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    now: NOW,
    operationId: 'bad_1',
    executeAction: async () => assert.fail('effect must not run'),
  };
  assert.equal((await executeWithCapability({ ...common, secret: Buffer.alloc(32), action: scopedAction('bad_1') })).reason, 'invalid_secret');
  assert.equal((await executeWithCapability({ ...common, secret: minted.secret, action: scopedAction('bad_1', { currency: 'EUR' }) })).reason, 'capability action currency does not match the budget');
  assert.equal((await executeWithCapability({ ...common, secret: minted.secret, verifyBaseReceipt: () => false, action: scopedAction('bad_1') })).reason, 'base_receipt_rejected');
  assert.equal((await executeWithCapability({
    ...common,
    secret: minted.secret,
    operationId: null,
    action: scopedAction('bad_1'),
  })).reason, 'capability_operation_id_required');
});

test('threshold capability uses unique Shamir shares and requires m-of-n', async () => {
  const secret = Buffer.alloc(32, 7);
  const shares = splitCapabilitySecret(secret, { m: 2, n: 3 }, { randomBytesFn: () => Buffer.alloc(66, 9) });
  assert.equal(Buffer.compare(reconstructCapabilitySecret(shares.slice(0, 2), { m: 2, n: 3 }), secret), 0);
  assert.throws(() => reconstructCapabilitySecret([shares[0]], { m: 2, n: 3 }), /insufficient/);
  assert.throws(() => reconstructCapabilitySecret([shares[0], shares[0]], { m: 2, n: 3 }), /duplicate/);

  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    threshold: { m: 2, n: 3 },
    secret,
    capabilityId: 'threshold_1',
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(minted.capabilityReceipt), true);
  const result = await executeWithThreshold({
    capabilityReceipt: minted.capabilityReceipt,
    shares: minted.shares.slice(0, 2),
    action: scopedAction('threshold_op_1', { amount: 25 }),
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    now: NOW,
    operationId: 'threshold_op_1',
    executeAction: async () => 'threshold-settled',
  });
  assert.equal(result.ok, true);
  assert.equal(result.result, 'threshold-settled');
});

test('delegation burns parent budget before registering a spendable child', async () => {
  const keys = issuer();
  const parent = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'parent_1',
    secret: Buffer.alloc(32, 8),
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(parent.capabilityReceipt), true);

  const child = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 40, currency: 'USD' },
    expiry: NOW + 30_000,
    delegateId: 'pilot-operator',
    capabilityId: 'child_1',
    secret: Buffer.alloc(32, 9),
    store,
    now: NOW,
  });
  assert.equal(child.ok, true);
  assert.equal(child.capabilityReceipt.capability.delegation_chain.at(-1).parent_capability_id, 'parent_1');
  assert.equal(store.getState('parent_1').consumed_amount, 40);
  assert.equal(store.getState('child_1').budget_amount, 40);

  const tooLarge = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 61, currency: 'USD' },
    expiry: NOW + 30_000,
    delegateId: 'pilot-operator',
    capabilityId: 'child_2',
    store,
    now: NOW,
  });
  assert.equal(tooLarge.ok, false);
  assert.equal(tooLarge.reason, 'budget_exceeded');
  assert.equal(store.getState('parent_1').consumed_amount, 40);
});

test('delegation cannot outlive its parent, including across multiple hops', async () => {
  const keys = issuer();
  const parent = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'temporal_parent',
    expiry: NOW + 30_000,
    secret: Buffer.alloc(32, 10),
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(parent.capabilityReceipt), true);

  const directOutlivesParent = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 10, currency: 'USD' },
    expiry: NOW + 30_001,
    delegateId: 'temporal-direct',
    capabilityId: 'temporal_child_invalid',
    store,
    now: NOW,
  });
  assert.equal(directOutlivesParent.ok, false);
  assert.equal(directOutlivesParent.reason, 'delegated_capability_expiry_exceeds_parent');
  assert.equal(store.getState('temporal_parent').consumed_amount, 0);

  const child = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 10, currency: 'USD' },
    expiry: NOW + 20_000,
    delegateId: 'temporal-child',
    capabilityId: 'temporal_child',
    secret: Buffer.alloc(32, 11),
    store,
    now: NOW,
  });
  assert.equal(child.ok, true);

  const grandchildOutlivesChild = await delegateCapabilityReceipt({
    parentCapabilityReceipt: child.capabilityReceipt,
    parentSecret: child.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 5, currency: 'USD' },
    expiry: NOW + 20_001,
    delegateId: 'temporal-grandchild',
    capabilityId: 'temporal_grandchild_invalid',
    store,
    now: NOW,
  });
  assert.equal(grandchildOutlivesChild.ok, false);
  assert.equal(grandchildOutlivesChild.reason, 'delegated_capability_expiry_exceeds_parent');
  assert.equal(store.getState('temporal_child').consumed_amount, 0);
});

test('capability stores bind an id to the complete signed envelope', async () => {
  const keys = issuer();
  const first = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'envelope_collision',
    secret: Buffer.alloc(32, 12),
  }));
  const conflicting = mintCapabilityReceipt(baseReceipt({
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    receiptId: 'base_2',
  }), options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'envelope_collision',
    secret: Buffer.alloc(32, 13),
  }));
  const store = createMemoryCapabilityStore();

  assert.equal(store.registerCapability(first.capabilityReceipt), true);
  assert.equal(store.registerCapability(first.capabilityReceipt), true);
  assert.equal(store.registerCapability(conflicting.capabilityReceipt), false);

  const spend = await executeWithCapability({
    capabilityReceipt: conflicting.capabilityReceipt,
    secret: conflicting.secret,
    action: scopedAction('envelope_collision_spend'),
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    operationId: 'envelope_collision_spend',
    now: NOW,
    executeAction: async () => assert.fail('conflicting envelope must not spend'),
  });
  assert.equal(spend.ok, false);
  assert.equal(spend.reason, 'capability_envelope_mismatch');
});

test('postgres capability state also rejects a conflicting envelope', async () => {
  const keys = issuer();
  const first = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'postgres_envelope_collision',
    secret: Buffer.alloc(32, 14),
  }));
  const conflicting = mintCapabilityReceipt(baseReceipt({
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    receiptId: 'base_3',
  }), options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'postgres_envelope_collision',
    secret: Buffer.alloc(32, 15),
  }));
  let row = null;
  const transaction = async (callback) => callback(async (sql, params) => {
    if (sql === CAPABILITY_SQL.register) {
      if (!row) {
        row = {
          capability_id: params[0],
          capability_fingerprint: params[4],
          budget_amount: String(params[1]),
          currency: params[2],
          consumed_amount: '0',
          reserved_amount: '0',
          expires_at: params[3],
        };
      }
      return { rowCount: row.capability_fingerprint === params[4] ? 1 : 0 };
    }
    if (sql === CAPABILITY_SQL.readState) return { rows: row ? [row] : [] };
    throw new Error(`unexpected SQL in registration test: ${sql}`);
  });
  const store = createPostgresCapabilityStore({ transaction });

  assert.equal(await store.registerCapability(first.capabilityReceipt), true);
  assert.equal(await store.registerCapability(first.capabilityReceipt), true);
  assert.equal(await store.registerCapability(conflicting.capabilityReceipt), false);
});

const ISO = new Date(NOW - 500).toISOString();

function chainEntry({ delegation_id, parent, delegate = 'operator', amount, currency = 'USD' }) {
  return { delegation_id, parent_capability_id: parent, delegate_id: delegate, amount, currency, issued_at: ISO };
}

// Re-sign a mutated capability envelope with a trusted issuer key so the only
// thing standing between a forged chain and acceptance is the structural
// ingest check, not the signature.
function resignEnvelope(capabilityReceipt, privateKey) {
  const body = {
    '@version': CAPABILITY_RECEIPT_VERSION,
    base_receipt_id: capabilityReceipt.receipt.payload.receipt_id,
    base_receipt_digest: capabilityBaseReceiptDigest(capabilityReceipt.receipt),
    capability: capabilityReceipt.capability,
  };
  capabilityReceipt.capability_signature.value = sign(null, Buffer.from(canonicalize(body)), privateKey).toString('base64url');
  return capabilityReceipt;
}

test('a valid linear delegation chain mints and verifies', () => {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'linear_leaf',
    secret: Buffer.alloc(32, 20),
    delegationChain: [
      chainEntry({ delegation_id: 'd1', parent: 'root_cap', amount: 50 }),
      chainEntry({ delegation_id: 'd2', parent: 'mid_cap', amount: 30 }),
    ],
  }));
  assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: [keys.receipt.public_key] }).ok, true);
  assert.equal(minted.capabilityReceipt.capability.delegation_chain.length, 2);
});

test('a real multi-hop delegation produces a chain that survives acyclicity ingest', async () => {
  const keys = issuer();
  const parent = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'acyc_parent',
    expiry: NOW + 40_000,
    secret: Buffer.alloc(32, 21),
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(parent.capabilityReceipt), true);

  const child = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 40, currency: 'USD' },
    expiry: NOW + 30_000,
    delegateId: 'acyc-child',
    capabilityId: 'acyc_child',
    secret: Buffer.alloc(32, 22),
    store,
    now: NOW,
  });
  assert.equal(child.ok, true);

  const grandchild = await delegateCapabilityReceipt({
    parentCapabilityReceipt: child.capabilityReceipt,
    parentSecret: child.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 20, currency: 'USD' },
    expiry: NOW + 20_000,
    delegateId: 'acyc-grandchild',
    capabilityId: 'acyc_grandchild',
    secret: Buffer.alloc(32, 23),
    store,
    now: NOW,
  });
  assert.equal(grandchild.ok, true);
  const chain = grandchild.capabilityReceipt.capability.delegation_chain;
  assert.equal(chain.length, 2);
  // Distinct parents, non-increasing amount: a genuine chain is a simple path.
  assert.equal(new Set(chain.map((e) => e.parent_capability_id)).size, 2);
  assert.ok(chain[1].amount <= chain[0].amount);
  assert.equal(verifyCapabilityReceipt(grandchild.capabilityReceipt, { trustedIssuerKeys: [keys.receipt.public_key] }).ok, true);
});

test('a cyclic delegation chain is rejected at ingest, even when validly signed', () => {
  const keys = issuer();
  const cyclic = [
    chainEntry({ delegation_id: 'd1', parent: 'cap_A', amount: 50 }),
    chainEntry({ delegation_id: 'd2', parent: 'cap_A', amount: 30 }), // cap_A recurs as parent
  ];
  // Minting refuses to construct the forged envelope.
  assert.throws(
    () => mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey, capabilityId: 'cyclic_leaf', delegationChain: cyclic })),
    /repeats a parent_capability_id/,
  );

  // And a hand-crafted, correctly-signed envelope is still refused on ingest.
  const good = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey, capabilityId: 'cyclic_leaf', secret: Buffer.alloc(32, 24) }));
  const forged = structuredClone(good.capabilityReceipt);
  forged.capability.delegation_chain = cyclic;
  resignEnvelope(forged, keys.privateKey);
  const verified = verifyCapabilityReceipt(forged, { trustedIssuerKeys: [keys.receipt.public_key] });
  assert.equal(verified.ok, false);
  assert.equal(verified.reason, 'capability_malformed');
});

test('a repeated delegation_id is rejected as a cycle', () => {
  const keys = issuer();
  assert.throws(
    () => mintCapabilityReceipt(keys.receipt, options({
      issuerPrivateKey: keys.privateKey,
      capabilityId: 'dupid_leaf',
      delegationChain: [
        chainEntry({ delegation_id: 'same', parent: 'cap_A', amount: 20 }),
        chainEntry({ delegation_id: 'same', parent: 'cap_B', amount: 10 }),
      ],
    })),
    /repeats a delegation_id/,
  );
});

test('a delegation chain that grants increasing authority is rejected', () => {
  const keys = issuer();
  assert.throws(
    () => mintCapabilityReceipt(keys.receipt, options({
      issuerPrivateKey: keys.privateKey,
      capabilityId: 'inflate_leaf',
      delegationChain: [
        chainEntry({ delegation_id: 'd1', parent: 'cap_A', amount: 30 }),
        chainEntry({ delegation_id: 'd2', parent: 'cap_B', amount: 50 }), // 50 > 30
      ],
    })),
    /increasing authority/,
  );
});

test('a delegation chain naming the leaf capability as a parent is rejected as a broken link', () => {
  const keys = issuer();
  assert.throws(
    () => mintCapabilityReceipt(keys.receipt, options({
      issuerPrivateKey: keys.privateKey,
      capabilityId: 'broken_leaf',
      delegationChain: [
        chainEntry({ delegation_id: 'd1', parent: 'broken_leaf', amount: 10 }), // parent == leaf id
      ],
    })),
    /references the leaf capability as a parent/,
  );
});
