// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';

import {
  GATE_ALLOWANCE_CLAIM_BOUNDARY,
  GATE_ALLOWANCE_VERSION,
  allowanceDigest,
  executeWithGateAllowance,
  issueGateAllowance,
  signGateAllowance,
  verifyGateAllowance,
} from './allowance.js';
import {
  capabilityActionDigest,
  capabilityBaseReceiptDigest,
  createMemoryCapabilityStore,
  delegateCapabilityReceipt,
  reconcileCapabilityOperation,
} from './capability-receipt.js';
import { canonicalize } from './execution-binding.js';

const NOW = Date.parse('2026-07-30T18:00:00.000Z');
const D = (label: string) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const currentStatus = (epoch = 1) => ({
  ok: true,
  status_epoch: epoch,
  status_head_digest: D(`allowance-status:${epoch}`),
});

function initializeCurrentStatus(store, issued, epoch = 1) {
  const status = currentStatus(epoch);
  const result = store.advanceAllowanceStatus({
    allowance_profile_id: `${issued.allowance.tenant_id}/${issued.allowance.allowance_id}`,
    allowance_digest: allowanceDigest(issued.allowance),
    revision: issued.allowance.revision,
    status_epoch: status.status_epoch,
    status_head_digest: status.status_head_digest,
    expected_status_epoch: null,
    expected_status_head_digest: null,
    status: 'active',
  });
  assert.equal(result.ok, true);
}

function material() {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    pair,
    publicKey,
    signer: {
      issuer_id: 'customer:example-security',
      key_id: 'key:allowance-authorizer',
      private_key: pair.privateKey,
    },
    trustedKeys: {
      'key:allowance-authorizer': {
        issuer_id: 'customer:example-security',
        public_key: publicKey,
      },
    },
  };
}

function authorizationReceipt(keys: ReturnType<typeof material>) {
  const payload = {
    receipt_id: 'receipt:allowance-authorization:01',
    created_at: new Date(NOW - 1_000).toISOString(),
    subject: 'owner@example.test',
    claim: {
      action_type: 'gate.allowance.issue',
      outcome: 'allow',
      capability_only: true,
    },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(
        null,
        Buffer.from(canonicalize(payload)),
        keys.pair.privateKey,
      ).toString('base64url'),
    },
    public_key: keys.publicKey,
  };
}

function allowanceInput(
  receipt: ReturnType<typeof authorizationReceipt>,
  keys: ReturnType<typeof material>,
) {
  return {
    allowance_id: 'allowance:stripe-payout:01',
    tenant_id: 'tenant:example',
    subject_id: 'agent:finance:01',
    audience: 'gate:finance:production',
    connector_id: 'stripe',
    action_type: 'stripe.payout.create',
    capability_id: 'capability:allowance:stripe-payout:01',
    capability_issuer_key_digest: `sha256:${crypto
      .createHash('sha256')
      .update(Buffer.from(keys.publicKey, 'base64url'))
      .digest('hex')}`,
    revision: 1,
    supersedes_allowance_digest: null,
    authorization_receipt_digest: capabilityBaseReceiptDigest(receipt),
    presentation_digest: D('presentation:stripe-payout-allowance'),
    issued_at: '2026-07-30T17:59:00.000Z',
    valid_from: '2026-07-30T18:00:00.000Z',
    expires_at: '2026-07-31T18:00:00.000Z',
    constraints: {
      currency: 'USD',
      aggregate_amount: 50_000,
      max_amount_per_action: 5_000,
      material_fields: [
        'action_type',
        'amount',
        'currency',
        'destination',
        'operation_id',
      ],
      operation_id_field: 'operation_id',
      amount_field: 'amount',
      currency_field: 'currency',
      target_field: 'destination',
      allowed_targets: ['acct_known_a', 'acct_known_b'],
      allowed_values: {},
    },
  };
}

function verificationOptions(keys: ReturnType<typeof material>) {
  return {
    trusted_keys: keys.trustedKeys,
    now: NOW,
    expected_allowance_id: 'allowance:stripe-payout:01',
    expected_tenant_id: 'tenant:example',
    expected_subject_id: 'agent:finance:01',
    expected_audience: 'gate:finance:production',
    expected_connector_id: 'stripe',
    expected_authorizer_id: 'customer:example-security',
  };
}

function payout(operationId: string, overrides: Record<string, unknown> = {}) {
  return {
    action_type: 'stripe.payout.create',
    amount: 2_500,
    currency: 'USD',
    destination: 'acct_known_a',
    operation_id: operationId,
    ...overrides,
  };
}

test('a Gate allowance is a signed, closed, context-pinned artifact', () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const artifact = signGateAllowance(allowanceInput(receipt, keys), keys.signer);
  assert.equal(artifact['@version'], GATE_ALLOWANCE_VERSION);
  assert.equal(artifact.claim_boundary, GATE_ALLOWANCE_CLAIM_BOUNDARY);
  const verified = verifyGateAllowance(artifact, verificationOptions(keys));
  assert.equal(verified.accepted, true);
  assert.equal(verified.allowance_digest, allowanceDigest(artifact));

  const substituted = structuredClone(artifact);
  substituted.constraints.max_amount_per_action = 50_000;
  assert.equal(
    verifyGateAllowance(substituted, verificationOptions(keys)).reason,
    'allowance_signature_invalid',
  );
  assert.equal(
    verifyGateAllowance(artifact, {
      ...verificationOptions(keys),
      expected_tenant_id: 'tenant:attacker',
    }).reason,
    'tenant_mismatch',
  );
  assert.equal(
    verifyGateAllowance(artifact, {
      ...verificationOptions(keys),
      expected_connector_id: 'github:production',
    }).reason,
    'connector_mismatch',
  );
});

test('issue binds the authorization receipt and wires the allowance to the capability ledger', () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: allowanceInput(receipt, keys),
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  assert.equal(
    issued.allowance.authorization_receipt_digest,
    capabilityBaseReceiptDigest(receipt),
  );
  assert.equal(
    issued.capabilityReceipt.capability.scope.profile_digest,
    allowanceDigest(issued.allowance),
  );
  assert.equal(issued.capabilityReceipt.capability.budget.amount, 50_000);
  assert.equal(issued.capabilityReceipt.capability.budget.currency, 'USD');
  assert.equal(
    issued.allowance.capability_id,
    issued.capabilityReceipt.capability.id,
  );
  assert.equal(
    issued.allowance.capability_issuer_key_digest,
    `sha256:${crypto
      .createHash('sha256')
      .update(Buffer.from(issued.capabilityReceipt.capability_signature.public_key, 'base64url'))
      .digest('hex')}`,
  );
});

test('one allowance binds exactly one capability envelope and refuses delegation', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const input = allowanceInput(receipt, keys);
  const stableSecret = Buffer.alloc(32, 7);
  const first = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: input,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
    secret: stableSecret,
  });
  const identical = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: input,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
    secret: stableSecret,
  });
  const conflicting = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: input,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
    secret: Buffer.alloc(32, 8),
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(first.capabilityReceipt), true);
  assert.equal(store.registerCapability(identical.capabilityReceipt), true);
  assert.equal(store.registerCapability(conflicting.capabilityReceipt), false);
  assert.throws(
    () => issueGateAllowance({
      authorizationReceipt: receipt,
      allowance: input,
      signer: keys.signer,
      capabilityIssuerPrivateKey: keys.pair.privateKey,
      capabilityId: 'capability:allowance:duplicate',
    }),
    /allowance capability_id does not match/,
  );

  const delegated = await delegateCapabilityReceipt({
    parentCapabilityReceipt: first.capabilityReceipt,
    parentSecret: first.secret,
    issuerPrivateKey: keys.pair.privateKey,
    budget: { amount: 1_000, currency: 'USD' },
    expiry: input.expires_at,
    delegateId: 'agent:unapproved:b',
    capabilityId: 'capability:allowance:delegated',
    store,
    trustedIssuerKeys: [keys.publicKey],
    now: NOW,
  });
  assert.equal(delegated.ok, true);
  const result = await executeWithGateAllowance({
    allowance: first.allowance,
    capabilityReceipt: delegated.capabilityReceipt,
    secret: delegated.secret,
    action: payout('payout:delegated', { amount: 500 }),
    operationId: 'payout:delegated',
    store,
    executeAction: async () => assert.fail('delegated allowance must not execute'),
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => currentStatus(),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: 'allowance:stripe-payout:01',
      tenant_id: 'tenant:example',
      subject_id: 'agent:finance:01',
      audience: 'gate:finance:production',
      connector_id: 'stripe',
      authorizer_id: 'customer:example-security',
    },
    now: NOW,
  });
  assert.equal(result.reason, 'allowance_capability_binding_mismatch');
});

test('allowed draws run unattended and atomically deplete the aggregate allowance', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: allowanceInput(receipt, keys),
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  initializeCurrentStatus(store, issued);
  let authorizationChecks = 0;
  const result = await executeWithGateAllowance({
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    action: payout('payout:01'),
    operationId: 'payout:01',
    store,
    executeAction: async (action) => ({ id: 'po_1', action }),
    verifyAuthorizationReceipt: (candidate) => {
      authorizationChecks += 1;
      return candidate.payload.receipt_id === receipt.payload.receipt_id;
    },
    verifyAllowanceStatus: (_candidate, context) => ({
      ...currentStatus(),
      ok: context.revision === 1,
    }),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: 'allowance:stripe-payout:01',
      tenant_id: 'tenant:example',
      subject_id: 'agent:finance:01',
      audience: 'gate:finance:production',
      connector_id: 'stripe',
      authorizer_id: 'customer:example-security',
    },
    now: NOW,
  });
  assert.equal(result.ok, true);
  assert.equal(result.remaining, 47_500);
  assert.equal(authorizationChecks, 1);
});

test('allowance execution fences one material action across wrapper operation ids', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const input = allowanceInput(receipt, keys);
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: input,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  initializeCurrentStatus(store, issued);
  const actions = [payout('payout:wrapper-a'), payout('payout:wrapper-b')];
  const effects: string[] = [];
  const common = {
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    store,
    executeAction: async (candidate) => {
      effects.push(candidate.operation_id);
      return { id: candidate.operation_id };
    },
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => currentStatus(),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: input.allowance_id,
      tenant_id: input.tenant_id,
      subject_id: input.subject_id,
      audience: input.audience,
      connector_id: input.connector_id,
      authorizer_id: keys.signer.issuer_id,
    },
    now: NOW,
  };

  const first = await executeWithGateAllowance({
    ...common,
    action: actions[0],
    operationId: actions[0].operation_id,
  });
  const duplicate = await executeWithGateAllowance({
    ...common,
    action: actions[1],
    operationId: actions[1].operation_id,
  });

  assert.equal(first.ok, true);
  assert.equal(duplicate.ok, false);
  assert.equal(duplicate.reason, 'action_already_committed');
  assert.notEqual(first.action_digest, duplicate.action_digest);
  assert.equal(first.action_fence_digest, duplicate.action_fence_digest);
  assert.equal(duplicate.holding_operation_id, actions[0].operation_id);
  assert.deepEqual(effects, [actions[0].operation_id]);
  assert.equal(
    first.action_fence_digest,
    capabilityActionDigest({
      action_type: actions[0].action_type,
      amount: actions[0].amount,
      currency: actions[0].currency,
      destination: actions[0].destination,
    }),
  );
});

test('authorization receipt verifier exceptions fail closed before execution', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: allowanceInput(receipt, keys),
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  initializeCurrentStatus(store, issued);
  let effects = 0;

  const result = await executeWithGateAllowance({
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    action: payout('payout:verifier-exception'),
    operationId: 'payout:verifier-exception',
    store,
    executeAction: async () => { effects += 1; },
    verifyAuthorizationReceipt: async () => {
      throw new Error('malformed receipt verifier input');
    },
    verifyAllowanceStatus: () => currentStatus(),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: 'allowance:stripe-payout:01',
      tenant_id: 'tenant:example',
      subject_id: 'agent:finance:01',
      audience: 'gate:finance:production',
      connector_id: 'stripe',
      authorizer_id: 'customer:example-security',
    },
    now: NOW,
  });

  assert.deepEqual(result, {
    ok: false,
    reason: 'allowance_authorization_receipt_verification_failed',
  });
  assert.equal(effects, 0);
});

test('per-action cap, beneficiary allowlist, action shape, and receipt binding fail before effect', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: allowanceInput(receipt, keys),
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  let effects = 0;
  const common = {
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    store,
    executeAction: async () => { effects += 1; },
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => currentStatus(),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: 'allowance:stripe-payout:01',
      tenant_id: 'tenant:example',
      subject_id: 'agent:finance:01',
      audience: 'gate:finance:production',
      connector_id: 'stripe',
      authorizer_id: 'customer:example-security',
    },
    now: NOW,
  };
  assert.equal((await executeWithGateAllowance({
    ...common,
    action: payout('payout:cap', { amount: 5_001 }),
    operationId: 'payout:cap',
  })).reason, 'allowance_per_action_limit_exceeded');
  assert.equal((await executeWithGateAllowance({
    ...common,
    action: payout('payout:target', { destination: 'acct_attacker' }),
    operationId: 'payout:target',
  })).reason, 'allowance_target_not_allowed');
  assert.equal((await executeWithGateAllowance({
    ...common,
    action: payout('payout:shape', { memo: 'ignored by display' }),
    operationId: 'payout:shape',
  })).reason, 'allowance_action_shape_invalid');

  const receiptSubstitution = structuredClone(issued.capabilityReceipt);
  receiptSubstitution.receipt.payload.receipt_id = 'receipt:attacker';
  assert.equal((await executeWithGateAllowance({
    ...common,
    capabilityReceipt: receiptSubstitution,
    action: payout('payout:receipt'),
    operationId: 'payout:receipt',
  })).reason, 'allowance_authorization_receipt_mismatch');
  assert.equal(effects, 0);
});

test('concurrent draws linearize and post-entry uncertainty consumes replay authority', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const input = allowanceInput(receipt, keys);
  input.constraints.aggregate_amount = 5_000;
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: input,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  initializeCurrentStatus(store, issued);
  const common = {
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    store,
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => currentStatus(),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: 'allowance:stripe-payout:01',
      tenant_id: 'tenant:example',
      subject_id: 'agent:finance:01',
      audience: 'gate:finance:production',
      connector_id: 'stripe',
      authorizer_id: 'customer:example-security',
    },
    now: NOW,
  };
  const concurrent = await Promise.all([
    executeWithGateAllowance({
      ...common,
      action: payout('payout:concurrent-a', { amount: 4_000 }),
      operationId: 'payout:concurrent-a',
      executeAction: async () => ({ id: 'po_a' }),
    }),
    executeWithGateAllowance({
      ...common,
      action: payout('payout:concurrent-b', { amount: 4_000, destination: 'acct_known_b' }),
      operationId: 'payout:concurrent-b',
      executeAction: async () => ({ id: 'po_b' }),
    }),
  ]);
  assert.equal(concurrent.filter((entry) => entry.ok).length, 1);
  assert.equal(
    concurrent.filter((entry) => !entry.ok)[0].reason,
    'budget_exceeded',
  );

  const indeterminate = await executeWithGateAllowance({
    ...common,
    action: payout('payout:timeout', { amount: 1_000 }),
    operationId: 'payout:timeout',
    executeAction: async () => { throw new Error('response lost'); },
  });
  assert.equal(indeterminate.reason, 'effect_indeterminate');
  assert.equal((await executeWithGateAllowance({
    ...common,
    action: payout('payout:timeout', { amount: 1_000 }),
    operationId: 'payout:timeout',
    executeAction: async () => ({ id: 'must-not-run' }),
  })).reason, 'operation_already_committed');
});

test('execution fails closed without current status and successors bind the predecessor digest', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const first = signGateAllowance(allowanceInput(receipt, keys), keys.signer);
  const successorInput = allowanceInput(receipt, keys);
  successorInput.revision = 2;
  successorInput.supersedes_allowance_digest = allowanceDigest(first);
  successorInput.allowance_id = 'allowance:stripe-payout:02';
  const successor = signGateAllowance(successorInput, keys.signer);
  assert.equal(successor.revision, 2);
  assert.equal(successor.supersedes_allowance_digest, allowanceDigest(first));

  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: allowanceInput(receipt, keys),
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  const result = await executeWithGateAllowance({
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    action: payout('payout:status'),
    operationId: 'payout:status',
    store,
    executeAction: async () => assert.fail('missing currentness must not execute'),
    verifyAuthorizationReceipt: () => true,
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: 'allowance:stripe-payout:01',
      tenant_id: 'tenant:example',
      subject_id: 'agent:finance:01',
      audience: 'gate:finance:production',
      connector_id: 'stripe',
      authorizer_id: 'customer:example-security',
    },
    now: NOW,
  });
  assert.equal(result.reason, 'allowance_status_verifier_required');
  const superseded = await executeWithGateAllowance({
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    action: payout('payout:superseded'),
    operationId: 'payout:superseded',
    store,
    executeAction: async () => assert.fail('superseded allowance must not execute'),
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => ({ ok: false, reason: 'allowance_superseded' }),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: 'allowance:stripe-payout:01',
      tenant_id: 'tenant:example',
      subject_id: 'agent:finance:01',
      audience: 'gate:finance:production',
      connector_id: 'stripe',
      authorizer_id: 'customer:example-security',
    },
    now: NOW,
  });
  assert.equal(superseded.reason, 'allowance_superseded');
});

test('revocation landing after status verification but before spend reservation refuses the effect', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const input = allowanceInput(receipt, keys);
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: input,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const capabilityStore = createMemoryCapabilityStore();
  assert.equal(capabilityStore.registerCapability(issued.capabilityReceipt), true);

  const activeHead = D('allowance-status:active:1');
  assert.equal((await capabilityStore.advanceAllowanceStatus({
    allowance_profile_id: `${input.tenant_id}/${input.allowance_id}`,
    allowance_digest: allowanceDigest(issued.allowance),
    revision: 1,
    status_epoch: 1,
    status_head_digest: activeHead,
    expected_status_epoch: null,
    expected_status_head_digest: null,
    status: 'active',
  })).ok, true);
  let effects = 0;
  const result = await executeWithGateAllowance({
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    action: payout('payout:status-race'),
    operationId: 'payout:status-race',
    store: capabilityStore,
    executeAction: async () => { effects += 1; },
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: async () => {
      assert.equal((await capabilityStore.advanceAllowanceStatus({
        allowance_profile_id: `${input.tenant_id}/${input.allowance_id}`,
        allowance_digest: allowanceDigest(issued.allowance),
        revision: 1,
        status: 'revoked',
        status_epoch: 2,
        status_head_digest: D('allowance-status:revoked:2'),
        expected_status_epoch: 1,
        expected_status_head_digest: activeHead,
      })).ok, true);
      return { ok: true, status_epoch: 1, status_head_digest: activeHead };
    },
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: input.allowance_id,
      tenant_id: input.tenant_id,
      subject_id: input.subject_id,
      audience: input.audience,
      connector_id: input.connector_id,
      authorizer_id: keys.signer.issuer_id,
    },
    now: NOW,
  });

  assert.equal(result.reason, 'allowance_revoked');
  assert.equal(effects, 0);
});

test('a successor allowance cannot replay an operation consumed by its predecessor', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const firstInput = allowanceInput(receipt, keys);
  const first = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: firstInput,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const successorInput = {
    ...allowanceInput(receipt, keys),
    capability_id: 'capability:allowance:stripe-payout:successor',
    revision: 2,
    supersedes_allowance_digest: allowanceDigest(first.allowance),
  };
  const successor = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: successorInput,
    predecessorAllowance: first.allowance,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(first.capabilityReceipt), true);
  initializeCurrentStatus(store, first);
  assert.equal(store.registerCapability(successor.capabilityReceipt), true);
  const action = payout('payout:stable-across-successors');
  const common = {
    secret: first.secret,
    action,
    operationId: action.operation_id,
    store,
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => currentStatus(),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: firstInput.allowance_id,
      tenant_id: firstInput.tenant_id,
      subject_id: firstInput.subject_id,
      audience: firstInput.audience,
      connector_id: firstInput.connector_id,
      authorizer_id: keys.signer.issuer_id,
    },
    now: NOW,
  };
  assert.equal((await executeWithGateAllowance({
    ...common,
    allowance: first.allowance,
    capabilityReceipt: first.capabilityReceipt,
    executeAction: async () => ({ id: 'po_first' }),
  })).ok, true);
  assert.equal((await store.advanceAllowanceStatus({
    allowance_profile_id: `${firstInput.tenant_id}/${firstInput.allowance_id}`,
    allowance_digest: allowanceDigest(successor.allowance),
    revision: 2,
    status_epoch: 2,
    status_head_digest: currentStatus(2).status_head_digest,
    expected_status_epoch: 1,
    expected_status_head_digest: currentStatus(1).status_head_digest,
    status: 'active',
  })).ok, true);
  const replay = await executeWithGateAllowance({
    ...common,
    allowance: successor.allowance,
    capabilityReceipt: successor.capabilityReceipt,
    secret: successor.secret,
    verifyAllowanceStatus: () => currentStatus(2),
    executeAction: async () => assert.fail('successor must not reset replay state'),
  });
  assert.equal(replay.reason, 'operation_already_committed');
});

test('a provider success followed by commit failure remains reconcilable without retry', async () => {
  const keys = material();
  const receipt = authorizationReceipt(keys);
  const input = allowanceInput(receipt, keys);
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: input,
    signer: keys.signer,
    capabilityIssuerPrivateKey: keys.pair.privateKey,
  });
  const durableBoundary = createMemoryCapabilityStore();
  assert.equal(durableBoundary.registerCapability(issued.capabilityReceipt), true);
  initializeCurrentStatus(durableBoundary, issued);
  let failCommit = true;
  const store = {
    ...durableBoundary,
    async commitSpend(options) {
      if (failCommit) {
        failCommit = false;
        return { ok: false, reason: 'simulated_post_provider_commit_loss' };
      }
      return durableBoundary.commitSpend(options);
    },
  };
  const action = payout('payout:provider-succeeded-commit-lost');
  let providerCalls = 0;
  const execution = await executeWithGateAllowance({
    allowance: issued.allowance,
    capabilityReceipt: issued.capabilityReceipt,
    secret: issued.secret,
    action,
    operationId: action.operation_id,
    store,
    executeAction: async () => {
      providerCalls += 1;
      return { id: 'po_provider_confirmed' };
    },
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => currentStatus(),
    trustedAllowanceKeys: keys.trustedKeys,
    trustedCapabilityIssuerKeys: [keys.publicKey],
    expected: {
      allowance_id: input.allowance_id,
      tenant_id: input.tenant_id,
      subject_id: input.subject_id,
      audience: input.audience,
      connector_id: input.connector_id,
      authorizer_id: keys.signer.issuer_id,
    },
    now: NOW,
  });
  assert.equal(execution.reason, 'capability_commit_indeterminate');
  assert.equal(providerCalls, 1);

  const reconciliation = await reconcileCapabilityOperation({
    store: durableBoundary,
    capabilityId: input.capability_id,
    operationNamespace: `${input.tenant_id}/${input.allowance_id}`,
    operationId: action.operation_id,
    action,
    evidence: { provider_id: 'po_provider_confirmed' },
    verifyEvidence: (_evidence, context) => ({
      valid: true,
      outcome: 'executed',
      action_digest: context.action_digest,
      evidence_digest: D('stripe:po_provider_confirmed'),
    }),
    now: NOW + 1,
  });
  assert.equal(reconciliation.ok, true);
  assert.equal(
    durableBoundary.getOperation(
      action.operation_id,
      input.capability_id,
      `${input.tenant_id}/${input.allowance_id}`,
    ).outcome,
    'indeterminate',
  );
  assert.equal(
    durableBoundary.getOperation(
      action.operation_id,
      input.capability_id,
      `${input.tenant_id}/${input.allowance_id}`,
    ).reconciliation_outcome,
    'executed',
  );
});
