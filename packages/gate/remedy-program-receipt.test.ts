// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import test from 'node:test';

import { canonicalize } from './execution-binding.js';
import {
  ACTION_REMEDY_RECEIPT_DOMAIN,
  ACTION_REMEDY_RECEIPT_VERSION,
  expectedRemedyProgramReceiptBindings,
  issueRemedyProgramReceipt,
  remedyProgramReceiptSigningBytes,
  verifyRemedyProgramReceipt,
} from './remedy-program-receipt.js';

const HASH = (character: string) => `sha256:${character.repeat(64)}`;
const CAID = (operation: string, character: string) => (
  `caid:1:${operation}.1:jcs-sha256:${character.repeat(43)}`
);
const CONTEXT = {
  issuer: 'emilia-gate-operator',
  tenant: 'tenant-a',
  environment: 'production',
  audience: 'remedy-auditor',
  key_id: 'remedy-key-1',
};

function outcomeEvidence() {
  return {
    evidence_id: 'remedy-outcome-evidence-1',
    evidence_digest: HASH('8'),
    remedy_operation_id: 'refund-op-1',
    remedy_action_digest: HASH('5'),
    destination_binding_digest: HASH('3'),
    units: 4_000,
    unit: 'USD-cent',
    outcome: 'executed',
    observed_at: '2026-07-21T18:28:00.000Z',
  };
}

function remedyAttempt(overrides: Record<string, unknown> = {}) {
  return {
    evidence_id: 'remedy-authorization-evidence-1',
    evidence_digest: HASH('7'),
    dispute_id: 'dispute-1',
    original_operation_id: 'payment-op-1',
    remedy_operation_id: 'refund-op-1',
    remedy_caid: CAID('payments.refund', 'B'),
    remedy_action_digest: HASH('5'),
    consequence_mode: 'receipt-program',
    capability_template_digest: HASH('2'),
    escrow_profile_digest: null,
    destination_binding_digest: HASH('3'),
    units: 4_000,
    unit: 'USD-cent',
    authorized_at: '2026-07-21T18:25:00.000Z',
    request_digest: HASH('6'),
    status: 'executed',
    claim_token_digest: HASH('9'),
    claimed_at: '2026-07-21T18:26:00.000Z',
    claim_request_digest: HASH('a'),
    outcome: 'executed',
    outcome_evidence: outcomeEvidence(),
    finalize_request_digest: HASH('b'),
    reconciliation: null,
    reconcile_request_digest: null,
    ...overrides,
  };
}

function remedyState(overrides: Record<string, unknown> = {}) {
  return {
    version: 'EP-GATE-REMEDY-PROGRAM-PROFILE-v1',
    instance_id: 'remedy-case-1',
    tenant_id: 'tenant-a',
    environment: 'production',
    audience: 'remedy-auditor',
    status: 'partially_remedied',
    revision: 5,
    created_at: '2026-07-21T18:00:00.000Z',
    updated_at: '2026-07-21T18:30:00.000Z',
    original: {
      caid: CAID('payments.capture', 'A'),
      action_digest: HASH('0'),
      operation_id: 'payment-op-1',
      consequence_mode: 'receipt-program',
      consequence_digest: HASH('1'),
      terminal_evidence_digest: HASH('4'),
      outcome: 'executed',
      occurred_at: '2026-07-21T18:10:00.000Z',
      evidence_digest: HASH('4'),
    },
    remedy_profile_digest: HASH('c'),
    destination_binding_digest: HASH('3'),
    max_remedy_units: 10_000,
    unit: 'USD-cent',
    remedied_units: 4_000,
    remaining_units: 6_000,
    used_evidence_ids: [
      'dispute-evidence-1',
      'remedy-authorization-evidence-1',
      'remedy-outcome-evidence-1',
    ],
    used_evidence_digests: [HASH('d'), HASH('7'), HASH('8')],
    original_reconciliation: null,
    revocation: null,
    dispute: {
      dispute_id: 'dispute-1',
      evidence_id: 'dispute-evidence-1',
      evidence_digest: HASH('d'),
      challenger_id: 'buyer-1',
      requested_units: 10_000,
      opened_at: '2026-07-21T18:20:00.000Z',
      original_operation_id: 'payment-op-1',
      original_action_digest: HASH('0'),
      request_digest: HASH('e'),
    },
    active_remedy: null,
    remedies: [remedyAttempt()],
    resolution: null,
    create_request_digest: HASH('f'),
    ...overrides,
  };
}

function publicKeyB64u(key: any) {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function contentDigest(receipt: any) {
  const content = {
    version: receipt.version,
    issuer: receipt.issuer,
    payload: receipt.payload,
  };
  return `sha256:${createHash('sha256').update(canonicalize(content)).digest('hex')}`;
}

function resign(receipt: any, privateKey: any) {
  const changed = structuredClone(receipt);
  changed.content_digest = contentDigest(changed);
  changed.signature = {
    algorithm: 'Ed25519',
    value: cryptoSign(null, remedyProgramReceiptSigningBytes(changed), privateKey)
      .toString('base64url'),
  };
  return changed;
}

async function fixture() {
  const keys = generateKeyPairSync('ed25519');
  const state = remedyState();
  const expected = expectedRemedyProgramReceiptBindings(state, 'refund-op-1');
  const receipt = await issueRemedyProgramReceipt({
    state,
    remedyOperationId: 'refund-op-1',
  }, {
    context: CONTEXT,
    privateKey: keys.privateKey,
    allowEphemeralState: true,
  });
  const options = {
    trustedKeys: { [CONTEXT.key_id]: publicKeyB64u(keys.publicKey) },
    expectedIssuer: CONTEXT,
    state,
    expected,
  };
  return { keys, state, expected, receipt, options };
}

test('issues an offline-verifiable receipt over one exact Remedy Program snapshot', async () => {
  const { keys, state, receipt, options } = await fixture();
  assert.equal(receipt.version, ACTION_REMEDY_RECEIPT_VERSION);
  assert.deepEqual(receipt.issuer, CONTEXT);
  assert.equal(receipt.payload.original_effect.operation_id, 'payment-op-1');
  assert.equal(receipt.payload.original_effect.terminal_evidence_digest, HASH('4'));
  assert.equal(receipt.payload.original_reconciliation, null);
  assert.equal(receipt.payload.remedy.operation_id, 'refund-op-1');
  assert.equal(receipt.payload.remedy.owner_mode, 'receipt-program');
  assert.equal(receipt.payload.remedy.owner_digest, HASH('2'));
  assert.deepEqual(receipt.payload.semantics, {
    original_effect: 'immutable_fact',
    remedy_effect: 'compensating_action',
    rollback: false,
  });
  assert.equal(Object.isFrozen(receipt), true);
  assert.equal(state.original.operation_id, 'payment-op-1');

  const verified = verifyRemedyProgramReceipt(receipt, options);
  assert.equal(verified.valid, true, verified.reason);
  assert.equal(verified.reason, 'verified');
  assert.deepEqual(
    Object.values(verified.checks),
    Array(Object.keys(verified.checks).length).fill(true),
  );

  const canonicalBodyOnly = Buffer.from(canonicalize({
    version: receipt.version,
    issuer: receipt.issuer,
    payload: receipt.payload,
    content_digest: receipt.content_digest,
  }), 'utf8');
  const signature = Buffer.from(receipt.signature.value, 'base64url');
  assert.equal(
    cryptoVerify(null, remedyProgramReceiptSigningBytes(receipt), keys.publicKey, signature),
    true,
  );
  assert.equal(cryptoVerify(null, canonicalBodyOnly, keys.publicKey, signature), false);
  assert.equal(
    remedyProgramReceiptSigningBytes(receipt).subarray(0, Buffer.byteLength(ACTION_REMEDY_RECEIPT_DOMAIN)).toString(),
    ACTION_REMEDY_RECEIPT_DOMAIN,
  );
});

test('requires exact issuer and expected original, case, state, and remedy bindings', async (t) => {
  const { receipt, options } = await fixture();
  const cases: Array<[string, any]> = [
    ['tenant', { expectedIssuer: { ...CONTEXT, tenant: 'tenant-b' } }],
    ['environment', { expectedIssuer: { ...CONTEXT, environment: 'staging' } }],
    ['audience', { expectedIssuer: { ...CONTEXT, audience: 'executor' } }],
    ['issuer', { expectedIssuer: { ...CONTEXT, issuer: 'other-operator' } }],
    ['key id', { expectedIssuer: { ...CONTEXT, key_id: 'other-key' } }],
    ['original operation', { expected: { ...options.expected, original_operation_id: 'payment-op-2' } }],
    ['original action', { expected: { ...options.expected, original_action_digest: HASH('c') } }],
    ['terminal evidence', { expected: { ...options.expected, original_terminal_evidence_digest: HASH('c') } }],
    ['case instance', { expected: { ...options.expected, case_instance_id: 'remedy-case-2' } }],
    ['revision', { expected: { ...options.expected, case_revision: 6 } }],
    ['status', { expected: { ...options.expected, case_status: 'remedied' } }],
    ['remedy operation', { expected: { ...options.expected, remedy_operation_id: 'refund-op-2' } }],
    ['remedy action', { expected: { ...options.expected, remedy_action_digest: HASH('c') } }],
    ['remedy CAID', { expected: { ...options.expected, remedy_caid: CAID('payments.refund', 'C') } }],
    ['destination', { expected: { ...options.expected, destination_binding_digest: HASH('c') } }],
    ['units', { expected: { ...options.expected, units: 4_001 } }],
    ['owner mode', { expected: { ...options.expected, owner_mode: 'action-escrow' } }],
    ['owner digest', { expected: { ...options.expected, owner_digest: HASH('c') } }],
  ];
  for (const [name, override] of cases) {
    await t.test(name, () => {
      const result = verifyRemedyProgramReceipt(receipt, { ...options, ...override });
      assert.equal(result.valid, false);
      assert.match(result.reason, /expected_(issuer|binding)_mismatch/);
    });
  }
});

test('rejects cross-tenant, cross-case, and changed-state replay', async () => {
  const { receipt, options } = await fixture();
  const tenantState = remedyState({ tenant_id: 'tenant-b' });
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    ...options,
    state: tenantState,
  }).reason, 'receipt_state_snapshot_mismatch');

  const caseState = remedyState({ instance_id: 'remedy-case-2' });
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    ...options,
    state: caseState,
  }).reason, 'receipt_state_snapshot_mismatch');

  const changedState = remedyState({
    revision: 6,
    updated_at: '2026-07-21T18:31:00.000Z',
    used_evidence_ids: [
      ...remedyState().used_evidence_ids,
      'later-evidence',
    ],
    used_evidence_digests: [
      ...remedyState().used_evidence_digests,
      HASH('c'),
    ],
  });
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    ...options,
    state: changedState,
  }).reason, 'receipt_state_snapshot_mismatch');
});

test('rejects missing, extra, accessor, symbol, and prototype-named fields', async () => {
  const { receipt, options, keys } = await fixture();

  const missing = structuredClone(receipt);
  delete missing.payload.remedy.destination_binding_digest;
  assert.equal(verifyRemedyProgramReceipt(missing, options).reason, 'receipt_structure_invalid');

  const extra = structuredClone(receipt);
  extra.rollback_claim = true;
  assert.equal(verifyRemedyProgramReceipt(extra, options).reason, 'receipt_structure_invalid');

  const nestedExtra = structuredClone(receipt);
  nestedExtra.payload.original_effect.untrusted_hint = 'signed-but-unsupported';
  assert.equal(verifyRemedyProgramReceipt(nestedExtra, options).reason, 'receipt_structure_invalid');

  const prototypeNamed = structuredClone(receipt);
  Object.defineProperty(prototypeNamed.payload.remedy, '__proto__', {
    enumerable: true,
    configurable: true,
    value: { rollback: true },
  });
  assert.equal(verifyRemedyProgramReceipt(prototypeNamed, options).reason, 'receipt_structure_invalid');

  const symbolField = structuredClone(receipt);
  symbolField.payload[Symbol('hidden')] = true;
  assert.equal(verifyRemedyProgramReceipt(symbolField, options).reason, 'receipt_structure_invalid');

  const accessor: any = {};
  Object.defineProperty(accessor, 'version', {
    enumerable: true,
    get() { throw new Error('secret'); },
  });
  assert.doesNotThrow(() => verifyRemedyProgramReceipt(accessor, options));
  assert.equal(verifyRemedyProgramReceipt(accessor, options).reason, 'receipt_structure_invalid');

  const hostileState = remedyState();
  Object.defineProperty(hostileState.original, 'constructor', {
    enumerable: true,
    configurable: true,
    value: 'attacker',
  });
  await assert.rejects(() => issueRemedyProgramReceipt({
    state: hostileState,
    remedyOperationId: 'refund-op-1',
  }, {
    context: CONTEXT,
    privateKey: keys.privateKey,
    allowEphemeralState: true,
  }), /prototype-named field/);
});

test('rejects malformed, noncanonical, non-Ed25519, and substituted signatures', async () => {
  const { receipt, options } = await fixture();
  const malformed = structuredClone(receipt);
  malformed.signature.value = 'not-a-signature';
  assert.equal(verifyRemedyProgramReceipt(malformed, options).reason, 'receipt_signature_invalid');

  const padded = structuredClone(receipt);
  padded.signature.value += '=';
  assert.equal(verifyRemedyProgramReceipt(padded, options).reason, 'receipt_signature_invalid');

  const algorithm = structuredClone(receipt);
  algorithm.signature.algorithm = 'Ed448';
  assert.equal(verifyRemedyProgramReceipt(algorithm, options).reason, 'receipt_signature_invalid');

  const attacker = generateKeyPairSync('ed25519');
  const substituted = resign(receipt, attacker.privateKey);
  assert.equal(
    verifyRemedyProgramReceipt(substituted, options).reason,
    'receipt_signature_invalid',
  );

  const substitutedId = structuredClone(receipt);
  substitutedId.issuer.key_id = 'attacker-key';
  const attackerReceipt = resign(substitutedId, attacker.privateKey);
  assert.equal(verifyRemedyProgramReceipt(attackerReceipt, {
    ...options,
    trustedKeys: {
      ...options.trustedKeys,
      'attacker-key': publicKeyB64u(attacker.publicKey),
    },
  }).reason, 'receipt_expected_issuer_mismatch');
});

test('detects content tampering independently of signature verification', async () => {
  const { keys, receipt, options } = await fixture();
  const digestTamper = structuredClone(receipt);
  digestTamper.content_digest = HASH('c');
  assert.equal(
    verifyRemedyProgramReceipt(digestTamper, options).reason,
    'receipt_content_digest_mismatch',
  );

  const factTamper = structuredClone(receipt);
  factTamper.payload.original_effect.consequence_digest = HASH('c');
  assert.equal(
    verifyRemedyProgramReceipt(factTamper, options).reason,
    'receipt_content_digest_mismatch',
  );

  const signedContradiction = structuredClone(receipt);
  signedContradiction.payload.original_effect.consequence_digest = HASH('c');
  assert.equal(
    verifyRemedyProgramReceipt(
      resign(signedContradiction, keys.privateKey),
      options,
    ).reason,
    'receipt_expected_binding_mismatch',
  );
});

test('supports the action-escrow remedy owner mode without changing the receipt semantics', async () => {
  const keys = generateKeyPairSync('ed25519');
  const state = remedyState({
    remedies: [remedyAttempt({
      consequence_mode: 'action-escrow',
      capability_template_digest: null,
      escrow_profile_digest: HASH('2'),
    })],
  });
  const expected = expectedRemedyProgramReceiptBindings(state, 'refund-op-1');
  const receipt = await issueRemedyProgramReceipt({
    state,
    remedyOperationId: 'refund-op-1',
  }, {
    context: CONTEXT,
    privateKey: keys.privateKey,
    allowEphemeralState: true,
  });
  assert.equal(receipt.payload.remedy.owner_mode, 'action-escrow');
  assert.equal(receipt.payload.remedy.owner_digest, HASH('2'));
  assert.equal(receipt.payload.semantics.remedy_effect, 'compensating_action');
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    trustedKeys: { [CONTEXT.key_id]: publicKeyB64u(keys.publicKey) },
    expectedIssuer: CONTEXT,
    state,
    expected,
  }).valid, true);
});

test('preserves an indeterminate original and its authenticated executed reconciliation', async () => {
  const keys = generateKeyPairSync('ed25519');
  const state = remedyState({
    original: {
      ...remedyState().original,
      outcome: 'indeterminate',
    },
    original_reconciliation: {
      evidence_id: 'original-reconciliation-1',
      evidence_digest: HASH('6'),
      original_operation_id: 'payment-op-1',
      original_action_digest: HASH('0'),
      terminal_evidence_digest: HASH('4'),
      outcome: 'executed',
      observed_at: '2026-07-21T18:22:00.000Z',
      request_digest: HASH('9'),
    },
  });
  const expected = expectedRemedyProgramReceiptBindings(state, 'refund-op-1');
  const receipt = await issueRemedyProgramReceipt({
    state,
    remedyOperationId: 'refund-op-1',
  }, {
    context: CONTEXT,
    privateKey: keys.privateKey,
    allowEphemeralState: true,
  });
  assert.equal(receipt.payload.original_effect.outcome, 'indeterminate');
  assert.equal(receipt.payload.original_reconciliation.outcome, 'executed');
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    trustedKeys: { [CONTEXT.key_id]: publicKeyB64u(keys.publicKey) },
    expectedIssuer: CONTEXT,
    state,
    expected,
  }).valid, true);
});

test('refuses a rollback-shaped remedy and preserves the original effect as facts', async () => {
  const keys = generateKeyPairSync('ed25519');
  const sameOperation = remedyState({
    remedies: [remedyAttempt({ remedy_operation_id: 'payment-op-1' })],
  });
  await assert.rejects(() => issueRemedyProgramReceipt({
    state: sameOperation,
    remedyOperationId: 'payment-op-1',
  }, {
    context: CONTEXT,
    privateKey: keys.privateKey,
    allowEphemeralState: true,
  }), /compensating/);

  const sameAction = remedyState({
    remedies: [remedyAttempt({ remedy_action_digest: HASH('0') })],
  });
  await assert.rejects(() => issueRemedyProgramReceipt({
    state: sameAction,
    remedyOperationId: 'refund-op-1',
  }, {
    context: CONTEXT,
    privateKey: keys.privateKey,
    allowEphemeralState: true,
  }), /compensating/);
});

test('production issuance requires KMS/HSM custody and self-checks external signatures', async () => {
  const keys = generateKeyPairSync('ed25519');
  const state = remedyState();
  const input = { state, remedyOperationId: 'refund-op-1' };

  await assert.rejects(() => issueRemedyProgramReceipt(input, {
    context: CONTEXT,
    privateKey: keys.privateKey,
  }), /external KMS\/HSM signer/);

  await assert.rejects(() => issueRemedyProgramReceipt(input, {
    context: CONTEXT,
    signer: {
      keyId: CONTEXT.key_id,
      custody: 'software',
      publicKey: publicKeyB64u(keys.publicKey),
      sign: async (bytes: Buffer) => cryptoSign(null, bytes, keys.privateKey),
    },
  }), /custody must be kms or hsm/);

  const external = await issueRemedyProgramReceipt(input, {
    context: CONTEXT,
    signer: {
      keyId: CONTEXT.key_id,
      custody: 'hsm',
      publicKey: publicKeyB64u(keys.publicKey),
      sign: async (bytes: Buffer) => cryptoSign(null, bytes, keys.privateKey),
    },
  });
  assert.equal(verifyRemedyProgramReceipt(external, {
    trustedKeys: { [CONTEXT.key_id]: publicKeyB64u(keys.publicKey) },
    expectedIssuer: CONTEXT,
    state,
    expected: expectedRemedyProgramReceiptBindings(state, 'refund-op-1'),
  }).valid, true);

  const wrong = generateKeyPairSync('ed25519');
  await assert.rejects(() => issueRemedyProgramReceipt(input, {
    context: CONTEXT,
    signer: {
      keyId: CONTEXT.key_id,
      custody: 'kms',
      publicKey: publicKeyB64u(keys.publicKey),
      sign: async (bytes: Buffer) => cryptoSign(null, bytes, wrong.privateKey),
    },
  }), /self-verification failed/);
});

test('refuses non-Ed25519 keys, context substitution, and ambiguous remedy selection', async () => {
  const ed25519 = generateKeyPairSync('ed25519');
  const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const input = { state: remedyState(), remedyOperationId: 'refund-op-1' };

  await assert.rejects(() => issueRemedyProgramReceipt(input, {
    context: CONTEXT,
    privateKey: p256.privateKey,
    allowEphemeralState: true,
  }), /Ed25519/);

  await assert.rejects(() => issueRemedyProgramReceipt(input, {
    context: { ...CONTEXT, tenant: 'tenant-b' },
    privateKey: ed25519.privateKey,
    allowEphemeralState: true,
  }), /context does not match state/);

  const duplicated = remedyState({
    active_remedy: remedyAttempt({ status: 'claimed', outcome: null }),
    remedies: [remedyAttempt()],
  });
  await assert.rejects(() => issueRemedyProgramReceipt({
    state: duplicated,
    remedyOperationId: 'refund-op-1',
  }, {
    context: CONTEXT,
    privateKey: ed25519.privateKey,
    allowEphemeralState: true,
  }), /remedy operation is not unique/);
});

test('verification requires relying-party issuer, state, and expected-binding pins', async () => {
  const { receipt, options } = await fixture();
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    ...options,
    expectedIssuer: undefined,
  }).reason, 'receipt_expected_issuer_mismatch');
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    ...options,
    state: undefined,
  }).reason, 'receipt_state_snapshot_mismatch');
  assert.equal(verifyRemedyProgramReceipt(receipt, {
    ...options,
    expected: undefined,
  }).reason, 'receipt_expected_binding_mismatch');
});
