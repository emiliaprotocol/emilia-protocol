// SPDX-License-Identifier: Apache-2.0

import { generateKeyPairSync } from 'node:crypto';

import { computeCaid } from '../../caid/impl/js/caid.mjs';
import {
  CAPABILITY_CAID_SCOPE_PROFILE,
  createDefaultActionRiskManifest,
  createEg1Harness,
  createGate,
  createMemoryCapabilityStore,
  createReceiptProgramKernel,
  createRuntimeMonitor,
  mintCapabilityReceipt,
  verifyReceiptProgramCertificate,
} from '../../packages/gate/index.js';

const now = Date.parse('2026-08-07T17:00:00.000Z');

// The owner's mandate grammar. Only travel.book.1 exists: an action type the
// grammar cannot resolve has no CAID and therefore no authorization path.
const mandateDefinitions = [{
  action_type: 'travel.book.1',
  required_fields: [
    { name: 'amount', type: 'amount-string' },
    { name: 'currency', type: 'enum', values_ref: 'ISO 4217 alpha-3' },
    { name: 'route', type: 'string' },
    { name: 'booking_reference', type: 'string' },
  ],
  optional_fields: [],
}];

// Pinned relying-party resolver: recompute the CAID from the observed action
// under the mandate grammar. A grammar refusal throws a typed reason the
// kernel converts into a refusal certificate, never a crash.
function resolveCaid(observed) {
  const material = {
    action_type: `${observed?.action_type}.1`,
    amount: observed?.amount,
    currency: observed?.currency,
    route: observed?.route,
    booking_reference: observed?.booking_reference,
  };
  const computed = computeCaid(material, { suite: 'jcs-sha256', definitions: mandateDefinitions });
  if (!computed.caid) throw new Error(`receipt_program:mandate_refused:${computed.refusals?.join(',') ?? 'unknown reason'}`);
  return computed.caid;
}

function bookingAction(amountUsd, route, reference) {
  return Object.freeze({
    action_type: 'travel.book',
    amount: `${amountUsd}.00`,
    amount_usd: amountUsd,
    currency: 'USD',
    route,
    booking_reference: reference,
  });
}

const flight340 = bookingAction(340, 'LAX-SFO', 'bk_2026_0340');
const flight620 = bookingAction(620, 'LAX-JFK', 'bk_2026_0620');
const flight120 = bookingAction(120, 'LAX-LAS', 'bk_2026_0120');
const alcoholPurchase = Object.freeze({
  action_type: 'purchase.alcohol',
  amount: '89.00',
  amount_usd: 89,
  currency: 'USD',
  vendor: 'duty-free',
  booking_reference: 'bk_2026_0089',
});

const caid340 = resolveCaid(flight340);
const caid620 = resolveCaid(flight620);
const caid120 = resolveCaid(flight120);

// One owner ceremony: a Class-A signed receipt over the mandate claim itself.
// Exact-action identity is enforced per run by the CAID scope, not by this claim.
const mandateClaim = Object.freeze({
  action_type: 'travel.book',
  mandate_id: 'unattended-travel-under-500-v1',
  unattended_limit_usd: 500,
  currency: 'USD',
});
const harness = createEg1Harness({ action: mandateClaim, now: () => now, idPrefix: 'authority-loop' });
const mandateReceipt = harness.mint({ outcome: 'allow_with_signoff', extra: { capability_only: true } });

const capabilityIssuer = generateKeyPairSync('ed25519');
const capabilityIssuerKey = capabilityIssuer.publicKey
  .export({ type: 'spki', format: 'der' }).toString('base64url');
const capabilityStore = createMemoryCapabilityStore();

// Unattended envelope: 500 USD budget over the mandate's identified actions.
// The scope can NAME an over-limit action (caid620); the budget refuses it.
const unattended = mintCapabilityReceipt(mandateReceipt, {
  issuerPrivateKey: capabilityIssuer.privateKey,
  budget: { amount: 500, currency: 'USD' },
  expiry: now + 30 * 24 * 60 * 60 * 1000,
  revocationMode: 'direct',
  capabilityId: 'cap_mandate_unattended',
  secret: Buffer.alloc(32, 7),
  scope: {
    profile: CAPABILITY_CAID_SCOPE_PROFILE,
    operation_id_field: 'booking_reference',
    caids: [caid340, caid620, caid120],
  },
});
if (!capabilityStore.registerCapability(unattended.capabilityReceipt)) {
  throw new Error('unattended capability registration failed');
}

// The reusable mandate receipt statically binds the action type. On every
// capability run, the CAID scope plus the amount/currency budget bind the
// exact observed booking; the reusable receipt is not relabeled as approval
// of a particular itinerary.
const manifest = createDefaultActionRiskManifest({
  extraActions: [{
    id: 'travel.booking',
    label: 'Travel booking',
    action_type: 'travel.book',
    risk: 'high',
    receipt_required: true,
    assurance_class: 'class_a',
    execution_binding: { required_fields: ['action_type'] },
    match: { protocol: 'mcp', tool: 'book_travel' },
    why: 'Spends the owner\'s money on external, non-reversible reservations.',
  }],
});

const certificateOperator = generateKeyPairSync('ed25519');
const certificateOperatorKey = certificateOperator.publicKey
  .export({ type: 'spki', format: 'der' }).toString('base64url');

const gate = createGate({
  manifest,
  trustedKeys: [harness.publicKey],
  approverKeys: harness.approverKeys,
  quorumPolicy: harness.quorumPolicy,
  rpId: harness.rpId,
  allowedOrigins: harness.allowedOrigins,
  capabilityStore,
  capabilityTrustedIssuerKeys: [capabilityIssuerKey],
  capabilityCaidResolver: resolveCaid,
  runtimeMonitor: createRuntimeMonitor({ now: () => now }),
  allowEphemeralStore: true,
  now: () => now,
});
const kernel = createReceiptProgramKernel({
  gate,
  resolveCaid,
  operationIdField: 'booking_reference',
  certificatePrivateKey: certificateOperator.privateKey,
  certificateContext: {
    issuer: 'emilia-authority-loop-demo',
    tenant: 'demo',
    environment: 'local-demo',
    audience: 'demo-verifier',
    key_id: 'local-dev',
  },
  projectResult: (result) => ({
    provider: result.provider,
    provider_operation_id: result.provider_operation_id,
    status: result.status,
  }),
  effectTimeoutMs: 50,
  allowEphemeralState: true,
  now: () => now,
});

function expect(condition, message) {
  if (!condition) throw new Error(`authority loop expectation failed: ${message}`);
}

function verifyCertificate(run) {
  return verifyReceiptProgramCertificate(run.certificate, {
    trustedCertificateKeys: { [kernel.certificate_context.key_id]: certificateOperatorKey },
    resolveCaid,
    expectedContext: kernel.certificate_context,
    certificateEvidence: run.certificate_evidence,
    verifyCertificateInclusion: (candidate) => gate.evidence.all().some(
      (record) => JSON.stringify(record) === JSON.stringify(candidate),
    ),
  });
}

function bookingRequest(action, caid, capability, capabilitySecret, instructionId) {
  return {
    programId: 'authority-loop-v1',
    instructionId,
    caid,
    selector: { protocol: 'mcp', tool: 'book_travel' },
    observedAction: action,
    capability: {
      capabilityReceipt: capability,
      secret: capabilitySecret,
      action: { amount: action.amount_usd, currency: action.currency },
      operationId: action.booking_reference,
    },
  };
}

let providerCalls = 0;
async function airline(_authorization, operation) {
  providerCalls += 1;
  return {
    provider: 'simulated-airline',
    provider_operation_id: operation.providerIdempotencyKey,
    status: 'ticketed',
  };
}

function envelopeState() {
  const state = capabilityStore.getState('cap_mandate_unattended');
  return `${state.consumed_amount} of ${state.budget_amount} USD consumed`;
}

console.log('EMILIA AUTHORITY LOOP');
console.log('Mandate: book travel under 500 USD unattended; ask above; never alcohol.');

// ── Scene 1: ALLOW ─────────────────────────────────────────────────────────
console.log('--- Scene 1: book a 340 USD flight (inside the unattended envelope)');
const allowRun = await kernel.run(
  bookingRequest(flight340, caid340, unattended.capabilityReceipt, unattended.secret, 'book-flight-340'),
  airline,
);
expect(allowRun.ok && allowRun.outcome === 'executed', `scene 1 outcome ${allowRun.outcome}: ${allowRun.reason}`);
expect(verifyCertificate(allowRun).ok, 'scene 1 certificate verification');
console.log(`CAID: ${caid340}`);
console.log(`ALLOW: executed, certificate verified offline (${allowRun.certificate.result.status})`);
console.log(`Unattended envelope: ${envelopeState()}`);

// ── Scene 2: ASK ───────────────────────────────────────────────────────────
console.log('--- Scene 2: book a 620 USD flight (above the unattended envelope)');
const askRefusal = await kernel.run(
  bookingRequest(flight620, caid620, unattended.capabilityReceipt, unattended.secret, 'book-flight-620'),
  airline,
);
expect(!askRefusal.ok && askRefusal.outcome === 'refused' && askRefusal.reason === 'budget_exceeded',
  `scene 2 refusal ${askRefusal.outcome}: ${askRefusal.reason}`);
expect(verifyCertificate(askRefusal).ok, 'scene 2 refusal certificate verification');
console.log(`ASK: refused unattended (${askRefusal.reason}); escalated to the owner`);

// Fresh owner approval: a new owner-signed capability pinned to exactly this
// action's CAID, with a budget of exactly this amount, spendable once.
const approval620 = mintCapabilityReceipt(mandateReceipt, {
  issuerPrivateKey: capabilityIssuer.privateKey,
  budget: { amount: 620, currency: 'USD' },
  expiry: now + 24 * 60 * 60 * 1000,
  revocationMode: 'direct',
  capabilityId: 'cap_owner_approval_620',
  secret: Buffer.alloc(32, 8),
  scope: {
    profile: CAPABILITY_CAID_SCOPE_PROFILE,
    operation_id_field: 'booking_reference',
    caids: [caid620],
  },
});
if (!capabilityStore.registerCapability(approval620.capabilityReceipt)) {
  throw new Error('owner approval capability registration failed');
}
const approvedRun = await kernel.run(
  bookingRequest(flight620, caid620, approval620.capabilityReceipt, approval620.secret, 'book-flight-620'),
  airline,
);
expect(approvedRun.ok && approvedRun.outcome === 'executed', `scene 2 approval ${approvedRun.outcome}: ${approvedRun.reason}`);
expect(verifyCertificate(approvedRun).ok, 'scene 2 approval certificate verification');
console.log(`APPROVED ONCE: exact-action capability (CAID-pinned, 620 USD) executed (${approvedRun.certificate.result.status})`);

const replay = await kernel.run(
  bookingRequest(flight620, caid620, approval620.capabilityReceipt, approval620.secret, 'book-flight-620'),
  airline,
);
expect(!replay.ok && replay.outcome === 'refused' && replay.reason === 'operation_already_committed',
  `scene 2 replay ${replay.outcome}: ${replay.reason}`);
expect(verifyCertificate(replay).ok, 'scene 2 replay certificate verification');
console.log(`REPLAY REFUSED: ${replay.reason} (the approval was consumed exactly once)`);

// ── Scene 3: REFUSE ────────────────────────────────────────────────────────
console.log('--- Scene 3: buy 89 USD of alcohol (outside the mandate grammar)');
const alcoholIdentity = computeCaid({
  action_type: 'purchase.alcohol.1',
  amount: alcoholPurchase.amount,
  currency: alcoholPurchase.currency,
  vendor: alcoholPurchase.vendor,
  booking_reference: alcoholPurchase.booking_reference,
}, { suite: 'jcs-sha256', definitions: mandateDefinitions });
expect(!alcoholIdentity.caid, 'mandate grammar must refuse the alcohol action type');
console.log(`Mandate grammar refusals: ${alcoholIdentity.refusals?.join(',') ?? 'unknown reason'}`);

// The agent asserts a CAID under its own permissive grammar; the kernel's
// pinned mandate resolver still refuses before any reservation or effect.
const agentClaimedCaid = computeCaid({
  action_type: 'purchase.alcohol.1',
  amount: alcoholPurchase.amount,
  currency: alcoholPurchase.currency,
  vendor: alcoholPurchase.vendor,
  booking_reference: alcoholPurchase.booking_reference,
}, {
  suite: 'jcs-sha256',
  definitions: [{
    action_type: 'purchase.alcohol.1',
    required_fields: [
      { name: 'amount', type: 'amount-string' },
      { name: 'currency', type: 'enum', values_ref: 'ISO 4217 alpha-3' },
      { name: 'vendor', type: 'string' },
      { name: 'booking_reference', type: 'string' },
    ],
    optional_fields: [],
  }],
}).caid;
const beforeRefusal = capabilityStore.getState('cap_mandate_unattended').consumed_amount;
const refuseRun = await kernel.run(
  bookingRequest(alcoholPurchase, agentClaimedCaid, unattended.capabilityReceipt, unattended.secret, 'buy-alcohol-89'),
  airline,
);
expect(!refuseRun.ok && refuseRun.outcome === 'refused'
  && refuseRun.reason === 'mandate_refused:unknown_action_type',
  `scene 3 refusal ${refuseRun.outcome}: ${refuseRun.reason}`);
expect(verifyCertificate(refuseRun).ok, 'scene 3 refusal certificate verification');
expect(capabilityStore.getState('cap_mandate_unattended').consumed_amount === beforeRefusal,
  'scene 3 must not consume any budget');
console.log(`REFUSE: ${refuseRun.reason} (fail-closed refusal with a reason; provider never entered)`);

// ── Scene 4: INDETERMINATE ─────────────────────────────────────────────────
console.log('--- Scene 4: book a 120 USD flight; the provider times out mid-execution');
const beforeIndeterminate = providerCalls;
const indeterminateRun = await kernel.run(
  bookingRequest(flight120, caid120, unattended.capabilityReceipt, unattended.secret, 'book-flight-120'),
  async (_authorization, _operation) => {
    providerCalls += 1;
    return new Promise(() => {}); // the provider hangs past the effect deadline
  },
);
expect(!indeterminateRun.ok && indeterminateRun.outcome === 'indeterminate'
  && indeterminateRun.reason === 'effect_indeterminate',
  `scene 4 outcome ${indeterminateRun.outcome}: ${indeterminateRun.reason}`);
expect(verifyCertificate(indeterminateRun).ok, 'scene 4 certificate verification');
expect(providerCalls === beforeIndeterminate + 1, 'scene 4 provider entered exactly once');
expect(capabilityStore.getOperation('bk_2026_0120').outcome === 'indeterminate',
  'scene 4 operation recorded as indeterminate');
console.log(`INDETERMINATE: ${indeterminateRun.reason} (the flight may or may not exist; the reservation is committed as unknown, never reopened)`);
console.log(`Unattended envelope: ${envelopeState()} (the 120 USD stays committed pending reconciliation)`);

const blindRetry = await kernel.run(
  bookingRequest(flight120, caid120, unattended.capabilityReceipt, unattended.secret, 'book-flight-120'),
  airline,
);
expect(!blindRetry.ok && blindRetry.outcome === 'refused' && blindRetry.reason === 'operation_already_committed',
  `scene 4 retry ${blindRetry.outcome}: ${blindRetry.reason}`);
expect(verifyCertificate(blindRetry).ok, 'scene 4 retry certificate verification');
expect(providerCalls === beforeIndeterminate + 1, 'scene 4 blind retry must not re-enter the provider');
console.log(`BLIND RETRY REFUSED: ${blindRetry.reason} (reconcile against provider evidence, never re-fire)`);

console.log(`Evidence log: ${gate.evidence.all().length} records; all seven certificates verified offline`);
console.log('Authority loop complete: ALLOW, ASK, REFUSE, INDETERMINATE all terminal and certified.');
