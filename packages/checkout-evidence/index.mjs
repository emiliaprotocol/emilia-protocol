// SPDX-License-Identifier: Apache-2.0
/**
 * Experimental agentic-checkout evidence packet.
 *
 * This package proves content and cross-object binding. It does not decide
 * whether a purchase was legally authorized, whether a card-network rule is
 * satisfied, or whether a dispute will be won.
 */

import crypto from 'node:crypto';
import { canonicalizeStrictJson } from '../verify/strict-json.js';
import { computeCaid, verifyCaid } from '../../caid/impl/js/caid.mjs';

export const CHECKOUT_EVIDENCE_PROFILE = 'EP-CHECKOUT-EVIDENCE-v0';
export const CHECKOUT_DISPUTE_DOSSIER_PROFILE = 'EP-CHECKOUT-DISPUTE-DOSSIER-v0';
export const PURCHASE_ACTION_TYPE = 'commerce.purchase.submit.1';

export const PURCHASE_ACTION_DEFINITION = Object.freeze({
  action_type: PURCHASE_ACTION_TYPE,
  status: 'local-experimental',
  risk_class: 'irreversible-financial',
  summary: 'Submission of one finalized merchant checkout for payment and fulfillment.',
  required_fields: Object.freeze([
    Object.freeze({ name: 'merchant_account', type: 'digest' }),
    Object.freeze({ name: 'checkout_digest', type: 'digest' }),
    Object.freeze({ name: 'amount', type: 'amount-string' }),
    Object.freeze({ name: 'currency', type: 'enum', values_ref: 'ISO 4217 alpha-3' }),
    Object.freeze({ name: 'payment_instruction_id', type: 'string' }),
  ]),
  optional_fields: Object.freeze([]),
  digest_notes: 'The checkout_digest binds the complete structured checkout terms; amounts remain strings.',
  references: Object.freeze([]),
});

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:commerce\.purchase\.submit\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const AMOUNT = /^(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const CURRENCY = /^[A-Z]{3}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/;
const SENSITIVE_KEY = /^(?:pan|card_number|primary_account_number|cvv|cvc|card_security_code|security_code)$/i;
const ARTIFACT_MEDIA = /^(?:application|text)\/[A-Za-z0-9!#$&^_.+-]+$/;
const EFFECT_STATES = new Set(['confirmed', 'failed', 'unknown']);
const CONSUMPTION_STATES = new Set(['consumed', 'not_consumed', 'unknown']);
const PACKET_FIELDS = new Set([
  '@type',
  'profile_status',
  'created_at',
  'checkout_terms',
  'checkout_digest',
  'action',
  'action_caid',
  'presentation',
  'authorization',
  'execution',
  'consumption',
  'native_evidence',
  'packet_digest',
]);

const LIMITS = Object.freeze([
  'Content binding is not a legal conclusion that the consumer authorized the transaction.',
  'The packet is not automatically eligible evidence under any card-network dispute rule.',
  'The packet does not prove delivery, product quality, refund entitlement, or merchant performance.',
  'Native evidence remains subject to its own trust anchors, verification rules, retention, and disclosure policy.',
]);

function plain(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function strictClone(value) {
  return JSON.parse(canonicalizeStrictJson(value, {
    maxDepth: 64,
    maxNodes: 100_000,
    maxStringBytes: 4 * 1024 * 1024,
  }));
}

function canonical(value) {
  return canonicalizeStrictJson(value, {
    maxDepth: 64,
    maxNodes: 100_000,
    maxStringBytes: 4 * 1024 * 1024,
  });
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex')}`;
}

function assertNoRawCardSecrets(value) {
  const stack = [value];
  const seen = new WeakSet();
  while (stack.length) {
    const next = stack.pop();
    if (!next || typeof next !== 'object') continue;
    if (seen.has(next)) continue;
    seen.add(next);
    for (const [key, child] of Object.entries(next)) {
      if (SENSITIVE_KEY.test(key)) throw new Error(`raw payment credential field is prohibited: ${key}`);
      if (child && typeof child === 'object') stack.push(child);
    }
  }
}

function assertDigest(value, label) {
  if (!DIGEST.test(value ?? '')) throw new Error(`${label} must be sha256:<64 lowercase hex>`);
}

function assertTimestamp(value, label) {
  if (!RFC3339_UTC.test(value ?? '') || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an RFC 3339 UTC timestamp`);
  }
}

function assertIdentifier(value, label) {
  if (!IDENTIFIER.test(value ?? '') || String(value).includes('..')) {
    throw new Error(`${label} is invalid`);
  }
}

function assertAmount(value, label) {
  if (!AMOUNT.test(value ?? '')) throw new Error(`${label} must be a non-negative decimal string`);
}

function assertCheckoutTerms(value) {
  if (!plain(value) || !plain(value.merchant) || !Array.isArray(value.items) || value.items.length === 0
      || !plain(value.totals)) {
    throw new Error('checkout_terms requires merchant, non-empty items, and totals');
  }
  assertNoRawCardSecrets(value);
  assertDigest(value.merchant.account_digest, 'merchant.account_digest');
  if (typeof value.merchant.display_name !== 'string' || !value.merchant.display_name.trim()
      || value.merchant.display_name.length > 200) {
    throw new Error('merchant.display_name is invalid');
  }
  for (const [index, item] of value.items.entries()) {
    if (!plain(item) || typeof item.item_ref !== 'string' || !item.item_ref
        || typeof item.description !== 'string' || !item.description.trim()
        || !Number.isSafeInteger(item.quantity) || item.quantity < 1) {
      throw new Error(`items[${index}] is invalid`);
    }
    assertAmount(item.unit_amount, `items[${index}].unit_amount`);
    assertAmount(item.line_total, `items[${index}].line_total`);
  }
  if (!CURRENCY.test(value.totals.currency ?? '')) throw new Error('totals.currency must be an uppercase ISO 4217 alpha-3 code');
  assertAmount(value.totals.total, 'totals.total');
  for (const field of ['subtotal', 'tax', 'shipping', 'discount']) {
    if (value.totals[field] !== undefined) assertAmount(value.totals[field], `totals.${field}`);
  }
  canonical(value);
}

function artifactEnvelope(input, label) {
  if (!plain(input)) throw new Error(`${label} must be an object`);
  if (typeof input.media_type !== 'string' || !ARTIFACT_MEDIA.test(input.media_type)) {
    throw new Error(`${label}.media_type is invalid`);
  }
  if (!Object.hasOwn(input, 'content') && !input.artifact_ref) {
    throw new Error(`${label} requires content or artifact_ref`);
  }
  if (input.artifact_ref !== undefined) assertIdentifier(input.artifact_ref, `${label}.artifact_ref`);
  let artifactDigest = input.digest;
  let content;
  if (Object.hasOwn(input, 'content')) {
    assertNoRawCardSecrets(input.content);
    content = strictClone(input.content);
    const computed = digest(content);
    if (artifactDigest !== undefined && artifactDigest !== computed) throw new Error(`${label}.digest does not match content`);
    artifactDigest = computed;
  }
  assertDigest(artifactDigest, `${label}.digest`);
  return {
    media_type: input.media_type,
    digest: artifactDigest,
    ...(content !== undefined ? { content } : {}),
    ...(input.artifact_ref ? { artifact_ref: input.artifact_ref } : {}),
  };
}

function verifyArtifactEnvelope(input, label, invalid) {
  try {
    const normalized = artifactEnvelope(input, label);
    if (canonical(normalized) !== canonical(input)) invalid.push(`${label}_not_canonical`);
  } catch (error) {
    invalid.push(`${label}_invalid:${error instanceof Error ? error.message : 'unknown'}`);
  }
}

export function buildPurchaseAction({ checkoutTerms, paymentInstructionId }) {
  assertCheckoutTerms(checkoutTerms);
  assertIdentifier(paymentInstructionId, 'paymentInstructionId');
  const terms = strictClone(checkoutTerms);
  const checkoutDigest = digest(terms);
  const action = {
    action_type: PURCHASE_ACTION_TYPE,
    merchant_account: terms.merchant.account_digest,
    checkout_digest: checkoutDigest,
    amount: terms.totals.total,
    currency: terms.totals.currency,
    payment_instruction_id: paymentInstructionId,
  };
  const computed = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: [PURCHASE_ACTION_DEFINITION],
  });
  if (!computed.caid || !computed.digest) throw new Error(`purchase action cannot form CAID: ${(computed.refusals ?? []).join(', ')}`);
  return Object.freeze({
    checkout_terms: terms,
    checkout_digest: checkoutDigest,
    action: Object.freeze(action),
    action_caid: computed.caid,
  });
}

function expectedDisplay(checkoutTerms, action, actionCaid, confirmation) {
  return {
    action_caid: actionCaid,
    checkout_digest: action.checkout_digest,
    // Carry the complete structured terms, not a selected summary. Otherwise a
    // caller could add a material field that is committed by checkout_digest
    // but never shown to the approving person.
    checkout_terms: strictClone(checkoutTerms),
    confirmation,
  };
}

export function buildStructuredPresentation({
  checkoutTerms,
  action,
  actionCaid,
  renderProfile = 'ep.checkout.summary.v0',
  locale = 'en-US',
  confirmation = 'Authorize this exact purchase',
}) {
  if (!CAID.test(actionCaid ?? '')) throw new Error('actionCaid is invalid');
  if (typeof renderProfile !== 'string' || !renderProfile || typeof locale !== 'string' || !locale
      || typeof confirmation !== 'string' || !confirmation.trim()) {
    throw new Error('presentation metadata is invalid');
  }
  const display = expectedDisplay(checkoutTerms, action, actionCaid, confirmation);
  const normalized = {
    method: 'structured-summary',
    render_profile: renderProfile,
    locale,
    display,
    display_digest: digest(display),
  };
  return Object.freeze(strictClone(normalized));
}

function normalizeAuthorization(input) {
  if (!plain(input) || typeof input.profile !== 'string' || !input.profile) throw new Error('authorization.profile is required');
  if (!CAID.test(input.action_caid ?? '')) throw new Error('authorization.action_caid is invalid');
  assertDigest(input.presentation_digest, 'authorization.presentation_digest');
  assertTimestamp(input.authorized_at, 'authorization.authorized_at');
  return {
    profile: input.profile,
    action_caid: input.action_caid,
    presentation_digest: input.presentation_digest,
    authorized_at: input.authorized_at,
    artifact: artifactEnvelope(input.artifact, 'authorization.artifact'),
  };
}

function normalizeExecution(input) {
  if (!plain(input) || typeof input.provider !== 'string' || !input.provider) throw new Error('execution.provider is required');
  assertIdentifier(input.operation_id, 'execution.operation_id');
  assertIdentifier(input.payment_instruction_id, 'execution.payment_instruction_id');
  assertTimestamp(input.observed_at, 'execution.observed_at');
  if (!EFFECT_STATES.has(input.status)) throw new Error('execution.status is invalid');
  const observed = strictClone(input.observed_action);
  const computed = computeCaid(observed, { suite: 'jcs-sha256', definitions: [PURCHASE_ACTION_DEFINITION] });
  if (!computed.caid) throw new Error(`execution.observed_action cannot form CAID: ${(computed.refusals ?? []).join(', ')}`);
  return {
    provider: input.provider,
    operation_id: input.operation_id,
    payment_instruction_id: input.payment_instruction_id,
    status: input.status,
    observed_action: observed,
    observed_action_caid: computed.caid,
    observed_at: input.observed_at,
    ...(input.evidence ? { evidence: artifactEnvelope(input.evidence, 'execution.evidence') } : {}),
  };
}

function normalizeConsumption(input) {
  if (!plain(input) || !CONSUMPTION_STATES.has(input.status)) throw new Error('consumption.status is invalid');
  if (!CAID.test(input.action_caid ?? '')) throw new Error('consumption.action_caid is invalid');
  assertIdentifier(input.operation_id, 'consumption.operation_id');
  assertTimestamp(input.recorded_at, 'consumption.recorded_at');
  return {
    status: input.status,
    action_caid: input.action_caid,
    operation_id: input.operation_id,
    recorded_at: input.recorded_at,
    ...(input.evidence ? { evidence: artifactEnvelope(input.evidence, 'consumption.evidence') } : {}),
  };
}

function normalizeNativeEvidence(entries) {
  if (entries === undefined) return [];
  if (!Array.isArray(entries)) throw new Error('native_evidence must be an array');
  return entries.map((entry, index) => {
    if (!plain(entry) || typeof entry.profile !== 'string' || !entry.profile
        || typeof entry.required !== 'boolean' || !plain(entry.artifacts)) {
      throw new Error(`native_evidence[${index}] is invalid`);
    }
    const artifacts = {};
    for (const key of Object.keys(entry.artifacts).sort()) {
      if (!/^[a-z][a-z0-9_]{1,63}$/.test(key)) throw new Error(`native_evidence[${index}] artifact name is invalid`);
      artifacts[key] = artifactEnvelope(entry.artifacts[key], `native_evidence[${index}].artifacts.${key}`);
    }
    if (Object.keys(artifacts).length === 0) throw new Error(`native_evidence[${index}] has no artifacts`);
    return { profile: entry.profile, required: entry.required, artifacts };
  });
}

export function createCheckoutEvidencePacket({
  createdAt,
  checkoutTerms,
  paymentInstructionId,
  presentation,
  authorization,
  execution,
  consumption,
  nativeEvidence = [],
}) {
  assertTimestamp(createdAt, 'createdAt');
  const built = buildPurchaseAction({ checkoutTerms, paymentInstructionId });
  const normalizedPresentation = presentation
    ? strictClone(presentation)
    : buildStructuredPresentation({
      checkoutTerms: built.checkout_terms,
      action: built.action,
      actionCaid: built.action_caid,
    });
  const core = {
    '@type': CHECKOUT_EVIDENCE_PROFILE,
    profile_status: 'experimental',
    created_at: createdAt,
    checkout_terms: built.checkout_terms,
    checkout_digest: built.checkout_digest,
    action: built.action,
    action_caid: built.action_caid,
    presentation: normalizedPresentation,
    authorization: normalizeAuthorization(authorization),
    execution: normalizeExecution(execution),
    consumption: normalizeConsumption(consumption),
    native_evidence: normalizeNativeEvidence(nativeEvidence),
  };
  return Object.freeze({ ...strictClone(core), packet_digest: digest(core) });
}

function normalizeVerifierResult(value) {
  if (value === true || value === 'valid' || value?.status === 'valid') return 'valid';
  if (value === false || value === 'invalid' || value?.status === 'invalid') return 'invalid';
  return 'indeterminate';
}

async function callVerifier(verifier, evidence, label, invalid, unknown) {
  if (typeof verifier !== 'function') {
    unknown.push(`${label}_verifier_missing`);
    return false;
  }
  try {
    const status = normalizeVerifierResult(await verifier(strictClone(evidence)));
    if (status === 'invalid') invalid.push(`${label}_verification_failed`);
    if (status === 'indeterminate') unknown.push(`${label}_verification_indeterminate`);
    return status === 'valid';
  } catch {
    unknown.push(`${label}_verification_error`);
    return false;
  }
}

export async function verifyCheckoutEvidencePacket(packet, {
  verifyAuthorization,
  verifyExecution,
  verifyConsumption,
  nativeVerifiers = {},
} = {}) {
  const invalid = [];
  const unknown = [];
  const facts = [];
  if (!plain(packet) || packet['@type'] !== CHECKOUT_EVIDENCE_PROFILE || packet.profile_status !== 'experimental') {
    return { verdict: 'INVALID', reasons: ['packet_profile_invalid'], facts, limits: [...LIMITS] };
  }
  let normalized;
  try {
    normalized = strictClone(packet);
  } catch {
    return { verdict: 'INVALID', reasons: ['packet_not_canonicalizable'], facts, limits: [...LIMITS] };
  }
  if (Object.keys(normalized).some((field) => !PACKET_FIELDS.has(field))
      || [...PACKET_FIELDS].some((field) => !Object.hasOwn(normalized, field))) {
    invalid.push('packet_fields_invalid');
  }
  const { packet_digest: packetDigest, ...core } = normalized;
  if (!DIGEST.test(packetDigest ?? '') || digest(core) !== packetDigest) invalid.push('packet_digest_mismatch');
  try { assertTimestamp(core.created_at, 'created_at'); } catch { invalid.push('created_at_invalid'); }

  let rebuilt;
  try {
    rebuilt = buildPurchaseAction({
      checkoutTerms: core.checkout_terms,
      paymentInstructionId: core.action?.payment_instruction_id,
    });
  } catch {
    invalid.push('checkout_terms_invalid');
  }
  if (rebuilt) {
    if (core.checkout_digest !== rebuilt.checkout_digest) invalid.push('checkout_digest_mismatch');
    if (canonical(core.action) !== canonical(rebuilt.action)) invalid.push('action_not_derived_from_checkout');
    if (core.action_caid !== rebuilt.action_caid) invalid.push('action_caid_mismatch');
  }
  if (!CAID.test(core.action_caid ?? '')
      || !verifyCaid(core.action, core.action_caid, { definitions: [PURCHASE_ACTION_DEFINITION] }).valid) {
    invalid.push('action_caid_invalid');
  }

  try {
    const expected = buildStructuredPresentation({
      checkoutTerms: core.checkout_terms,
      action: core.action,
      actionCaid: core.action_caid,
      renderProfile: core.presentation?.render_profile,
      locale: core.presentation?.locale,
      confirmation: core.presentation?.display?.confirmation,
    });
    if (canonical(core.presentation) !== canonical(expected)) invalid.push('presentation_not_exact_checkout');
  } catch {
    invalid.push('presentation_invalid');
  }

  const authorization = core.authorization;
  if (!plain(authorization)
      || authorization.action_caid !== core.action_caid
      || authorization.presentation_digest !== core.presentation?.display_digest) {
    invalid.push('authorization_binding_mismatch');
  } else {
    verifyArtifactEnvelope(authorization.artifact, 'authorization_artifact', invalid);
    try {
      if (canonical(normalizeAuthorization(authorization)) !== canonical(authorization)) {
        invalid.push('authorization_fields_invalid');
      }
    } catch {
      invalid.push('authorization_fields_invalid');
    }
  }

  const execution = core.execution;
  if (!plain(execution) || !EFFECT_STATES.has(execution.status)
      || execution.payment_instruction_id !== core.action?.payment_instruction_id) {
    invalid.push('execution_binding_invalid');
  } else {
    const observed = verifyCaid(execution.observed_action, execution.observed_action_caid, {
      definitions: [PURCHASE_ACTION_DEFINITION],
    });
    if (!observed.valid || execution.observed_action_caid !== core.action_caid
        || canonical(execution.observed_action) !== canonical(core.action)) {
      invalid.push('executed_action_mismatch');
    }
    if (execution.evidence) verifyArtifactEnvelope(execution.evidence, 'execution_evidence', invalid);
    try {
      if (canonical(normalizeExecution(execution)) !== canonical(execution)) invalid.push('execution_fields_invalid');
    } catch {
      invalid.push('execution_fields_invalid');
    }
    if (execution.status === 'unknown') unknown.push('execution_effect_unknown');
    if (execution.status !== 'unknown' && !execution.evidence) unknown.push('execution_evidence_missing');
  }

  const consumption = core.consumption;
  if (!plain(consumption) || !CONSUMPTION_STATES.has(consumption.status)
      || consumption.action_caid !== core.action_caid
      || consumption.operation_id !== execution?.operation_id) {
    invalid.push('consumption_binding_invalid');
  } else {
    if (consumption.evidence) verifyArtifactEnvelope(consumption.evidence, 'consumption_evidence', invalid);
    if (consumption.status === 'unknown') unknown.push('consumption_unknown');
    if (consumption.status === 'consumed' && !consumption.evidence) unknown.push('consumption_evidence_missing');
    if (execution?.status === 'confirmed' && consumption.status !== 'consumed') {
      invalid.push('confirmed_effect_without_consumption');
    }
    try {
      if (canonical(normalizeConsumption(consumption)) !== canonical(consumption)) {
        invalid.push('consumption_fields_invalid');
      }
    } catch {
      invalid.push('consumption_fields_invalid');
    }
  }

  if (!Array.isArray(core.native_evidence)) {
    invalid.push('native_evidence_invalid');
  } else {
    for (const [index, entry] of core.native_evidence.entries()) {
      if (!plain(entry) || typeof entry.profile !== 'string' || typeof entry.required !== 'boolean'
          || !plain(entry.artifacts)) {
        invalid.push(`native_evidence_${index}_invalid`);
        continue;
      }
      for (const [name, artifact] of Object.entries(entry.artifacts)) {
        verifyArtifactEnvelope(artifact, `native_evidence_${index}_${name}`, invalid);
      }
    }
    try {
      if (canonical(normalizeNativeEvidence(core.native_evidence)) !== canonical(core.native_evidence)) {
        invalid.push('native_evidence_fields_invalid');
      }
    } catch {
      invalid.push('native_evidence_fields_invalid');
    }
  }

  if (invalid.length > 0) {
    return {
      verdict: 'INVALID',
      packet_digest: packetDigest,
      action_caid: core.action_caid,
      effect_status: execution?.status,
      reasons: [...new Set(invalid)],
      facts,
      limits: [...LIMITS],
    };
  }

  facts.push('The packet content is intact and the purchase action is derived from the complete checkout terms.');
  facts.push('The structured presentation names the same merchant, items, total, currency, checkout digest, and action CAID.');
  facts.push('The observed execution names the same exact purchase action.');

  const authorizationValid = await callVerifier(
    verifyAuthorization,
    { authorization, action: core.action, presentation: core.presentation },
    'authorization',
    invalid,
    unknown,
  );
  const executionValid = execution.status === 'unknown' ? false : await callVerifier(
    verifyExecution,
    { execution, action: core.action },
    'execution',
    invalid,
    unknown,
  );
  const consumptionValid = consumption.status === 'unknown' ? false : await callVerifier(
    verifyConsumption,
    { consumption, action: core.action },
    'consumption',
    invalid,
    unknown,
  );

  let nativeValid = true;
  for (const entry of core.native_evidence) {
    const verifier = nativeVerifiers?.[entry.profile];
    if (typeof verifier !== 'function' && entry.required === false) continue;
    const valid = await callVerifier(verifier, entry, `native_${entry.profile}`, invalid, unknown);
    nativeValid = nativeValid && (valid || entry.required === false);
  }

  if (authorizationValid) facts.push('The configured authorization verifier accepted the bound authorization artifact.');
  if (executionValid) facts.push(`The configured execution verifier accepted the ${execution.status} provider evidence.`);
  if (consumptionValid) facts.push(`The configured consumption verifier accepted the ${consumption.status} record.`);
  if (nativeValid && core.native_evidence.length) facts.push('Every required native evidence profile was accepted by its configured verifier.');

  const verdict = invalid.length > 0 ? 'INVALID' : unknown.length > 0 ? 'INDETERMINATE' : 'VERIFIED';
  return {
    verdict,
    packet_digest: packetDigest,
    action_caid: core.action_caid,
    effect_status: execution.status,
    reasons: [...new Set([...invalid, ...unknown])],
    facts,
    limits: [...LIMITS],
  };
}

export function buildDisputeDossier(packet, verification, { generatedAt }) {
  assertTimestamp(generatedAt, 'generatedAt');
  if (!plain(packet) || !DIGEST.test(packet.packet_digest ?? '')) throw new Error('packet is invalid');
  if (!plain(verification) || !['VERIFIED', 'INVALID', 'INDETERMINATE'].includes(verification.verdict)) {
    throw new Error('verification result is invalid');
  }
  const dossier = {
    '@type': CHECKOUT_DISPUTE_DOSSIER_PROFILE,
    profile_status: 'experimental',
    generated_at: generatedAt,
    source_packet_digest: packet.packet_digest,
    action_caid: packet.action_caid,
    payment_instruction_id: packet.action?.payment_instruction_id,
    verification: strictClone(verification),
    timeline: [
      { event: 'authorization_recorded', at: packet.authorization?.authorized_at },
      { event: `execution_${packet.execution?.status}`, at: packet.execution?.observed_at ?? null },
      { event: `authority_${packet.consumption?.status}`, at: packet.consumption?.recorded_at },
    ],
    evidence_packet: strictClone(packet),
    scheme_mapping: {
      status: 'not_supplied',
      note: 'A processor- and reason-code-specific adapter must map accepted fields under current network rules.',
    },
  };
  return Object.freeze({ ...strictClone(dossier), dossier_digest: digest(dossier) });
}

export const _internals = Object.freeze({ canonical, digest, artifactEnvelope, assertCheckoutTerms });
