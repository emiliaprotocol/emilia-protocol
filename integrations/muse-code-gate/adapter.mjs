// SPDX-License-Identifier: Apache-2.0
/**
 * Exact-action payment.release adapter used by the Muse Code MCP demo.
 *
 * The consequential path is deliberately implemented with the repository's
 * Gate MCP wrapper. Muse hooks are not used as the authorization boundary.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  canonicalize as canonicalizeGate,
  createEg1Harness,
  createTrustedActionFirewall,
} from '../../packages/gate/index.js';
import { gateMcpTool } from '../../packages/gate/mcp.js';
import { verifyReceipt } from '../../packages/verify/index.js';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import { REGISTRY_ENUM_SNAPSHOTS } from '../../caid/registry/enum-snapshots.mjs';

export const ADAPTER_VERSION = 'EP-MUSE-CODE-GATE-v2';
export const LEGACY_OUTCOME_PROFILE = 'EP-MUSE-CODE-GATE-OUTCOME-v1';
export const OUTCOME_PROFILE = 'EP-MUSE-CODE-GATE-OUTCOME-v2';
export const RECONCILIATION_PROFILE = 'EP-MUSE-CODE-GATE-RECONCILIATION-v1';
const PROVIDER_ASSERTION_PROFILE = 'EP-MUSE-CODE-GATE-PROVIDER-ASSERTION-v1';
export const PAYMENT_TOOL = 'release_payment';
export const RECONCILIATION_TOOL = 'reconcile_payment';
export const PAYMENT_ACTION_TYPE = 'payment.release.1';

const REGISTRY = JSON.parse(readFileSync(
  new URL('../../caid/registry/action-types.json', import.meta.url),
  'utf8',
));
const DEFINITIONS = REGISTRY.types;
const REQUIRED_INPUT_FIELDS = Object.freeze(['payee', 'account', 'amount', 'currency', 'operation']);
const RECEIPT_FIELDS = new Set(['_emilia_receipt', 'emilia_receipt', '_emilia_receipt_b64']);
const RECONCILIATION_RECEIPT_FIELD = '_emilia_outcome_receipt';
const PROVIDER_REFUSAL_REASONS = new Set(['AGENT_ACCESS_DENIED', 'PROVIDER_DECLINED']);
const RECONCILIATION_NOT_ACCEPTED_REASONS = new Set([
  'AGENT_ACCESS_DENIED',
  'NO_PROVIDER_RECORD',
  'PROVIDER_DECLINED',
]);
const AMOUNT = /^(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,2})?$/;
const CURRENCY = /^[A-Z]{3}$/;
const CAID = /^caid:1:payment\.release\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/;

function caidMatchesActionDigest(caid, actionDigest) {
  if (!CAID.test(caid ?? '') || !/^sha256:[0-9a-f]{64}$/.test(actionDigest ?? '')) return false;
  const encoded = caid.slice(caid.lastIndexOf(':') + 1);
  return Buffer.from(encoded, 'base64url').toString('hex') === actionDigest.slice('sha256:'.length);
}

function validReceiptEnvelope(receipt, subject) {
  return receipt?.['@version'] === 'EP-RECEIPT-v1'
    && receipt?.payload?.subject === subject
    && typeof receipt?.payload?.receipt_id === 'string'
    && receipt.payload.receipt_id.length > 0
    && typeof receipt?.payload?.issuer === 'string'
    && receipt.payload.issuer.length > 0;
}

export const PAYMENT_RELEASE_MANIFEST = Object.freeze({
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: [Object.freeze({
    id: 'muse.payment.release',
    label: 'Muse-connected payment release',
    action_type: PAYMENT_ACTION_TYPE,
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'class_a',
    match: Object.freeze({ protocol: 'mcp', tool: PAYMENT_TOOL }),
    execution_binding: Object.freeze({
      required_fields: Object.freeze([
        'action_type',
        'payee_ref',
        'beneficiary_account',
        'amount',
        'currency',
        'payment_instruction_id',
      ]),
    }),
  })],
});

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function exactString(value, name, maxBytes = 256) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${name}_required`);
  if (value !== value.trim()) throw new TypeError(`${name}_not_canonical`);
  if (!validUnicode(value) || /[\u0000-\u001f\u007f]/u.test(value)) throw new TypeError(`${name}_invalid`);
  if (Buffer.byteLength(value, 'utf8') > maxBytes) throw new TypeError(`${name}_too_long`);
  return value;
}

/**
 * Validate the provider-facing input and remove the receipt carrier. Unknown
 * properties fail closed because an unbound provider option can change the
 * effect just as surely as a changed amount.
 */
export function paymentProviderInput(value, { allowReceiptCarrier = true } = {}) {
  if (!isPlainRecord(value)) throw new TypeError('payment_input_must_be_object');
  const allowed = new Set(REQUIRED_INPUT_FIELDS);
  if (allowReceiptCarrier) for (const field of RECEIPT_FIELDS) allowed.add(field);
  const keys = Object.keys(value);
  const unknown = keys.filter((field) => !allowed.has(field));
  if (unknown.length > 0) throw new TypeError(`unbound_payment_field:${unknown.sort()[0]}`);
  const carriers = keys.filter((field) => RECEIPT_FIELDS.has(field));
  if (carriers.length > 1) throw new TypeError('ambiguous_receipt_carrier');
  for (const field of REQUIRED_INPUT_FIELDS) {
    if (!Object.hasOwn(value, field)) throw new TypeError(`missing_payment_field:${field}`);
  }
  const payee = exactString(value.payee, 'payee');
  const account = exactString(value.account, 'account');
  const amount = exactString(value.amount, 'amount', 64);
  const currency = exactString(value.currency, 'currency', 3);
  const operation = exactString(value.operation, 'operation');
  if (!AMOUNT.test(amount) || /^0(?:\.0+)?$/.test(amount)) throw new TypeError('amount_invalid');
  if (!CURRENCY.test(currency)) throw new TypeError('currency_invalid');
  return Object.freeze({ payee, account, amount, currency, operation });
}

/** Map Muse/MCP arguments to the registered CAID action content. */
export function canonicalizePaymentRelease(input) {
  const clean = paymentProviderInput(input, { allowReceiptCarrier: true });
  const action = Object.freeze({
    action_type: PAYMENT_ACTION_TYPE,
    // Adapter-profile extension. CAID hashes the complete object, so payee_ref
    // remains material even though the base registry entry predates this field.
    payee_ref: clean.payee,
    beneficiary_account: `sha256:${createHash('sha256').update(clean.account, 'utf8').digest('hex')}`,
    amount: clean.amount,
    currency: clean.currency,
    payment_instruction_id: clean.operation,
  });
  const computed = computeCaid(action, {
    suite: 'jcs-sha256', definitions: DEFINITIONS, enumSnapshots: REGISTRY_ENUM_SNAPSHOTS,
  });
  if (!computed || typeof computed.caid !== 'string') {
    throw new TypeError(`caid_refused:${(computed?.refusals || ['unknown']).join(',')}`);
  }
  return Object.freeze({
    action,
    caid: computed.caid,
    actionDigest: computed.digest,
    providerInput: clean,
  });
}

function publicKeyB64u(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function privateKeyFrom(value) {
  if (value?.type === 'private') return value;
  if (typeof value === 'string' && value.length > 0) {
    return createPrivateKey({ key: Buffer.from(value, 'base64url'), format: 'der', type: 'pkcs8' });
  }
  throw new TypeError('outcome_private_key_required');
}

/**
 * @param {{ privateKey?: any, publicKey?: any, keyId?: string }} [options]
 */
export function createOutcomeSigner({ privateKey, publicKey, keyId = 'ep:key:muse-gate-outcome' } = {}) {
  const normalizedKeyId = exactString(keyId, 'outcome_key_id', 256);
  if (!privateKey && !publicKey) {
    const generated = generateKeyPairSync('ed25519');
    privateKey = generated.privateKey;
    publicKey = generated.publicKey;
  }
  const normalizedPrivateKey = privateKeyFrom(privateKey);
  if (normalizedPrivateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('outcome_private_key_must_be_ed25519');
  }
  const derivedPublicKeyObject = createPublicKey(normalizedPrivateKey);
  const suppliedPublicKeyObject = publicKey === undefined
    ? derivedPublicKeyObject
    : (typeof publicKey === 'string'
      ? createPublicKey({ key: Buffer.from(publicKey, 'base64url'), format: 'der', type: 'spki' })
      : publicKey);
  if (suppliedPublicKeyObject?.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('outcome_public_key_must_be_ed25519');
  }
  const derivedPublicKey = publicKeyB64u(derivedPublicKeyObject);
  const normalizedPublicKey = publicKeyB64u(suppliedPublicKeyObject);
  if (normalizedPublicKey !== derivedPublicKey) throw new TypeError('outcome_key_pair_mismatch');
  return Object.freeze({
    privateKey: normalizedPrivateKey,
    publicKey: normalizedPublicKey,
    keyId: normalizedKeyId,
  });
}

function issueOutcomeReceipt({
  outcome,
  canonical,
  gateEvidence,
  signer,
  now,
  providerEffect = outcome === 'EXECUTED' ? 'ACCEPTED' : 'UNKNOWN',
  reasonCode = null,
}) {
  const at = new Date(typeof now === 'function' ? now() : now).toISOString();
  const authorizationEvidenceHash = gateEvidence?.authorizationEvidence?.hash
    ?? gateEvidence?.execution?.authorizes_decision;
  const executionEvidenceHash = gateEvidence?.execution?.hash;
  const evidenceHash = (value) => (typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
    ? value : null);
  const boundAuthorizationHash = evidenceHash(authorizationEvidenceHash);
  const boundExecutionHash = evidenceHash(executionEvidenceHash);
  const claim = {
    profile: OUTCOME_PROFILE,
    execution_authorizing: false,
    action_type: PAYMENT_ACTION_TYPE,
    caid: canonical.caid,
    action_digest: canonical.actionDigest,
    operation_id: canonical.action.payment_instruction_id,
    provider_entry: 'ENTERED',
    provider_effect: providerEffect,
    outcome,
    retry: outcome === 'REFUSED' ? 'REQUIRES_NEW_AUTHORIZATION' : 'REFUSE',
    ...(reasonCode ? { reason_code: reasonCode } : {}),
    ...(boundAuthorizationHash
      ? { gate_authorization_evidence_hash: boundAuthorizationHash }
      : {}),
    ...(boundExecutionHash
      ? { gate_execution_evidence_hash: boundExecutionHash }
      : {}),
  };
  const payload = {
    receipt_id: `ep:muse-gate-outcome:${randomUUID()}`,
    created_at: at,
    subject: 'muse-code:release_payment',
    issuer: signer.keyId,
    claim,
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(null, Buffer.from(canonicalizeGate(payload), 'utf8'), signer.privateKey).toString('base64url'),
    },
  };
}

/** Verify the signed outcome with the repo's offline EP receipt verifier. */
export function verifyOutcomeReceipt(receipt, publicKey) {
  const base = verifyReceipt(receipt, publicKey);
  const claim = receipt?.payload?.claim;
  const currentProfile = claim?.profile === OUTCOME_PROFILE;
  const legacyProfile = claim?.profile === LEGACY_OUTCOME_PROFILE;
  const legacySemantics = legacyProfile
    && ['EXECUTED', 'INDETERMINATE'].includes(claim?.outcome)
    && claim?.retry === 'REFUSE';
  const currentSemantics = currentProfile && ((claim?.outcome === 'EXECUTED'
    && claim?.provider_effect === 'ACCEPTED'
    && claim?.retry === 'REFUSE')
    || (claim?.outcome === 'INDETERMINATE'
      && claim?.provider_effect === 'UNKNOWN'
      && claim?.retry === 'REFUSE')
    || (claim?.outcome === 'REFUSED'
      && claim?.provider_effect === 'NOT_ACCEPTED'
      && claim?.retry === 'REQUIRES_NEW_AUTHORIZATION'
      && PROVIDER_REFUSAL_REASONS.has(claim?.reason_code)));
  const terminalSemantics = legacySemantics || currentSemantics;
  const semantics = claim?.execution_authorizing === false
    && claim?.provider_entry === 'ENTERED'
    && terminalSemantics
    && claim?.action_type === PAYMENT_ACTION_TYPE
    && typeof claim?.action_digest === 'string'
    && /^sha256:[0-9a-f]{64}$/.test(claim.action_digest)
    && typeof claim?.caid === 'string'
    && caidMatchesActionDigest(claim.caid, claim.action_digest)
    && typeof claim?.operation_id === 'string'
    && claim.operation_id.length > 0
    && validReceiptEnvelope(receipt, 'muse-code:release_payment');
  return {
    ...base,
    valid: base.valid === true && (currentProfile || legacyProfile) && semantics,
    checks: { ...base.checks, profile: currentProfile || legacyProfile, semantics },
    execution_authorizing: false,
  };
}

function safeProviderReference(value) {
  if (value === undefined) return null;
  return exactString(value, 'provider_reference', 256);
}

function validOptionalProviderReference(value) {
  if (value === undefined) return true;
  try {
    return safeProviderReference(value) === value;
  } catch {
    return false;
  }
}

function normalizeProviderDecision(value) {
  if (!isPlainRecord(value)) throw new TypeError('provider_result_invalid');
  if (value.isError === true) throw new Error('provider_reported_error_after_entry');
  const providerReference = safeProviderReference(value.provider_reference);
  if (value.provider_status === 'ACCEPTED') {
    return Object.freeze({ status: 'ACCEPTED', providerReference });
  }
  if (value.provider_status === 'DECLINED'
    && PROVIDER_REFUSAL_REASONS.has(value.reason_code)) {
    return Object.freeze({
      status: 'DECLINED',
      reasonCode: value.reason_code,
      providerReference,
    });
  }
  throw new TypeError('provider_result_unrecognized');
}

function projectedProviderResult(decision) {
  const accepted = decision.status === 'ACCEPTED';
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        accepted,
        ...(decision.providerReference ? { provider_reference: decision.providerReference } : {}),
        ...(decision.reasonCode ? { reason_code: decision.reasonCode } : {}),
      }),
    }],
    accepted,
    ...(decision.providerReference ? { provider_reference: decision.providerReference } : {}),
    ...(decision.reasonCode ? { reason_code: decision.reasonCode } : {}),
    _provider_decision: decision,
  };
}

function structuredToolError(reason, extra = {}, toolName = PAYMENT_TOOL) {
  return {
    isError: true,
    content: [{ type: 'text', text: `EMILIA ${toolName}: ${reason}.` }],
    _emilia: {
      gate: 'refused',
      status: 428,
      reason,
      provider_entry: 'NOT_ENTERED',
      outcome: null,
      ...extra,
    },
  };
}

/**
 * Create the credential-owning exact-action boundary. The supplied provider is
 * called only from inside gateMcpTool/Gate.run after reservation and provider
 * entry. Receipt carriers are never passed to the provider.
 *
 * @param {{
 *   gate?: any,
 *   provider?: (payment: any, context: any) => any,
 *   outcomeSigner?: any,
 *   now?: () => number,
 * }} [options]
 */
export function createPaymentReleaseTool({ gate, provider, outcomeSigner, now = Date.now } = {}) {
  if (!gate || typeof gate.run !== 'function') throw new TypeError('gate_required');
  if (typeof provider !== 'function') throw new TypeError('provider_required');
  const signer = createOutcomeSigner(outcomeSigner);

  const gated = gateMcpTool(gate, {
    protocol: 'mcp',
    tool: PAYMENT_TOOL,
    action: PAYMENT_ACTION_TYPE,
    observedAction: (args) => canonicalizePaymentRelease(args).action,
  }, async (args) => {
    const canonical = canonicalizePaymentRelease(args);
    const providerResult = await provider(structuredClone(canonical.providerInput), {
      caid: canonical.caid,
      action: structuredClone(canonical.action),
    });
    // MCP isError is only an error response. It does not prove the provider
    // made no change. Throw while still inside Gate so the durable execution
    // record and adapter outcome both become INDETERMINATE.
    // Only the deployment-owned provider adapter can classify an authenticated
    // provider response. Projecting an allowlisted decision here prevents raw
    // provider payloads, credentials, and free-text errors from entering the
    // MCP response, receipt, or hook observation trail.
    return projectedProviderResult(normalizeProviderDecision(providerResult));
  });

  const tool = async (args = {}, extra) => {
    let canonical;
    let pinnedArgs;
    let providerEntered = false;
    try {
      // Pin one strict JSON snapshot before Gate awaits any verifier/store.
      // Receipt resolution, observed-action binding, and provider invocation
      // therefore see the same bytes even if a programmatic caller mutates its
      // original object while authorization is in flight.
      pinnedArgs = JSON.parse(canonicalizeGate(args));
      canonical = canonicalizePaymentRelease(pinnedArgs);
    } catch (error) {
      return structuredToolError(error instanceof Error ? error.message : 'payment_input_invalid');
    }
    try {
      const result = await gated(pinnedArgs, extra);
      if (result?._emilia?.gate === 'refused') {
        return {
          ...result,
          _emilia: {
            ...result._emilia,
            adapter: ADAPTER_VERSION,
            caid: canonical.caid,
            provider_entry: 'NOT_ENTERED',
            outcome: null,
            retry: 'REQUIRES_NEW_AUTHORIZATION',
          },
        };
      }
      if (result?._emilia?.gate !== 'allowed') {
        return structuredToolError('gate_result_unrecognized', {
          gate: 'unknown',
          status: 500,
          adapter: ADAPTER_VERSION,
          caid: canonical.caid,
          provider_entry: 'UNKNOWN',
          outcome: 'INDETERMINATE',
          retry: 'REFUSE',
        });
      }
      providerEntered = true;
      const decision = result?._provider_decision;
      if (!decision || !['ACCEPTED', 'DECLINED'].includes(decision.status)) {
        throw new Error('provider_decision_missing_after_entry');
      }
      const { _provider_decision: _privateDecision, ...projectedResult } = result;
      if (decision.status === 'DECLINED') {
        const receipt = issueOutcomeReceipt({
          outcome: 'REFUSED',
          providerEffect: 'NOT_ACCEPTED',
          reasonCode: decision.reasonCode,
          canonical,
          gateEvidence: { execution: result?._emilia?.execution },
          signer,
          now,
        });
        return structuredToolError(
          decision.reasonCode === 'AGENT_ACCESS_DENIED'
            ? 'provider_agent_access_denied'
            : 'provider_declined',
          {
            status: 403,
            gate: 'allowed',
            adapter: ADAPTER_VERSION,
            caid: canonical.caid,
            provider_entry: 'ENTERED',
            provider_effect: 'NOT_ACCEPTED',
            outcome: 'REFUSED',
            retry: 'REQUIRES_NEW_AUTHORIZATION',
            outcome_receipt: receipt,
          },
        );
      }
      const receipt = issueOutcomeReceipt({
        outcome: 'EXECUTED',
        canonical,
        gateEvidence: { execution: result?._emilia?.execution },
        signer,
        now,
      });
      return {
        ...projectedResult,
        _emilia: {
          ...result._emilia,
          adapter: ADAPTER_VERSION,
          caid: canonical.caid,
          provider_entry: 'ENTERED',
          provider_effect: 'ACCEPTED',
          outcome: 'EXECUTED',
          retry: 'REFUSE',
          outcome_receipt: receipt,
        },
      };
    } catch (error) {
      const terminal = error?.emiliaGateOutcome;
      if (terminal?.outcome === 'executed') {
        const receipt = issueOutcomeReceipt({
          outcome: 'EXECUTED', canonical, gateEvidence: terminal, signer, now,
        });
        return structuredToolError(terminal.reason || 'execution_evidence_unavailable', {
          status: 500,
          gate: 'allowed',
          adapter: ADAPTER_VERSION,
          caid: canonical.caid,
          provider_entry: 'ENTERED',
          provider_effect: 'ACCEPTED',
          outcome: 'EXECUTED',
          retry: 'REFUSE',
          outcome_receipt: receipt,
        });
      }
      if (terminal?.outcome === 'indeterminate') {
        const receipt = issueOutcomeReceipt({
          outcome: 'INDETERMINATE', canonical, gateEvidence: terminal, signer, now,
        });
        return structuredToolError('effect_attempted_outcome_unknown', {
          status: 409,
          gate: 'allowed',
          adapter: ADAPTER_VERSION,
          caid: canonical.caid,
          provider_entry: 'ENTERED',
          provider_effect: 'UNKNOWN',
          outcome: 'INDETERMINATE',
          retry: 'REFUSE',
          outcome_receipt: receipt,
        });
      }
      if (providerEntered) {
        return structuredToolError('post_entry_evidence_processing_failed', {
          status: 500,
          gate: 'allowed',
          adapter: ADAPTER_VERSION,
          caid: canonical.caid,
          provider_entry: 'ENTERED',
          provider_effect: 'UNKNOWN',
          outcome: 'INDETERMINATE',
          retry: 'REFUSE',
        });
      }
      return structuredToolError(terminal?.reason || 'gate_terminal_state_unknown', {
        gate: 'unknown',
        status: 500,
        adapter: ADAPTER_VERSION,
        caid: canonical.caid,
        provider_entry: 'UNKNOWN',
        outcome: 'INDETERMINATE',
        retry: 'REFUSE',
      });
    }
  };
  Object.defineProperty(tool, 'outcomePublicKey', { value: signer.publicKey });
  return tool;
}

function reconciliationInput(value) {
  if (!isPlainRecord(value)) throw new TypeError('reconciliation_input_must_be_object');
  const allowed = new Set([...REQUIRED_INPUT_FIELDS, RECONCILIATION_RECEIPT_FIELD]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field));
  if (unknown.length > 0) throw new TypeError(`unbound_reconciliation_field:${unknown.sort()[0]}`);
  if (!Object.hasOwn(value, RECONCILIATION_RECEIPT_FIELD)) {
    throw new TypeError('indeterminate_outcome_receipt_required');
  }
  const providerInput = paymentProviderInput(Object.fromEntries(
    REQUIRED_INPUT_FIELDS.map((field) => [field, value[field]]),
  ), { allowReceiptCarrier: false });
  return Object.freeze({ providerInput, priorReceipt: value[RECONCILIATION_RECEIPT_FIELD] });
}

function reconciliationClaim({ canonical, priorReceipt, decision }) {
  if (!['ACCEPTED', 'NOT_ACCEPTED'].includes(decision.status)) {
    throw new TypeError('terminal_reconciliation_decision_required');
  }
  const outcome = decision.status === 'ACCEPTED' ? 'EXECUTED' : 'REFUSED';
  const claim = {
    profile: RECONCILIATION_PROFILE,
    execution_authorizing: false,
    action_type: PAYMENT_ACTION_TYPE,
    caid: canonical.caid,
    action_digest: canonical.actionDigest,
    operation_id: canonical.action.payment_instruction_id,
    prior_outcome_receipt_id: priorReceipt.payload.receipt_id,
    original_authority: 'CONSUMED',
    reconciliation: decision.status,
    outcome,
    retry: decision.status === 'NOT_ACCEPTED' ? 'REQUIRES_NEW_AUTHORIZATION' : 'REFUSE',
    ...(decision.providerReference
      ? { provider_reference: decision.providerReference }
      : {}),
    ...(decision.reasonCode ? { reason_code: decision.reasonCode } : {}),
  };
  const assertion = providerAssertionFromClaim(claim);
  if (assertion === null) throw new TypeError('provider_assertion_invalid');
  return {
    ...claim,
    provider_assertion_digest: providerAssertionDigest(assertion),
  };
}

function issueReconciliationReceipt({ canonical, priorReceipt, decision, signer, now }) {
  const payload = {
    receipt_id: `ep:muse-gate-reconciliation:${randomUUID()}`,
    created_at: new Date(typeof now === 'function' ? now() : now).toISOString(),
    subject: 'muse-code:reconcile_payment',
    issuer: signer.keyId,
    claim: reconciliationClaim({ canonical, priorReceipt, decision }),
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(null, Buffer.from(canonicalizeGate(payload), 'utf8'), signer.privateKey).toString('base64url'),
    },
  };
}

export function verifyReconciliationReceipt(receipt, publicKey) {
  const base = verifyReceipt(receipt, publicKey);
  const claim = receipt?.payload?.claim;
  const decisiveNotAccepted = claim?.reconciliation === 'NOT_ACCEPTED'
    && claim?.outcome === 'REFUSED'
    && claim?.retry === 'REQUIRES_NEW_AUTHORIZATION'
    && RECONCILIATION_NOT_ACCEPTED_REASONS.has(claim?.reason_code);
  const assertion = providerAssertionFromClaim(claim);
  const semantics = claim?.profile === RECONCILIATION_PROFILE
    && claim?.execution_authorizing === false
    && claim?.original_authority === 'CONSUMED'
    && ((claim?.reconciliation === 'ACCEPTED'
      && claim?.outcome === 'EXECUTED'
      && claim?.retry === 'REFUSE'
      && typeof claim?.provider_reference === 'string'
      && validOptionalProviderReference(claim.provider_reference))
      || decisiveNotAccepted)
    && claim?.action_type === PAYMENT_ACTION_TYPE
    && validOptionalProviderReference(claim?.provider_reference)
    && assertion !== null
    && claim?.provider_assertion_digest === providerAssertionDigest(assertion)
    && /^sha256:[0-9a-f]{64}$/.test(claim?.action_digest ?? '')
    && caidMatchesActionDigest(claim?.caid, claim?.action_digest)
    && typeof claim?.operation_id === 'string'
    && claim.operation_id.length > 0
    && typeof claim?.prior_outcome_receipt_id === 'string'
    && claim.prior_outcome_receipt_id.length > 0
    && validReceiptEnvelope(receipt, 'muse-code:reconcile_payment');
  return {
    ...base,
    valid: base.valid === true && semantics,
    checks: { ...base.checks, profile: claim?.profile === RECONCILIATION_PROFILE, semantics },
    execution_authorizing: false,
  };
}

function providerAssertionDigest(value) {
  return `sha256:${createHash('sha256').update(canonicalizeGate(value), 'utf8').digest('hex')}`;
}

function providerAssertionFromClaim(claim) {
  const commonValid = claim?.action_type === PAYMENT_ACTION_TYPE
    && CAID.test(claim?.caid ?? '')
    && /^sha256:[0-9a-f]{64}$/.test(claim?.action_digest ?? '')
    && typeof claim?.operation_id === 'string'
    && claim.operation_id.length > 0
    && typeof claim?.prior_outcome_receipt_id === 'string'
    && claim.prior_outcome_receipt_id.length > 0;
  if (!commonValid) return null;
  const common = {
    profile: PROVIDER_ASSERTION_PROFILE,
    authenticated: true,
    action_type: claim.action_type,
    caid: claim.caid,
    action_digest: claim.action_digest,
    operation_id: claim.operation_id,
    prior_outcome_receipt_id: claim.prior_outcome_receipt_id,
  };
  if (claim?.reconciliation === 'ACCEPTED'
    && validOptionalProviderReference(claim?.provider_reference)
    && typeof claim?.provider_reference === 'string') {
    return {
      ...common,
      provider_status: 'ACCEPTED',
      provider_reference: claim.provider_reference,
    };
  }
  if (claim?.reconciliation === 'NOT_ACCEPTED'
    && RECONCILIATION_NOT_ACCEPTED_REASONS.has(claim?.reason_code)
    && validOptionalProviderReference(claim?.provider_reference)) {
    return {
      ...common,
      authoritative: true,
      provider_status: 'NOT_ACCEPTED',
      reason_code: claim.reason_code,
      ...(claim.provider_reference ? { provider_reference: claim.provider_reference } : {}),
    };
  }
  return null;
}

function normalizeReconciliation(value) {
  if (!isPlainRecord(value) || value.authenticated !== true) {
    return Object.freeze({ status: 'INDETERMINATE' });
  }
  if (value.provider_status === 'ACCEPTED') {
    const providerReference = safeProviderReference(value.provider_reference);
    if (!providerReference) return Object.freeze({ status: 'INDETERMINATE' });
    return Object.freeze({
      status: 'ACCEPTED',
      providerReference,
      reasonCode: null,
    });
  }
  if (value.provider_status === 'NOT_ACCEPTED'
    && value.authoritative === true
    && RECONCILIATION_NOT_ACCEPTED_REASONS.has(value.reason_code)) {
    const providerReference = safeProviderReference(value.provider_reference);
    return Object.freeze({
      status: 'NOT_ACCEPTED',
      reasonCode: value.reason_code,
      providerReference,
    });
  }
  return Object.freeze({ status: 'INDETERMINATE' });
}

function reconciliationStoreKey(priorReceiptId) {
  return `muse-reconciliation:sha256:${createHash('sha256').update(priorReceiptId, 'utf8').digest('hex')}`;
}

/** @param {string} reason @param {any} [canonical] */
function reconciliationIndeterminate(reason, canonical = null) {
  return {
    isError: true,
    content: [{ type: 'text', text: `EMILIA ${RECONCILIATION_TOOL}: ${reason}.` }],
    _emilia: {
      gate: 'reconciled',
      adapter: ADAPTER_VERSION,
      reason,
      ...(canonical ? { caid: canonical.caid } : {}),
      original_authority: 'CONSUMED',
      reconciliation: 'INDETERMINATE',
      outcome: 'INDETERMINATE',
      retry: 'REFUSE',
    },
  };
}

function reconciliationResponseFromReceipt(receipt) {
  const claim = receipt.payload.claim;
  const response = {
    content: [{
      type: 'text',
      text: JSON.stringify({
        reconciliation: claim.reconciliation,
        outcome: claim.outcome,
        retry: claim.retry,
        ...(claim.provider_reference ? { provider_reference: claim.provider_reference } : {}),
      }),
    }],
    ...(claim.provider_reference ? { provider_reference: claim.provider_reference } : {}),
    _emilia: {
      gate: 'reconciled',
      adapter: ADAPTER_VERSION,
      caid: claim.caid,
      original_authority: 'CONSUMED',
      reconciliation: claim.reconciliation,
      outcome: claim.outcome,
      retry: claim.retry,
      provider_assertion_digest: claim.provider_assertion_digest,
      ...(claim.provider_reference ? { provider_reference: claim.provider_reference } : {}),
      ...(claim.reason_code ? { reason_code: claim.reason_code } : {}),
      reconciliation_receipt: receipt,
    },
  };
  return claim.outcome === 'EXECUTED' ? response : { ...response, isError: true };
}

function validReconciliationStore(value, { allowEphemeral = false } = {}) {
  const methods = value
    && typeof value.get === 'function'
    && typeof value.addIfAbsent === 'function'
    && typeof value.compareAndSet === 'function'
    && typeof value.deleteIfValue === 'function';
  const productionCapabilities = value?.durable === true
    && value?.ownershipFenced === true
    && value?.permanentConsumption === true
    && value?.atomicReplayFenced === true;
  return methods && (productionCapabilities || allowEphemeral === true);
}

function createMemoryReconciliationStore() {
  const state = new Map();
  return Object.freeze({
    durable: false,
    ownershipFenced: false,
    permanentConsumption: false,
    atomicReplayFenced: false,
    async get(key) { return state.has(key) ? state.get(key) : null; },
    async addIfAbsent(key, value) {
      if (state.has(key)) return false;
      state.set(key, value);
      return true;
    },
    async compareAndSet(key, expected, replacement) {
      if (state.get(key) !== expected) return false;
      state.set(key, replacement);
      return true;
    },
    async deleteIfValue(key, expected) {
      if (state.get(key) !== expected) return false;
      state.delete(key);
      return true;
    },
  });
}

/**
 * Build a read-only reconciliation surface. It never reopens or executes the
 * consumed authority. A decisive NOT_ACCEPTED result only tells the caller to
 * obtain a fresh authorization before attempting the action again.
 * @param {{
 *   reconcile?: (query: any) => any,
 *   outcomeSigner?: any,
 *   reconciliationStore?: any,
 *   allowEphemeralStore?: boolean,
 *   now?: () => number,
 * }} [options]
 */
export function createPaymentReconciliationTool({
  reconcile,
  outcomeSigner,
  reconciliationStore,
  allowEphemeralStore = false,
  now = Date.now,
} = {}) {
  if (typeof reconcile !== 'function') throw new TypeError('provider_reconciler_required');
  if (!validReconciliationStore(reconciliationStore, { allowEphemeral: allowEphemeralStore })) {
    throw new TypeError('durable_reconciliation_store_required');
  }
  const signer = createOutcomeSigner(outcomeSigner);
  return async (args = {}) => {
    /** @type {any} */
    let canonical;
    /** @type {any} */
    let priorReceipt;
    try {
      const pinned = JSON.parse(canonicalizeGate(args));
      const validated = reconciliationInput(pinned);
      canonical = canonicalizePaymentRelease(validated.providerInput);
      priorReceipt = validated.priorReceipt;
      const verified = verifyOutcomeReceipt(priorReceipt, signer.publicKey);
      const claim = priorReceipt?.payload?.claim;
      if (!verified.valid
        || claim?.outcome !== 'INDETERMINATE'
        || claim?.caid !== canonical.caid
        || claim?.action_digest !== canonical.actionDigest
        || claim?.operation_id !== canonical.action.payment_instruction_id) {
        return structuredToolError('indeterminate_outcome_receipt_required', {
          adapter: ADAPTER_VERSION,
          retry: 'REFUSE',
        }, RECONCILIATION_TOOL);
      }
    } catch (error) {
      return structuredToolError(error instanceof Error ? error.message : 'reconciliation_input_invalid', {
        adapter: ADAPTER_VERSION,
        retry: 'REFUSE',
      }, RECONCILIATION_TOOL);
    }

    const priorReceiptId = priorReceipt.payload.receipt_id;
    const storeKey = reconciliationStoreKey(priorReceiptId);
    const restorePinned = async () => {
      let stored;
      try {
        stored = await reconciliationStore.get(storeKey);
      } catch {
        return reconciliationIndeterminate('reconciliation_store_unavailable', canonical);
      }
      if (stored === null) return null;
      if (typeof stored === 'string' && stored.startsWith('pending:')) {
        return reconciliationIndeterminate(
          'reconciliation_in_progress_or_recovery_required',
          canonical,
        );
      }
      try {
        const receipt = JSON.parse(stored);
        const verified = verifyReconciliationReceipt(receipt, signer.publicKey);
        const claim = receipt?.payload?.claim;
        if (!verified.valid
          || claim?.prior_outcome_receipt_id !== priorReceiptId
          || claim?.caid !== canonical.caid
          || claim?.action_digest !== canonical.actionDigest
          || claim?.operation_id !== canonical.action.payment_instruction_id) {
          return reconciliationIndeterminate('reconciliation_store_record_invalid', canonical);
        }
        return reconciliationResponseFromReceipt(receipt);
      } catch {
        return reconciliationIndeterminate('reconciliation_store_record_invalid', canonical);
      }
    };

    const existing = await restorePinned();
    if (existing) return existing;
    const pending = `pending:${randomUUID()}`;
    let reserved;
    try {
      reserved = await reconciliationStore.addIfAbsent(storeKey, pending);
    } catch {
      return reconciliationIndeterminate('reconciliation_store_unavailable', canonical);
    }
    if (reserved !== true) {
      return (await restorePinned())
        ?? reconciliationIndeterminate('reconciliation_store_unavailable', canonical);
    }

    let decision;
    try {
      decision = normalizeReconciliation(await reconcile({
        operation: canonical.action.payment_instruction_id,
        caid: canonical.caid,
        action_digest: canonical.actionDigest,
      }));
    } catch {
      decision = Object.freeze({ status: 'INDETERMINATE' });
    }
    if (decision.status === 'INDETERMINATE') {
      let released = false;
      try {
        released = (await reconciliationStore.deleteIfValue(storeKey, pending)) === true;
      } catch {
        // Leave the pending marker as an explicit operator-recovery boundary.
      }
      return reconciliationIndeterminate(
        released
          ? 'provider_reconciliation_indeterminate'
          : 'reconciliation_in_progress_or_recovery_required',
        canonical,
      );
    }
    const receipt = issueReconciliationReceipt({ canonical, priorReceipt, decision, signer, now });
    let committed = false;
    try {
      committed = (await reconciliationStore.compareAndSet(
        storeKey,
        pending,
        canonicalizeGate(receipt),
      )) === true;
    } catch {
      // A signed value is never returned unless its terminal pin is durable.
    }
    return committed
      ? reconciliationResponseFromReceipt(receipt)
      : reconciliationIndeterminate('reconciliation_in_progress_or_recovery_required', canonical);
  };
}

/**
 * Explicit local fixture API. It never represents a production key store.
 *
 * @param {{
 *   input?: any,
 *   provider?: (payment: any, context: any) => any,
 *   reconcile?: (query: any) => any,
 *   now?: () => number,
 * }} [options]
 */
export function createDemoPaymentReleaseFixture({
  input,
  provider = async (payment) => ({
    provider_status: 'ACCEPTED',
    provider_reference: `demo:${payment.operation}`,
  }),
  reconcile = async () => ({
    authenticated: true,
    authoritative: true,
    provider_status: 'NOT_ACCEPTED',
    reason_code: 'NO_PROVIDER_RECORD',
  }),
  now = Date.now,
} = {}) {
  const canonical = canonicalizePaymentRelease(input);
  const harness = createEg1Harness({ action: canonical.action, now, idPrefix: 'muse-gate-demo' });
  const gate = createTrustedActionFirewall({
    manifest: PAYMENT_RELEASE_MANIFEST,
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    allowEphemeralStore: true,
    now,
  });
  const signer = createOutcomeSigner();
  const providerCalls = [];
  const reconciliationCalls = [];
  const reconciliationStore = createMemoryReconciliationStore();
  const tool = createPaymentReleaseTool({
    gate,
    outcomeSigner: signer,
    now,
    provider: async (payment, context) => {
      providerCalls.push(structuredClone(payment));
      return provider(payment, context);
    },
  });
  const reconcileTool = createPaymentReconciliationTool({
    outcomeSigner: signer,
    reconciliationStore,
    allowEphemeralStore: true,
    now,
    reconcile: async (query) => {
      reconciliationCalls.push(structuredClone(query));
      return reconcile(query);
    },
  });
  return Object.freeze({
    action: canonical.action,
    caid: canonical.caid,
    gate,
    harness,
    mintReceipt: () => harness.mint({ outcome: 'allow_with_signoff' }),
    outcomePublicKey: signer.publicKey,
    providerCalls,
    reconciliationCalls,
    reconcileTool,
    tool,
  });
}
