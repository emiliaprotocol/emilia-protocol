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

export const ADAPTER_VERSION = 'EP-MUSE-CODE-GATE-v1';
export const OUTCOME_PROFILE = 'EP-MUSE-CODE-GATE-OUTCOME-v1';
export const PAYMENT_TOOL = 'release_payment';
export const PAYMENT_ACTION_TYPE = 'payment.release.1';

const REGISTRY = JSON.parse(readFileSync(
  new URL('../../caid/registry/action-types.json', import.meta.url),
  'utf8',
));
const DEFINITIONS = REGISTRY.types;
const REQUIRED_INPUT_FIELDS = Object.freeze(['payee', 'account', 'amount', 'currency', 'operation']);
const RECEIPT_FIELDS = new Set(['_emilia_receipt', 'emilia_receipt', '_emilia_receipt_b64']);
const AMOUNT = /^(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,2})?$/;
const CURRENCY = /^[A-Z]{3}$/;
const CAID = /^caid:1:payment\.release\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/;

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
  const computed = computeCaid(action, { suite: 'jcs-sha256', definitions: DEFINITIONS });
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

export function createOutcomeSigner({ privateKey, publicKey, keyId = 'ep:key:muse-gate-outcome' } = {}) {
  if (!privateKey && !publicKey) {
    const generated = generateKeyPairSync('ed25519');
    privateKey = generated.privateKey;
    publicKey = generated.publicKey;
  }
  const normalizedPrivateKey = privateKeyFrom(privateKey);
  const normalizedPublicKey = typeof publicKey === 'string'
    ? publicKey
    : publicKeyB64u(publicKey);
  return Object.freeze({ privateKey: normalizedPrivateKey, publicKey: normalizedPublicKey, keyId });
}

function issueOutcomeReceipt({ outcome, canonical, gateEvidence, signer, now }) {
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
    outcome,
    retry: 'REFUSE',
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
  const profile = claim?.profile === OUTCOME_PROFILE;
  const semantics = claim?.execution_authorizing === false
    && claim?.provider_entry === 'ENTERED'
    && ['EXECUTED', 'INDETERMINATE'].includes(claim?.outcome)
    && claim?.retry === 'REFUSE'
    && claim?.action_type === PAYMENT_ACTION_TYPE
    && typeof claim?.action_digest === 'string'
    && /^sha256:[0-9a-f]{64}$/.test(claim.action_digest)
    && typeof claim?.caid === 'string'
    && CAID.test(claim.caid);
  return {
    ...base,
    valid: base.valid === true && profile && semantics,
    checks: { ...base.checks, profile, semantics },
    execution_authorizing: false,
  };
}

function structuredToolError(reason, extra = {}) {
  return {
    isError: true,
    content: [{ type: 'text', text: `EMILIA Gate refused release_payment: ${reason}.` }],
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
    return provider(structuredClone(canonical.providerInput), {
      caid: canonical.caid,
      action: structuredClone(canonical.action),
    });
  });

  const tool = async (args = {}, extra) => {
    let canonical;
    let pinnedArgs;
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
      if (result?.isError) {
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
      const receipt = issueOutcomeReceipt({
        outcome: 'EXECUTED',
        canonical,
        gateEvidence: { execution: result?._emilia?.execution },
        signer,
        now,
      });
      return {
        ...result,
        _emilia: {
          ...result._emilia,
          adapter: ADAPTER_VERSION,
          caid: canonical.caid,
          provider_entry: 'ENTERED',
          outcome: 'EXECUTED',
          retry: 'REFUSE',
          outcome_receipt: receipt,
          outcome_verification_key: signer.publicKey,
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
          adapter: ADAPTER_VERSION,
          caid: canonical.caid,
          provider_entry: 'ENTERED',
          outcome: 'EXECUTED',
          retry: 'REFUSE',
          outcome_receipt: receipt,
          outcome_verification_key: signer.publicKey,
        });
      }
      if (terminal?.outcome !== 'indeterminate') {
        return structuredToolError(terminal?.reason || 'gate_terminal_error');
      }
      const receipt = issueOutcomeReceipt({
        outcome: 'INDETERMINATE', canonical, gateEvidence: terminal, signer, now,
      });
      return structuredToolError('effect_attempted_outcome_unknown', {
        status: 409,
        adapter: ADAPTER_VERSION,
        caid: canonical.caid,
        provider_entry: 'ENTERED',
        outcome: 'INDETERMINATE',
        retry: 'REFUSE',
        outcome_receipt: receipt,
        outcome_verification_key: signer.publicKey,
      });
    }
  };
  Object.defineProperty(tool, 'outcomePublicKey', { value: signer.publicKey });
  return tool;
}

/** Explicit local fixture API. It never represents a production key store. */
export function createDemoPaymentReleaseFixture({
  input,
  provider = async (payment) => ({ provider_reference: `demo:${payment.operation}`, accepted: true }),
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
  const tool = createPaymentReleaseTool({
    gate,
    outcomeSigner: signer,
    now,
    provider: async (payment, context) => {
      providerCalls.push(structuredClone(payment));
      return provider(payment, context);
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
    tool,
  });
}
