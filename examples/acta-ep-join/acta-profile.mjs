// SPDX-License-Identifier: Apache-2.0
// Non-normative ACTA-02 component profile for EP-AEC.

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

import { canonicalize } from '../../packages/verify/index.js';
import { actionDigest } from '../../packages/verify/evidence-chain.js';
import {
  mapAction,
  mappingProfileHash,
} from '../../caid/impl/js/mapping.mjs';

export const ACTA_COMPONENT_TYPE = 'acta-decision';
export const ACTA_RECEIPT_TYPE = 'protectmcp:decision';
export const ACTA_PROFILE_REVISION = 'draft-farley-acta-signed-receipts-02';

const HEX_256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[0-9a-f]{128}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const EMBEDDED_KEY_FIELD = /^(?:public[_-]?key|verification[_-]?(?:key|jwk)|jwk|issuer[_-]?public[_-]?key)$/i;

const registry = JSON.parse(readFileSync(
  new URL('../../caid/registry/action-types.json', import.meta.url),
  'utf8',
));
const definitions = registry.types;

export const PAYMENT_RELEASE_MAPPING_PROFILE = Object.freeze({
  '@version': 'CAID-MAPPING-PROFILE-v1',
  profile_id: 'urn:emilia:mapping:ep-payment-release-to-caid:1',
  source_format: Object.freeze({
    media_type: 'application/ep-action+json',
    schema: 'urn:emilia:ep-action:1',
    version: '1',
  }),
  target_action_type: 'payment.release.1',
  loss_policy: 'no-material-field-loss',
  material_source_paths: Object.freeze([
    '/amount',
    '/currency',
    '/beneficiary_account',
    '/payment_instruction_id',
  ]),
  rules: Object.freeze([
    Object.freeze({ source_path: '/amount', target_field: 'amount', transform: 'copy' }),
    Object.freeze({ source_path: '/currency', target_field: 'currency', transform: 'copy' }),
    Object.freeze({ source_path: '/beneficiary_account', target_field: 'beneficiary_account', transform: 'copy' }),
    Object.freeze({ source_path: '/payment_instruction_id', target_field: 'payment_instruction_id', transform: 'copy' }),
  ]),
});

export const PAYMENT_RELEASE_MAPPING_PROFILE_HASH = mappingProfileHash(
  PAYMENT_RELEASE_MAPPING_PROFILE,
);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function normalizedDigest(value) {
  if (typeof value !== 'string') return null;
  const digest = value.replace(/^sha256:/i, '').toLowerCase();
  return HEX_256.test(digest) ? `sha256:${digest}` : null;
}

function strictInstantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) {
    return NaN;
  }
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) {
    return NaN;
  }
  return Date.parse(value);
}

function hasEmbeddedVerificationKey(value) {
  const stack = [value];
  const seen = new WeakSet();
  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    if (seen.has(current)) return true;
    seen.add(current);
    for (const [key, child] of Object.entries(current)) {
      if (EMBEDDED_KEY_FIELD.test(key)) return true;
      if (child && typeof child === 'object') stack.push(child);
    }
  }
  return false;
}

function decodePinnedEd25519Key(value) {
  if (typeof value !== 'string' || !B64URL.test(value)) return null;
  try {
    const der = Buffer.from(value, 'base64url');
    if (der.toString('base64url') !== value) return null;
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function activePinnedKey(entry, kid, at) {
  if (!isRecord(entry) || entry.status !== 'active' || entry.issuer_id !== kid) return false;
  const from = strictInstantMs(entry.valid_from);
  const to = strictInstantMs(entry.valid_to);
  if (!Number.isFinite(at) || !Number.isFinite(from) || !Number.isFinite(to)
      || at < from || at > to) return false;
  if (entry.revoked_at === undefined || entry.revoked_at === null) return true;
  const revoked = strictInstantMs(entry.revoked_at);
  return Number.isFinite(revoked) && at < revoked;
}

function freshRegistrySnapshot(policy, at) {
  const checked = strictInstantMs(policy?.registry_checked_at);
  return Number.isFinite(at) && Number.isFinite(checked)
    && Number.isInteger(policy?.max_registry_age_sec)
    && policy.max_registry_age_sec >= 0
    && checked <= at && at - checked <= policy.max_registry_age_sec * 1000;
}

export function artifactDigest(value) {
  try {
    return `sha256:${sha256(Buffer.from(canonicalize(value), 'utf8'))}`;
  } catch {
    return null;
  }
}

export function mapPaymentReleaseCaid(action, policy = {}) {
  const profile = policy.mapping_profile ?? PAYMENT_RELEASE_MAPPING_PROFILE;
  const sourceDescriptor = policy.source_descriptor ?? PAYMENT_RELEASE_MAPPING_PROFILE.source_format;
  const expectedProfileHash = policy.mapping_profile_hash ?? PAYMENT_RELEASE_MAPPING_PROFILE_HASH;
  return mapAction(action, {
    profile,
    sourceDescriptor,
    expectedProfileHash,
    nativeVerified: true,
    definitions,
    suite: 'jcs-sha256',
  });
}

/** ACTA-02 Section 2.2 action_ref, preserving the draft's exact field names. */
export function computeActaActionRef(evaluation) {
  if (!isRecord(evaluation)
      || typeof evaluation.agentId !== 'string' || !evaluation.agentId
      || typeof evaluation.actionType !== 'string' || !evaluation.actionType
      || !Array.isArray(evaluation.scopeRequired) || evaluation.scopeRequired.length === 0
      || evaluation.scopeRequired.some((scope) => typeof scope !== 'string' || !scope)
      || !Number.isFinite(strictInstantMs(evaluation.timestamp))) {
    return null;
  }
  const input = {
    agentId: evaluation.agentId,
    actionType: evaluation.actionType,
    scopeRequired: [...evaluation.scopeRequired].sort(),
    timestamp: evaluation.timestamp,
  };
  try {
    return sha256(Buffer.from(canonicalize(input), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Build an EP-AEC custom verifier for one ACTA decision and one exact EP receipt.
 * The expected ACTA evaluation and EP artifact digest are relying-party inputs;
 * neither is read from unsigned presenter metadata.
 */
export function createActaDecisionVerifier({
  expectedActionRef,
  expectedHumanAuthorizationDigest,
  policy,
} = {}) {
  const pinnedPolicy = isRecord(policy) ? structuredClone(policy) : null;
  const expectedReceipt = normalizedDigest(expectedHumanAuthorizationDigest);

  return (evidence, ctx = {}) => {
    const fail = (reason) => ({ valid: false, action_digest: null, detail: { reason } });
    try {
      if (!isRecord(pinnedPolicy)) return fail('missing relying-party ACTA profile');
      if (!isRecord(evidence) || !isRecord(evidence.payload) || !isRecord(evidence.signature)) {
        return fail('malformed ACTA envelope');
      }
      if (Object.keys(evidence).some((key) => key !== 'payload' && key !== 'signature')) {
        return fail('unexpected ACTA envelope member');
      }
      if (Object.keys(evidence.signature).some((key) => !['alg', 'kid', 'sig'].includes(key))) {
        return fail('unexpected ACTA signature member');
      }
      if (hasEmbeddedVerificationKey(evidence)) {
        return fail('embedded verification key refused');
      }

      const { payload, signature } = evidence;
      if (signature.alg !== 'EdDSA' || typeof signature.kid !== 'string'
          || !ED25519_SIGNATURE.test(signature.sig)) {
        return fail('unsupported or malformed ACTA signature');
      }
      if (payload.issuer_id !== signature.kid) return fail('ACTA issuer_id and kid differ');

      const at = strictInstantMs(ctx.verificationTime);
      const issued = strictInstantMs(payload.issued_at);
      if (!Number.isFinite(at) || !Number.isFinite(issued)
          || !Number.isInteger(pinnedPolicy.max_age_sec) || pinnedPolicy.max_age_sec < 0
          || issued > at || at - issued > pinnedPolicy.max_age_sec * 1000) {
        return fail('ACTA decision is stale or has an invalid timestamp');
      }
      if (!freshRegistrySnapshot(pinnedPolicy, at)) {
        return fail('ACTA issuer registry snapshot is stale or malformed');
      }

      const keyEntry = ctx.keysByType?.[ACTA_COMPONENT_TYPE]?.[signature.kid];
      if (!activePinnedKey(keyEntry, signature.kid, at)) {
        return fail('ACTA issuer key is not active and pinned for the ACTA role');
      }
      const publicKey = decodePinnedEd25519Key(keyEntry.public_key);
      if (!publicKey) return fail('pinned ACTA key is not an Ed25519 SPKI key');
      const signatureBytes = Buffer.from(signature.sig, 'hex');
      const signedBytes = Buffer.from(canonicalize(payload), 'utf8');
      if (!crypto.verify(null, signedBytes, publicKey, signatureBytes)) {
        return fail('ACTA signature did not verify');
      }

      if (payload.type !== ACTA_RECEIPT_TYPE
          || payload.tool_name !== pinnedPolicy.expected_tool_name
          || payload.decision !== pinnedPolicy.expected_decision
          || payload.policy_digest !== pinnedPolicy.expected_policy_digest) {
        return fail('ACTA decision is outside the relying-party policy');
      }
      if (!HEX_256.test(expectedActionRef ?? '') || payload.action_ref !== expectedActionRef) {
        return fail('ACTA action_ref does not match the relying-party evaluation');
      }

      const mapped = mapPaymentReleaseCaid(ctx.action, pinnedPolicy);
      if (!mapped.ok || payload.caid !== mapped.caid) {
        return fail('ACTA CAID does not match the pinned material-action mapping');
      }

      const boundActionDigest = normalizedDigest(payload.ep_action_digest);
      const expectedEpActionDigest = `sha256:${actionDigest(ctx.action)}`;
      if (boundActionDigest !== expectedEpActionDigest) {
        return fail('ACTA signed payload binds a different EP action');
      }

      const humanRef = payload.human_authorization_ref;
      if (!expectedReceipt || !isRecord(humanRef)
          || humanRef.format !== 'EP-RECEIPT-v1'
          || normalizedDigest(humanRef.digest) !== expectedReceipt) {
        return fail('ACTA decision does not reference the exact EP human receipt');
      }

      return {
        valid: true,
        action_digest: boundActionDigest,
        detail: {
          caid: mapped.caid,
          action_ref: payload.action_ref,
          human_authorization_digest: expectedReceipt,
        },
      };
    } catch {
      return fail('unexpected ACTA verification error');
    }
  };
}
