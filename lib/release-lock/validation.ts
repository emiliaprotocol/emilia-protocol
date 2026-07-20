// SPDX-License-Identifier: Apache-2.0

import { canonicalize, isCanonicalizable } from '../../packages/verify/index.js';
import {
  RELEASE_LOCK_DIGEST_PATTERN,
  RELEASE_LOCK_HMAC_PATTERN,
  RELEASE_LOCK_MAX_ACTION_BYTES,
  RELEASE_LOCK_MAX_LIFETIME_MS,
  RELEASE_LOCK_MAX_MATERIAL_FIELDS_BYTES,
  RELEASE_LOCK_MIN_LIFETIME_MS,
  RELEASE_LOCK_ROLES,
} from './constants.js';
import { canonicalDigest, timingSafeTextEqual } from './crypto.js';
import { releaseLockRefusal } from './errors.js';

const CONTROL = /[\u0000-\u001f\u007f]/;
const PARTY_ID = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const PROVIDER_ID = /^[a-z0-9][a-z0-9._-]{1,127}$/;
const CURRENCY = /^[A-Z]{3}$/;
const MONEY = /^(?:0|[1-9][0-9]{0,11})\.[0-9]{2}$/;
const SIGNED_MONEY = /^-?(?:0|[1-9][0-9]{0,11})\.[0-9]{2}$/;
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const PHONE = /^\+[1-9][0-9]{7,14}$/;
const SENSITIVE_KEY = /(authorization|cookie|secret|passw(or)?d|token|bearer|api[-_]?key|private[-_]?key)/i;
const AUTHORITY_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;

/**
 * The raw, not-yet-validated provider-document object as received on the
 * wire (change_order.document, draw.completion_evidence,
 * draw.lien_waivers[].document, draw.draw_documents[]).
 * @typedef {{provider: unknown, reference: unknown, verification: unknown}} ReleaseLockRawProviderDocument
 */

/**
 * The raw, not-yet-validated party object as received on the wire
 * (contractor_party / customer_party on a change-order Release Lock input).
 * @typedef {{
 *   party_id: unknown,
 *   display_name: unknown,
 *   contact: unknown,
 *   authority: unknown,
 * }} ReleaseLockRawParty
 */

/**
 * A party object as constructed internally by normalizedParty(): party_id /
 * display_name have already been validated, but contact/authority are still
 * raw, not-yet-verified request data at this point.
 * @typedef {{
 *   party_id: string,
 *   display_name: string,
 *   role: string,
 *   contact: any,
 *   authority: any,
 * }} ReleaseLockPartyDraft
 */

/**
 * The raw, not-yet-validated request body for validateChangeOrderInput().
 * @typedef {{
 *   organization_id?: unknown,
 *   change_order: {
 *     document: ReleaseLockRawProviderDocument,
 *     scope: unknown,
 *     price_delta: unknown,
 *     currency: unknown,
 *     progress_schedule_effect: unknown,
 *     expires_at: unknown,
 *   },
 *   lock_expires_at: string,
 *   contractor_party: ReleaseLockRawParty,
 *   customer_party: ReleaseLockRawParty,
 *   invitation_expires_at?: unknown,
 * }} ReleaseLockChangeOrderInput
 */

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * @param {unknown} value
 * @param {Set<string>} allowed
 * @param {Set<string>} [required]
 * @returns {boolean}
 */
function exactKeys(value, allowed, required = allowed) {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

/**
 * @param {unknown} value
 * @param {string} field
 * @param {{min?: number, max?: number, pattern?: RegExp|null}} [opts]
 * @returns {string}
 */
function text(value, field, { min = 1, max = 512, pattern = null } = {}) {
  if (typeof value !== 'string'
      || value.length < min
      || value.length > max
      || CONTROL.test(value)
      || (pattern && !pattern.test(value))) {
    throw releaseLockRefusal(400, 'invalid_request', `${field} is invalid.`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {number}
 */
function instant(value, field) {
  text(value, field, { max: 64 });
  const parsed = Date.parse(/** @type {string} */ (value));
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw releaseLockRefusal(400, 'invalid_request', `${field} must be a canonical UTC instant.`);
  }
  return parsed;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @param {number} maxBytes
 * @returns {any}
 */
function canonicalCopy(value, field, maxBytes) {
  if (!isCanonicalizable(value)) {
    throw releaseLockRefusal(400, 'invalid_request', `${field} is outside the canonical JSON profile.`);
  }
  const encoded = canonicalize(value);
  if (Buffer.byteLength(encoded, 'utf8') > maxBytes) {
    throw releaseLockRefusal(413, 'payload_too_large', `${field} is too large.`);
  }
  return JSON.parse(encoded);
}

/**
 * @param {unknown} value
 * @param {string} field
 * @param {number} [depth]
 */
function assertNoSensitiveKeys(value, field, depth = 0) {
  if (depth > 16) {
    throw releaseLockRefusal(400, 'invalid_request', `${field} is nested too deeply.`);
  }
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const child of value) assertNoSensitiveKeys(child, field, depth + 1);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) {
      throw releaseLockRefusal(400, 'sensitive_material_field', `${field} must not contain credential or token fields.`);
    }
    assertNoSensitiveKeys(child, field, depth + 1);
  }
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {Record<string, unknown>}
 */
function materialObject(value, field) {
  const copy = canonicalCopy(value, field, RELEASE_LOCK_MAX_MATERIAL_FIELDS_BYTES);
  if (!isRecord(copy) || Object.keys(copy).length === 0) {
    throw releaseLockRefusal(400, 'invalid_request', `${field} must be a non-empty object.`);
  }
  assertNoSensitiveKeys(copy, field);
  return copy;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @param {number} nowMs
 * @param {string|null} [maxExpiresAt]
 * @returns {number}
 */
function boundedExpiry(value, field, nowMs, maxExpiresAt = null) {
  const expiresAtMs = instant(value, field);
  if (expiresAtMs < nowMs + RELEASE_LOCK_MIN_LIFETIME_MS
      || expiresAtMs > nowMs + RELEASE_LOCK_MAX_LIFETIME_MS) {
    throw releaseLockRefusal(400, 'invalid_expiry', `${field} is outside the permitted lifetime.`);
  }
  if (maxExpiresAt !== null && expiresAtMs > Date.parse(maxExpiresAt)) {
    throw releaseLockRefusal(
      400,
      'amendment_expiry_exceeds_lock',
      'An amendment cannot extend beyond the original Release Lock lifetime.',
    );
  }
  return expiresAtMs;
}

/**
 * @param {unknown} channel
 * @param {unknown} identifier
 * @returns {string}
 */
export function normalizeContactIdentifier(channel, identifier) {
  if (channel === 'email') {
    return text(identifier, 'contact.identifier', { max: 254, pattern: EMAIL }).toLowerCase();
  }
  if (channel === 'sms') {
    return text(identifier, 'contact.identifier', { max: 16, pattern: PHONE });
  }
  throw releaseLockRefusal(400, 'invalid_contact_channel', 'contact.channel must be email or sms.');
}

/**
 * @param {ReleaseLockPartyDraft} party
 * @param {string} role
 * @param {number} nowMs
 * @param {*} cryptoSuite
 */
function verifiedContact(party, role, nowMs, cryptoSuite) {
  const contactKeys = new Set(['channel', 'identifier', 'verification']);
  if (!exactKeys(party.contact, contactKeys)) {
    throw releaseLockRefusal(400, 'contact_verification_required', `${role} contact verification is required.`);
  }
  const channel = text(party.contact.channel, `${role}.contact.channel`, { max: 16 });
  const identifier = normalizeContactIdentifier(channel, party.contact.identifier);
  const verification = party.contact.verification;
  const verificationKeys = new Set([
    'provider',
    'reference',
    'verified_at',
    'expires_at',
    'proof',
  ]);
  if (!exactKeys(verification, verificationKeys)) {
    throw releaseLockRefusal(400, 'contact_verification_required', `${role} contact verification is required.`);
  }
  const provider = text(verification.provider, `${role}.contact.verification.provider`, {
    max: 128,
    pattern: PROVIDER_ID,
  });
  const reference = text(verification.reference, `${role}.contact.verification.reference`, {
    max: 512,
  });
  const verifiedAt = instant(verification.verified_at, `${role}.contact.verification.verified_at`);
  const verificationExpiresAt = instant(
    verification.expires_at,
    `${role}.contact.verification.expires_at`,
  );
  if (verifiedAt > nowMs || verificationExpiresAt <= nowMs) {
    throw releaseLockRefusal(
      400,
      'contact_verification_invalid',
      `${role} contact verification is outside its validity window.`,
    );
  }
  const proofBody = {
    '@version': 'EP-RELEASE-LOCK-CONTACT-PROOF-v1',
    role,
    party_id: party.party_id,
    channel,
    identifier,
    provider,
    reference,
    verified_at: verification.verified_at,
    expires_at: verification.expires_at,
  };
  if (!timingSafeTextEqual(
    cryptoSuite.contactProofDigest(proofBody),
    verification.proof,
  )) {
    throw releaseLockRefusal(
      403,
      'contact_verification_invalid',
      `${role} contact verification proof did not verify.`,
    );
  }
  return {
    channel,
    identifier,
    identifier_digest: cryptoSuite.contactDigest(channel, identifier),
    verification_provider: provider,
    verification_reference: reference,
    verification_proof_digest: verification.proof,
    verified_at: verification.verified_at,
    verification_expires_at: verification.expires_at,
  };
}

/**
 * @param {ReleaseLockPartyDraft} party
 * @param {string} role
 * @param {{identifier_digest: unknown}} contact
 * @param {number} nowMs
 * @param {*} cryptoSuite
 */
function verifiedAuthority(party, role, contact, nowMs, cryptoSuite) {
  const authorityKeys = new Set(['assertion', 'signature']);
  if (!exactKeys(party.authority, authorityKeys)) {
    throw releaseLockRefusal(
      400,
      'authority_verification_required',
      `${role} external authority verification is required.`,
    );
  }
  const assertionKeys = new Set([
    '@version',
    'algorithm',
    'provider',
    'key_id',
    'reference',
    'role',
    'party_id',
    'subject_digest',
    'contact_binding_digest',
    'verified_at',
    'expires_at',
  ]);
  const assertion = party.authority.assertion;
  if (!exactKeys(assertion, assertionKeys)
      || assertion['@version'] !== 'EP-RELEASE-LOCK-AUTHORITY-ASSERTION-v1'
      || assertion.algorithm !== 'Ed25519'
      || assertion.role !== role
      || assertion.party_id !== party.party_id
      || assertion.contact_binding_digest !== contact.identifier_digest
      || !RELEASE_LOCK_DIGEST_PATTERN.test(assertion.subject_digest || '')
      || !RELEASE_LOCK_HMAC_PATTERN.test(assertion.contact_binding_digest || '')
      || !AUTHORITY_SIGNATURE.test(party.authority.signature || '')) {
    throw releaseLockRefusal(
      400,
      'authority_verification_invalid',
      `${role} external authority assertion is malformed or bound to another role.`,
    );
  }
  const provider = text(assertion.provider, `${role}.authority.assertion.provider`, {
    max: 128,
    pattern: PROVIDER_ID,
  });
  const keyId = text(assertion.key_id, `${role}.authority.assertion.key_id`, {
    max: 256,
    pattern: PARTY_ID,
  });
  const reference = text(assertion.reference, `${role}.authority.assertion.reference`, {
    max: 512,
  });
  const verifiedAt = instant(
    assertion.verified_at,
    `${role}.authority.assertion.verified_at`,
  );
  const expiresAt = instant(
    assertion.expires_at,
    `${role}.authority.assertion.expires_at`,
  );
  if (verifiedAt > nowMs || expiresAt <= nowMs) {
    throw releaseLockRefusal(
      400,
      'authority_verification_invalid',
      `${role} external authority verification is outside its validity window.`,
    );
  }
  if (!cryptoSuite.verifyAuthorityAssertion(assertion, party.authority.signature)) {
    throw releaseLockRefusal(
      403,
      'authority_verification_invalid',
      `${role} external authority signature did not verify under a pinned provider key.`,
    );
  }
  return {
    provider,
    key_id: keyId,
    reference,
    assertion,
    signature: party.authority.signature,
    assertion_digest: canonicalDigest(assertion),
    subject_digest: assertion.subject_digest,
    contact_binding_digest: assertion.contact_binding_digest,
    verified_at: assertion.verified_at,
    expires_at: assertion.expires_at,
  };
}

/**
 * @param {ReleaseLockRawParty} value
 * @param {string} role
 * @param {number} nowMs
 * @param {*} cryptoSuite
 */
function normalizedParty(value, role, nowMs, cryptoSuite) {
  const keys = new Set(['party_id', 'display_name', 'contact', 'authority']);
  if (!exactKeys(value, keys)) {
    throw releaseLockRefusal(400, 'invalid_request', `${role}_party is malformed.`);
  }
  const party = {
    party_id: text(value.party_id, `${role}_party.party_id`, {
      max: 256,
      pattern: PARTY_ID,
    }),
    display_name: text(value.display_name, `${role}_party.display_name`, { max: 200 }),
    role,
    contact: value.contact,
    authority: value.authority,
  };
  const contact = verifiedContact(party, role, nowMs, cryptoSuite);
  const authority = verifiedAuthority(party, role, contact, nowMs, cryptoSuite);
  return {
    party: {
      party_id: party.party_id,
      display_name: party.display_name,
      role,
      authority: {
        provider: authority.provider,
        key_id: authority.key_id,
        reference: authority.reference,
        assertion: authority.assertion,
        signature: authority.signature,
        assertion_digest: authority.assertion_digest,
        subject_digest: authority.subject_digest,
        contact_binding_digest: authority.contact_binding_digest,
        verified_at: authority.verified_at,
        expires_at: authority.expires_at,
      },
    },
    contact,
    authority,
  };
}

/**
 * @param {ReleaseLockRawProviderDocument} value
 * @param {string} [field]
 */
export function normalizeProviderDocument(value, field = 'document') {
  const keys = new Set(['provider', 'reference', 'verification']);
  if (!exactKeys(value, keys)) {
    throw releaseLockRefusal(400, 'invalid_request', `${field} is malformed.`);
  }
  const verification = canonicalCopy(value.verification, `${field}.verification`, 32 * 1024);
  assertNoSensitiveKeys(verification, `${field}.verification`);
  return {
    provider: text(value.provider, `${field}.provider`, { max: 128, pattern: PROVIDER_ID }),
    reference: text(value.reference, `${field}.reference`, { max: 512 }),
    verification,
  };
}

/**
 * @param {{id: unknown, label: unknown}} value
 */
function normalizedMilestone(value) {
  const keys = new Set(['id', 'label']);
  if (!exactKeys(value, keys)) {
    throw releaseLockRefusal(400, 'invalid_request', 'milestone is malformed.');
  }
  return {
    id: text(value.id, 'milestone.id', { max: 256 }),
    label: text(value.label, 'milestone.label', { max: 512 }),
  };
}

/**
 * @param {{
 *   provider: unknown,
 *   environment: unknown,
 *   transaction_id: unknown,
 *   milestone_id: unknown,
 *   instruction: unknown,
 * }} value
 */
function normalizedCustodian(value) {
  const keys = new Set([
    'provider',
    'environment',
    'transaction_id',
    'milestone_id',
    'instruction',
  ]);
  if (!exactKeys(value, keys)) {
    throw releaseLockRefusal(400, 'invalid_request', 'custodian is malformed.');
  }
  const environment = text(value.environment, 'custodian.environment', { max: 16 });
  if (!['sandbox', 'production'].includes(environment)) {
    throw releaseLockRefusal(400, 'invalid_request', 'custodian.environment must be sandbox or production.');
  }
  if (value.instruction !== 'release_milestone') {
    throw releaseLockRefusal(
      400,
      'invalid_custodian_instruction',
      'custodian.instruction must be release_milestone.',
    );
  }
  return {
    provider: text(value.provider, 'custodian.provider', { max: 128, pattern: PROVIDER_ID }),
    environment,
    transaction_id: text(value.transaction_id, 'custodian.transaction_id', { max: 256 }),
    milestone_id: text(value.milestone_id, 'custodian.milestone_id', { max: 256 }),
    instruction: value.instruction,
  };
}

/**
 * @param {unknown} value
 * @param {string} amount
 * @param {string} currency
 */
function normalizedPayees(value, amount, currency) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 20) {
    throw releaseLockRefusal(400, 'invalid_payees', 'draw.payees must contain 1-20 exact payees.');
  }
  const ids = new Set();
  let total = 0n;
  const payees = value.map((payee, index) => {
    const keys = new Set(['party_id', 'destination_id', 'amount']);
    if (!exactKeys(payee, keys)) {
      throw releaseLockRefusal(400, 'invalid_payees', `draw.payees[${index}] is malformed.`);
    }
    const normalized = {
      party_id: text(payee.party_id, `draw.payees[${index}].party_id`, {
        max: 256,
        pattern: PARTY_ID,
      }),
      destination_id: text(
        payee.destination_id,
        `draw.payees[${index}].destination_id`,
        { max: 512 },
      ),
      amount: text(payee.amount, `draw.payees[${index}].amount`, {
        max: 32,
        pattern: MONEY,
      }),
    };
    const key = `${normalized.party_id}\0${normalized.destination_id}`;
    if (ids.has(key)) {
      throw releaseLockRefusal(400, 'invalid_payees', 'draw.payees contains a duplicate payee.');
    }
    ids.add(key);
    total += BigInt(normalized.amount.replace('.', ''));
    return normalized;
  });
  if (total !== BigInt(amount.replace('.', ''))) {
    throw releaseLockRefusal(
      400,
      'payee_total_mismatch',
      `Exact payee amounts must sum to draw.amount in ${currency}.`,
    );
  }
  return payees;
}

/**
 * @param {unknown} value
 * @param {string} field
 * @param {{min?: number, max?: number}} [opts]
 */
function normalizedDocumentList(value, field, { min = 0, max = 20 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    throw releaseLockRefusal(400, 'invalid_request', `${field} must contain ${min}-${max} documents.`);
  }
  const seen = new Set();
  return value.map((entry, index) => {
    const document = normalizeProviderDocument(entry, `${field}[${index}]`);
    const key = `${document.provider}\0${document.reference}`;
    if (seen.has(key)) {
      throw releaseLockRefusal(400, 'duplicate_document_reference', `${field} contains a duplicate provider reference.`);
    }
    seen.add(key);
    return document;
  });
}

/**
 * @param {unknown} value
 * @param {{party_id: string}[]} payees
 */
function normalizedLienWaivers(value, payees) {
  if (!Array.isArray(value) || value.length < payees.length || value.length > 40) {
    throw releaseLockRefusal(
      400,
      'invalid_lien_waivers',
      'draw.lien_waivers must include at least one payee-bound document for every payee.',
    );
  }
  const allowedPayees = new Set(payees.map((payee) => payee.party_id));
  const coveredPayees = new Set();
  const seenDocuments = new Set();
  const waivers = value.map((entry, index) => {
    if (!exactKeys(entry, new Set(['payee_party_id', 'document']))) {
      throw releaseLockRefusal(
        400,
        'invalid_lien_waivers',
        `draw.lien_waivers[${index}] is malformed.`,
      );
    }
    const payeePartyId = text(
      entry.payee_party_id,
      `draw.lien_waivers[${index}].payee_party_id`,
      { max: 256, pattern: PARTY_ID },
    );
    if (!allowedPayees.has(payeePartyId)) {
      throw releaseLockRefusal(
        400,
        'lien_waiver_payee_mismatch',
        'Every lien waiver must identify a payee in draw.payees.',
      );
    }
    const document = normalizeProviderDocument(
      entry.document,
      `draw.lien_waivers[${index}].document`,
    );
    const documentKey = `${document.provider}\0${document.reference}`;
    if (seenDocuments.has(documentKey)) {
      throw releaseLockRefusal(
        400,
        'duplicate_document_reference',
        'draw.lien_waivers contains a duplicate provider reference.',
      );
    }
    seenDocuments.add(documentKey);
    coveredPayees.add(payeePartyId);
    return {
      payee_party_id: payeePartyId,
      document,
    };
  });
  if (coveredPayees.size !== allowedPayees.size) {
    throw releaseLockRefusal(
      400,
      'lien_waiver_coverage_incomplete',
      'Every exact payee must have payee-bound lien-waiver evidence.',
    );
  }
  return waivers;
}

/**
 * @param {{
 *   completionEvidence: {provider: unknown, reference: unknown},
 *   lienWaivers: {payee_party_id: string, document: {provider: unknown, reference: unknown}}[],
 *   drawDocuments: {provider: unknown, reference: unknown}[],
 * }} params
 */
function assertDisjointEvidenceReferences({
  completionEvidence,
  lienWaivers,
  drawDocuments,
}) {
  const references = [
    {
      category: 'completion_evidence',
      document: completionEvidence,
    },
    ...lienWaivers.map((waiver) => ({
      category: `lien_waiver:${waiver.payee_party_id}`,
      document: waiver.document,
    })),
    ...drawDocuments.map((document) => ({
      category: 'draw_document',
      document,
    })),
  ];
  const seen = new Map();
  for (const { category, document } of references) {
    const key = `${document.provider}\0${document.reference}`;
    const previous = seen.get(key);
    if (previous) {
      throw releaseLockRefusal(
        400,
        'evidence_category_collision',
        `One provider document cannot satisfy both ${previous} and ${category}.`,
      );
    }
    seen.set(key, category);
  }
}

/**
 * input is accepted as Record<string, any> (matching how every caller in
 * this codebase declares it, e.g. service.js's amendLock()); once exactKeys()
 * has confirmed its shape at runtime, it is treated internally as the more
 * specific ReleaseLockChangeOrderInput via the typedInput alias below so
 * that its fields are concretely typed rather than `any`.
 * @param {Record<string, any>} input
 * @param {object} [opts]
 * @param {number|(() => number)} [opts.now]
 * @param {*} [opts.cryptoSuite]
 * @param {string} [opts.contractorEntityId]
 * @param {string|null} [opts.maxExpiresAt]
 * @param {boolean} [opts.amendment]
 */
export function validateChangeOrderInput(input, {
  now = Date.now(),
  cryptoSuite,
  contractorEntityId,
  maxExpiresAt = null,
  amendment = false,
} = {}) {
  const keys = new Set([
    'organization_id',
    'change_order',
    'lock_expires_at',
    'contractor_party',
    'customer_party',
    ...(amendment ? [] : ['invitation_expires_at']),
  ]);
  const required = new Set([...keys].filter((key) => key !== 'organization_id'));
  if (!exactKeys(input, keys, required) || !cryptoSuite) {
    throw releaseLockRefusal(400, 'invalid_request', 'Change-order Release Lock is malformed.');
  }
  /** @type {ReleaseLockChangeOrderInput} */
  const typedInput = /** @type {any} */ (input);
  const nowMs = typeof now === 'function' ? now() : now;
  if (!Number.isFinite(nowMs)) throw new Error('Release Lock clock is invalid');
  if (maxExpiresAt !== null && typedInput.lock_expires_at !== maxExpiresAt) {
    throw releaseLockRefusal(
      400,
      'lock_expiry_immutable',
      'An amendment cannot change lock_expires_at.',
    );
  }
  const coKeys = new Set([
    'document',
    'scope',
    'price_delta',
    'currency',
    'progress_schedule_effect',
    'expires_at',
  ]);
  if (!exactKeys(typedInput.change_order, coKeys)) {
    throw releaseLockRefusal(400, 'invalid_request', 'change_order is malformed.');
  }
  const lockExpiresAtMs = boundedExpiry(
    typedInput.lock_expires_at,
    'lock_expires_at',
    nowMs,
    maxExpiresAt,
  );
  const expiresAtMs = boundedExpiry(
    typedInput.change_order.expires_at,
    'change_order.expires_at',
    nowMs,
    typedInput.lock_expires_at,
  );
  const invitationExpiresAtMs = amendment
    ? null
    : instant(typedInput.invitation_expires_at, 'invitation_expires_at');
  if (!amendment && (
    /** @type {number} */ (invitationExpiresAtMs) <= nowMs
      || /** @type {number} */ (invitationExpiresAtMs) > lockExpiresAtMs
  )) {
    throw releaseLockRefusal(
      400,
      'invalid_invitation_expiry',
      'invitation_expires_at must be in the future and no later than lock_expires_at.',
    );
  }
  const contractor = normalizedParty(
    typedInput.contractor_party,
    RELEASE_LOCK_ROLES[0],
    nowMs,
    cryptoSuite,
  );
  const customer = normalizedParty(
    typedInput.customer_party,
    RELEASE_LOCK_ROLES[1],
    nowMs,
    cryptoSuite,
  );
  if (contractor.party.party_id !== contractorEntityId) {
    throw releaseLockRefusal(
      403,
      'contractor_party_mismatch',
      'contractor_party.party_id must match the authenticated contractor entity.',
    );
  }
  if (contractor.party.party_id === customer.party.party_id) {
    throw releaseLockRefusal(400, 'party_reused_across_roles', 'Contractor and customer parties must be distinct.');
  }
  if (contractor.contact.identifier_digest === customer.contact.identifier_digest) {
    throw releaseLockRefusal(
      400,
      'contact_reused_across_roles',
      'Contractor and customer contacts must be separately verified and distinct.',
    );
  }
  if (contractor.authority.provider !== customer.authority.provider) {
    throw releaseLockRefusal(
      400,
      'authority_provider_mismatch',
      'Both Release Lock roles must be verified by the same pinned external authority.',
    );
  }
  if (contractor.authority.subject_digest === customer.authority.subject_digest) {
    throw releaseLockRefusal(
      400,
      'authority_subject_reused',
      'Contractor and customer must be distinct subjects under the pinned external authority.',
    );
  }
  if (Date.parse(contractor.contact.verification_expires_at) < lockExpiresAtMs
      || Date.parse(customer.contact.verification_expires_at) < lockExpiresAtMs) {
    throw releaseLockRefusal(
      400,
      'contact_verification_too_short',
      'Each verified contact binding must remain valid through lock_expires_at.',
    );
  }
  if (Date.parse(contractor.authority.expires_at) < lockExpiresAtMs
      || Date.parse(customer.authority.expires_at) < lockExpiresAtMs) {
    throw releaseLockRefusal(
      400,
      'authority_verification_too_short',
      'Each external authority binding must remain valid through lock_expires_at.',
    );
  }
  if (!amendment
      && (/** @type {number} */ (invitationExpiresAtMs) > Date.parse(contractor.contact.verification_expires_at)
        || /** @type {number} */ (invitationExpiresAtMs) > Date.parse(customer.contact.verification_expires_at))) {
    throw releaseLockRefusal(
      400,
      'invalid_invitation_expiry',
      'invitation_expires_at cannot outlive either verified contact binding.',
    );
  }
  const normalized = {
    change_order: {
      document: normalizeProviderDocument(typedInput.change_order.document, 'change_order.document'),
      scope: materialObject(typedInput.change_order.scope, 'change_order.scope'),
      price_delta: text(typedInput.change_order.price_delta, 'change_order.price_delta', {
        max: 33,
        pattern: SIGNED_MONEY,
      }),
      currency: text(typedInput.change_order.currency, 'change_order.currency', {
        max: 3,
        pattern: CURRENCY,
      }),
      progress_schedule_effect: materialObject(
        typedInput.change_order.progress_schedule_effect,
        'change_order.progress_schedule_effect',
      ),
      expires_at: typedInput.change_order.expires_at,
    },
    ...(amendment ? {} : { invitation_expires_at: typedInput.invitation_expires_at }),
    lock_expires_at: typedInput.lock_expires_at,
    parties: [contractor.party, customer.party],
    contacts: {
      contractor: {
        ...contractor.contact,
        authority: contractor.authority,
      },
      customer: {
        ...customer.contact,
        authority: customer.authority,
      },
    },
  };
  canonicalCopy(normalized, 'Change-order Release Lock', RELEASE_LOCK_MAX_ACTION_BYTES);
  return normalized;
}

/**
 * @param {object} input
 * @param {object} [opts]
 * @param {number|(() => number)} [opts.now]
 * @param {string} [opts.maxExpiresAt]
 */
export function validateDrawReleaseInput(input, {
  now = Date.now(),
  maxExpiresAt,
} = {}) {
  const keys = new Set(['organization_id', 'expected_version', 'draw']);
  const required = new Set(['expected_version', 'draw']);
  if (!exactKeys(input, keys, required)
      || !Number.isSafeInteger(/** @type {{expected_version: unknown}} */ (input).expected_version)
      || input.expected_version < 1) {
    throw releaseLockRefusal(400, 'invalid_request', 'DRAW_RELEASE request is malformed.');
  }
  const drawKeys = new Set([
    'draw_id',
    'amount',
    'currency',
    'payees',
    'milestone',
    'completion_evidence',
    'lien_waivers',
    'draw_documents',
    'custodian',
    'expires_at',
  ]);
  if (!exactKeys(input.draw, drawKeys)) {
    throw releaseLockRefusal(400, 'invalid_request', 'draw is malformed.');
  }
  const nowMs = typeof now === 'function' ? now() : now;
  boundedExpiry(input.draw.expires_at, 'draw.expires_at', nowMs, maxExpiresAt);
  const amount = text(input.draw.amount, 'draw.amount', { max: 32, pattern: MONEY });
  if (BigInt(amount.replace('.', '')) <= 0n) {
    throw releaseLockRefusal(400, 'invalid_amount', 'draw.amount must be greater than zero.');
  }
  const currency = text(input.draw.currency, 'draw.currency', {
    max: 3,
    pattern: CURRENCY,
  });
  const payees = normalizedPayees(input.draw.payees, amount, currency);
  const completionEvidence = normalizeProviderDocument(
    input.draw.completion_evidence,
    'draw.completion_evidence',
  );
  const lienWaivers = normalizedLienWaivers(input.draw.lien_waivers, payees);
  const drawDocuments = normalizedDocumentList(
    input.draw.draw_documents,
    'draw.draw_documents',
  );
  assertDisjointEvidenceReferences({
    completionEvidence,
    lienWaivers,
    drawDocuments,
  });
  const normalized = {
    expected_version: input.expected_version,
    draw: {
      draw_id: text(input.draw.draw_id, 'draw.draw_id', { max: 256 }),
      amount,
      currency,
      payees,
      milestone: normalizedMilestone(input.draw.milestone),
      completion_evidence: completionEvidence,
      lien_waivers: lienWaivers,
      draw_documents: drawDocuments,
      custodian: normalizedCustodian(input.draw.custodian),
      expires_at: input.draw.expires_at,
    },
  };
  canonicalCopy(normalized, 'DRAW_RELEASE', RELEASE_LOCK_MAX_ACTION_BYTES);
  return normalized;
}

export const releaseLockValidationInternals = Object.freeze({
  exactKeys,
  isRecord,
  canonicalCopy,
  assertNoSensitiveKeys,
  instant,
  text,
});
