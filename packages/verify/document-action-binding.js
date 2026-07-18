// SPDX-License-Identifier: Apache-2.0
/**
 * EP-DOCUMENT-ACTION-BINDING-v1
 *
 * A mapping issuer binds one final document to structured material terms, one
 * exact release action template, and the party roster a separate acceptance
 * workflow must satisfy. This artifact does NOT prove that any party accepted
 * the document. E-sign provider metadata is intentionally outside the profile;
 * EP-RESOLUTION receipts can supply acceptance evidence to a state engine.
 *
 * Verification is offline, pure, and fail-closed. The only verification key is
 * selected from the relying party's issuerKeys option. The artifact cannot
 * carry a public key.
 */

import crypto from 'node:crypto';
import { canonicalize } from './index.js';

export const DOCUMENT_ACTION_BINDING_VERSION = 'EP-DOCUMENT-ACTION-BINDING-v1';
export const DOCUMENT_ACTION_BINDING_DOMAIN = `${DOCUMENT_ACTION_BINDING_VERSION}\0`;
export const DOCUMENT_ACTION_MATERIAL_TERM_TYPES = Object.freeze([
  'amount',
  'boolean',
  'date',
  'decimal',
  'digest',
  'identifier',
  'integer',
  'string',
  'timestamp',
]);

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const DECIMAL = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const AMOUNT = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const AMOUNT_FIELD = /(?:^|_)amount$/;
const MINOR_AMOUNT_FIELD = /(?:^|_)amount_minor$/;
const CURRENCY = /^[A-Z]{3}$/;
const VOCABULARY = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const MEDIA_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const MAX_DEPTH = 64;
const MAX_NODES = 20_000;
const MAX_TERMS = 256;
const MAX_PARTIES = 256;

const TOP_LEVEL_KEYS = new Set([
  'profile',
  'binding_id',
  'agreement_id',
  'mapping_issuer',
  'document',
  'material_terms',
  'release_action',
  'parties',
  'required_parties',
  'validity',
  'supersedes_digest',
  'binding_digest',
  'issuer_signatures',
]);
const TOP_LEVEL_REQUIRED = new Set([
  'profile',
  'binding_id',
  'agreement_id',
  'mapping_issuer',
  'document',
  'material_terms',
  'release_action',
  'parties',
  'required_parties',
  'validity',
  'binding_digest',
  'issuer_signatures',
]);
const CORE_KEYS = new Set([
  'profile',
  'binding_id',
  'agreement_id',
  'mapping_issuer',
  'document',
  'material_terms',
  'release_action',
  'parties',
  'required_parties',
  'validity',
  'supersedes_digest',
]);
const CORE_REQUIRED = new Set([
  'profile',
  'binding_id',
  'agreement_id',
  'mapping_issuer',
  'document',
  'material_terms',
  'release_action',
  'parties',
  'required_parties',
  'validity',
]);

function isRecord(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function exactKeys(value, allowed, required = allowed) {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

function canonicalString(value) {
  if (typeof value !== 'string' || value.normalize('NFC') !== value) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function canonicalJsonIssue(value) {
  const seen = new WeakSet();
  const state = { nodes: 0 };

  function visit(current, depth) {
    state.nodes += 1;
    if (state.nodes > MAX_NODES) return 'canonical_value_too_large';
    if (depth > MAX_DEPTH) return 'canonical_value_too_deep';
    if (current === null || typeof current === 'boolean') return null;
    if (typeof current === 'string') return canonicalString(current) ? null : 'noncanonical_string';
    if (typeof current === 'number') {
      return Number.isSafeInteger(current) ? null : 'noncanonical_number';
    }
    if (typeof current !== 'object') return 'non_json_value';
    if (seen.has(current)) return 'cyclic_or_aliased_value';
    seen.add(current);

    if (Array.isArray(current)) {
      if (Object.getPrototypeOf(current) !== Array.prototype) return 'non_plain_array';
      if (Object.getOwnPropertySymbols(current).length > 0) return 'symbol_member';
      const keys = Object.keys(current);
      if (keys.length !== current.length
        || keys.some((key, index) => key !== String(index))) return 'sparse_or_extended_array';
      const descriptors = Object.getOwnPropertyDescriptors(current);
      const descriptorKeys = Object.keys(descriptors);
      if (descriptorKeys.length !== current.length + 1
        || !Object.hasOwn(descriptors, 'length')) return 'hidden_array_member';
      for (let index = 0; index < current.length; index += 1) {
        const descriptor = descriptors[index];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
          return 'accessor_or_hidden_member';
        }
        const issue = visit(descriptor.value, depth + 1);
        if (issue) return issue;
      }
      return null;
    }

    if (!isRecord(current)) return 'non_plain_object';
    if (Object.getOwnPropertySymbols(current).length > 0) return 'symbol_member';
    const descriptors = Object.getOwnPropertyDescriptors(current);
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return 'accessor_or_hidden_member';
      }
      if (!canonicalString(key)) return 'noncanonical_member_name';
      const issue = visit(descriptor.value, depth + 1);
      if (issue) return issue;
    }
    return null;
  }

  return visit(value, 0);
}

function strictBase64url(value, expectedLength) {
  if (typeof value !== 'string' || value.length === 0
    || !BASE64URL.test(value) || value.length % 4 === 1) return null;
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) return null;
  if (expectedLength !== undefined && bytes.length !== expectedLength) return null;
  return bytes;
}

function digestBytes(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function asBytes(value) {
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  return null;
}

function strictInstant(value) {
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
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function strictDate(value) {
  if (typeof value !== 'string') return false;
  const match = value.match(DATE);
  if (!match) return false;
  const [, year, month, day] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(0, 0, 0, 0);
  return calendar.toISOString().slice(0, 10) === value;
}

function normalizeNow(value) {
  if (value === undefined) return Date.now();
  if (typeof value === 'number') return Number.isFinite(value) ? value : NaN;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.getTime() : NaN;
  return strictInstant(value);
}

function canonicalCopy(value) {
  const issue = canonicalJsonIssue(value);
  if (issue) throw new TypeError(`value is outside the DAB canonical JSON profile: ${issue}`);
  return JSON.parse(canonicalize(value));
}

function sortedBy(items, key) {
  return [...items].sort((left, right) => {
    const leftKey = key(left);
    const rightKey = key(right);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}

function partySortKey(party) {
  return `${party.role}\0${party.party_id}`;
}

function isCanonicallySorted(items, key) {
  for (let index = 1; index < items.length; index += 1) {
    if (key(items[index - 1]) >= key(items[index])) return false;
  }
  return true;
}

function validateTerm(term) {
  if (!isRecord(term)
    || typeof term.term_id !== 'string'
    || !VOCABULARY.test(term.term_id)
    || !DOCUMENT_ACTION_MATERIAL_TERM_TYPES.includes(term.type)) return false;
  if (MINOR_AMOUNT_FIELD.test(term.term_id)
    || (AMOUNT_FIELD.test(term.term_id) && term.type !== 'amount')) return false;
  const amount = term.type === 'amount';
  const allowed = amount
    ? new Set(['term_id', 'type', 'value', 'currency'])
    : new Set(['term_id', 'type', 'value']);
  if (!exactKeys(term, allowed)) return false;
  if (amount) return typeof term.value === 'string'
    && AMOUNT.test(term.value)
    && typeof term.currency === 'string'
    && CURRENCY.test(term.currency);
  if (term.type === 'decimal') return typeof term.value === 'string' && DECIMAL.test(term.value);
  if (term.type === 'integer') return Number.isSafeInteger(term.value);
  if (term.type === 'boolean') return typeof term.value === 'boolean';
  if (term.type === 'date') return strictDate(term.value);
  if (term.type === 'timestamp') return Number.isFinite(strictInstant(term.value));
  if (term.type === 'digest') return typeof term.value === 'string' && SHA256.test(term.value);
  if (term.type === 'identifier') return typeof term.value === 'string' && IDENTIFIER.test(term.value);
  return typeof term.value === 'string' && term.value.length > 0;
}

function validateMaterialTerms(terms) {
  if (!Array.isArray(terms) || terms.length === 0 || terms.length > MAX_TERMS) {
    return { ok: false, reason: 'invalid_material_terms' };
  }
  if (!terms.every(validateTerm)) return { ok: false, reason: 'invalid_material_terms' };
  const ids = terms.map((term) => term.term_id);
  if (new Set(ids).size !== ids.length) return { ok: false, reason: 'duplicate_material_term' };
  if (!isCanonicallySorted(terms, (term) => term.term_id)) {
    return { ok: false, reason: 'noncanonical_material_term_order' };
  }
  return { ok: true };
}

function amountFieldsValid(value) {
  if (Array.isArray(value)) return value.every(amountFieldsValid);
  if (!isRecord(value)) return true;
  for (const [key, child] of Object.entries(value)) {
    if (MINOR_AMOUNT_FIELD.test(key)) return false;
    if (AMOUNT_FIELD.test(key)
      && (typeof child !== 'string' || !AMOUNT.test(child))) return false;
    if (!amountFieldsValid(child)) return false;
  }
  if (value.type === 'amount' && (typeof value.value !== 'string' || !AMOUNT.test(value.value))) {
    return false;
  }
  return true;
}

function validateReleaseAction(releaseAction) {
  if (!exactKeys(releaseAction, new Set(['digest', 'template']))) {
    return { ok: false, reason: 'invalid_release_action' };
  }
  if (typeof releaseAction.digest !== 'string' || !SHA256.test(releaseAction.digest)
    || !isRecord(releaseAction.template)
    || typeof releaseAction.template.action_type !== 'string'
    || !VOCABULARY.test(releaseAction.template.action_type)
    || !amountFieldsValid(releaseAction.template)) {
    return { ok: false, reason: 'invalid_release_action' };
  }
  const computed = computeReleaseActionDigest(releaseAction.template);
  if (computed === null || computed !== releaseAction.digest) {
    return { ok: false, reason: 'action_digest_mismatch' };
  }
  return { ok: true, digest: computed };
}

function validatePartyArray(parties, label) {
  if (!Array.isArray(parties) || parties.length === 0 || parties.length > MAX_PARTIES) {
    return { ok: false, reason: `invalid_${label}` };
  }
  const pairKeys = [];
  const ids = [];
  for (const party of parties) {
    if (!exactKeys(party, new Set(['party_id', 'role']))
      || typeof party.party_id !== 'string' || !IDENTIFIER.test(party.party_id)
      || typeof party.role !== 'string' || !VOCABULARY.test(party.role)) {
      return { ok: false, reason: `invalid_${label}` };
    }
    pairKeys.push(`${party.party_id}\0${party.role}`);
    ids.push(party.party_id);
  }
  if (new Set(ids).size !== ids.length) return { ok: false, reason: 'duplicate_party_id' };
  if (new Set(pairKeys).size !== pairKeys.length) {
    return { ok: false, reason: 'duplicate_party_role_pair' };
  }
  if (!isCanonicallySorted(parties, partySortKey)) {
    return { ok: false, reason: `noncanonical_${label}_order` };
  }
  return { ok: true };
}

function validateValidity(validity, now) {
  if (!exactKeys(validity, new Set(['not_before', 'not_after']))) {
    return { ok: false, reason: 'invalid_validity_window' };
  }
  const notBefore = strictInstant(validity.not_before);
  const notAfter = strictInstant(validity.not_after);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || notBefore >= notAfter) {
    return { ok: false, reason: 'invalid_validity_window' };
  }
  if (!Number.isFinite(now)) return { ok: false, reason: 'invalid_evaluation_time' };
  if (now < notBefore) return { ok: false, reason: 'binding_not_yet_valid' };
  if (now > notAfter) return { ok: false, reason: 'binding_expired' };
  return { ok: true };
}

function bindingCore(binding) {
  if (!isRecord(binding)) return null;
  const core = {};
  for (const key of CORE_KEYS) {
    if (Object.hasOwn(binding, key)) core[key] = binding[key];
  }
  return core;
}

function signingBytes(core) {
  return Buffer.from(DOCUMENT_ACTION_BINDING_DOMAIN + canonicalize(core), 'utf8');
}

function validateCore(core, now) {
  if (!exactKeys(core, CORE_KEYS, CORE_REQUIRED)) return { ok: false, reason: 'malformed_binding' };
  if (core.profile !== DOCUMENT_ACTION_BINDING_VERSION) {
    return { ok: false, reason: 'unsupported_profile' };
  }
  if (typeof core.binding_id !== 'string' || !IDENTIFIER.test(core.binding_id)) {
    return { ok: false, reason: 'invalid_binding_id' };
  }
  if (typeof core.agreement_id !== 'string' || !IDENTIFIER.test(core.agreement_id)) {
    return { ok: false, reason: 'invalid_agreement_id' };
  }
  if (!exactKeys(core.mapping_issuer, new Set(['issuer_id', 'key_id']))
    || typeof core.mapping_issuer.issuer_id !== 'string'
    || !IDENTIFIER.test(core.mapping_issuer.issuer_id)
    || typeof core.mapping_issuer.key_id !== 'string'
    || !IDENTIFIER.test(core.mapping_issuer.key_id)) {
    return { ok: false, reason: 'invalid_mapping_issuer' };
  }
  if (!exactKeys(core.document, new Set(['digest', 'media_type', 'byte_length']))
    || typeof core.document.digest !== 'string' || !SHA256.test(core.document.digest)
    || typeof core.document.media_type !== 'string' || !MEDIA_TYPE.test(core.document.media_type)
    || !Number.isSafeInteger(core.document.byte_length) || core.document.byte_length < 0) {
    return { ok: false, reason: 'invalid_document' };
  }
  const terms = validateMaterialTerms(core.material_terms);
  if (!terms.ok) return terms;
  const action = validateReleaseAction(core.release_action);
  if (!action.ok) return action;
  const parties = validatePartyArray(core.parties, 'parties');
  if (!parties.ok) return parties;
  const required = validatePartyArray(core.required_parties, 'required_parties');
  if (!required.ok) return required;
  const declared = new Set(core.parties.map((party) => `${party.party_id}\0${party.role}`));
  if (!core.required_parties.every((party) => declared.has(`${party.party_id}\0${party.role}`))) {
    return { ok: false, reason: 'required_party_not_declared' };
  }
  const validity = validateValidity(core.validity, now);
  if (!validity.ok) return validity;
  if (Object.hasOwn(core, 'supersedes_digest')
    && (typeof core.supersedes_digest !== 'string' || !SHA256.test(core.supersedes_digest))) {
    return { ok: false, reason: 'invalid_supersedes_digest' };
  }
  return { ok: true };
}

function normalizedStringSet(value) {
  if (!Array.isArray(value) || value.length === 0
    || value.some((item) => typeof item !== 'string' || item.length === 0)) return null;
  return new Set(value);
}

function baseResult(reason = 'malformed_binding') {
  return {
    valid: false,
    reason,
    binding_id: null,
    agreement_id: null,
    supersedes_digest: null,
    binding_digest: null,
    document_digest: null,
    action_digest: null,
    required_parties: [],
  };
}

/**
 * SHA-256 over the final document bytes.
 *
 * @param {Uint8Array|ArrayBuffer} documentBytes
 * @returns {string|null}
 */
export function computeDocumentSha256(documentBytes) {
  try {
    const bytes = asBytes(documentBytes);
    return bytes === null ? null : digestBytes(bytes);
  } catch {
    return null;
  }
}

/**
 * SHA-256 over the canonical release action template.
 *
 * @param {object} template
 * @returns {string|null}
 */
export function computeReleaseActionDigest(template) {
  try {
    if (!isRecord(template) || canonicalJsonIssue(template) !== null || !amountFieldsValid(template)) {
      return null;
    }
    return digestBytes(Buffer.from(canonicalize(template), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Compute the domain-separated digest signed by the mapping issuer.
 *
 * @param {object} binding
 * @returns {string|null}
 */
export function computeDocumentActionBindingDigest(binding) {
  try {
    const core = bindingCore(binding);
    if (core === null || canonicalJsonIssue(core) !== null) return null;
    return digestBytes(signingBytes(core));
  } catch {
    return null;
  }
}

/**
 * Sign a DAB mapping. The signer hashes the supplied final document bytes; it
 * never accepts a presenter-supplied document digest. This function may throw
 * on issuer-side programming errors. verifyDocumentActionBinding never throws.
 *
 * @param {object} spec
 * @param {{issuer_id:string,key_id:string,privateKey:crypto.KeyObject|string|Buffer}} signer
 * @returns {object}
 */
export function signDocumentActionBinding(spec, signer) {
  if (!isRecord(spec) || !isRecord(signer)) throw new TypeError('DAB spec and signer are required');
  const documentBytes = asBytes(spec.document?.bytes);
  if (documentBytes === null) throw new TypeError('spec.document.bytes must be a Uint8Array or ArrayBuffer');

  const materialTerms = sortedBy(canonicalCopy(spec.material_terms), (term) => term.term_id);
  const parties = sortedBy(canonicalCopy(spec.parties), partySortKey);
  const requiredParties = sortedBy(canonicalCopy(spec.required_parties), partySortKey);
  const actionTemplate = canonicalCopy(spec.release_action_template);
  const core = {
    profile: DOCUMENT_ACTION_BINDING_VERSION,
    binding_id: spec.binding_id,
    agreement_id: spec.agreement_id,
    mapping_issuer: {
      issuer_id: signer.issuer_id,
      key_id: signer.key_id,
    },
    document: {
      digest: digestBytes(documentBytes),
      media_type: spec.document.media_type,
      byte_length: documentBytes.byteLength,
    },
    material_terms: materialTerms,
    release_action: {
      digest: computeReleaseActionDigest(actionTemplate),
      template: actionTemplate,
    },
    parties,
    required_parties: requiredParties,
    validity: canonicalCopy(spec.validity),
  };
  if (spec.supersedes_digest !== undefined) core.supersedes_digest = spec.supersedes_digest;

  const issue = canonicalJsonIssue(core);
  if (issue) throw new TypeError(`DAB is outside the canonical JSON profile: ${issue}`);
  const validated = validateCore(core, strictInstant(core.validity.not_before));
  if (!validated.ok) throw new TypeError(`invalid DAB spec: ${validated.reason}`);

  const privateKey = signer.privateKey instanceof crypto.KeyObject
    ? signer.privateKey
    : crypto.createPrivateKey(signer.privateKey);
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('DAB issuer key must be Ed25519');
  }
  const bytes = signingBytes(core);
  const bindingDigest = digestBytes(bytes);
  const signature = crypto.sign(null, bytes, privateKey);
  return {
    ...core,
    binding_digest: bindingDigest,
    issuer_signatures: [{
      algorithm: 'Ed25519',
      signature_b64u: signature.toString('base64url'),
    }],
  };
}

/**
 * Verify a DAB mapping under a relying-party-pinned issuer key.
 *
 * `valid:true` authenticates the mapping only. It never means that any listed
 * party accepted the document. The returned required_parties are inputs for a
 * separate acceptance/state engine.
 *
 * @param {unknown} binding
 * @param {object} [opts]
 * @returns {{
 *   valid:boolean,
 *   reason:string,
 *   binding_id:string|null,
 *   agreement_id:string|null,
 *   supersedes_digest:string|null,
 *   binding_digest:string|null,
 *   document_digest:string|null,
 *   action_digest:string|null,
 *   required_parties:Array<{party_id:string,role:string}>
 * }}
 */
export function verifyDocumentActionBinding(binding, opts = {}) {
  const result = baseResult();
  try {
    if (!isRecord(binding) || !exactKeys(binding, TOP_LEVEL_KEYS, TOP_LEVEL_REQUIRED)) {
      return { ...result, reason: 'malformed_binding' };
    }
    const issue = canonicalJsonIssue(binding);
    if (issue) return { ...result, reason: 'noncanonical_binding' };

    const now = normalizeNow(isRecord(opts) ? opts.now : undefined);
    const core = bindingCore(binding);
    const coreCheck = validateCore(core, now);
    if (!coreCheck.ok) return { ...result, reason: coreCheck.reason };

    const mediaTypes = normalizedStringSet(opts.allowedMediaTypes);
    const partyRoles = normalizedStringSet(opts.allowedPartyRoles);
    const actionTypes = normalizedStringSet(opts.allowedActionTypes);
    if (mediaTypes === null || partyRoles === null || actionTypes === null) {
      return { ...result, reason: 'vocabulary_not_pinned' };
    }
    if (!mediaTypes.has(core.document.media_type)) {
      return { ...result, reason: 'media_type_not_allowed' };
    }
    if (!core.parties.every((party) => partyRoles.has(party.role))) {
      return { ...result, reason: 'unknown_party_role' };
    }
    if (!actionTypes.has(core.release_action.template.action_type)) {
      return { ...result, reason: 'unknown_action_type' };
    }

    if (opts.requiredMaterialTermIds !== undefined) {
      const requiredTermIds = normalizedStringSet(opts.requiredMaterialTermIds);
      if (requiredTermIds === null) return { ...result, reason: 'invalid_required_material_terms' };
      const present = new Set(core.material_terms.map((term) => term.term_id));
      if ([...requiredTermIds].some((termId) => !present.has(termId))) {
        return { ...result, reason: 'required_material_term_missing' };
      }
    }

    const computedBindingDigest = digestBytes(signingBytes(core));
    if (binding.binding_digest !== computedBindingDigest) {
      return { ...result, reason: 'binding_digest_mismatch' };
    }

    if (!Array.isArray(binding.issuer_signatures) || binding.issuer_signatures.length === 0) {
      return { ...result, reason: 'issuer_signature_missing' };
    }
    if (binding.issuer_signatures.length !== 1) {
      return { ...result, reason: 'duplicate_issuer_signatures' };
    }
    const signature = binding.issuer_signatures[0];
    if (!exactKeys(signature, new Set(['algorithm', 'signature_b64u']))
      || signature.algorithm !== 'Ed25519') {
      return { ...result, reason: 'malformed_issuer_signature' };
    }
    const signatureBytes = strictBase64url(signature.signature_b64u, 64);
    if (signatureBytes === null) return { ...result, reason: 'malformed_issuer_signature' };

    const issuerKeys = isRecord(opts.issuerKeys) ? opts.issuerKeys : null;
    const keyId = core.mapping_issuer.key_id;
    const pin = issuerKeys && Object.hasOwn(issuerKeys, keyId) ? issuerKeys[keyId] : null;
    if (!exactKeys(pin, new Set(['issuer_id', 'public_key']))
      || pin.issuer_id !== core.mapping_issuer.issuer_id
      || typeof pin.public_key !== 'string') {
      return { ...result, reason: 'issuer_key_not_pinned' };
    }
    const publicKeyBytes = strictBase64url(pin.public_key);
    if (publicKeyBytes === null) return { ...result, reason: 'issuer_key_not_pinned' };

    let publicKey;
    try {
      publicKey = crypto.createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
      if (publicKey.asymmetricKeyType !== 'ed25519'
        || !publicKey.export({ format: 'der', type: 'spki' }).equals(publicKeyBytes)) {
        return { ...result, reason: 'issuer_key_not_pinned' };
      }
    } catch {
      return { ...result, reason: 'issuer_key_not_pinned' };
    }
    if (!crypto.verify(null, signingBytes(core), publicKey, signatureBytes)) {
      return { ...result, reason: 'issuer_signature_invalid' };
    }

    Object.assign(result, {
      binding_id: core.binding_id,
      agreement_id: core.agreement_id,
      supersedes_digest: Object.hasOwn(core, 'supersedes_digest')
        ? core.supersedes_digest
        : null,
      binding_digest: computedBindingDigest,
      document_digest: core.document.digest,
      action_digest: core.release_action.digest,
    });

    if (opts.expectedBindingId !== undefined && opts.expectedBindingId !== core.binding_id) {
      return { ...result, reason: 'binding_id_mismatch' };
    }
    if (opts.expectedAgreementId !== undefined && opts.expectedAgreementId !== core.agreement_id) {
      return { ...result, reason: 'agreement_id_mismatch' };
    }
    if (opts.documentBytes !== undefined) {
      const expectedBytes = asBytes(opts.documentBytes);
      const expectedDigest = expectedBytes === null ? null : digestBytes(expectedBytes);
      if (expectedDigest === null) return { ...result, reason: 'invalid_expected_document' };
      if (expectedDigest !== core.document.digest) {
        return { ...result, reason: 'document_digest_mismatch' };
      }
      if (expectedBytes.byteLength !== core.document.byte_length) {
        return { ...result, reason: 'document_byte_length_mismatch' };
      }
    }
    if (opts.documentMediaType !== undefined
      && opts.documentMediaType !== core.document.media_type) {
      return { ...result, reason: 'document_media_type_mismatch' };
    }
    if (opts.releaseActionTemplate !== undefined) {
      const expectedActionDigest = computeReleaseActionDigest(opts.releaseActionTemplate);
      if (expectedActionDigest === null) return { ...result, reason: 'invalid_expected_action' };
      if (expectedActionDigest !== core.release_action.digest) {
        return { ...result, reason: 'action_digest_mismatch' };
      }
    }
    if (opts.expectedRequiredParties !== undefined) {
      const expected = canonicalCopy(opts.expectedRequiredParties);
      const expectedCheck = validatePartyArray(expected, 'required_parties');
      if (!expectedCheck.ok) return { ...result, reason: 'invalid_expected_required_parties' };
      if (canonicalize(expected) !== canonicalize(core.required_parties)) {
        return { ...result, reason: 'required_party_roster_mismatch' };
      }
    }
    if (Object.hasOwn(opts, 'expectedSupersedesDigest')) {
      const expected = opts.expectedSupersedesDigest;
      const actual = Object.hasOwn(core, 'supersedes_digest') ? core.supersedes_digest : null;
      if (expected !== actual) return { ...result, reason: 'supersedes_digest_mismatch' };
    }

    return {
      valid: true,
      reason: 'valid',
      binding_id: core.binding_id,
      agreement_id: core.agreement_id,
      supersedes_digest: Object.hasOwn(core, 'supersedes_digest')
        ? core.supersedes_digest
        : null,
      binding_digest: computedBindingDigest,
      document_digest: core.document.digest,
      action_digest: core.release_action.digest,
      required_parties: canonicalCopy(core.required_parties),
    };
  } catch {
    return result;
  }
}

const documentActionBinding = {
  DOCUMENT_ACTION_BINDING_VERSION,
  DOCUMENT_ACTION_BINDING_DOMAIN,
  DOCUMENT_ACTION_MATERIAL_TERM_TYPES,
  computeDocumentSha256,
  computeReleaseActionDigest,
  computeDocumentActionBindingDigest,
  signDocumentActionBinding,
  verifyDocumentActionBinding,
};

export default documentActionBinding;
