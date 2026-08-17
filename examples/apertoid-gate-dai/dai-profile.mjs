// SPDX-License-Identifier: Apache-2.0
//
// Minimal verifier-side model of the Domain-Authorized Issuer (DAI) Trust
// Method from draft-mcguinness-oauth-domain-authorized-issuer-00
// ("OAuth Domain-Authorized Issuer Trust Method", K. McGuinness,
// 4 July 2026, expires 5 January 2027). The exact draft text this file was
// written against is pinned by SHA-256 in this example's README.
//
// Scope: this is a non-normative composition prototype, not a DAI
// implementation claim. It models the Issuer Authorization Policy document
// (Section 3), the Affirmative / Negative / Indeterminate lookup-state
// classification (Section 5.1), the verification procedure (Section 6),
// and monitor mode (Section 6.1). DNS TXT parsing, HTTPS retrieval,
// caching (Section 7), signed_policy processing, and the parent
// TRUST-FRAMEWORK document are all out of scope; lookup outcomes arrive as
// fixtures already classified by transport state.

import crypto from 'node:crypto';

export const DAI_DRAFT = Object.freeze({
  name: 'draft-mcguinness-oauth-domain-authorized-issuer',
  revision: '00',
  title: 'OAuth Domain-Authorized Issuer Trust Method',
  sha256: '2520dd24a6ed6c7936b32c0b2bba01af48ca95b486cad145a282f109d5b9606c',
});

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const VALID_FROM_SKEW_SEC = 300; // <= 5 minutes, Section 3 (valid_from only).

// Members this prototype recognizes AND implements processing for. Any
// `crit` entry outside this set makes the policy malformed (Section 3).
// `signed_policy` is deliberately absent: this prototype does not implement
// signed policy processing, so a policy that makes it critical must be
// treated as malformed rather than silently accepted unsigned.
const IMPLEMENTED_MEMBERS = new Set([
  'subject_authority',
  'authorized_issuers',
  'mode',
  'last_updated',
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isInstant(value) {
  return typeof value === 'string' && RFC3339.test(value) && Number.isFinite(Date.parse(value));
}

function isHttpsIssuerIdentifier(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  // Section 3: absolute HTTPS URL, no fragment. The raw string is what gets
  // compared octet-for-octet, so also refuse strings the URL parser altered
  // in ways that would hide a fragment.
  if (url.protocol !== 'https:') return false;
  if (value.includes('#')) return false;
  return true;
}

/**
 * Structural validation of an Issuer Authorization Policy document per the
 * Section 3 validation table. Returns { valid: true } or
 * { valid: false, reason }. A malformed policy is classified Indeterminate
 * by the lookup classifier (Section 5.1, "HTTPS document validation").
 *
 * Known limit, stated rather than hidden: this prototype receives parsed
 * JSON objects, so the Section 3 duplicate-member-name rejection (a
 * wire-parsing concern) is not exercised here.
 */
export function validateIssuerAuthorizationPolicy(policy) {
  if (!isPlainObject(policy)) return { valid: false, reason: 'policy_not_object' };
  if (typeof policy.subject_authority !== 'string' || policy.subject_authority.length === 0) {
    return { valid: false, reason: 'subject_authority_missing' };
  }
  // A-label form is ASCII by definition (Section 3).
  if (!/^[\x21-\x7e]+$/.test(policy.subject_authority)) {
    return { valid: false, reason: 'subject_authority_not_ascii' };
  }
  if (!Array.isArray(policy.authorized_issuers)) {
    return { valid: false, reason: 'authorized_issuers_missing' };
  }
  for (const entry of policy.authorized_issuers) {
    if (!isPlainObject(entry)) return { valid: false, reason: 'issuer_entry_not_object' };
    if (!isHttpsIssuerIdentifier(entry.issuer)) {
      return { valid: false, reason: 'issuer_identifier_malformed' };
    }
    if ('tenant' in entry && (typeof entry.tenant !== 'string' || entry.tenant.length === 0)) {
      return { valid: false, reason: 'tenant_malformed' };
    }
    if ('subject_identifier_formats' in entry) {
      const formats = entry.subject_identifier_formats;
      if (!Array.isArray(formats) || !formats.every((f) => typeof f === 'string' && f.length > 0)) {
        return { valid: false, reason: 'subject_identifier_formats_malformed' };
      }
    }
    for (const member of ['valid_from', 'valid_until']) {
      if (member in entry && !isInstant(entry[member])) {
        return { valid: false, reason: `${member}_malformed` };
      }
    }
  }
  if ('mode' in policy && policy.mode !== 'enforce' && policy.mode !== 'monitor') {
    // Section 3: any other mode string is malformed; an unrecognized future
    // mode MUST NOT be silently treated as either defined value.
    return { valid: false, reason: 'mode_malformed' };
  }
  if ('last_updated' in policy && !isInstant(policy.last_updated)) {
    return { valid: false, reason: 'last_updated_malformed' };
  }
  if ('crit' in policy) {
    const crit = policy.crit;
    if (!Array.isArray(crit) || crit.length === 0
        || !crit.every((m) => typeof m === 'string' && m.length > 0)) {
      return { valid: false, reason: 'crit_malformed' };
    }
    for (const member of crit) {
      if (!IMPLEMENTED_MEMBERS.has(member)) {
        return { valid: false, reason: `crit_member_not_implemented:${member}` };
      }
    }
  }
  return { valid: true };
}

/**
 * Classify a lookup outcome into the Section 5.1 states. The transport-level
 * state (what DNS/HTTPS returned) arrives as a fixture; this function adds
 * the document-validation downgrades that Section 5.1 assigns to
 * Indeterminate: a structurally malformed policy, and a subject_authority
 * that does not match the computed Subject Authority.
 */
export function classifyLookup(lookup, computedSubjectAuthority) {
  if (!isPlainObject(lookup) || typeof lookup.state !== 'string') {
    return Object.freeze({ state: 'indeterminate', detail: 'lookup_shape_invalid' });
  }
  if (lookup.state === 'negative') {
    return Object.freeze({ state: 'negative', detail: lookup.detail ?? null });
  }
  if (lookup.state !== 'affirmative') {
    return Object.freeze({ state: 'indeterminate', detail: lookup.detail ?? null });
  }
  const validation = validateIssuerAuthorizationPolicy(lookup.policy);
  if (!validation.valid) {
    return Object.freeze({ state: 'indeterminate', detail: `policy_malformed:${validation.reason}` });
  }
  if (lookup.policy.subject_authority !== computedSubjectAuthority) {
    return Object.freeze({ state: 'indeterminate', detail: 'subject_authority_mismatch' });
  }
  return Object.freeze({ state: 'affirmative', policy: lookup.policy });
}

/**
 * Subject Authority extraction for the `email` Subject Identifier format,
 * modeled minimally (the full extraction-procedure registry belongs to the
 * parent TRUST-FRAMEWORK document, which this prototype does not implement).
 * Appendix C extracts the authority from the top-level email claim with
 * email_verified=true.
 */
export function subjectAuthorityFromEmailClaims(claims) {
  if (!isPlainObject(claims)) return null;
  if (claims.email_verified !== true) return null;
  const email = claims.email;
  if (typeof email !== 'string') return null;
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return null;
  const domain = email.slice(at + 1);
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) return null;
  return domain;
}

function entryMatches(entry, claims, subjectIdentifierFormat, evaluationTimeMs) {
  // Section 6 step 4a: exact case-sensitive octet equality, no normalization.
  if (entry.issuer !== claims.iss) return false;
  // Step 4b: tenant binding.
  if ('tenant' in entry) {
    if (typeof claims.tenant !== 'string' || claims.tenant !== entry.tenant) return false;
  }
  // Step 4c: subject identifier format restriction.
  if ('subject_identifier_formats' in entry
      && !entry.subject_identifier_formats.includes(subjectIdentifierFormat)) {
    return false;
  }
  // Step 4d: validity window; skew tolerance on valid_from only (Section 3).
  if ('valid_from' in entry
      && evaluationTimeMs < Date.parse(entry.valid_from) - VALID_FROM_SKEW_SEC * 1000) {
    return false;
  }
  if ('valid_until' in entry && evaluationTimeMs >= Date.parse(entry.valid_until)) {
    return false;
  }
  return true;
}

/**
 * Section 6 verification, given a signature-verified assertion's claims, the
 * computed Subject Authority, and a fixture lookup outcome. Returns a frozen
 * result:
 *   { satisfied, mode, matched, outcome, reason, monitor_log }
 * Negative and Indeterminate lookups reject unconditionally (Section 5.1).
 * Under monitor mode a mismatch still satisfies the Trust Method and is
 * logged (Section 6.1); whether a relying party ADMITS on that is a
 * separate, stricter decision taken by the caller, not by this function.
 */
export function evaluateDomainAuthorizedIssuer({
  claims,
  subjectAuthority,
  subjectIdentifierFormat,
  lookup,
  evaluationTime,
}) {
  if (typeof subjectAuthority !== 'string' || subjectAuthority.length === 0) {
    // Section 6 step 1: unregistered/unextractable format rejects.
    return Object.freeze({
      satisfied: false, mode: null, matched: false,
      outcome: 'rejected', reason: 'subject_authority_unavailable', monitor_log: null,
    });
  }
  const evaluationTimeMs = Date.parse(evaluationTime);
  if (!Number.isFinite(evaluationTimeMs)) {
    return Object.freeze({
      satisfied: false, mode: null, matched: false,
      outcome: 'rejected', reason: 'evaluation_time_invalid', monitor_log: null,
    });
  }
  const classified = classifyLookup(lookup, subjectAuthority);
  if (classified.state !== 'affirmative') {
    // Section 5.1: consumers MUST treat both Negative and Indeterminate as
    // assertion rejection. Fail closed, with the reason carried.
    return Object.freeze({
      satisfied: false, mode: null, matched: false,
      outcome: 'rejected',
      reason: `lookup_${classified.state}${classified.detail ? `:${classified.detail}` : ''}`,
      monitor_log: null,
    });
  }
  const policy = classified.policy;
  const mode = policy.mode === 'monitor' ? 'monitor' : 'enforce';
  const matched = policy.authorized_issuers.some(
    (entry) => entryMatches(entry, claims, subjectIdentifierFormat, evaluationTimeMs),
  );
  if (mode === 'monitor') {
    // Section 6.1: evaluate normally, log the evaluation, never reject on
    // the basis of a mismatch. Monitor mode provides no protection.
    return Object.freeze({
      satisfied: true, mode, matched,
      outcome: matched ? 'satisfied' : 'satisfied_monitor_mismatch_logged',
      reason: null,
      monitor_log: Object.freeze({
        subject_authority: subjectAuthority,
        assertion_issuer: claims.iss,
        matched,
        evaluated_at: evaluationTime,
      }),
    });
  }
  if (!matched) {
    return Object.freeze({
      satisfied: false, mode, matched: false,
      outcome: 'rejected', reason: 'no_authorized_issuer_entry_matches', monitor_log: null,
    });
  }
  return Object.freeze({
    satisfied: true, mode, matched: true,
    outcome: 'satisfied', reason: null, monitor_log: null,
  });
}

// ---------------------------------------------------------------------------
// ID-JAG-style identity assertion (the Delegation Artifact the DAI policy
// authorizes an issuer to mint). DAI itself does not define the assertion;
// Appendix C shows an ID-JAG with iss/aud/exp/iat/jti/sub/email/
// email_verified validated by the Resource Authorization Server before the
// Trust Method runs (C.4 step 1). This prototype models that pre-step with a
// compact Ed25519 JWS under issuer keys pinned by the relying party.
// ---------------------------------------------------------------------------

function b64uJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

export function signIdJagAssertion(claims, { privateKey, kid }) {
  const header = { alg: 'EdDSA', typ: 'oauth-id-jag+jwt', kid };
  const signingInput = `${b64uJson(header)}.${b64uJson(claims)}`;
  const signature = crypto
    .sign(null, Buffer.from(signingInput, 'utf8'), privateKey)
    .toString('base64url');
  return `${signingInput}.${signature}`;
}

export function assertionDigest(jws) {
  return `sha256:${crypto.createHash('sha256').update(jws, 'utf8').digest('hex')}`;
}

/**
 * Verify an ID-JAG-style assertion under relying-party-pinned issuer keys:
 * issuerKeys is { [issuer]: { [kid]: public_key_spki_b64u } }. The pinning
 * direction matters: the trust anchor is the verifier's own key table, never
 * material carried inside the assertion. Returns a frozen
 * { valid, reason, claims, digest } and never throws on hostile input.
 */
export function verifyIdJagAssertion(jws, { issuerKeys, evaluationTime }) {
  const refuse = (reason) => Object.freeze({ valid: false, reason, claims: null, digest: null });
  try {
    if (typeof jws !== 'string') return refuse('assertion_not_string');
    const parts = jws.split('.');
    if (parts.length !== 3) return refuse('assertion_not_compact_jws');
    const [encodedHeader, encodedClaims, encodedSignature] = parts;
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(encodedClaims, 'base64url').toString('utf8'));
    if (!isPlainObject(header) || !isPlainObject(claims)) return refuse('assertion_malformed');
    if (header.alg !== 'EdDSA' || typeof header.kid !== 'string') {
      return refuse('assertion_header_unsupported');
    }
    if (typeof claims.iss !== 'string' || typeof claims.aud !== 'string'
        || typeof claims.jti !== 'string' || typeof claims.sub !== 'string'
        || !Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat)) {
      return refuse('assertion_claims_malformed');
    }
    const issuerTable = isPlainObject(issuerKeys) ? issuerKeys[claims.iss] : null;
    const spki = isPlainObject(issuerTable) ? issuerTable[header.kid] : null;
    if (typeof spki !== 'string') return refuse('assertion_issuer_key_not_pinned');
    const key = crypto.createPublicKey({
      key: Buffer.from(spki, 'base64url'),
      type: 'spki',
      format: 'der',
    });
    const valid = crypto.verify(
      null,
      Buffer.from(`${encodedHeader}.${encodedClaims}`, 'utf8'),
      key,
      Buffer.from(encodedSignature, 'base64url'),
    );
    if (!valid) return refuse('assertion_signature_invalid');
    const nowSec = Date.parse(evaluationTime) / 1000;
    if (!Number.isFinite(nowSec)) return refuse('evaluation_time_invalid');
    if (nowSec >= claims.exp) return refuse('assertion_expired');
    if (claims.iat > nowSec + VALID_FROM_SKEW_SEC) return refuse('assertion_from_future');
    return Object.freeze({ valid: true, reason: null, claims, digest: assertionDigest(jws) });
  } catch {
    return refuse('assertion_unparseable');
  }
}

export default Object.freeze({
  DAI_DRAFT,
  validateIssuerAuthorizationPolicy,
  classifyLookup,
  subjectAuthorityFromEmailClaims,
  evaluateDomainAuthorizedIssuer,
  signIdJagAssertion,
  verifyIdJagAssertion,
  assertionDigest,
});
