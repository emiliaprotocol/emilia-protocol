// SPDX-License-Identifier: Apache-2.0
/**
 * Independent RSL-MEDIA-shaped clearance handoff.
 *
 * RSL-MEDIA 1.0 is a draft and explicitly says it MUST NOT be used for
 * production. This module does not parse or claim conformance with that draft.
 * It consumes a normalized result from a separate RSL-MEDIA evaluator and
 * demonstrates the adjacent clearance artifact: a signed standing grant plus a
 * fresh, exact-action human authorization receipt.
 */

export const RSL_MEDIA_NORMALIZED_VERSION = 'RSL-MEDIA-1.0-DRAFT-NORMALIZED-v1';
export const RSL_MEDIA_CLEARANCE_PROFILE = 'EP-RSL-MEDIA-CLEARANCE-REFERENCE-v1';

export const RSL_CLEARANCE_VERDICTS = Object.freeze({
  ELIGIBLE: 'eligible_for_clearance',
  DECLARATION_COVERS_GRANT: 'declaration_covers_grant',
  NO_DECLARATION: 'refuse_no_declaration',
  UNVERIFIED_SOURCE: 'refuse_unverified_source',
  INOPERATIVE: 'refuse_inoperative_declaration',
  CONFLICT: 'refuse_declaration_conflict',
  PROHIBITED: 'refuse_prohibited_use',
  MINOR: 'refuse_minor_identity_use',
  STALE: 'refuse_stale_declaration',
  UNSUPPORTED: 'refuse_unsupported_use',
  GRANT_MISMATCH: 'refuse_declaration_grant_mismatch',
});

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RFC3339_OFFSET =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function instant(value) {
  if (typeof value !== 'string') return Number.NaN;
  const match = value.match(RFC3339_OFFSET);
  if (!match) return Number.NaN;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) {
    return Number.NaN;
  }
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) {
    return Number.NaN;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function refuse(verdict, reason) {
  return { eligible: false, verdict, reason };
}

/**
 * Evaluate the normalized output of an external RSL-MEDIA processor.
 *
 * The `trusted_source`, `operative`, and `conflict_free` properties are inputs
 * from that processor under the relying party's trust policy. EMILIA does not
 * manufacture or silently widen them.
 */
export function assessRslMediaEvaluation(evaluation, { now } = {}) {
  if (!isObject(evaluation)) {
    return refuse(RSL_CLEARANCE_VERDICTS.NO_DECLARATION, 'no normalized declaration was supplied');
  }
  if (evaluation.profile !== RSL_MEDIA_NORMALIZED_VERSION
      || evaluation.trusted_source !== true
      || !SHA256.test(String(evaluation.source_document_digest ?? ''))) {
    return refuse(
      RSL_CLEARANCE_VERDICTS.UNVERIFIED_SOURCE,
      'the source was not accepted under the relying party trust policy',
    );
  }
  if (evaluation.operative !== true || evaluation.status !== 'active') {
    return refuse(
      RSL_CLEARANCE_VERDICTS.INOPERATIVE,
      'the declaration is absent, withdrawn, superseded, or otherwise inoperative',
    );
  }
  if (evaluation.conflict_free !== true) {
    return refuse(
      RSL_CLEARANCE_VERDICTS.CONFLICT,
      'the applicable declaration scope is unresolved because authoritative declarations conflict',
    );
  }
  if (evaluation.subject === 'identity' && evaluation.subject_is_minor === true) {
    return refuse(
      RSL_CLEARANCE_VERDICTS.MINOR,
      'the identity is a minor and no authorizing clearance may be produced',
    );
  }
  if (evaluation.usage_decision === 'prohibited') {
    return refuse(RSL_CLEARANCE_VERDICTS.PROHIBITED, 'the requested usage category is prohibited');
  }
  if (evaluation.usage_decision !== 'clearance_required'
      || evaluation.usage_token !== 'media:ai-generate') {
    return refuse(
      RSL_CLEARANCE_VERDICTS.UNSUPPORTED,
      'this reference profile handles identity generation that requires external clearance',
    );
  }

  const evaluatedAt = instant(now ?? evaluation.evaluated_at);
  const currentThrough = instant(evaluation.current_through);
  if (!Number.isFinite(evaluatedAt)
      || !Number.isFinite(currentThrough)
      || evaluatedAt > currentThrough) {
    return refuse(
      RSL_CLEARANCE_VERDICTS.STALE,
      'declaration currency was not established at the clearance decision time',
    );
  }
  if (!isNonEmptyString(evaluation.isrd)
      || evaluation.subject !== 'identity'
      || !isObject(evaluation.allowed_terms)) {
    return refuse(
      RSL_CLEARANCE_VERDICTS.INOPERATIVE,
      'the normalized declaration is missing an identity subject, ISRD, or clearance terms',
    );
  }
  return {
    eligible: true,
    verdict: RSL_CLEARANCE_VERDICTS.ELIGIBLE,
    reason: null,
  };
}

function includesExact(values, candidate) {
  return Array.isArray(values)
    && values.every(isNonEmptyString)
    && values.includes(candidate);
}

/**
 * Convert one eligible declaration plus one requested use into an exact,
 * signed-grant specification. The rights holder still signs the resulting
 * grant; the registry evaluation never authorizes by itself.
 */
export function buildRslMediaGrantSpec({
  evaluation,
  request,
  principal,
  grantId,
  issuedAt,
  expiresAt,
  now = issuedAt,
} = {}) {
  const assessment = assessRslMediaEvaluation(evaluation, { now });
  if (!assessment.eligible) {
    throw new Error(`${assessment.verdict}: ${assessment.reason}`);
  }
  if (!isObject(request)) throw new Error('request must be an object');
  if (!isNonEmptyString(principal) || !isNonEmptyString(grantId)) {
    throw new Error('principal and grantId are required');
  }
  if (!Number.isFinite(instant(issuedAt)) || !Number.isFinite(instant(expiresAt))) {
    throw new Error('issuedAt and expiresAt must be RFC 3339 instants with explicit offsets');
  }
  if (instant(issuedAt) >= instant(expiresAt)) {
    throw new Error('expiresAt must be later than issuedAt');
  }

  const terms = evaluation.allowed_terms;
  for (const [field, allowed] of [
    ['purpose', terms.purposes],
    ['media_type', terms.media_types],
    ['territory', terms.territories],
  ]) {
    if (!isNonEmptyString(request[field]) || !includesExact(allowed, request[field])) {
      throw new Error(`request ${field} is outside the declaration's clearance terms`);
    }
  }
  if (!isNonEmptyString(request.campaign_id)) throw new Error('request campaign_id is required');

  return {
    grant_id: grantId,
    principal,
    asset: `rsl-media:${evaluation.isrd}`,
    control_verb: evaluation.usage_token,
    constraints: {
      profile: RSL_MEDIA_CLEARANCE_PROFILE,
      isrd: evaluation.isrd,
      declaration_digest: evaluation.source_document_digest,
      usage_token: evaluation.usage_token,
      purpose: request.purpose,
      media_type: request.media_type,
      territory: request.territory,
      campaign_id: request.campaign_id,
    },
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
}

/** Construct the exact action that the human authorization receipt signs. */
export function buildRslMediaAction({
  evaluation,
  request,
  grantHash,
  initiator,
  policyId,
  requestedAt,
} = {}) {
  if (!isObject(evaluation) || !isObject(request)) throw new Error('evaluation and request are required');
  if (!SHA256.test(String(grantHash ?? ''))) throw new Error('grantHash must be sha256:<64 hex>');
  if (!SHA256.test(String(request.output_description_digest ?? ''))) {
    throw new Error('request output_description_digest must be sha256:<64 hex>');
  }
  if (!isNonEmptyString(initiator) || !isNonEmptyString(policyId)) {
    throw new Error('initiator and policyId are required');
  }
  return {
    ep_version: '1.0',
    action_type: 'media.identity.generate',
    asset: `rsl-media:${evaluation.isrd}`,
    control_verb: evaluation.usage_token,
    grant_hash: grantHash,
    initiator,
    policy_id: policyId,
    requested_at: requestedAt,
    rsl_media: {
      profile: RSL_MEDIA_CLEARANCE_PROFILE,
      isrd: evaluation.isrd,
      declaration_digest: evaluation.source_document_digest,
      usage_token: evaluation.usage_token,
      purpose: request.purpose,
      media_type: request.media_type,
      territory: request.territory,
      campaign_id: request.campaign_id,
      output_description_digest: request.output_description_digest,
    },
  };
}

/**
 * Profile-specific evaluator passed to verifyReceiptUnderGrant().
 *
 * It deliberately uses exact string equality. Any broader language, territory,
 * or purpose semantics belong in a future versioned profile with its own
 * vectors; this reference never guesses.
 */
export function rslMediaConstraintsCover(action, constraints) {
  if (!isObject(action) || !isObject(constraints) || !isObject(action.rsl_media)) return false;
  const material = action.rsl_media;
  if (constraints.profile !== RSL_MEDIA_CLEARANCE_PROFILE
      || material.profile !== RSL_MEDIA_CLEARANCE_PROFILE) return false;
  for (const field of [
    'isrd',
    'declaration_digest',
    'usage_token',
    'purpose',
    'media_type',
    'territory',
    'campaign_id',
  ]) {
    if (!isNonEmptyString(constraints[field]) || material[field] !== constraints[field]) return false;
  }
  return action.asset === `rsl-media:${constraints.isrd}`
    && action.control_verb === constraints.usage_token
    && SHA256.test(String(material.output_description_digest ?? ''));
}

/**
 * Re-check the current declaration view against the standing grant.
 *
 * A signed grant does not manufacture current RSL declaration state. The
 * executor supplies a fresh normalized evaluation and this join binds that
 * evaluation to the exact declaration digest and terms the grant names.
 */
export function rslMediaDeclarationCoversGrant(evaluation, grant, { now } = {}) {
  const assessment = assessRslMediaEvaluation(evaluation, { now });
  if (!assessment.eligible) {
    return { valid: false, verdict: assessment.verdict, reason: assessment.reason };
  }
  const constraints = grant?.constraints;
  if (!isObject(grant)
      || !isObject(constraints)
      || constraints.profile !== RSL_MEDIA_CLEARANCE_PROFILE
      || constraints.isrd !== evaluation.isrd
      || constraints.declaration_digest !== evaluation.source_document_digest
      || constraints.usage_token !== evaluation.usage_token
      || grant.asset !== `rsl-media:${evaluation.isrd}`
      || grant.control_verb !== evaluation.usage_token
      || !includesExact(evaluation.allowed_terms?.purposes, constraints.purpose)
      || !includesExact(evaluation.allowed_terms?.media_types, constraints.media_type)
      || !includesExact(evaluation.allowed_terms?.territories, constraints.territory)
      || !isNonEmptyString(constraints.campaign_id)) {
    return refuse(
      RSL_CLEARANCE_VERDICTS.GRANT_MISMATCH,
      'the current declaration view does not cover the signed grant',
    );
  }
  return {
    valid: true,
    eligible: true,
    verdict: RSL_CLEARANCE_VERDICTS.DECLARATION_COVERS_GRANT,
    reason: null,
  };
}
