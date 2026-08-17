// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Gate admission joining two independent evidence legs over one
// consequential action:
//
//   Leg A (memory/identity context): a signed MEMORY-PROJECTION-RECORD-v1,
//   verified by the existing ApertoMemory Trusted Context provider in its
//   own trust boundary (pinned adapter key; the provider never sees the
//   other leg and never decrypts .amem objects).
//
//   Leg B (delegated authorization): an ID-JAG-style identity assertion
//   whose issuer must be authorized for the subject's namespace under the
//   Domain-Authorized Issuer Trust Method of
//   draft-mcguinness-oauth-domain-authorized-issuer-00, verified in its own
//   trust boundary (pinned issuer keys plus the domain-published policy).
//
// The legs join ONLY by shared digests on the exact action: the CAID is
// computed over the action object, which itself names the projection-record
// digest (leg A join) and the resource plus on-behalf-of subject that the
// assertion must cover (leg B join). Neither verifier ingests the other's
// evidence; the Gate compares digests and admits the exact action at most
// once. An INDETERMINATE leg never admits.

import { createApertoMemoryContextProvider } from '../../packages/gate/apertomemory-context.js';
import { actionDigest } from '../../packages/verify/evidence-chain.js';
import {
  evaluateDomainAuthorizedIssuer,
  subjectAuthorityFromEmailClaims,
  verifyIdJagAssertion,
} from './dai-profile.mjs';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;

export function createApertoIdGateDaiAdmission({
  adapterKeys,
  adapterStatusCheckedAt,
  memoryLimits,
  issuerKeys,
  verificationTime,
  // Relying-party admission floor: a consequential action is only admitted
  // under an ENFORCE-mode DAI policy. Section 6.1 of the pinned draft is
  // explicit that monitor mode provides no protection, so a monitor-mode
  // "satisfied" outcome is recorded but does not clear this floor. This is a
  // local Gate policy on top of the Trust Method, not a DAI requirement.
  requireEnforceMode = true,
}) {
  const provider = createApertoMemoryContextProvider({
    adapterKeys,
    statusCheckedAt: adapterStatusCheckedAt,
  });
  const consumed = new Set();

  function decide(caid, state, reason, legs) {
    return Object.freeze({
      admitted: state === 'ADMITTED',
      state,
      reason,
      caid,
      verification_time: verificationTime,
      legs: Object.freeze(legs),
    });
  }

  /**
   * Admit exactly one execution of the exact action. `effect` runs only on
   * admission. Refusals and INDETERMINATE outcomes return a decision record
   * with a reason and never execute the effect.
   */
  async function admit({ action, memoryRecord, assertion, lookup }, effect) {
    if (!isPlainObject(action)
        || typeof action.resource !== 'string'
        || typeof action.on_behalf_of !== 'string'
        || !isPlainObject(action.context_binding)
        || !DIGEST.test(action.context_binding.projection_record_digest ?? '')) {
      return decide(null, 'REFUSED', 'action_malformed', {});
    }
    const caid = `sha256:${actionDigest(action)}`;

    // Leg A: memory/identity context, verified in its own boundary.
    const memory = provider.verifyProjection(memoryRecord, {
      verificationTime,
      maxSignerStatusAgeSec: memoryLimits.maxSignerStatusAgeSec,
      maxProjectionAgeSec: memoryLimits.maxProjectionAgeSec,
      maxTrustAgeSec: memoryLimits.maxTrustAgeSec,
    });
    const memoryClaims = memory.state === 'VERIFIED' && memory.claims ? memory.claims : null;
    const memoryLeg = {
      state: memory.state,
      reason: memory.reason ?? null,
      projection_record_digest: memoryClaims ? memoryClaims.projection_record_digest : null,
      projection_digest: memoryClaims ? memoryClaims.projection_digest : null,
    };
    if (memory.state === 'INDETERMINATE') {
      // The leg cannot be evaluated. INDETERMINATE never authorizes; it is
      // also not upgraded to a tamper claim.
      return decide(caid, 'INDETERMINATE',
        `memory_leg_indeterminate:${memory.reason}`, { memory: memoryLeg });
    }
    if (!memoryClaims) {
      return decide(caid, 'REFUSED',
        `memory_leg_not_verified:${memory.reason}`, { memory: memoryLeg });
    }
    // Join A: the verified record must be the exact context the action was
    // prepared under. Digest comparison only; the Gate re-derives nothing
    // from inside the record.
    if (memoryClaims.projection_record_digest
        !== action.context_binding.projection_record_digest) {
      return decide(caid, 'REFUSED', 'memory_context_join_mismatch', { memory: memoryLeg });
    }

    // Leg B: assertion verification in its own boundary (pinned issuer
    // keys), then the DAI Trust Method over the domain-published policy.
    const verified = verifyIdJagAssertion(assertion, { issuerKeys, evaluationTime: verificationTime });
    if (!verified.valid) {
      return decide(caid, 'REFUSED', `dai_${verified.reason}`, { memory: memoryLeg });
    }
    const claims = verified.claims;
    const daiLegBase = {
      assertion_digest: verified.digest,
      issuer: claims.iss,
      subject: claims.email ?? claims.sub,
    };
    // Join B: the assertion must cover the exact action's resource and
    // subject. An assertion minted for another audience or user is refused
    // even though it verifies on its own.
    if (claims.aud !== action.resource) {
      return decide(caid, 'REFUSED', 'dai_assertion_audience_mismatch',
        { memory: memoryLeg, dai: Object.freeze(daiLegBase) });
    }
    if (claims.email !== action.on_behalf_of) {
      return decide(caid, 'REFUSED', 'dai_assertion_subject_mismatch',
        { memory: memoryLeg, dai: Object.freeze(daiLegBase) });
    }
    const subjectAuthority = subjectAuthorityFromEmailClaims(claims);
    const dai = evaluateDomainAuthorizedIssuer({
      claims,
      subjectAuthority,
      subjectIdentifierFormat: 'email',
      lookup,
      evaluationTime: verificationTime,
    });
    const daiLeg = Object.freeze({
      ...daiLegBase,
      subject_authority: subjectAuthority,
      trust_method: 'domain_authorized_issuer',
      satisfied: dai.satisfied,
      mode: dai.mode,
      matched: dai.matched,
      outcome: dai.outcome,
      monitor_log: dai.monitor_log,
    });
    if (!dai.satisfied) {
      return decide(caid, 'REFUSED', `dai_${dai.reason}`, { memory: memoryLeg, dai: daiLeg });
    }
    if (requireEnforceMode && dai.mode !== 'enforce') {
      return decide(caid, 'REFUSED', 'dai_monitor_mode_below_admission_floor',
        { memory: memoryLeg, dai: daiLeg });
    }

    // Single use: the exact action admits at most once in this consumption
    // domain (process-local here; see README for the production caveat).
    if (consumed.has(caid)) {
      return decide(caid, 'REFUSED', 'replay_refused', { memory: memoryLeg, dai: daiLeg });
    }
    consumed.add(caid);

    const decision = decide(caid, 'ADMITTED', null, { memory: memoryLeg, dai: daiLeg });
    if (typeof effect === 'function') await effect(decision);
    return decision;
  }

  return Object.freeze({ admit });
}

export default Object.freeze({ createApertoIdGateDaiAdmission });
