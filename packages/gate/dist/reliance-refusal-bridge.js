// SPDX-License-Identifier: Apache-2.0
/**
 * Reliance refusal bridge.
 *
 * `createRelianceKernel` denies with an unsigned `application/problem+json`
 * challenge. `EP-ACTION-REFUSAL-STATEMENT-v1` is a signed, offline-verifiable
 * statement of that same refusal. Before this module the two were never
 * connected: `signActionRefusalStatement` had no caller outside its own test,
 * so a running Gate produced no signed artifact when it said no.
 *
 * This module is the adapter. It maps one closed reliance verdict onto the
 * refusal statement's closed `refusal_class` and semantic axes, and signs it.
 *
 * What this module does NOT do, deliberately:
 *   - It does not decide. It reports a decision the kernel already made.
 *   - It never emits a statement for an ALLOW. The statement format requires
 *     at least one failed requirement and rejects `satisfaction: SATISFIED`.
 *   - It does not invent evidence. Evidence and challenge digests are supplied
 *     by the caller, which is the only party that saw the artifacts.
 *
 * Claim boundary: a signed refusal proves the relying party refused this exact
 * action under this exact program. It is not a legal or benefit determination,
 * and it is not proof that the action did not occur by some other path.
 */
import { signActionRefusalStatement, ACTION_REFUSAL_CLAIM_BOUNDARY } from './action-refusal-statement.js';
/**
 * Closed mapping from a reliance verdict to the refusal statement's closed
 * class plus the semantic axes that `validSemantics` requires for that class.
 *
 * `satisfaction` is never `SATISFIED` in any row: a refusal statement that
 * claimed satisfaction would be self-contradictory and the validator rejects it.
 */
const VERDICT_MAP = Object.freeze({
    // Signature or issuer trust failed outright.
    do_not_rely_unsigned: {
        refusal_class: 'verification_failed',
        semantics: { verification: 'NOT_VERIFIED', match: 'INDETERMINATE', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_EVALUATED' },
    },
    do_not_rely_untrusted_issuer: {
        refusal_class: 'verification_failed',
        semantics: { verification: 'NOT_VERIFIED', match: 'INDETERMINATE', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_EVALUATED' },
    },
    // Verified evidence that does not describe this exact action.
    do_not_rely_scope_mismatch: {
        refusal_class: 'authorization_refused',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    do_not_rely_policy_mismatch: {
        refusal_class: 'authorization_refused',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    do_not_rely_amount_exceeded: {
        refusal_class: 'authorization_refused',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    // Evidence verified and matched, but the required set was not satisfied.
    do_not_rely_no_profile: {
        refusal_class: 'indeterminate',
        semantics: { verification: 'INDETERMINATE', match: 'INDETERMINATE', satisfaction: 'INDETERMINATE', authorization: 'INDETERMINATE' },
    },
    do_not_rely_no_class_a: {
        refusal_class: 'evidence_unsatisfied',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_EVALUATED' },
    },
    do_not_rely_quorum_unsatisfied: {
        refusal_class: 'evidence_unsatisfied',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_EVALUATED' },
    },
    // The authority behind the approval failed, so authorization is refused.
    do_not_rely_authority_missing: {
        refusal_class: 'authorization_refused',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    do_not_rely_authority_revoked: {
        refusal_class: 'authorization_refused',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    do_not_rely_authority_subject_mismatch: {
        refusal_class: 'authorization_refused',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    do_not_rely_authority_organization_mismatch: {
        refusal_class: 'authorization_refused',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    // Already spent.
    do_not_rely_already_consumed: {
        refusal_class: 'replay_detected',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    // Time bound passed.
    do_not_rely_authority_expired: {
        refusal_class: 'expired',
        semantics: { verification: 'VERIFIED', match: 'MATCH', satisfaction: 'NOT_SATISFIED', authorization: 'NOT_AUTHORIZED' },
    },
    // Could not be determined. These are the fail-closed rows: the relying party
    // could not establish current status, so it refuses rather than guessing.
    do_not_rely_registry_unavailable: {
        refusal_class: 'indeterminate',
        semantics: { verification: 'VERIFIED', match: 'INDETERMINATE', satisfaction: 'INDETERMINATE', authorization: 'INDETERMINATE' },
    },
    do_not_rely_stale_revocation: {
        refusal_class: 'indeterminate',
        semantics: { verification: 'VERIFIED', match: 'INDETERMINATE', satisfaction: 'INDETERMINATE', authorization: 'INDETERMINATE' },
    },
});
/**
 * An unmapped non-`rely` verdict is refused as indeterminate rather than being
 * silently forced into a specific class. A new verdict must never quietly
 * acquire the semantics of an unrelated one.
 */
const UNMAPPED = Object.freeze({
    refusal_class: 'indeterminate',
    semantics: Object.freeze({
        verification: 'INDETERMINATE', match: 'INDETERMINATE', satisfaction: 'INDETERMINATE', authorization: 'INDETERMINATE',
    }),
});
/** Closed mapping of a reliance verdict. Exported for tests and for callers that want to inspect coverage. */
export function relianceRefusalClass(verdict) {
    const hit = Object.hasOwn(VERDICT_MAP, verdict) ? VERDICT_MAP[verdict] : null;
    if (!hit)
        return { refusal_class: UNMAPPED.refusal_class, semantics: { ...UNMAPPED.semantics }, mapped: false };
    return { refusal_class: hit.refusal_class, semantics: { ...hit.semantics }, mapped: true };
}
/**
 * Build and sign an `EP-ACTION-REFUSAL-STATEMENT-v1` for a reliance refusal.
 *
 * Throws when the verdict is an allow, because a refusal statement asserting a
 * satisfied requirement set is a contradiction the format refuses to carry.
 */
export function signRelianceRefusal(context, signer) {
    const verdict = context?.decision?.verdict;
    if (typeof verdict !== 'string' || verdict.length === 0) {
        throw new TypeError('reliance refusal requires a verdict');
    }
    if (verdict === 'rely' || context?.decision?.allow === true) {
        throw new TypeError('reliance refusal cannot be signed for an allow verdict');
    }
    const { refusal_class, semantics } = relianceRefusalClass(verdict);
    if (!Array.isArray(context.failed_requirement_ids) || context.failed_requirement_ids.length === 0) {
        throw new TypeError('reliance refusal requires explicit failed requirement ids');
    }
    const input = {
        refusal_id: context.refusal_id,
        relying_party_id: context.relying_party_id,
        caid: context.caid,
        action_digest: context.action_digest,
        program: {
            program_id: context.program.program_id,
            version: context.program.version,
            source_digest: context.program.source_digest,
            program_digest: context.program.program_digest,
        },
        failed_requirement_ids: context.failed_requirement_ids,
        evidence_digests: context.evidence_digests ?? [],
        nonce: context.nonce,
        refused_at: context.refused_at,
        expires_at: context.expires_at,
        refusal_class,
        semantics,
        claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
    };
    // Exactly one of challenge_digest / challenge_digests, per the format.
    if (context.challenge_digests !== undefined)
        input.challenge_digests = context.challenge_digests;
    else
        input.challenge_digest = context.challenge_digest;
    if (context.delivery !== undefined)
        input.delivery = context.delivery;
    if (context.custody !== undefined)
        input.custody = context.custody;
    if (context.transparency_anchor !== undefined)
        input.transparency_anchor = context.transparency_anchor;
    return signActionRefusalStatement(input, signer);
}
/** The verdicts this bridge maps explicitly. Anything else refuses as indeterminate. */
export const MAPPED_RELIANCE_VERDICTS = Object.freeze(Object.keys(VERDICT_MAP));
//# sourceMappingURL=reliance-refusal-bridge.js.map