// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
// Auditor / insurer-facing reliance packet for an EMILIA Gate decision.
import { CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION, claimAssuranceResultCandidate, validateClaimAssuranceAdmissibilityResult, } from './claim-assurance-result.js';
export const RELIANCE_PACKET_VERSION = 'EP-GATE-RELIANCE-PACKET-v1';
// The CLOSED admissibility verdict set (mirror of lib/evidence/admissibility.js
// ADMISSIBILITY_VERDICTS). The gate does NOT import that app module — it stays a
// dependency-light published package — so the closed set is restated here as a
// value contract. 'admissible' is the ONLY verdict that reads as success; every
// other member, and anything not in this set, fails closed. Precedence lives in
// the evaluator; the gate never re-derives a verdict, it only checks the one the
// relying party's offline evaluator already computed.
export const ADMISSIBILITY_VERDICTS = Object.freeze([
    'admissible', 'missing_evidence', 'stale', 'conflicted', 'unverifiable',
]);
/**
 * Normalize an admissibility block onto the packet. FAIL CLOSED: a missing block,
 * a missing/unrecognized verdict, or a non-'admissible' verdict all produce
 * admissible:false. The block is only carried when the caller supplies one; when
 * absent, `admissibility` is null and no admissibility gating applies (backwards
 * compatible with pre-profile packets).
 *
 * @param {object|null} adm  the relying-party evaluator's result, carrying
 *   { admissibility_profile:{id,version}, profile_hash, verdict, replay_digest, challenge_id?, challenge_digest? }
 */
function normalizeAdmissibility(adm) {
    if (!adm || typeof adm !== 'object')
        return null;
    const claimAssuranceCandidate = claimAssuranceResultCandidate(adm);
    const claimAssuranceValidation = claimAssuranceCandidate === null
        ? null
        : validateClaimAssuranceAdmissibilityResult(claimAssuranceCandidate);
    const isClaimAssurance = claimAssuranceValidation !== null;
    // Never inspect or carry fields from an invalid Claim Assurance object. The
    // validator's success value is the strict-cloned, deeply frozen snapshot.
    // This prevents a malformed/getter-backed object from becoming green during
    // normalization or mutating after the reliance verdict is computed.
    if (claimAssuranceValidation && !claimAssuranceValidation.ok) {
        return {
            block: null,
            is_claim_assurance: true,
            admissibility_profile: null,
            profile_hash: null,
            verdict: null,
            verdict_recognized: false,
            admissible: false,
            replay_digest: null,
            challenge_id: null,
            challenge_digest: null,
            assurance_record_digest: null,
            claim_case_digest: null,
            action_digest: null,
            claim_assurance_verdict: null,
            profile_satisfied: false,
            authorizes_action: null,
            as_of: null,
            evaluated_at: null,
            reasons: [],
            validation_error: claimAssuranceValidation.reason,
        };
    }
    const normalizedInput = claimAssuranceValidation?.block ?? adm;
    const verdict = typeof normalizedInput.verdict === 'string' ? normalizedInput.verdict : null;
    const recognized = verdict !== null && ADMISSIBILITY_VERDICTS.includes(verdict);
    // Only a recognized 'admissible' verdict reads as success. Missing, malformed,
    // or any other closed-set member (missing_evidence/stale/conflicted/unverifiable)
    // is non-admissible.
    // A Claim Assurance result is evidence only. Its explicit non-authority bit
    // is part of the bridge contract; a missing or changed value fails reliance
    // closed instead of letting a claim-shaped object masquerade as authority.
    const claimAssuranceBoundaryOk = !isClaimAssurance
        || (claimAssuranceValidation?.ok === true && normalizedInput.authorizes_action === false);
    const admissible = recognized && verdict === 'admissible' && claimAssuranceBoundaryOk;
    const profile = normalizedInput.admissibility_profile && typeof normalizedInput.admissibility_profile === 'object'
        ? { id: normalizedInput.admissibility_profile.id ?? null, version: normalizedInput.admissibility_profile.version ?? null }
        : null;
    const evaluation = {
        is_claim_assurance: isClaimAssurance,
        admissibility_profile: profile,
        profile_hash: typeof normalizedInput.profile_hash === 'string' ? normalizedInput.profile_hash : null,
        verdict: verdict, // preserved verbatim (including null / unrecognized) for the auditor
        verdict_recognized: recognized,
        admissible,
        replay_digest: typeof normalizedInput.replay_digest === 'string' ? normalizedInput.replay_digest : null,
        // The evidence-challenge loop (lib/negotiate/evidence-challenge.js) keys each
        // round by challenge_id; challenge_digest is carried through when the caller
        // hashes the challenge. Either identifies which challenge round this verdict
        // answers. Both null-safe.
        challenge_id: normalizedInput.challenge_id ?? null,
        challenge_digest: typeof normalizedInput.challenge_digest === 'string' ? normalizedInput.challenge_digest : null,
        ...(isClaimAssurance ? {
            assurance_record_digest: typeof normalizedInput.assurance_record_digest === 'string'
                ? normalizedInput.assurance_record_digest : null,
            claim_case_digest: typeof normalizedInput.claim_case_digest === 'string'
                ? normalizedInput.claim_case_digest : null,
            action_digest: typeof normalizedInput.action_digest === 'string' ? normalizedInput.action_digest : null,
            claim_assurance_verdict: typeof normalizedInput.claim_assurance_verdict === 'string'
                ? normalizedInput.claim_assurance_verdict : null,
            profile_satisfied: normalizedInput.profile_satisfied === true,
            authorizes_action: normalizedInput.authorizes_action === false ? false : null,
            as_of: typeof normalizedInput.as_of === 'string' ? normalizedInput.as_of : null,
            evaluated_at: typeof normalizedInput.evaluated_at === 'string' ? normalizedInput.evaluated_at : null,
            reasons: Array.isArray(normalizedInput.reasons)
                ? normalizedInput.reasons.filter((reason) => typeof reason === 'string')
                : [],
        } : {}),
    };
    return {
        ...evaluation,
        // A typed Claim Assurance result stays byte-for-byte within its closed
        // public schema. Derived packet-local fields live in
        // `admissibility_evaluation`; adding them to the typed block would make the
        // block impossible to validate or re-consume. Legacy untyped admissibility
        // blocks retain the enriched projection for backwards compatibility.
        block: isClaimAssurance
            ? normalizedInput
            : {
                admissibility_profile: evaluation.admissibility_profile,
                profile_hash: evaluation.profile_hash,
                verdict: evaluation.verdict,
                verdict_recognized: evaluation.verdict_recognized,
                admissible: evaluation.admissible,
                replay_digest: evaluation.replay_digest,
                challenge_id: evaluation.challenge_id,
                challenge_digest: evaluation.challenge_digest,
            },
    };
}
async function evidenceStatus(evidence) {
    if (!evidence) {
        return { ok: false, length: null, head: null, reason: 'evidence_verification_unavailable' };
    }
    try {
        const status = typeof evidence.verify === 'function'
            ? await evidence.verify()
            : await evidence;
        if (!status || typeof status !== 'object' || Array.isArray(status)) {
            return { ok: false, length: null, head: null, reason: 'evidence_verification_malformed' };
        }
        if (status.ok !== true) {
            return {
                ok: false,
                length: Number.isSafeInteger(status.length) ? status.length : null,
                head: typeof status.head === 'string' ? status.head : null,
                reason: status.reason || 'evidence_verification_rejected',
            };
        }
        return {
            ...status,
            ok: true,
            length: Number.isSafeInteger(status.length) ? status.length : null,
            head: typeof status.head === 'string' ? status.head : null,
        };
    }
    catch {
        return { ok: false, length: null, head: null, reason: 'evidence_verification_failed' };
    }
}
/**
 * Generic check-result builder. `detail` is an opaque payload — sometimes a
 * plain string reason, sometimes a structured object — carried through
 * verbatim for the auditor. Its real type varies per call site; annotate it
 * as `*` rather than over-constraining it to the `null` the default value
 * would otherwise narrow it to.
 * @param {string} id
 * @param {boolean|null} ok
 * @param {*} [detail]
 */
function check(id, ok, detail = null) {
    return { id, ok, ...(detail ? { detail } : {}) };
}
/**
 * @param {{ decision?: any, execution?: any, evidence?: any, manifest?: any, binding?: any, admissibility?: any, verifier?: string }} [o]
 */
export async function buildReliancePacket({ decision, execution = null, evidence = null, manifest = null, binding = null, admissibility = null, verifier = '@emilia-protocol/gate', } = {}) {
    const evidenceCheck = await evidenceStatus(evidence);
    const decisionHash = decision?.evidence?.hash || decision?.hash || null;
    const executionBound = Boolean(execution
        && execution.kind === 'execution'
        && decisionHash
        && execution.authorizes_decision === decisionHash);
    // Prefer the binding carried by the execution proof. Authorization-time
    // binding alone is not enough: an executor could otherwise attest a
    // different mutation and still receive a rely verdict.
    const bindingCheck = execution?.execution_binding
        || binding
        || decision?.evidence?.execution_binding
        || decision?.execution_binding
        || null;
    const allowed = decision?.allow === true;
    const evidenceOk = evidenceCheck.ok === true;
    const bindingOk = bindingCheck ? bindingCheck.ok === true : true;
    // Admissibility block (relying-party evaluator output, computed OFFLINE against
    // its PINNED profile — never re-derived here). When present it is an additional
    // gate on 'rely': a non-'admissible' verdict (or a missing/unrecognized one)
    // fails closed. When absent, admissibility does not affect the verdict.
    const adm = normalizeAdmissibility(admissibility);
    const admissibilityOk = adm === null ? true : adm.admissible === true;
    const verdict = allowed && executionBound && evidenceOk && bindingOk && admissibilityOk ? 'rely' : 'do_not_rely';
    return {
        '@version': RELIANCE_PACKET_VERSION,
        product: 'EMILIA Gate',
        verifier,
        verdict,
        summary: {
            action: decision?.action || null,
            receipt_id: decision?.evidence?.receipt_id || decision?.receipt_id || null,
            subject: decision?.evidence?.subject || null,
            policy_id: decision?.evidence?.evaluated_policy_id || null,
            policy_hash: decision?.evidence?.evaluated_policy_hash || null,
            tenant_id: decision?.evidence?.evaluated_tenant_id || null,
            approvers: decision?.evidence?.evaluated_approvers || [],
            required_tier: decision?.evidence?.required_tier || decision?.required_tier || null,
            observed_tier: decision?.evidence?.have_tier || decision?.have_tier || null,
            decision_hash: decisionHash,
            execution_hash: execution?.hash || null,
            evidence_head: evidenceCheck.head || null,
            // Surface the admissibility verdict + pinned profile in the summary so an
            // auditor sees WHICH bar was cleared without digging into checks. Null when
            // no admissibility block was supplied.
            admissibility_verdict: adm ? adm.verdict : null,
            admissibility_profile: adm ? adm.admissibility_profile : null,
            admissibility_profile_hash: adm ? adm.profile_hash : null,
        },
        // Full admissibility block (or null). A valid typed Claim Assurance result is
        // preserved exactly so it remains valid under its closed schema and can be
        // re-consumed by Gate. Invalid typed inputs are never echoed under that type.
        // Derived packet-local interpretation is carried separately below.
        admissibility: adm?.block ?? null,
        admissibility_evaluation: adm === null ? null : {
            contract: adm.is_claim_assurance
                ? CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION
                : 'legacy-untyped-admissibility',
            verdict_recognized: adm.verdict_recognized,
            admissible: adm.admissible,
            validation_error: adm.validation_error ?? null,
        },
        checks: [
            check('receipt_present_and_valid', allowed && !String(decision?.reason || '').startsWith('receipt_rejected'), decision?.reason || null),
            check('assurance_sufficient', allowed || decision?.reason !== 'assurance_too_low', decision?.reason === 'assurance_too_low' ? 'receipt tier below action requirement' : null),
            check('receipt_one_time_consumed', allowed || decision?.reason === 'replay_refused' ? decision?.reason !== 'replay_refused' : null),
            check('execution_fields_bound', bindingCheck ? bindingCheck.ok === true : null, bindingCheck ? { missing_observed_fields: bindingCheck.missing_observed_fields || [], mismatched_fields: bindingCheck.mismatched_fields || [] } : 'no material execution-field binding required by this action'),
            check('execution_attests_decision', executionBound, execution ? null : 'no execution record supplied'),
            check('evidence_log_intact', evidenceCheck.ok === true, evidenceCheck.reason || null),
            // Admissibility verdict against the relying party's PINNED profile. null when
            // no profile/verdict was supplied (this reliance did not gate on admissibility);
            // true only for a recognized 'admissible' verdict; false otherwise (fail closed).
            check('admissibility_verdict_admissible', adm === null ? null : adm.admissible === true, adm === null
                ? 'no admissibility profile / verdict supplied for this reliance'
                : { verdict: adm.verdict, verdict_recognized: adm.verdict_recognized, profile: adm.admissibility_profile, profile_hash: adm.profile_hash, replay_digest: adm.replay_digest }),
        ],
        manifest_version: manifest?.['@version'] || null,
        limitations: [
            'The packet proves the gate verified a receipt and enforced its configured policy; it does not prove the human made a wise decision.',
            'Identity, authority enrollment, and key custody remain external trust roots that must be operated correctly.',
            'For execution-field binding, observedAction must come from the system of record, not from attacker-controlled request input.',
            'An admissible verdict means the evidence bundle cleared the bar THIS relying party pinned; it does not establish the action is correct, safe, or currently valid beyond the freshness bounds evaluated. The verdict is computed OFFLINE by the relying party against its own pinned profile — EMILIA neither hosts the authoritative registry nor adjudicates.',
        ],
    };
}
export default { RELIANCE_PACKET_VERSION, ADMISSIBILITY_VERDICTS, buildReliancePacket };
//# sourceMappingURL=reliance-packet.js.map