// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-KERNEL-v1 — runtime enforcement wrapper.
 *
 * The pure verdict lives in @emilia-protocol/verify/reliance (evaluateReliance).
 * This is the deny-by-default RUNTIME point a relying party puts in front of a
 * consequential action: it evaluates the evidence packet against the relying
 * party's pinned EP-RELIANCE-PROFILE-v1, appends the decision to a tamper-evident
 * evidence log, and — on anything other than `rely` — returns a machine-readable
 * refusal (HTTP 428, the same Receipt-Required status the Gate uses) naming the
 * closed verdict and what evidence was required.
 *
 * ALLOW iff verdict === 'rely'. Every other closed verdict, a thrown verifier,
 * or a strict evidence-log failure denies. The kernel never re-derives a verdict
 * of its own — it enforces the one the pure offline verifier computed.
 */
import { createEvidenceLog } from './evidence.js';
import { actionRefusalStatementDigest, } from './action-refusal-statement.js';
import { signRelianceRefusal, } from './reliance-refusal-bridge.js';
import { evaluateReliance, RELIANCE_PROFILE_VERSION, RELIANCE_VERDICTS, } from '@emilia-protocol/verify/reliance';
const RECEIPT_REQUIRED_STATUS = 428;
export { RELIANCE_VERDICTS, RELIANCE_PROFILE_VERSION };
/** Build the 428 refusal for a non-`rely` verdict. */
function relianceChallenge(verdict, reasons, profile) {
    return {
        status: RECEIPT_REQUIRED_STATUS,
        error: 'do_not_rely',
        verdict,
        reasons: Array.isArray(reasons) ? reasons : [],
        required_assurance: profile?.required_assurance ?? null,
        required_authority: profile?.required_authority === true,
        required_evidence: Array.isArray(profile?.required_evidence) ? profile.required_evidence : [],
        header: { name: 'Reliance-Refused', value: verdict },
    };
}
/**
 * Create a reliance kernel bound to one relying-party profile.
 *
 * @param {object} [cfg]
 * @param {object} [cfg.profile]      the pinned EP-RELIANCE-PROFILE-v1
 * @param {object} [cfg.log]          an evidence log (createEvidenceLog); one is created if absent
 * @param {boolean} [cfg.strictEvidence=true]  fail closed if the evidence log sink fails
 * @returns {{ check: Function, evidence: object }}
 */
export function createRelianceKernel({ profile, log, strictEvidence = true, refusal, } = {}) {
    const evidence = log || createEvidenceLog({ strict: strictEvidence });
    if (refusal !== undefined
        && (typeof refusal !== 'object' || typeof refusal.context !== 'function'
            || typeof refusal.signer !== 'object' || refusal.signer === null)) {
        throw new TypeError('reliance refusal runtime requires signer and context');
    }
    /**
     * Evaluate + enforce one evidence packet.
     * @param {object} input  the evaluateReliance input MINUS relying_party_profile (bound here)
     * @param {object} [opts] verifier options { approverKeys, logPublicKey, rpId, revokerKeys }
     * @returns {Promise<{ allow:boolean, status:number, verdict:string, reasons:string[], checks:object, challenge:(object|null), decision:object }>}
     */
    async function check(input = {}, opts = {}) {
        let result;
        try {
            result = evaluateReliance({ ...input, relying_party_profile: profile }, opts);
        }
        catch (err) {
            // A thrown verifier is not a maybe — it is a refusal.
            result = { verdict: 'do_not_rely_unsigned', rely: false, reasons: [`verifier_error:${err?.message || 'threw'}`], checks: {} };
        }
        const allow = result.verdict === 'rely';
        const actionHash = input?.action?.action_hash ?? input?.receipt?.action_hash ?? null;
        // Deny-by-default: record the decision to the tamper-evident log first. In
        // strict mode a log-sink failure THROWS, which we convert to a refusal — an
        // action whose decision cannot be durably recorded must not proceed.
        let decision;
        try {
            decision = await evidence.record({
                type: 'reliance.decision',
                verdict: result.verdict,
                allow,
                action_hash: actionHash,
                reasons: result.reasons,
                checks: result.checks,
                profile: result.profile ?? null,
            });
        }
        catch (err) {
            return {
                allow: false,
                status: RECEIPT_REQUIRED_STATUS,
                verdict: 'do_not_rely_unsigned',
                reasons: [`evidence_log_failed:${err?.message || 'sink'}`],
                checks: result.checks || {},
                challenge: relianceChallenge('do_not_rely_unsigned', ['evidence_log_failed'], profile),
                decision: null,
            };
        }
        const challenge = allow ? null : relianceChallenge(result.verdict, result.reasons, profile);
        let refusalStatement = null;
        let refusalStatementDigest = null;
        let refusalStatementError = null;
        if (!allow && refusal && challenge) {
            try {
                const supplied = await refusal.context({
                    input,
                    options: opts,
                    profile,
                    result,
                    decision,
                    challenge,
                });
                refusalStatement = signRelianceRefusal({
                    ...supplied,
                    decision: { verdict: result.verdict, reasons: result.reasons, allow: false },
                }, refusal.signer);
                refusalStatementDigest = actionRefusalStatementDigest(refusalStatement);
                // A configured signed-refusal lane is governed evidence, not a response
                // decoration. Record the exact signed digest before exposing the artifact.
                await evidence.record({
                    type: 'reliance.refusal_statement',
                    verdict: result.verdict,
                    action_hash: actionHash,
                    refusal_digest: refusalStatementDigest,
                    refusal_id: refusalStatement.refusal_id,
                    relying_party_id: refusalStatement.relying_party_id,
                    program_digest: refusalStatement.program.program_digest,
                });
            }
            catch (err) {
                refusalStatement = null;
                refusalStatementDigest = null;
                refusalStatementError = `signed_refusal_unavailable:${err?.message || 'failed'}`;
            }
        }
        const responseChallenge = challenge === null ? null : {
            ...challenge,
            refusal_statement: refusalStatement,
            refusal_statement_digest: refusalStatementDigest,
            refusal_statement_error: refusalStatementError,
        };
        return {
            allow,
            status: allow ? 200 : RECEIPT_REQUIRED_STATUS,
            verdict: result.verdict,
            reasons: refusalStatementError === null
                ? result.reasons
                : [...result.reasons, refusalStatementError],
            checks: result.checks,
            challenge: responseChallenge,
            decision,
            refusal_statement: refusalStatement,
            refusal_statement_digest: refusalStatementDigest,
            refusal_statement_recorded: refusalStatement !== null,
        };
    }
    return { check, evidence };
}
const relianceKernelApi = { createRelianceKernel };
export default relianceKernelApi;
//# sourceMappingURL=reliance-kernel.js.map