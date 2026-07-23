// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-GAP-REPORT-v1 - the acceptance preflight.
 *
 * THE LAYER
 * ---------
 * The reliance kernel (reliance.js) answers "may this relying party rely on
 * this action?" with one closed verdict. This module answers the question the
 * relying party asks NEXT: if not, exactly which evidence is missing, why does
 * each piece matter, and what would close the gap. It is the diagnostic wrapper
 * that turns the kernel's refusal into an actionable, auditor-readable report
 * BEFORE money, dispensing, denial, appeal, audit, or execution depends on the
 * action.
 *
 * THE CONTRACT
 * ------------
 * buildRelianceGapReport(packet, profile, opts) consumes a de-identified action
 * packet ({ action, evidence, context }) and the relying party's own pinned
 * EP-RELIANCE-PROFILE-v1, runs the kernel, and emits ONE deterministic report:
 *   - kernel_verdict: exactly what evaluateReliance returned, never reinterpreted;
 *   - missing_evidence: each gap with a plain sentence for why it matters and
 *     a plain sentence for how to close it;
 *   - action_digest: JCS + sha256 of the action object;
 *   - profile: { id, digest } per the reliance-profile-registry hash convention;
 *   - control_mapping: every requirement mapped to plain control language
 *     (authority, identity, freshness, revocation, consumption, signoff,
 *     audit trail) so an auditor can read it with no EP knowledge;
 *   - limitations: a closed, always-present honest-boundary list;
 *   - reproduce: the exact offline CLI command and versions that rebuild it.
 *
 * PURE. OFFLINE. FAIL-CLOSED. DETERMINISTIC. No wall-clock reads: the
 * evaluation time comes ONLY from opts.now or packet.evaluated_at, and the
 * builder refuses with a reason when neither is supplied. Evidence artifacts
 * with no registered verifier are recorded as unverifiable presence and NEVER
 * count toward satisfaction. Keys are emitted sorted and arrays in a stable
 * order, so the same inputs reproduce the same report byte for byte.
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { evaluateReliance, RELIANCE_KERNEL_VERSION, RELIANCE_PROFILE_VERSION, } from './reliance.js';
import { PROFILE_REGISTRY_VERSION } from './reliance-profile-registry.js';
export const RELIANCE_GAP_REPORT_VERSION = 'EP-RELIANCE-GAP-REPORT-v1';
export const RELIANCE_GAP_MULTI_VERSION = 'EP-RELIANCE-GAP-MULTI-v1';
/** The evidence slots the reliance kernel consumes. Anything else is foreign. */
export const KERNEL_EVIDENCE_TYPES = Object.freeze([
    'receipt',
    'quorum',
    'authority_proof',
    'revocation_state',
    'consumption',
]);
/**
 * The honest closed limitations list. ALWAYS present in every report,
 * including a `rely`. A scope limit is substance, never a hedge.
 */
export const RELIANCE_GAP_LIMITATIONS = Object.freeze([
    'This report evaluates evidence sufficiency under the pinned profile, not business correctness.',
    'A rely verdict is not a guarantee; it is reproducible evidence the profile\'s checks passed.',
    'Artifact types with no registered verifier are counted as unverifiable presence, never as evidence.',
    'The kernel evaluates its checks in a fixed order and stops at the first failure; closing a reported gap can surface further gaps on re-evaluation.',
    'The evaluation time is supplied by the caller (opts.now or packet.evaluated_at); the verdict holds as of that instant and no other.',
]);
const ASSURANCE_PACKAGE_RELATION = 'This report is the per-action preflight; EP-ASSURANCE-PACKAGE-v1 bundles a population of such reliance decisions so an independent assurer can re-perform every verdict offline.';
const sha256hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const digestOf = (value) => `sha256:${sha256hex(Buffer.from(canonicalize(value), 'utf8'))}`;
/** Parse a caller-supplied evaluation time. NEVER falls back to the wall clock. */
function parseTimeMs(t) {
    if (typeof t === 'number' && Number.isFinite(t))
        return t;
    if (typeof t === 'string') {
        const ms = Date.parse(t);
        return Number.isNaN(ms) ? null : ms;
    }
    return null;
}
/** Deep key-sort so JSON.stringify of the report is byte-stable. Arrays keep their (already stable) order. */
function sortKeysDeep(value) {
    if (Array.isArray(value))
        return value.map(sortKeysDeep);
    if (value !== null && typeof value === 'object') {
        const out = {};
        for (const k of Object.keys(value).sort())
            out[k] = sortKeysDeep(value[k]);
        return out;
    }
    return value;
}
function refusal(reason) {
    return sortKeysDeep({
        '@type': RELIANCE_GAP_REPORT_VERSION,
        refused: true,
        refusal_reason: reason,
    });
}
/**
 * Classify one evidence artifact into a kernel slot, or mark it foreign.
 * An explicit envelope ({ type, artifact }) wins; otherwise the artifact's
 * shape decides, using the same detection rules as the verify CLI. Anything
 * unrecognized is foreign: recorded, never consumed (fail-closed).
 */
function classifyEvidenceItem(item) {
    if (item && typeof item === 'object' && typeof item.type === 'string' && 'artifact' in item) {
        const usable = KERNEL_EVIDENCE_TYPES.includes(item.type)
            && item.artifact !== null && typeof item.artifact === 'object';
        return { slot: usable ? item.type : null, artifact: item.artifact, declared: item.type };
    }
    const a = item;
    if (a === null || typeof a !== 'object')
        return { slot: null, artifact: a, declared: 'unknown' };
    if (a['@type'] === 'EP-AUTHORITY-PROOF-v1')
        return { slot: 'authority_proof', artifact: a, declared: 'authority_proof' };
    if (a['@type'] === 'ep.quorum' || (a.policy && Array.isArray(a.members) && typeof a.action_hash === 'string')) {
        return { slot: 'quorum', artifact: a, declared: 'quorum' };
    }
    if (Array.isArray(a.contexts) && Array.isArray(a.signoffs))
        return { slot: 'receipt', artifact: a, declared: 'receipt' };
    if (typeof a.consumed === 'boolean')
        return { slot: 'consumption', artifact: a, declared: 'consumption' };
    if (typeof a.checked_at === 'string' && a['@type'] === undefined) {
        return { slot: 'revocation_state', artifact: a, declared: 'revocation_state' };
    }
    const declared = typeof a['@type'] === 'string' ? a['@type']
        : typeof a.type === 'string' ? a.type : 'unknown';
    return { slot: null, artifact: a, declared };
}
// Gap catalog for a kernel refusal: one entry per closed verdict, each with a
// plain sentence for why it matters and a plain sentence for how to close it.
// Never invent verdicts; every key here is a member of RELIANCE_VERDICTS.
const VERDICT_GAPS = Object.freeze({
    do_not_rely_no_profile: {
        requirement: 'pinned_reliance_profile',
        why_it_matters: 'Without a pinned EP-RELIANCE-PROFILE-v1 there is no rule to evaluate the evidence against, so reliance is refused by default.',
        how_to_close: 'Pin a well-formed EP-RELIANCE-PROFILE-v1 (assurance floor, trusted keys, required evidence) and re-run the preflight.',
    },
    do_not_rely_unsigned: {
        requirement: 'receipt',
        why_it_matters: 'No cryptographically valid receipt binds named approvers to this exact action, so nothing ties the approval to what is being relied on.',
        how_to_close: 'Supply the authorization receipt for this action together with the approver keys and log key needed to verify it.',
    },
    do_not_rely_untrusted_issuer: {
        requirement: 'trusted_issuer',
        why_it_matters: 'The transparency checkpoint was signed by a key the relying party has not pinned, so the record could come from anyone.',
        how_to_close: 'Pin the issuing log key in the profile, or obtain a receipt checkpointed by an issuer the profile already pins.',
    },
    do_not_rely_no_class_a: {
        requirement: 'class_a_signoff',
        why_it_matters: 'The profile demands a device-bound (Class-A) human signoff and the receipt carries none, so the approval ceremony is below the pinned floor.',
        how_to_close: 'Have the approver sign with a registered Class-A device key and reissue the receipt.',
    },
    do_not_rely_quorum_unsatisfied: {
        requirement: 'quorum',
        why_it_matters: 'The profile demands a satisfied multi-party quorum bound to this action and none verifies, so the two-person rule is not met.',
        how_to_close: 'Collect the required quorum signoffs into an EP-QUORUM-v1 document bound to this action hash and add it to the packet.',
    },
    do_not_rely_authority_missing: {
        requirement: 'authority_proof',
        why_it_matters: 'No verifiable proof shows the approver held scoped authority for this action at approval time.',
        how_to_close: 'Attach an EP-AUTHORITY-PROOF-v1 for the approving subject, signed by a registry key the profile pins.',
    },
    do_not_rely_authority_subject_mismatch: {
        requirement: 'authority_proof',
        why_it_matters: 'The authority proof belongs to someone other than the person who actually approved this action.',
        how_to_close: 'Obtain an authority proof whose subject is the verified approver on this receipt.',
    },
    do_not_rely_authority_revoked: {
        requirement: 'authority_proof',
        why_it_matters: 'The authority behind this approval was revoked, so actions approved under it cannot be relied on.',
        how_to_close: 'Obtain a current, unrevoked authority grant and reissue the approval under it.',
    },
    do_not_rely_authority_expired: {
        requirement: 'authority_proof',
        why_it_matters: 'The authority is outside its validity window at the evaluation time, so the grant does not cover this moment.',
        how_to_close: 'Renew the authority grant, or evaluate within its validity window.',
    },
    do_not_rely_scope_mismatch: {
        requirement: 'authority_proof',
        why_it_matters: 'The approver\'s authority does not cover this action type, so the approval is out of scope.',
        how_to_close: 'Obtain an authority grant whose scope includes this exact action type.',
    },
    do_not_rely_amount_exceeded: {
        requirement: 'authority_proof',
        why_it_matters: 'The action amount exceeds the approver\'s authority ceiling, or is denominated in a currency the ceiling does not cover.',
        how_to_close: 'Route the action to an approver with a sufficient ceiling, or bring the amount under the existing limit.',
    },
    do_not_rely_policy_mismatch: {
        requirement: 'accepted_policy',
        why_it_matters: 'The action cites a policy hash the relying party has not accepted, so it was governed by a rule the relying party does not recognize.',
        how_to_close: 'Bind the action to a policy hash on the profile\'s accepted list, or update the profile pin if the policy is genuinely accepted.',
    },
    do_not_rely_stale_revocation: {
        requirement: 'revocation_freshness',
        why_it_matters: 'The most recent not-revoked check is older than the profile\'s freshness bound, so a revocation could have happened since.',
        how_to_close: 'Perform a fresh revocation check within the pinned bound and attach its attestation to the packet.',
    },
    do_not_rely_already_consumed: {
        requirement: 'unconsumed_authorization',
        why_it_matters: 'The authorization has already been consumed once, so relying on it again would permit a replay.',
        how_to_close: 'Obtain a new one-time authorization for this action instead of reusing the consumed one.',
    },
    do_not_rely_registry_unavailable: {
        requirement: 'authority_registry',
        why_it_matters: 'The authority registry evidence could not be relied on (unpinned key, stale epoch, or head mismatch), so authority cannot be established.',
        how_to_close: 'Pin the correct registry key in the profile and supply an authority proof from a fresh registry epoch.',
    },
});
// Gap catalog for a profile requirement with NO artifact present at all. These
// are enumerated statically so a single run lists every absent leg, even though
// the kernel itself stops at its first failure.
const PRESENCE_GAPS = Object.freeze({
    receipt: {
        requirement: 'receipt',
        why_it_matters: 'The packet carries no receipt, so there is no signed record binding named approvers to this exact action.',
        how_to_close: 'Add the authorization receipt for this action to the evidence array.',
    },
    quorum: {
        requirement: 'quorum',
        why_it_matters: 'The profile requires a multi-party quorum and the packet carries no quorum document.',
        how_to_close: 'Add the EP-QUORUM-v1 document whose action hash matches this action.',
    },
    authority_proof: {
        requirement: 'authority_proof',
        why_it_matters: 'The profile requires scoped authority and the packet carries no authority proof.',
        how_to_close: 'Add an EP-AUTHORITY-PROOF-v1 for the approving subject to the evidence array.',
    },
    revocation_freshness: {
        requirement: 'revocation_freshness',
        why_it_matters: 'The profile requires a fresh revocation check and the packet carries none.',
        how_to_close: 'Add a revocation freshness attestation whose checked_at falls inside the pinned bound.',
    },
    consumption_proof: {
        requirement: 'unconsumed_authorization',
        why_it_matters: 'The profile requires proof the authorization is unconsumed and the packet carries no consumption state.',
        how_to_close: 'Add the consumption state for this authorization showing it has not been consumed.',
    },
});
/**
 * Map the kernel's per-check outcomes onto plain control language an auditor
 * can read without EP knowledge. Statuses: satisfied, missing, not_required,
 * not_evaluated (the kernel stops at its first failure, so later checks may
 * honestly never run).
 */
function buildControlMapping(kernel) {
    const c = kernel.checks || {};
    if (kernel.verdict === 'do_not_rely_no_profile') {
        // Nothing was evaluated: there was no rule to evaluate under.
        return CONTROL_ROWS.map((row) => ({ ...row, status: 'not_evaluated' }));
    }
    const statusOf = {
        receipt: c.receipt === true ? 'satisfied' : 'missing',
        trusted_issuer: c.issuer === null ? 'not_evaluated' : c.issuer === true ? 'satisfied' : 'missing',
        assurance: c.assurance === null ? 'not_evaluated' : c.assurance === false ? 'missing' : 'satisfied',
        authority_proof: c.authority === null ? 'not_evaluated'
            : c.authority === 'not_required' ? 'not_required'
                : c.authority && c.authority.accepted === true ? 'satisfied' : 'missing',
        accepted_policy: c.policy === null ? 'not_evaluated'
            : c.policy === 'not_pinned' ? 'not_required'
                : c.policy === true ? 'satisfied' : 'missing',
        revocation_freshness: c.revocation === null ? 'not_evaluated'
            : c.revocation === 'not_required' ? 'not_required'
                : c.revocation === 'fresh' ? 'satisfied' : 'missing',
        not_revoked: kernel.verdict === 'do_not_rely_authority_revoked' ? 'missing'
            : kernel.verdict === 'rely' || c.revocation === 'fresh' || (c.authority && c.authority.accepted === true) ? 'satisfied'
                : 'not_evaluated',
        unconsumed_authorization: c.consumption === null ? 'not_evaluated'
            : c.consumption === 'not_required' ? 'not_required'
                : c.consumption === 'unconsumed' ? 'satisfied' : 'missing',
    };
    return CONTROL_ROWS.map((row) => ({ ...row, status: statusOf[row.requirement] }));
}
// Fixed row order (sorted by control then requirement) so the array is stable.
const CONTROL_ROWS = Object.freeze([
    { control: 'audit trail', requirement: 'trusted_issuer', description: 'The record is checkpointed in a transparency log whose key the relying party pinned, so it can be independently re-verified later.' },
    { control: 'authority', requirement: 'accepted_policy', description: 'The action was governed by a written policy the relying party accepts.' },
    { control: 'authority', requirement: 'authority_proof', description: 'The approving person held verifiable, scoped, unexpired authority for this exact action.' },
    { control: 'consumption', requirement: 'unconsumed_authorization', description: 'The authorization is one-time and has not already been used.' },
    { control: 'freshness', requirement: 'revocation_freshness', description: 'The not-revoked status was checked recently enough to meet the relying party\'s bound.' },
    { control: 'identity', requirement: 'receipt', description: 'Named approvers cryptographically signed this exact action under keys the relying party pinned.' },
    { control: 'revocation', requirement: 'not_revoked', description: 'No valid revocation statement cancels this authorization.' },
    { control: 'signoff', requirement: 'assurance', description: 'The approval ceremony meets the pinned floor: a signature, a device-bound human signoff, or a multi-party quorum.' },
]);
/** Resolve the pinned profile: a bare EP-RELIANCE-PROFILE-v1 or a signed registry entry (unwrapped, id taken from the entry). */
function resolveProfile(profile) {
    let pinned = profile;
    let id = null;
    if (pinned && typeof pinned === 'object' && pinned['@type'] === PROFILE_REGISTRY_VERSION
        && pinned.profile && typeof pinned.profile === 'object') {
        id = typeof pinned.profile_id === 'string' ? pinned.profile_id : null;
        pinned = pinned.profile;
    }
    if (id === null && pinned && typeof pinned === 'object' && typeof pinned.profile_id === 'string') {
        id = pinned.profile_id;
    }
    let digest = null;
    try {
        digest = digestOf(pinned);
    }
    catch {
        digest = null;
    }
    return { pinned, id, digest };
}
/**
 * Build one EP-RELIANCE-GAP-REPORT-v1 for a de-identified action packet under
 * a single pinned profile.
 *
 * @param {object} packet
 * @param {object} packet.action        the action object (digested with JCS + sha256)
 * @param {Array}  [packet.evidence]    artifacts: { type, artifact } envelopes or bare
 *                                      shape-detected artifacts; unknown types are
 *                                      recorded as unverifiable presence
 * @param {object} [packet.context]     verification material supplied by the relying
 *                                      party: { approver_keys, log_public_key, rp_id,
 *                                      revoker_keys }
 * @param {string} [packet.evaluated_at] RFC 3339 evaluation time (used when opts.now absent)
 * @param {object} profile              EP-RELIANCE-PROFILE-v1, or a signed
 *                                      EP-RELIANCE-PROFILE-REGISTRY-v1 entry (unwrapped)
 * @param {object} [opts]
 * @param {string|number} [opts.now]    evaluation time; overrides packet.evaluated_at
 * @param {string} [opts.packet_path]   path used verbatim in reproduce.command
 * @param {string} [opts.profile_path]  path used verbatim in reproduce.command
 * @returns {object} the report, or { refused: true, refusal_reason } on a
 *                   pre-evaluation refusal (no evaluation time, unusable packet)
 */
export function buildRelianceGapReport(packet, profile, opts = {}) {
    if (packet === null || typeof packet !== 'object' || Array.isArray(packet)) {
        return refusal('packet must be an object of shape { action, evidence, context }');
    }
    if (packet.action === null || typeof packet.action !== 'object' || Array.isArray(packet.action)) {
        return refusal('packet.action must be an object; the action digest is computed over it');
    }
    const nowMs = parseTimeMs(opts.now !== undefined && opts.now !== null ? opts.now : packet.evaluated_at);
    if (nowMs === null) {
        return refusal('no evaluation time supplied: pass opts.now (or --now) or set packet.evaluated_at as RFC 3339; this builder never reads the wall clock');
    }
    const evaluatedAt = new Date(nowMs).toISOString();
    let actionDigest;
    try {
        actionDigest = digestOf(packet.action);
    }
    catch {
        return refusal('packet.action could not be canonicalized (JCS); remove non-JSON values before digesting');
    }
    // Sort the evidence into kernel slots. First artifact per slot is used;
    // duplicates are recorded and ignored; foreign types are recorded as
    // unverifiable presence and never consumed.
    const evidence = Array.isArray(packet.evidence) ? packet.evidence : [];
    const slots = {};
    const inventory = [];
    const foreignTypes = [];
    evidence.forEach((item, index) => {
        const { slot, artifact, declared } = classifyEvidenceItem(item);
        if (slot === null) {
            inventory.push({ index, status: 'unverifiable_present', type: declared });
            if (!foreignTypes.includes(declared))
                foreignTypes.push(declared);
        }
        else if (slots[slot] !== undefined) {
            inventory.push({ index, status: 'duplicate_unused', type: slot });
        }
        else {
            slots[slot] = artifact;
            inventory.push({ index, status: 'used', type: slot });
        }
    });
    const { pinned, id: profileId, digest: profileDigest } = resolveProfile(profile);
    const context = packet.context && typeof packet.context === 'object' ? packet.context : {};
    const verifierOpts = {
        approverKeys: context.approver_keys && typeof context.approver_keys === 'object' ? context.approver_keys : {},
        logPublicKey: context.log_public_key ?? null,
        revokerKeys: context.revoker_keys && typeof context.revoker_keys === 'object' ? context.revoker_keys : {},
    };
    if (typeof context.rp_id === 'string')
        verifierOpts.rpId = context.rp_id;
    if (Array.isArray(context.allowed_origins))
        verifierOpts.allowedOrigins = context.allowed_origins;
    // THE VERDICT: exactly what the kernel returns. Never reinterpreted here.
    const kernel = evaluateReliance({
        action: packet.action,
        receipt: slots.receipt,
        quorum: slots.quorum,
        authority_proof: slots.authority_proof,
        revocation_state: slots.revocation_state,
        consumption: slots.consumption,
        relying_party_profile: pinned,
        now: nowMs,
    }, verifierOpts);
    // Missing evidence = statically absent required legs (so one run lists every
    // absent artifact) + the kernel's own refusal (which sees deeper failures in
    // artifacts that ARE present) + every foreign artifact. Deduplicated by
    // requirement; the kernel's more specific entry wins on collision.
    const gaps = new Map();
    const addGap = (g) => { gaps.set(g.requirement, g); };
    if (pinned && typeof pinned === 'object' && pinned['@type'] === RELIANCE_PROFILE_VERSION) {
        const requiredEvidence = new Set(Array.isArray(pinned.required_evidence) ? pinned.required_evidence : []);
        if (!slots.receipt)
            addGap(PRESENCE_GAPS.receipt);
        if (pinned.required_assurance === 'quorum' && !slots.quorum)
            addGap(PRESENCE_GAPS.quorum);
        if ((pinned.required_authority === true || requiredEvidence.has('authority_proof')) && !slots.authority_proof) {
            addGap(PRESENCE_GAPS.authority_proof);
        }
        if (requiredEvidence.has('revocation_freshness') && !slots.revocation_state)
            addGap(PRESENCE_GAPS.revocation_freshness);
        if (requiredEvidence.has('consumption_proof') && !slots.consumption)
            addGap(PRESENCE_GAPS.consumption_proof);
    }
    if (kernel.verdict !== 'rely' && VERDICT_GAPS[kernel.verdict]) {
        addGap(VERDICT_GAPS[kernel.verdict]);
    }
    for (const t of [...foreignTypes].sort()) {
        addGap({
            requirement: `verifiable_evidence_only:${t}`,
            why_it_matters: `An artifact of type "${t}" has no registered verifier, so it is recorded as unverifiable presence and can never count as evidence.`,
            how_to_close: 'Replace it with an artifact type the kernel verifies (receipt, quorum, authority_proof, revocation_state, consumption), or remove it from the packet.',
        });
    }
    const missingEvidence = [...gaps.values()]
        .sort((a, b) => (a.requirement < b.requirement ? -1 : a.requirement > b.requirement ? 1 : 0));
    const packetPath = typeof opts.packet_path === 'string' ? opts.packet_path : '<packet.json>';
    const profilePath = typeof opts.profile_path === 'string' ? opts.profile_path : '<profile.json>';
    return sortKeysDeep({
        '@type': RELIANCE_GAP_REPORT_VERSION,
        evaluated_at: evaluatedAt,
        action_digest: actionDigest,
        profile: { id: profileId, digest: profileDigest },
        kernel_verdict: kernel.verdict,
        kernel_reasons: kernel.reasons,
        evidence_inventory: inventory,
        missing_evidence: missingEvidence,
        control_mapping: buildControlMapping(kernel),
        limitations: [...RELIANCE_GAP_LIMITATIONS],
        assurance_package_relation: ASSURANCE_PACKAGE_RELATION,
        reproduce: {
            command: `npx @emilia-protocol/verify reliance-gap ${packetPath} --profile ${profilePath} --now ${evaluatedAt}`,
            kernel_version: RELIANCE_KERNEL_VERSION,
            profile_version: RELIANCE_PROFILE_VERSION,
            report_version: RELIANCE_GAP_REPORT_VERSION,
            note: 'Offline and deterministic: the same packet, profile, and evaluation time reproduce this report byte for byte.',
        },
    });
}
/**
 * Evaluate the SAME packet against several pinned profiles (one per relying
 * party) and emit one combined EP-RELIANCE-GAP-MULTI-v1 report: same
 * transaction, N parties, N pinned profiles, one portable evidence packet.
 *
 * @param {object} packet   as for buildRelianceGapReport
 * @param {Array<{label?:string, profile:object, path?:string}>} profiles
 * @param {object} [opts]   { now, packet_path, profiles_path }
 * @returns {object} the combined report, or a refusal object
 */
export function buildMultiPartyRelianceGapReport(packet, profiles, opts = {}) {
    if (!Array.isArray(profiles) || profiles.length === 0) {
        return refusal('profiles must be a non-empty array of { label, profile }');
    }
    const labeled = profiles.map((p, i) => ({
        label: typeof p?.label === 'string' ? p.label : `profile-${i}`,
        profile: p?.profile,
        path: typeof p?.path === 'string' ? p.path : undefined,
    })).sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
    const reports = [];
    for (const entry of labeled) {
        const report = buildRelianceGapReport(packet, entry.profile, {
            now: opts.now,
            packet_path: opts.packet_path,
            profile_path: entry.path,
        });
        if (report.refused === true)
            return report; // packet-level refusal: same for every profile
        reports.push({ label: entry.label, report });
    }
    const summary = reports.map(({ label, report }) => ({
        profile: label,
        profile_id: report.profile.id,
        verdict: report.kernel_verdict,
    }));
    const allRely = reports.every(({ report }) => report.kernel_verdict === 'rely');
    const packetPath = typeof opts.packet_path === 'string' ? opts.packet_path : '<packet.json>';
    const profilesPath = typeof opts.profiles_path === 'string' ? opts.profiles_path : '<profiles-dir>';
    return sortKeysDeep({
        '@type': RELIANCE_GAP_MULTI_VERSION,
        evaluated_at: reports[0].report.evaluated_at,
        action_digest: reports[0].report.action_digest,
        profiles_evaluated: reports.length,
        all_rely: allRely,
        summary,
        reports,
        limitations: [...RELIANCE_GAP_LIMITATIONS],
        assurance_package_relation: ASSURANCE_PACKAGE_RELATION,
        reproduce: {
            command: `npx @emilia-protocol/verify reliance-gap ${packetPath} --profiles ${profilesPath} --now ${reports[0].report.evaluated_at}`,
            kernel_version: RELIANCE_KERNEL_VERSION,
            profile_version: RELIANCE_PROFILE_VERSION,
            report_version: RELIANCE_GAP_MULTI_VERSION,
            note: 'Offline and deterministic: the same packet, profiles, and evaluation time reproduce this report byte for byte.',
        },
    });
}
//# sourceMappingURL=reliance-gap.js.map