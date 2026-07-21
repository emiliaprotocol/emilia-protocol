/**
 * @emilia-protocol/gate — EMILIA Gate: the Consequence Firewall.
 * @license Apache-2.0
 *
 * Deny-by-default enforcement for consequential machine actions. A guarded
 * action runs ONLY if it arrives with a receipt that is:
 *   1. valid          — Ed25519 over canonical JSON, signed by a pinned issuer;
 *   2. in-scope       — bound to the exact action the manifest guards;
 *   3. sufficiently   — meets the action's required assurance tier, and the
 *      assured           credited tier is CRYPTOGRAPHICALLY VERIFIED, not read
 *                        from self-asserted payload fields: class_a requires a
 *                        valid WebAuthn device signoff, quorum requires a valid
 *                        EP-QUORUM-v1 (distinct humans + distinct keys +
 *                        threshold + per-signer assertions);
 *   4. fresh          — within max age; and
 *   5. unused         — not a replay (one-time consumption).
 * Otherwise it is refused with a machine-readable Receipt-Required challenge
 * (HTTP 428). Every decision is appended to a tamper-evident evidence log.
 *
 * It is NOT authentication ("who are you") and NOT permissions ("are you
 * allowed here"). It is a policy-enforcement point that requires portable proof
 * a named human authorized THIS exact action before the world is mutated.
 *
 * Composes @emilia-protocol/require-receipt (manifest + verify + challenge) and
 * adds the three things a firewall needs over a bare verifier: assurance-tier
 * enforcement, replay defense, and the evidence log. Fails closed.
 */
import crypto from 'node:crypto';
import { verifyEmiliaReceipt, receiptChallenge, receiptRequiredHeader, validateActionRiskManifest, findActionRequirement, evaluateReceiptAssurance, validatePinnedQuorumPolicy, receiptAssuranceTier as receiptAssuranceTierFromProof, parseReceiptCarrier, RECEIPT_REQUIRED_STATUS, RECEIPT_REQUIRED_HEADER, } from '@emilia-protocol/require-receipt';
import { verifyWebAuthnSignoff, verifyQuorum } from '@emilia-protocol/verify';
import { MemoryConsumptionStore, isSecureConsumptionStore } from './store.js';
import { canonicalEvidenceJson, createAtomicEvidenceLog, createEvidenceLog, createMemoryAtomicEvidenceBackend, } from './evidence.js';
import { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest } from './action-packs.js';
import { hashCanonical, verifyExecutionBinding } from './execution-binding.js';
import { buildReliancePacket, ADMISSIBILITY_VERDICTS } from './reliance-packet.js';
import { createEg1Harness, makeGateInvoke, runEg1, EG1_DEFAULT_SELECTOR } from './eg1-conformance.js';
import { CF1_VERSION, CF1_CHECKS, runCf1 } from './cf1-conformance.js';
import { createKeyRegistry, asKeyRegistry } from './key-registry.js';
import { classifyRetention, buildRetentionExport } from './retention.js';
import { createDefaultActionControlManifest, findActionControl, validateActionControlManifest } from './action-control-manifest.js';
import { createRuntimeMonitor, RUNTIME_MONITOR_VERSION, RUNTIME_MONITOR_MODES, RUNTIME_INVARIANTS, } from './runtime-monitor.js';
import { FORMAL_RUNTIME_BRIDGE_VERSION, FORMAL_RUNTIME_SPEC, FORMAL_RUNTIME_CONFIG, FORMAL_RUNTIME_INVARIANT_MAP, } from './formal-runtime-map.js';
import { CAPABILITY_RECEIPT_VERSION, CAPABILITY_STATE_VERSION, CAPABILITY_SHARE_VERSION, CAPABILITY_SCOPE_PROFILE, CAPABILITY_CAID_SCOPE_PROFILE, CAPABILITY_STATE_DDL, CAPABILITY_SQL, capabilityBaseReceiptDigest, capabilityActionDigest, verifyCapabilityScope, mintCapabilityReceipt, verifyCapabilityReceipt, splitCapabilitySecret, reconstructCapabilitySecret, createMemoryCapabilityStore, createPostgresCapabilityStore, executeWithCapability, executeWithThreshold, reconcileCapabilityOperation, } from './capability-receipt.js';
import { ZK_RANGE_RECEIPT_VERSION, ZK_RANGE_SCHEME, ZK_RANGE_BACKEND_PACKAGE, deriveZkRangeBases, loadBulletproofBackend, mintZkRangeReceipt, verifyZkRangeReceipt, } from './zk-range-proof.js';
import { mintBreakGlassAuthorization, verifyBreakGlass, consumeBreakGlass, buildBreakGlassEvidence, runBreakGlass, BREAKGLASS_VERSION, BREAKGLASS_EVIDENCE_KIND, } from './breakglass.js';
export { MemoryConsumptionStore, canonicalEvidenceJson, createEvidenceLog, createAtomicEvidenceLog, createMemoryAtomicEvidenceBackend, };
export { createDurableConsumptionStore, createMemoryBackend, isSecureConsumptionStore, DURABLE_CONSUMPTION_VERSION, } from './store.js';
export { createDurableChallengeStore, challengeStorageKey, challengeBodyDigest, DURABLE_CHALLENGE_STORE_VERSION } from './challenge-store.js';
export { createKeyRegistry, asKeyRegistry } from './key-registry.js';
export { classifyRetention, buildRetentionExport, RETENTION_EXPORT_VERSION } from './retention.js';
export { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest };
export { ACTION_CONTROL_MANIFEST_VERSION, ACTION_CONTROL_SCHEMA_URL, ACTION_CONTROL_CONFORMANCE_LEVEL, ACTION_CONTROL_DEFAULTS, ACTION_CONTROL_EVIDENCE_PROFILES, ACTION_CONTROL_CONFORMANCE_CHECKS, toActionControl, createDefaultActionControlManifest, findActionControl, validateActionControlManifest, } from './action-control-manifest.js';
export { EXECUTION_BINDING_VERSION, canonicalize, hashCanonical, materialFieldsFor, verifyExecutionBinding } from './execution-binding.js';
export { RELIANCE_PACKET_VERSION, ADMISSIBILITY_VERDICTS, buildReliancePacket } from './reliance-packet.js';
export { EXTERNAL_VERIFICATION_STATEMENT_VERSION, EXTERNAL_VERIFICATION_DOMAIN, externalVerificationDigest, signExternalVerificationStatement, verifyExternalVerificationStatement, } from './reports/external-verification.js';
export { EG1_VERSION, EG1_CHECKS, EG1_DEFAULT_ACTION, EG1_DEFAULT_SELECTOR, createEg1Harness, makeGateInvoke, runEg1, mintDeviceSignoff, mintQuorumEvidence, } from './eg1-conformance.js';
export { CF1_VERSION, CF1_CHECKS, runCf1 } from './cf1-conformance.js';
export { mintBreakGlassAuthorization, verifyBreakGlass, consumeBreakGlass, buildBreakGlassEvidence, runBreakGlass, BREAKGLASS_VERSION, BREAKGLASS_EVIDENCE_KIND, };
export { createRuntimeMonitor, RUNTIME_MONITOR_VERSION, RUNTIME_MONITOR_MODES, RUNTIME_INVARIANTS } from './runtime-monitor.js';
export { FORMAL_RUNTIME_BRIDGE_VERSION, FORMAL_RUNTIME_SPEC, FORMAL_RUNTIME_CONFIG, FORMAL_RUNTIME_INVARIANT_MAP, } from './formal-runtime-map.js';
export { CAPABILITY_RECEIPT_VERSION, CAPABILITY_STATE_VERSION, CAPABILITY_SHARE_VERSION, CAPABILITY_SCOPE_PROFILE, CAPABILITY_CAID_SCOPE_PROFILE, CAPABILITY_STATE_DDL, CAPABILITY_SQL, capabilityBaseReceiptDigest, capabilityActionDigest, verifyCapabilityScope, mintCapabilityReceipt, verifyCapabilityReceipt, splitCapabilitySecret, reconstructCapabilitySecret, createMemoryCapabilityStore, createPostgresCapabilityStore, executeWithCapability, executeWithThreshold, reconcileCapabilityOperation, delegateCapabilityReceipt, } from './capability-receipt.js';
export { ZK_RANGE_RECEIPT_VERSION, ZK_RANGE_SCHEME, ZK_RANGE_BACKEND_PACKAGE, deriveZkRangeBases, loadBulletproofBackend, mintZkRangeReceipt, verifyZkRangeReceipt, } from './zk-range-proof.js';
export const ASSURANCE_TIERS = ['software', 'class_a', 'quorum'];
const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };
const CAPABILITY_FAILURE_STATUS = 409;
function safeCanonicalHash(value) {
    try {
        return hashCanonical(value);
    }
    catch {
        return null;
    }
}
/**
 * Capability spending is intentionally bound to the executor's observed
 * monetary action, not to a presenter-selected amount. The default action
 * packs use `amount_usd`; integrations that use the generic `amount` field
 * are supported as well. A missing or mismatched amount/currency fails closed
 * before the capability store is touched.
 */
function verifyCapabilityActionBinding({ capability, observedAction } = {}) {
    if (capability === null || capability === undefined)
        return { ok: true, required: false };
    const action = capability?.action;
    if (!action || typeof action !== 'object' || Array.isArray(action)
        || !Number.isSafeInteger(action.amount) || action.amount <= 0
        || typeof action.currency !== 'string' || action.currency.length === 0) {
        return { ok: false, reason: 'capability_action_invalid', required: true };
    }
    const observedAmount = Number.isSafeInteger(observedAction?.amount)
        ? observedAction.amount
        : observedAction?.amount_usd;
    const observedCurrency = observedAction?.currency;
    if (observedAmount !== action.amount || observedCurrency !== action.currency) {
        return {
            ok: false,
            reason: 'capability_action_binding_failed',
            required: true,
            capability_amount: action.amount,
            capability_currency: action.currency,
            observed_amount: observedAmount ?? null,
            observed_currency: observedCurrency ?? null,
        };
    }
    return {
        ok: true,
        required: true,
        amount: action.amount,
        currency: action.currency,
    };
}
function capabilitySummary(capability, operationId = null) {
    return {
        capability_id: capability?.capabilityReceipt?.capability?.id ?? null,
        operation_id: operationId ?? capability?.operationId ?? null,
        amount: capability?.action?.amount ?? null,
        currency: capability?.action?.currency ?? null,
    };
}
/**
 * Re-check the material execution fields at the proof-recording boundary.
 * Authorization-time binding proves what was observed before the effect; this
 * second check proves the execution record carries the same observation. A
 * reliance packet must not be able to reuse an earlier green binding after the
 * executor reports different system-of-record values.
 */
function bindExecutionProof({ authorization, observedAction, binding }) {
    if (!binding?.required)
        return binding;
    const requirement = authorization?.requirement || {
        execution_binding: { required_fields: binding.required_fields || [] },
    };
    const replay = verifyExecutionBinding({
        requirement,
        receipt: { payload: { claim: observedAction || {} } },
        observedAction,
    });
    const matchesAuthorization = replay.ok
        && typeof binding.observed_hash === 'string'
        && replay.observed_hash === binding.observed_hash;
    return {
        ...binding,
        execution_observed_hash: replay.observed_hash,
        execution_mismatched_fields: replay.mismatched_fields || [],
        execution_missing_observed_fields: replay.missing_observed_fields || [],
        execution_binding_match: matchesAuthorization,
        ok: binding.ok === true && matchesAuthorization,
    };
}
/**
 * Structurally compare a PRE-COMPUTED admissibility block with a profile hash.
 * This helper does NOT authenticate the block or establish evaluator provenance.
 * An execution gate must first verify a signature over the packet or recompute
 * the verdict from trusted evidence. createGate enforces that boundary through
 * its verifyAdmissibilityPacket callback whenever a profile is pinned.
 *
 * @param {{id?:string, profile_hash:string}} pinned  the profile the relying party requires
 * @param {object|null} presented  a reliance packet, or its `.admissibility` block,
 *   as produced by buildReliancePacket / the relying party's evaluator
 * @returns {{ok:boolean, reason:string|null, pinned_hash:string|null, presented_hash:string|null, verdict:string|null}}
 *   ok:true ONLY when the presented profile_hash equals the pinned hash AND the
 *   verdict is exactly 'admissible'. Every other case fails closed with a distinct reason.
 */
export function verifyAdmissibilityAgainstPinnedProfile(pinned, presented) {
    const pinnedHash = pinned && typeof pinned.profile_hash === 'string' ? pinned.profile_hash : null;
    // A pin with no hash is a misconfiguration: refuse, do not silently pass.
    if (!pinnedHash) {
        return { ok: false, reason: 'pinned_profile_missing_hash', pinned_hash: null, presented_hash: null, verdict: null };
    }
    // Accept either a full reliance packet (has .admissibility) or the block itself.
    const adm = presented && typeof presented === 'object'
        ? (presented.admissibility !== undefined ? presented.admissibility : presented)
        : null;
    if (!adm || typeof adm !== 'object') {
        return { ok: false, reason: 'admissibility_profile_pinned_but_absent', pinned_hash: pinnedHash, presented_hash: null, verdict: null };
    }
    const presentedHash = typeof adm.profile_hash === 'string' ? adm.profile_hash : null;
    const verdict = typeof adm.verdict === 'string' ? adm.verdict : null;
    // Constant-work equality is unnecessary (hashes are public), but the mismatch
    // MUST be a distinct, named refusal: a presented verdict for a DIFFERENT bar is
    // not evidence about the pinned bar.
    if (presentedHash === null || presentedHash !== pinnedHash) {
        return { ok: false, reason: 'profile_hash_mismatch', pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
    }
    // Verdict must be recognized AND exactly 'admissible'. Any other closed-set
    // member (missing_evidence/stale/conflicted/unverifiable), an unrecognized
    // string, or a missing verdict fails closed and names the verdict it saw.
    if (verdict === null || !ADMISSIBILITY_VERDICTS.includes(verdict)) {
        return { ok: false, reason: 'admissibility_verdict_unrecognized', pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
    }
    if (verdict !== 'admissible') {
        return { ok: false, reason: `admissibility_not_admissible:${verdict}`, pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
    }
    return { ok: true, reason: null, pinned_hash: pinnedHash, presented_hash: presentedHash, verdict };
}
export function receiptAssuranceTier(doc, opts = {}) {
    const detail = { tier: 'software', quorum: null, signoff: null };
    // --- Path (a): pinned assurance proof / caller-supplied verifier. ---
    // Never inferred from receipt fields without a pinned key or explicit verifier.
    let proofTier = 'software';
    try {
        proofTier = receiptAssuranceTierFromProof(doc, opts) || 'software';
    }
    catch {
        proofTier = 'software';
    }
    if ((TIER_RANK[proofTier] ?? 0) > (TIER_RANK[detail.tier] ?? 0))
        detail.tier = proofTier;
    // --- Path (b): self-contained embedded per-signer evidence (DoD audit fix). ---
    const p = doc?.payload || {};
    const verifyOpts = {
        ...(opts.rpId ? { rpId: opts.rpId } : {}),
        ...(Array.isArray(opts.allowedOrigins) ? { allowedOrigins: opts.allowedOrigins } : {}),
    };
    // The relying party's PINNED approver public keys (base64url SPKI-DER strings).
    // An embedded approver key elevates the tier only if it is in this set, unless
    // the caller explicitly opts into the self-contained mode.
    const allowEmbedded = opts.allowEmbeddedApproverKeys === true;
    const keyIsTrusted = (k, approver) => allowEmbedded
        || Boolean(findPinnedApproverKey(opts.approverKeys, k, approver));
    // quorum: a real, self-contained EP-QUORUM-v1 evidence document. Accept it
    // under payload.quorum or payload.claim.quorum. It only counts if it is a full
    // quorum document (policy + members with WebAuthn signoffs) AND verifyQuorum
    // returns valid. A bare {signers,threshold} block has no members to verify and
    // therefore CANNOT be credited quorum. The cryptographic verification runs
    // regardless (so `detail.quorum` reports validity), but the tier elevates only
    // when every member's embedded approver key is pinned (or the caller opted in).
    const q = p.quorum || p.claim?.quorum;
    if (detail.tier !== 'quorum' && isQuorumEvidence(q)) {
        const policy = validatePinnedQuorumPolicy((opts.quorumPolicy || opts.quorum_policy));
        const trustedMembers = Array.isArray(q.members) ? q.members.map((member) => {
            const entry = findPinnedApproverKey(opts.approverKeys, member?.approver_public_key, member?.signoff?.context?.approver);
            return entry ? { ...member, approver_public_key: entry.public_key } : null;
        }) : [];
        const membersTrusted = trustedMembers.length > 0 && trustedMembers.every(Boolean);
        const qr = policy.ok && membersTrusted
            ? verifyQuorum({ ...q, policy: policy.policy, members: trustedMembers }, verifyOpts)
            : { valid: false, checks: {} };
        detail.quorum = {
            valid: qr.valid,
            checks: qr.checks,
            policy_pinned: policy.ok,
            embedded_keys_trusted: membersTrusted,
            approvers: qr.valid
                ? trustedMembers.map((member) => member?.signoff?.context?.approver).filter(nonEmptyString)
                : [],
            roles: qr.valid
                ? trustedMembers.map((member) => ({
                    subject: member?.signoff?.context?.approver ?? null,
                    role: member?.role ?? null,
                }))
                : [],
            refusal: !policy.ok ? policy.reason : (!membersTrusted ? 'quorum_member_key_unpinned' : null),
        };
        if (qr.valid && policy.ok && membersTrusted)
            detail.tier = 'quorum';
    }
    // class_a: a verifiable WebAuthn device signoff. The signoff evidence is
    // {context, webauthn}; the approver key travels with it (signoff.approver_public_key)
    // or alongside it (payload.approver_public_key). That key elevates the tier only
    // when it is pinned by the relying party (or the caller opted into embedded keys).
    if ((TIER_RANK[detail.tier] ?? 0) < TIER_RANK.class_a) {
        const so = p.signoff || p.claim?.signoff;
        if (isSignoffEvidence(so)) {
            const key = so.approver_public_key || p.approver_public_key || p.claim?.approver_public_key;
            if (key) {
                const sr = verifyWebAuthnSignoff(so, key, verifyOpts);
                const trusted = keyIsTrusted(key, so?.context?.approver);
                detail.signoff = {
                    valid: sr.valid,
                    checks: sr.checks,
                    embedded_key_trusted: trusted,
                    approver: so?.context?.approver ?? null,
                };
                if (sr.valid && trusted && (TIER_RANK[detail.tier] ?? 0) < TIER_RANK.class_a)
                    detail.tier = 'class_a';
            }
        }
    }
    return opts.detail ? detail : detail.tier;
}
/**
 * The set of PINNED approver public keys (base64url SPKI-DER strings) a relying
 * party trusts, from the same `approverKeys` map path (a) uses. Accepts either a
 * map of { keyId: { public_key } } (the EP-ASSURANCE-PROOF-v1 shape) or a plain
 * array/set of key strings. Used to decide whether a receipt-embedded approver
 * key may elevate the path-(b) tier. Never throws.
 */
function spkiFingerprint(value) {
    try {
        const key = crypto.createPublicKey({ key: Buffer.from(value, 'base64url'), format: 'der', type: 'spki' });
        return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
    }
    catch {
        return null;
    }
}
function findPinnedApproverKey(approverKeys, presentedKey, approver) {
    if (!approverKeys || typeof approverKeys !== 'object' || Array.isArray(approverKeys))
        return null;
    const presentedFingerprint = spkiFingerprint(presentedKey);
    if (!presentedFingerprint || typeof approver !== 'string' || !approver)
        return null;
    const matches = Object.values(approverKeys).filter((entry) => entry && typeof entry === 'object'
        && entry.approver_id === approver
        && spkiFingerprint(entry.public_key) === presentedFingerprint);
    return matches.length === 1 ? matches[0] : null;
}
/** A quorum evidence doc must carry members with per-signer signoffs to be verifiable. */
function isQuorumEvidence(q) {
    return !!q && typeof q === 'object' && q.policy && Array.isArray(q.members) && q.members.length > 0
        && typeof q.action_hash === 'string' && q.action_hash.length > 0;
}
/** A device signoff must carry the WebAuthn assertion material to be verifiable. */
function isSignoffEvidence(s) {
    return !!s && typeof s === 'object' && s.context && s.webauthn;
}
function nonEmptyString(value) {
    return typeof value === 'string' && value.length > 0 ? value : null;
}
function businessAuthorizationSource(requirement) {
    if (!requirement || typeof requirement !== 'object')
        return null;
    const nested = requirement.business_authorization
        || requirement.businessAuthorization
        || requirement.authorization_requirement
        || requirement.authorizationRequirement
        || requirement.authorization_policy
        || requirement.authorizationPolicy
        || requirement.business_policy
        || requirement.control?.business_authorization
        || requirement.control?.authorization_requirement
        || requirement.control?.authorization_policy;
    if (nested && typeof nested === 'object' && !Array.isArray(nested))
        return nested;
    const hasDirect = [
        'policy', 'business_policy', 'policy_id', 'policy_hash', 'tenant_id', 'allowed_approvers',
        'allowed_approver_subjects', 'allowed_approver_roles',
    ].some((field) => Object.prototype.hasOwnProperty.call(requirement, field));
    return hasDirect ? requirement : null;
}
/**
 * Normalize the relying party's business-authorization pin for one action.
 *
 * Canonical manifest shape:
 *   business_authorization: {
 *     policy: { id, hash }, tenant_id,
 *     allowed_approvers: [{ subject, role }]
 *   }
 *
 * Flat policy_id/policy_hash and approver aliases are accepted so an existing
 * manifest can add the control without changing its surrounding schema. Once
 * any part is configured, every part is required; a partial pin is invalid.
 */
export function businessAuthorizationRequirement(requirement) {
    const source = businessAuthorizationSource(requirement);
    if (!source) {
        return {
            configured: false, ok: true, reason: null,
            policy_id: null, policy_hash: null, tenant_id: null, allowed_approvers: [],
        };
    }
    const policy = source.policy && typeof source.policy === 'object' && !Array.isArray(source.policy)
        ? source.policy
        : (source.business_policy && typeof source.business_policy === 'object' && !Array.isArray(source.business_policy)
            ? source.business_policy : {});
    const root = requirement && typeof requirement === 'object' ? requirement : {};
    const policyId = nonEmptyString(source.policy_id ?? source.id ?? policy.policy_id ?? policy.id ?? root.policy_id);
    const policyHash = nonEmptyString(source.policy_hash ?? source.hash ?? policy.policy_hash ?? policy.hash ?? root.policy_hash);
    const tenantId = nonEmptyString(source.tenant_id ?? source.tenant ?? source.organization_id
        ?? root.tenant_id ?? root.tenant ?? root.organization_id);
    const rawApprovers = source.allowed_approvers ?? source.approvers ?? source.approver_roster
        ?? root.allowed_approvers ?? root.approvers ?? root.approver_roster;
    const subjects = source.allowed_approver_subjects ?? source.approver_subjects
        ?? root.allowed_approver_subjects ?? root.approver_subjects;
    const roles = source.allowed_approver_roles ?? source.approver_roles
        ?? root.allowed_approver_roles ?? root.approver_roles;
    let allowed = [];
    if (Array.isArray(rawApprovers)) {
        allowed = rawApprovers.map((entry) => {
            if (typeof entry === 'string')
                return { subject: entry, role: null };
            if (!entry || typeof entry !== 'object' || Array.isArray(entry))
                return { subject: null, role: null };
            return {
                subject: nonEmptyString(entry.subject ?? entry.approver ?? entry.principal_id),
                role: nonEmptyString(entry.role ?? entry.approver_role),
            };
        });
    }
    else if (Array.isArray(subjects)) {
        const validRoles = Array.isArray(roles) ? roles.filter((role) => nonEmptyString(role)) : [];
        allowed = subjects.flatMap((subject) => {
            if (!validRoles.length)
                return [{ subject: nonEmptyString(subject), role: null }];
            return validRoles.map((role) => ({ subject: nonEmptyString(subject), role }));
        });
    }
    const malformed = !policyId || !policyHash || !tenantId || allowed.length === 0
        || allowed.some((entry) => !entry.subject || !entry.role);
    const duplicate = new Set(allowed.map((entry) => `${entry.subject}\u0000${entry.role}`)).size !== allowed.length;
    return {
        configured: true,
        ok: !malformed && !duplicate,
        reason: malformed ? 'business_authorization_incomplete'
            : (duplicate ? 'business_authorization_duplicate_approver' : null),
        policy_id: policyId,
        policy_hash: policyHash,
        tenant_id: tenantId,
        allowed_approvers: allowed,
    };
}
function signedString(candidates) {
    const present = candidates.filter((value) => value !== undefined && value !== null);
    if (!present.length)
        return { ok: true, value: null };
    if (present.some((value) => !nonEmptyString(value)))
        return { ok: false, value: null };
    const distinct = [...new Set(present)];
    return distinct.length === 1 ? { ok: true, value: distinct[0] } : { ok: false, value: null };
}
function receiptRoleAssertions(receipt, tierResult) {
    const claim = receipt?.payload?.claim || {};
    const assertions = [];
    const arrays = [claim.approvers, claim.approver_authorizations, claim.approver_roles];
    for (const entries of arrays) {
        if (!Array.isArray(entries))
            continue;
        for (const entry of entries) {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry))
                continue;
            const subject = nonEmptyString(entry.subject ?? entry.approver ?? entry.principal_id);
            const role = nonEmptyString(entry.role ?? entry.approver_role);
            if (subject && role)
                assertions.push({ subject, role });
        }
    }
    const singleSubject = nonEmptyString(claim.approver ?? claim.approver_subject);
    const singleRole = nonEmptyString(claim.approver_role ?? claim.role);
    if (singleSubject && singleRole)
        assertions.push({ subject: singleSubject, role: singleRole });
    if (tierResult?.quorum?.valid === true) {
        for (const member of (receipt?.payload?.quorum?.members || [])) {
            const subject = nonEmptyString(member?.signoff?.context?.approver);
            const role = nonEmptyString(member?.role);
            if (subject && role)
                assertions.push({ subject, role });
        }
    }
    return assertions;
}
function verifiedApproverSubjects(assurance, tierResult) {
    const subjects = new Set(Array.isArray(assurance?.approvers) ? assurance.approvers.filter(nonEmptyString) : []);
    if (tierResult?.signoff?.valid === true && nonEmptyString(tierResult.signoff.approver)) {
        subjects.add(tierResult.signoff.approver);
    }
    if (tierResult?.quorum?.valid === true) {
        for (const subject of (tierResult.quorum.approvers || [])) {
            if (nonEmptyString(subject))
                subjects.add(subject);
        }
    }
    return [...subjects].sort();
}
/**
 * Verify signed business-policy and tenant fields plus the cryptographically
 * credited human approvers against one action's relying-party pins.
 * @returns {{required:boolean, ok:boolean, reason:string|null, expected:object, evaluated:{policy_id:string|null, policy_hash:string|null, tenant_id:string|null, approvers:{subject:string, roles:string[]}[]}}}
 */
export function verifyBusinessAuthorization({ requirement, receipt, assurance, tierResult } = {}) {
    const expected = businessAuthorizationRequirement(requirement);
    const claim = receipt?.payload?.claim || {};
    const payload = receipt?.payload || {};
    const policyId = signedString([claim.policy_id, payload.policy_id]);
    const policyHash = signedString([claim.policy_hash, payload.policy_hash]);
    const tenantId = signedString([
        claim.tenant_id, claim.organization_id, payload.tenant_id, payload.organization_id,
    ]);
    const subjects = verifiedApproverSubjects(assurance, tierResult);
    const roleAssertions = receiptRoleAssertions(receipt, tierResult);
    const evaluatedApprovers = subjects.map((subject) => {
        const asserted = [...new Set(roleAssertions.filter((entry) => entry.subject === subject).map((entry) => entry.role))];
        return { subject, roles: asserted };
    });
    const evaluated = {
        policy_id: policyId.value,
        policy_hash: policyHash.value,
        tenant_id: tenantId.value,
        approvers: evaluatedApprovers,
    };
    const base = { required: expected.configured, ok: true, reason: null, expected, evaluated };
    if (!expected.configured)
        return base;
    if (!expected.ok)
        return { ...base, ok: false, reason: expected.reason };
    if (!policyId.ok)
        return { ...base, ok: false, reason: 'business_policy_id_ambiguous' };
    if (!policyHash.ok)
        return { ...base, ok: false, reason: 'business_policy_hash_ambiguous' };
    if (!tenantId.ok)
        return { ...base, ok: false, reason: 'business_tenant_ambiguous' };
    if (policyId.value !== expected.policy_id)
        return { ...base, ok: false, reason: 'business_policy_id_mismatch' };
    if (policyHash.value !== expected.policy_hash)
        return { ...base, ok: false, reason: 'business_policy_hash_mismatch' };
    if (tenantId.value !== expected.tenant_id)
        return { ...base, ok: false, reason: 'business_tenant_mismatch' };
    if (!subjects.length)
        return { ...base, ok: false, reason: 'business_approver_required' };
    for (const approver of evaluatedApprovers) {
        const allowedForSubject = expected.allowed_approvers.filter((entry) => entry.subject === approver.subject);
        if (!allowedForSubject.length)
            return { ...base, ok: false, reason: 'business_approver_not_allowed' };
        // The early `if (!expected.ok) return ...` above guarantees every allowed_approvers
        // entry has a non-null role (a null role would have made businessAuthorizationRequirement
        // mark the manifest malformed and expected.ok false).
        const allowedRoles = new Set(allowedForSubject.map((entry) => entry.role));
        if (approver.roles.length && !approver.roles.some((role) => allowedRoles.has(role))) {
            return { ...base, ok: false, reason: 'business_approver_role_not_allowed' };
        }
        // The manifest is the authoritative subject-to-role assignment. When the
        // receipt does not repeat a role, record the pinned role rather than trusting
        // an unsigned/free-text role label from elsewhere.
        if (!approver.roles.length)
            approver.roles = [...allowedRoles].sort();
    }
    return base;
}
export function createGate({ manifest = null, trustedKeys = [], maxAgeSec = 900, store, log, capabilityStore = null, capabilityTrustedIssuerKeys = [], capabilityCaidResolver = null, allowInlineKey = false, allowEphemeralStore = false, strictEvidence = true, now = Date.now, keyRegistry = null, approverKeys = {}, approver_keys = null, verifyAssurance = null, rpId = null, allowedOrigins = [], quorumPolicy = null, quorumPolicies = {}, requiredAdmissibilityProfile = null, verifyAdmissibilityPacket = null, allowEmbeddedApproverKeys = false, runtimeMonitor = createRuntimeMonitor({ now }) } = {}) {
    // Production key custody: a registry (rotation + revocation) supersedes a flat
    // trustedKeys list. A flat list is coerced to an always-valid registry, so
    // existing callers are unchanged.
    const registry = keyRegistry ? asKeyRegistry(keyRegistry) : (trustedKeys.length ? asKeyRegistry(trustedKeys) : null);
    if (manifest) {
        const m = validateActionRiskManifest(manifest);
        if (!m.ok)
            throw new Error('EMILIA Gate: invalid action-risk manifest: ' + m.errors.join('; '));
        for (const [index, actionRequirement] of (manifest.actions || []).entries()) {
            if (actionRequirement?.receipt_required !== true)
                continue;
            const business = businessAuthorizationRequirement(actionRequirement);
            if (business.configured && !business.ok) {
                throw new Error(`EMILIA Gate: invalid action-risk manifest: actions[${index}].business_authorization ${business.reason}`);
            }
        }
    }
    if (allowInlineKey) {
        // eslint-disable-next-line no-console
        console.warn('EMILIA Gate: allowInlineKey=true accepts a receipt\'s OWN key. This proves INTEGRITY (the receipt was not tampered with) but NOT issuer TRUST (anyone can mint a receipt with their own key). Use for demos only; pin trustedKeys in production.');
    }
    if (capabilityStore && (typeof capabilityStore.registerCapability !== 'function'
        || typeof capabilityStore.reserveSpend !== 'function'
        || typeof capabilityStore.commitSpend !== 'function')) {
        throw new Error('EMILIA Gate capabilityStore must implement registerCapability(), reserveSpend(), and commitSpend()');
    }
    if (capabilityStore && (!Array.isArray(capabilityTrustedIssuerKeys)
        || capabilityTrustedIssuerKeys.length === 0
        || capabilityTrustedIssuerKeys.some((key) => typeof key !== 'string' || key.length === 0))) {
        throw new Error('EMILIA Gate capabilityTrustedIssuerKeys must explicitly pin at least one capability issuer');
    }
    const effectiveCapabilityTrustedIssuerKeys = [...capabilityTrustedIssuerKeys];
    // Replay defense is only sound if the store is shared, ownership-fenced, and
    // permanent. This is a security property in every environment; NODE_ENV must
    // never silently decide whether a receipt can be replayed.
    let consumption = store;
    if (!consumption) {
        if (!allowEphemeralStore)
            throw new Error('EMILIA Gate requires a durable, ownership-fenced, permanent consumption store. '
                + 'Pass allowEphemeralStore:true only for an explicit test/demo gate.');
        consumption = new MemoryConsumptionStore();
    }
    for (const method of ['consume', 'reserve', 'commit']) {
        if (typeof consumption?.[method] !== 'function') {
            throw new Error(`EMILIA Gate consumption store must implement ${method}()`);
        }
    }
    if (!allowEphemeralStore && !isSecureConsumptionStore(consumption)) {
        throw new Error('EMILIA Gate requires a durable, ownership-fenced, permanent consumption store. '
            + 'Pass allowEphemeralStore:true only for an explicit test/demo gate.');
    }
    const evidence = log || createEvidenceLog({ strict: strictEvidence });
    async function check({ selector = {}, receipt = null, observedAction = null, consumptionMode = 'consume', admissibilityProfile = null, reliancePacket: presentedPacket = null, admissibility = null, capability = null } = {}) {
        const requirement = /** @type {any} */ (manifest ? findActionRequirement(manifest, selector) : null);
        const action = requirement?.action_type || selector.action_type || selector.action || null;
        const guarded = Boolean(requirement && requirement.receipt_required !== false);
        const runtimeCycleId = runtimeMonitor?.beginCheck({
            action,
            receipt_id: receipt?.payload?.receipt_id ?? null,
        });
        // Assurance tier the action requires (cryptographically checked below). For a
        // manifest-guarded action the tier MUST be declared explicitly: never fall
        // back to the weakest 'software' tier because assurance_class was omitted —
        // that would let a guarded, possibly critical, action accept a bare
        // machine-signed receipt (a fail-open). A guarded requirement with no tier
        // is a misconfiguration and fails closed just below. Only selector-only
        // checks (no manifest requirement) use the documented 'software' default.
        const declaredRequiredTier = requirement
            ? requirement.assurance_class
            : (selector.assurance_class || 'software');
        const requiredTier = runtimeMonitor?.minimumAssuranceTier(declaredRequiredTier) ?? declaredRequiredTier;
        const pinnedQuorumPolicy = requirement?.quorum_policy
            || (quorumPolicies && typeof quorumPolicies === 'object' ? quorumPolicies[action] : null)
            || quorumPolicy;
        const observed = observedAction || selector.observedAction || selector.actionDetails || null;
        const businessExpected = businessAuthorizationRequirement(requirement);
        let businessEvaluation = {
            required: businessExpected.configured,
            ok: !businessExpected.configured,
            reason: null,
            expected: businessExpected,
            evaluated: { policy_id: null, policy_hash: null, tenant_id: null, approvers: [] },
        };
        async function decide(allow, status, reason, extra = {}) {
            let runtimeExtra = {};
            // Cast to the real transition()/fail() runtime shape: the auto-inferred union
            // widens `ok` to `boolean` on both branches, which defeats the `!runtimeDecision.ok`
            // narrowing below (TS can't discriminate on a non-literal, same-typed property).
            const runtimeDecision = runtimeMonitor?.recordDecision(runtimeCycleId, {
                allow,
                status,
                reason,
                guarded,
                receipt_id: receipt?.payload?.receipt_id ?? null,
            });
            if (runtimeDecision && !runtimeDecision.ok) {
                allow = false;
                status = RECEIPT_REQUIRED_STATUS;
                reason = runtimeDecision.reason;
                runtimeExtra = { runtime_monitor: runtimeDecision.event };
            }
            const entry = {
                kind: 'decision',
                at: new Date(typeof now === 'function' ? now() : now).toISOString(),
                action,
                allow,
                status,
                reason,
                selector: { ...selector },
                required_tier: requiredTier,
                receipt_id: receipt?.payload?.receipt_id ?? null,
                subject: receipt?.payload?.subject ?? null,
                observed_action_hash: observed ? safeCanonicalHash(observed) : null,
                business_authorization: businessEvaluation,
                evaluated_policy_id: businessEvaluation.evaluated.policy_id,
                evaluated_policy_hash: businessEvaluation.evaluated.policy_hash,
                evaluated_tenant_id: businessEvaluation.evaluated.tenant_id,
                evaluated_approvers: businessEvaluation.evaluated.approvers,
                ...extra,
                ...runtimeExtra,
            };
            let record;
            try {
                record = await evidence.record(entry);
            }
            catch (e) {
                // The decision could not be durably recorded. Fail CLOSED: never
                // authorize an action we cannot account for. Downgrade any allow to a
                // refusal and best-effort note the downgrade (non-fatal if that fails too).
                allow = false;
                status = RECEIPT_REQUIRED_STATUS;
                reason = 'evidence_log_failed';
                try {
                    record = await evidence.record({ ...entry, allow: false, status, reason, evidence_error: String(e?.message ?? e) });
                }
                catch {
                    record = null;
                }
            }
            const out = { allow, status, reason, action, requirement, evidence: record };
            if (runtimeCycleId)
                Object.defineProperty(out, '_runtime_cycle_id', {
                    value: runtimeCycleId,
                    enumerable: false,
                });
            if (!allow) {
                out.challenge = receiptChallenge(action, reason, {
                    status: RECEIPT_REQUIRED_STATUS,
                    assuranceClass: requiredTier,
                    maxAgeSec,
                    manifest: selector.manifestUrl,
                });
                out.header = receiptRequiredHeader({ action, assuranceClass: requiredTier, maxAgeSec });
            }
            return out;
        }
        const runtimeSafeMode = runtimeMonitor?.getMode() !== RUNTIME_MONITOR_MODES.NORMAL;
        const runtimePreflight = runtimeMonitor?.preflight({ hasReceipt: Boolean(receipt) });
        if (runtimePreflight && !runtimePreflight.ok) {
            return decide(false, RECEIPT_REQUIRED_STATUS, runtimePreflight.reason, {
                runtime_mode: runtimePreflight.mode,
            });
        }
        // Manifest present and this selector is not guarded (or explicitly not required): pass through.
        // A runtime safe mode disables pass-through so every action must present
        // cryptographic signoff before the monitor permits execution again.
        if (manifest && (!requirement || requirement.receipt_required === false) && !runtimeSafeMode) {
            return decide(true, 200, 'not_guarded');
        }
        // Guarded, but no receipt was presented.
        if (!receipt) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'receipt_required');
        }
        // A capability issuance receipt is not a bearer bypass around the budget
        // path. The marker is inside the signed claim; stripping it breaks the
        // receipt signature. Such a receipt is accepted only while the capability
        // executor supplies the signed envelope and durable budget context.
        if (receipt?.payload?.claim?.capability_only === true && !capability) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'capability_required');
        }
        // A manifest-guarded action that declares no assurance_class is a
        // misconfiguration. Fail CLOSED rather than defaulting to the weakest tier
        // (which would accept a bare machine-signed receipt for a guarded action).
        // validateActionRiskManifest also rejects such a manifest at author time;
        // this is defense in depth for a manifest loaded without re-validation.
        if (requirement && requirement.receipt_required !== false && !requiredTier) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'manifest_missing_assurance_class');
        }
        // Signature / freshness / action-binding / outcome. Production key custody:
        // resolve the issuer keys valid (and not revoked) at THIS receipt's issuance
        // time. A revoked or out-of-window key is excluded, so its signature does not
        // verify and the action is refused (fail closed).
        const effectiveKeys = registry
            ? registry.keysValidAt(receipt?.payload?.created_at)
            : trustedKeys;
        const v = verifyEmiliaReceipt(receipt, {
            trustedKeys: effectiveKeys,
            allowInlineKey,
            action,
            maxAgeSec,
            now,
        });
        if (!v.ok) {
            return decide(false, RECEIPT_REQUIRED_STATUS, `receipt_rejected:${v.reason}`, { rejected: v });
        }
        // Assurance tier. CRYPTOGRAPHICALLY VERIFIED — never inferred from
        // self-asserted payload fields. The credited tier is the HIGHER of two
        // independent proof paths:
        //   (a) pinned assurance proof (payload.assurance_proof verified against
        //       pinned approverKeys) or a caller-supplied verifyAssurance hook;
        //   (b) self-contained embedded per-signer evidence (EP-QUORUM-v1 /
        //       WebAuthn device signoff) re-verified via verifyQuorum /
        //       verifyWebAuthnSignoff (DoD audit fix).
        // A receipt that only CLAIMS a higher tier earns 'software' and is refused.
        const needRank = TIER_RANK[requiredTier];
        if (needRank === undefined) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'unknown_required_tier', { have_tier: 'software', need_tier: requiredTier, assurance_tier_source: 'cryptographic_verification' });
        }
        if (needRank >= TIER_RANK.class_a && typeof verifyAssurance !== 'function'
            && (typeof rpId !== 'string' || !rpId
                || !Array.isArray(allowedOrigins) || allowedOrigins.length === 0
                || allowedOrigins.some((origin) => typeof origin !== 'string' || !origin))) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'assurance_context_unpinned', {
                have_tier: 'software', need_tier: requiredTier,
                assurance_tier_source: 'cryptographic_verification',
            });
        }
        if (requiredTier === 'quorum' && typeof verifyAssurance !== 'function') {
            const policy = validatePinnedQuorumPolicy(pinnedQuorumPolicy);
            if (!policy.ok) {
                return decide(false, RECEIPT_REQUIRED_STATUS, policy.reason, {
                    have_tier: 'software', need_tier: requiredTier,
                    assurance_tier_source: 'cryptographic_verification',
                });
            }
        }
        const assurance = evaluateReceiptAssurance(receipt, requiredTier, {
            approverKeys: approver_keys || approverKeys,
            verifyAssurance,
            rpId,
            allowedOrigins,
            quorumPolicy: pinnedQuorumPolicy,
        });
        // detail:true guarantees receiptAssuranceTier returns the AssuranceTierDetail
        // object branch, not the plain tier string.
        const tierResult = receiptAssuranceTier(receipt, {
            rpId, allowedOrigins, detail: true, approverKeys: approver_keys || approverKeys,
            verifyAssurance, quorumPolicy: pinnedQuorumPolicy,
            // Trust-laundering guard: a receipt-embedded approver key does NOT elevate
            // the tier unless it is in the pinned approverKeys set, or the operator
            // explicitly opted into the self-contained embedded-evidence mode. DEFAULT OFF.
            allowEmbeddedApproverKeys,
        });
        // Take the strongest tier either path proves.
        const have = (TIER_RANK[assurance.have] ?? 0) >= (TIER_RANK[tierResult.tier] ?? 0)
            ? assurance.have : tierResult.tier;
        if ((TIER_RANK[have] ?? 0) < needRank) {
            // The credited tier (from either proof path) is below what the action
            // requires. The canonical machine-readable reason is 'assurance_too_low';
            // main's proof-path detail (e.g. 'assurance_proof_required') is surfaced
            // separately so callers keep the diagnostic without changing the contract.
            return decide(false, RECEIPT_REQUIRED_STATUS, 'assurance_too_low', {
                have_tier: have, need_tier: requiredTier,
                assurance_tier_source: 'cryptographic_verification',
                assurance_detail: assurance.reason || null,
                tier_evidence: { quorum: tierResult.quorum, signoff: tierResult.signoff },
            });
        }
        // Business authorization is a distinct trust root from receipt issuer
        // integrity and assurance tier. The signed claim must name the exact policy
        // id+hash and tenant this action requirement pins, and the humans who
        // cryptographically earned the tier must belong to its subject/role roster.
        // This runs BEFORE execution binding, admissibility, and receipt reservation.
        businessEvaluation = verifyBusinessAuthorization({
            requirement,
            receipt,
            assurance,
            tierResult,
        });
        if (!businessEvaluation.ok) {
            return decide(false, RECEIPT_REQUIRED_STATUS, businessEvaluation.reason, {
                have_tier: have,
                assurance_tier_source: 'cryptographic_verification',
            });
        }
        // The high-risk action packs define material fields that must be observed
        // by the executor from the system of record. A signed, harmless-looking
        // claim cannot authorize a different real mutation.
        const executionBinding = verifyExecutionBinding({ requirement, receipt, observedAction: observed });
        if (!executionBinding.ok) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'execution_binding_failed', { execution_binding: executionBinding, have_tier: have, assurance_tier_source: 'cryptographic_verification' });
        }
        // OPT-IN admissibility pinning. When the caller pins a required admissibility
        // profile {id, profile_hash} (gate-level requiredAdmissibilityProfile, a
        // per-call admissibilityProfile, or selector.admissibilityProfile), the gate
        // REFUSES unless a presented reliance packet's admissibility block was computed
        // against the SAME pinned profile_hash AND carries an 'admissible' verdict. The
        // gate does NOT re-evaluate raw evidence and does NOT define the bar — the
        // relying party's own evaluator produced the verdict OFFLINE against its pinned
        // profile. Checked BEFORE consumption so a mismatch never burns the receipt.
        // When no profile is pinned, this whole block is inert — behavior is
        // byte-for-byte unchanged from the pre-admissibility gate.
        const pinnedProfile = admissibilityProfile || selector.admissibilityProfile || requiredAdmissibilityProfile;
        let trustedAdmissibility = null;
        if (pinnedProfile) {
            const presentedAdmissibility = admissibility ?? presentedPacket ?? selector.reliancePacket ?? selector.admissibility ?? null;
            if (typeof verifyAdmissibilityPacket !== 'function') {
                return decide(false, RECEIPT_REQUIRED_STATUS, 'admissibility_verifier_required', {
                    pinned_profile: { id: pinnedProfile.id ?? null, profile_hash: pinnedProfile.profile_hash ?? null },
                    have_tier: have,
                    assurance_tier_source: 'cryptographic_verification',
                });
            }
            try {
                trustedAdmissibility = await verifyAdmissibilityPacket({
                    pinned_profile: structuredClone(pinnedProfile),
                    presented: structuredClone(presentedAdmissibility),
                    receipt: structuredClone(receipt),
                    selector: structuredClone(selector),
                    observed_action: observed === null ? null : structuredClone(observed),
                });
            }
            catch {
                return decide(false, RECEIPT_REQUIRED_STATUS, 'admissibility_verification_failed', {
                    pinned_profile: { id: pinnedProfile.id ?? null, profile_hash: pinnedProfile.profile_hash ?? null },
                    have_tier: have,
                    assurance_tier_source: 'cryptographic_verification',
                });
            }
            const adm = verifyAdmissibilityAgainstPinnedProfile(pinnedProfile, trustedAdmissibility);
            if (!adm.ok) {
                return decide(false, RECEIPT_REQUIRED_STATUS, adm.reason, {
                    admissibility_check: adm,
                    pinned_profile: { id: pinnedProfile.id ?? null, profile_hash: pinnedProfile.profile_hash ?? null },
                    have_tier: have,
                    assurance_tier_source: 'cryptographic_verification',
                });
            }
        }
        const capabilityBinding = verifyCapabilityActionBinding({ capability, observedAction: observed });
        if (!capabilityBinding.ok) {
            return decide(false, RECEIPT_REQUIRED_STATUS, capabilityBinding.reason, {
                capability: {
                    ...capabilitySummary(capability, capability?.operationId),
                    ...capabilityBinding,
                },
                have_tier: have,
                assurance_tier_source: 'cryptographic_verification',
            });
        }
        // One-time consumption (replay defense). Require a stable, issuer-generated
        // receipt_id — never fall back to a content hash, whose canonicalization can
        // differ across language implementations and silently break replay detection
        // when services of different languages share a store.
        const receiptId = receipt?.payload?.receipt_id;
        if (!receiptId) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'receipt_rejected:missing_receipt_id');
        }
        let fresh;
        if (consumptionMode === 'reserve') {
            if (typeof consumption.reserve !== 'function') {
                return decide(false, RECEIPT_REQUIRED_STATUS, 'consumption_store_lacks_reserve', { consumption_key: receiptId });
            }
            fresh = await consumption.reserve(receiptId);
        }
        else if (consumptionMode === 'none') {
            fresh = true;
        }
        else {
            fresh = await consumption.consume(receiptId);
        }
        if (!fresh) {
            return decide(false, RECEIPT_REQUIRED_STATUS, 'replay_refused', { consumption_key: receiptId });
        }
        const allowExtra = {
            signer: v.signer,
            outcome: v.outcome,
            have_tier: have,
            assurance_tier_source: 'cryptographic_verification',
            execution_binding: executionBinding,
            consumption_mode: consumptionMode,
            ...(capability ? { capability: { ...capabilitySummary(capability, capability?.operationId), ...capabilityBinding } } : {}),
        };
        // Carry the admissibility block (from the presented packet) onto the decision
        // so a reliance packet built from this decision embeds the verdict the relying
        // party's evaluator computed. Only when something was actually presented.
        const presentedAdmForAllow = pinnedProfile
            ? trustedAdmissibility
            : (admissibility ?? presentedPacket ?? selector.reliancePacket ?? selector.admissibility ?? null);
        if (presentedAdmForAllow) {
            const admBlock = presentedAdmForAllow.admissibility !== undefined ? presentedAdmForAllow.admissibility : presentedAdmForAllow;
            if (admBlock)
                allowExtra.admissibility = admBlock;
        }
        return decide(true, 200, 'allow', allowExtra);
    }
    async function requestGateInput(req, opts = {}) {
        let selector = typeof opts.selector === 'function'
            ? await opts.selector(req)
            : { ...(opts.selector || {}) };
        if (!selector || typeof selector !== 'object' || Array.isArray(selector))
            selector = {};
        if (opts.action && !selector.action_type) {
            selector.action_type = typeof opts.action === 'function' ? await opts.action(req) : opts.action;
        }
        let receipt = typeof opts.receipt === 'function' ? await opts.receipt(req) : (opts.receipt ?? null);
        if (!receipt) {
            const hdr = req.headers?.['x-emilia-receipt'];
            if (hdr)
                receipt = parseReceiptCarrier(hdr);
            if (!receipt && req.body?.emilia_receipt)
                receipt = req.body.emilia_receipt;
        }
        const observedAction = typeof opts.observedAction === 'function'
            ? await opts.observedAction(req)
            : (opts.observedAction || req.emiliaObservedAction || null);
        const admissibilityProfile = typeof opts.admissibilityProfile === 'function'
            ? await opts.admissibilityProfile(req)
            : (opts.admissibilityProfile ?? null);
        const presentedPacket = typeof opts.reliancePacket === 'function'
            ? await opts.reliancePacket(req)
            : (opts.reliancePacket ?? opts.admissibility ?? null);
        const capability = typeof opts.capability === 'function'
            ? await opts.capability(req)
            : (opts.capability ?? req.emiliaCapability ?? req.body?.emilia_capability ?? null);
        return { selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket, capability };
    }
    function sendRefusal(res, authorization) {
        if (typeof res?.setHeader === 'function' && authorization.header) {
            res.setHeader(RECEIPT_REQUIRED_HEADER, authorization.header);
        }
        if (typeof res?.status === 'function' && typeof res?.json === 'function') {
            return res.status(authorization.status).json(authorization.challenge);
        }
        if (res)
            res.statusCode = authorization.status;
        if (typeof res?.end === 'function') {
            if (typeof res?.setHeader === 'function')
                res.setHeader('content-type', 'application/json');
            return res.end(JSON.stringify(authorization.challenge));
        }
        return authorization;
    }
    /**
     * Express/Connect route wrapper. The route handler itself is the effect
     * callback owned by gate.run(), so authorization, receipt reservation,
     * execution, consumption, and evidence form one lifecycle.
     */
    function route(handler, opts = {}) {
        if (typeof handler !== 'function')
            throw new Error('EMILIA Gate route(): handler is required');
        return async function emiliaGateRoute(req, res) {
            const input = await requestGateInput(req, opts);
            const out = await run(input, async (authorization) => {
                req.emiliaGate = authorization;
                return handler(req, res, authorization);
            });
            if (!out.ok)
                return sendRefusal(res, out.refusal || out.authorization);
            req.emiliaGate = out.authorization;
            req.emiliaGateExecution = out.execution;
            req.emiliaReliancePacket = out.packet;
            return out.result;
        };
    }
    /**
     * @deprecated Middleware cannot prove that code after next() actually ran.
     * It therefore fails closed without parsing or consuming a presented receipt.
     * Use gate.route(handler, opts), gate.guard(), or gate.run().
     */
    function middleware(opts = {}) {
        return async function emiliaGateDeprecatedMiddleware(req, res) {
            const selector = typeof opts.selector === 'function'
                ? await opts.selector(req)
                : { ...(opts.selector || {}) };
            const action = (selector && (selector.action_type || selector.action))
                || (typeof opts.action === 'function' ? await opts.action(req) : opts.action)
                || null;
            const reason = 'unsafe_middleware_deprecated';
            const challenge = receiptChallenge(action, reason, {
                status: RECEIPT_REQUIRED_STATUS,
                assuranceClass: selector?.assurance_class || null,
                maxAgeSec,
                manifest: selector?.manifestUrl,
            });
            const authorization = {
                allow: false,
                status: RECEIPT_REQUIRED_STATUS,
                reason,
                action,
                challenge,
                header: receiptRequiredHeader({ action, assuranceClass: selector?.assurance_class || null, maxAgeSec }),
            };
            return sendRefusal(res, authorization);
        };
    }
    /**
     * Emit a post-execution receipt bound to a prior authorization decision — the
     * "execution emits proof" half of the loop (maps to the EP Commit seal). It
     * commits to the exact authorization decision (`authorizes_decision` = that
     * decision's evidence hash), so authorization and execution are one chain.
     */
    async function recordExecution({ authorization, outcome = 'executed', detail, observedAction = null, executionBinding = null } = {}) {
        const auth = authorization?.evidence || authorization || {};
        const authorizationBinding = authorization?.evidence?.execution_binding
            || authorization?.execution_binding
            || executionBinding
            || null;
        const boundExecution = bindExecutionProof({
            authorization,
            observedAction,
            binding: authorizationBinding,
        });
        return evidence.record({
            kind: 'execution',
            at: new Date(typeof now === 'function' ? now() : now).toISOString(),
            authorizes_decision: auth.hash ?? null,
            action: authorization?.action ?? auth.action ?? null,
            receipt_id: auth.receipt_id ?? null,
            outcome, // 'executed' | 'failed'
            observed_action_hash: observedAction ? safeCanonicalHash(observedAction) : null,
            execution_binding: boundExecution,
            ...(detail !== undefined ? { detail } : {}),
        });
    }
    async function recordCapabilityEvent({ authorization, capability, outcome, reason = null } = {}) {
        return evidence.record({
            kind: 'capability',
            at: new Date(typeof now === 'function' ? now() : now).toISOString(),
            authorizes_decision: authorization?.evidence?.hash ?? null,
            action: authorization?.action ?? null,
            ...capabilitySummary(capability, capability?.operationId),
            outcome,
            ...(reason ? { reason } : {}),
        });
    }
    function capabilityRefusal({ authorization = null, capability = null, reason, status = CAPABILITY_FAILURE_STATUS, event = null } = {}) {
        const body = {
            rejected: {
                type: 'capability',
                reason,
                ...capabilitySummary(capability, capability?.operationId),
            },
        };
        return {
            ok: false,
            status,
            body,
            authorization,
            refusal: {
                allow: false,
                status,
                reason,
                action: authorization?.action ?? null,
                challenge: body,
                header: null,
            },
            capability: { reason, ...capabilitySummary(capability, capability?.operationId) },
            evidence: event,
        };
    }
    /**
     * Capability-backed execution is the real Marvel guard path. The ordinary
     * EP receipt is verified first without consuming it; the capability store
     * then reserves the exact observed monetary amount before the effect. A
     * successful effect commits the reservation, while an exception commits it
     * as indeterminate so the budget can never silently reopen.
     */
    async function runCapability({ selector = {}, receipt = null, observedAction = null, admissibilityProfile = null, reliancePacket: presentedPacket = null, admissibility = null, capability = null } = {}, fn, opts = {}) {
        if (!capabilityStore)
            return capabilityRefusal({ capability, reason: 'capability_store_required', status: 500 });
        if (!capability || typeof capability !== 'object' || Array.isArray(capability)
            || !capability.capabilityReceipt || !capability.action) {
            return capabilityRefusal({ capability, reason: 'capability_request_invalid' });
        }
        if (typeof capability.operationId !== 'string' || capability.operationId.length === 0
            || Buffer.byteLength(capability.operationId, 'utf8') > 128) {
            return capabilityRefusal({ capability, reason: 'capability_operation_id_required' });
        }
        const operationId = capability.operationId;
        const context = { ...capability, operationId };
        const baseReceipt = capability.capabilityReceipt.receipt;
        if (receipt && safeCanonicalHash(receipt) !== safeCanonicalHash(baseReceipt)) {
            return capabilityRefusal({ capability: context, reason: 'capability_receipt_mismatch' });
        }
        let authorization = null;
        let effectError = null;
        let effectStarted = false;
        const capabilityGate = {
            check: (input = {}) => check({
                ...input,
                capability: {
                    capabilityReceipt: context.capabilityReceipt,
                    action: context.action,
                    operationId,
                },
            }),
        };
        const executeAction = async (_action, executionContext) => {
            authorization = executionContext.authorization;
            const runtimeCycleId = authorization?._runtime_cycle_id;
            const runtimeStart = runtimeMonitor?.beginExecution(runtimeCycleId, authorization);
            if (runtimeStart && !runtimeStart.ok) {
                const error = new Error(`EMILIA Gate runtime monitor refused capability execution (${runtimeStart.reason})`);
                error.code = 'EMILIA_RUNTIME_MONITOR_REFUSED';
                throw error;
            }
            effectStarted = true;
            try {
                const value = await fn(authorization, {
                    operationId,
                    providerIdempotencyKey: operationId,
                    actionDigest: executionContext.action_digest,
                    observedAction: executionContext.observed_action,
                });
                runtimeMonitor?.effectReturned(runtimeCycleId);
                return value;
            }
            catch (error) {
                effectError = error;
                runtimeMonitor?.effectFailed(runtimeCycleId);
                throw error;
            }
        };
        const executorInput = {
            capabilityReceipt: context.capabilityReceipt,
            action: context.action,
            store: capabilityStore,
            gate: capabilityGate,
            selector,
            observedAction,
            trustedIssuerKeys: effectiveCapabilityTrustedIssuerKeys,
            resolveCaid: capabilityCaidResolver,
            operationId,
            now,
            executeAction,
        };
        const capabilityResult = Array.isArray(context.shares)
            ? await executeWithThreshold(/** @type {any} */ ({ ...executorInput, shares: context.shares }))
            : await executeWithCapability(/** @type {any} */ ({ ...executorInput, secret: context.secret }));
        authorization = authorization || capabilityResult.authorization || null;
        const runtimeCycleId = authorization?._runtime_cycle_id;
        if (capabilityResult.ok) {
            runtimeMonitor?.consumptionCommitted(runtimeCycleId);
            if (opts.recordExecution === false) {
                runtimeMonitor?.executionSkipped(runtimeCycleId);
                return { ok: true, result: capabilityResult.result, authorization, execution: null, packet: null, capability: capabilityResult };
            }
            const execution = await recordExecution({
                authorization,
                outcome: 'executed',
                observedAction,
                detail: { capability: { ...capabilitySummary(context, operationId), outcome: 'executed' } },
            });
            runtimeMonitor?.executionRecorded(runtimeCycleId);
            const packet = await reliancePacket({ authorization, execution });
            return { ok: true, result: capabilityResult.result, authorization, execution, packet, capability: capabilityResult };
        }
        if (effectStarted && (capabilityResult.reason === 'effect_indeterminate'
            || capabilityResult.reason === 'capability_commit_indeterminate')) {
            if (capabilityResult.reason === 'effect_indeterminate')
                runtimeMonitor?.consumptionCommitted(runtimeCycleId);
            const execution = opts.recordExecution === false ? null : await recordExecution({
                authorization,
                outcome: 'indeterminate',
                observedAction,
                detail: {
                    code: 'effect_attempted_outcome_unknown',
                    capability: { ...capabilitySummary(context, operationId), outcome: 'indeterminate' },
                },
            });
            if (capabilityResult.reason === 'effect_indeterminate' && opts.recordExecution !== false) {
                runtimeMonitor?.executionRecorded(runtimeCycleId);
            }
            if (effectError)
                throw effectError;
            return capabilityRefusal({ authorization, capability: context, reason: capabilityResult.reason, event: execution });
        }
        if (authorization?.allow === true) {
            const event = await recordCapabilityEvent({
                authorization,
                capability: context,
                outcome: 'refused',
                reason: capabilityResult.reason,
            });
            runtimeMonitor?.capabilityRefused(runtimeCycleId);
            return capabilityRefusal({ authorization, capability: context, reason: capabilityResult.reason, event });
        }
        if (authorization) {
            return {
                ok: false,
                status: authorization.status,
                body: authorization.challenge,
                authorization,
                refusal: authorization,
                capability: { reason: capabilityResult.reason, ...capabilitySummary(context, operationId) },
            };
        }
        return capabilityRefusal({ authorization, capability: context, reason: capabilityResult.reason, status: RECEIPT_REQUIRED_STATUS });
    }
    /**
     * Recommended end-to-end path. Reserves the receipt, runs the side effect,
     * commits one-time consumption after the effect attempt, and records execution.
     * Once the executor is invoked, an exception is an INDETERMINATE outcome: the
     * external effect may have happened before its response was lost. The receipt
     * is therefore committed (or left reserved if the store is unavailable),
     * never released automatically. Callers that need retries must make the
     * downstream effect idempotent under the receipt id and reconcile its result.
     */
    async function run({ selector = {}, receipt = null, observedAction = null, admissibilityProfile = null, reliancePacket: presentedPacket = null, admissibility = null, capability = null } = {}, fn, opts = {}) {
        if (typeof fn !== 'function')
            throw new Error('EMILIA Gate run(): fn is required');
        if (capability) {
            return runCapability({ selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket, admissibility, capability }, fn, opts);
        }
        const authorization = await check({ selector, receipt, observedAction, consumptionMode: 'reserve', admissibilityProfile, reliancePacket: presentedPacket, admissibility });
        if (!authorization.allow) {
            return { ok: false, status: authorization.status, body: authorization.challenge, authorization };
        }
        const receiptId = authorization.evidence?.receipt_id;
        const runtimeCycleId = authorization._runtime_cycle_id;
        if (runtimeMonitor && runtimeCycleId) {
            const runtimeStart = runtimeMonitor.beginExecution(runtimeCycleId, authorization);
            if (!runtimeStart.ok) {
                const error = new Error(`EMILIA Gate runtime monitor refused execution (${runtimeStart.reason})`);
                error.code = 'EMILIA_RUNTIME_MONITOR_REFUSED';
                throw error;
            }
        }
        let phase = 'reserved';
        let consumptionCommitted = false;
        try {
            phase = 'effect_attempted';
            const result = await fn(authorization);
            phase = 'effect_returned';
            runtimeMonitor?.effectReturned(runtimeCycleId);
            if (typeof consumption.commit === 'function')
                await consumption.commit(receiptId);
            consumptionCommitted = true;
            phase = 'consumed';
            runtimeMonitor?.consumptionCommitted(runtimeCycleId);
            if (opts.recordExecution === false) {
                runtimeMonitor?.executionSkipped(runtimeCycleId);
                return { ok: true, result, authorization, execution: null, packet: null };
            }
            phase = 'recording_execution';
            const execution = await recordExecution({ authorization, outcome: 'executed', observedAction });
            runtimeMonitor?.executionRecorded(runtimeCycleId);
            const packet = await reliancePacket({ authorization, execution });
            return { ok: true, result, authorization, execution, packet };
        }
        catch (e) {
            if (runtimeMonitor && runtimeCycleId && (phase === 'effect_attempted' || phase === 'effect_returned')) {
                runtimeMonitor.effectFailed(runtimeCycleId);
            }
            // An exception after invoking fn() cannot establish that no external
            // effect occurred. Burn the approval if possible; if storage is down, the
            // ownership-fenced reservation remains and still blocks replay.
            let consumptionError = null;
            if (!consumptionCommitted && phase !== 'reserved' && typeof consumption.commit === 'function') {
                try {
                    await consumption.commit(receiptId);
                    consumptionCommitted = true;
                    phase = 'consumed';
                    runtimeMonitor?.consumptionCommitted(runtimeCycleId);
                }
                catch (commitError) {
                    consumptionError = commitError;
                }
            }
            if (opts.recordExecution !== false && phase !== 'recording_execution') {
                try {
                    await recordExecution({
                        authorization,
                        outcome: 'indeterminate',
                        // Exception text frequently contains provider payloads, record IDs,
                        // or secrets. The caller still receives the original exception;
                        // the portable evidence record carries only the closed outcome.
                        detail: { code: 'effect_attempted_outcome_unknown' },
                        observedAction,
                    });
                    const runtimeState = runtimeMonitor?.getState(runtimeCycleId);
                    if (runtimeState && runtimeState.complete !== true) {
                        runtimeMonitor?.executionRecorded(runtimeCycleId);
                    }
                }
                catch (recordError) {
                    if (!consumptionError)
                        consumptionError = recordError;
                }
            }
            if (consumptionError && e && typeof e === 'object') {
                e.consumption_error = String(consumptionError?.message ?? consumptionError);
            }
            throw e;
        }
    }
    /**
     * Wrap any function so it runs only behind a passing gate check, and (unless
     * disabled) emits an execution receipt after it runs — the full firewall loop:
     * request -> check -> execute -> execution receipt. Framework-agnostic.
     */
    function guard(fn, opts = {}) {
        return async function guarded(...args) {
            // Guard providers may load the selector, receipt, or system-of-record
            // action asynchronously. Resolve each one before check() so a Promise
            // object can never be mistaken for a selector/receipt and accidentally
            // bypass the manifest's guarded action requirement.
            const selector = typeof opts.selector === 'function'
                ? await opts.selector(...args)
                : (opts.selector || {});
            const receipt = typeof opts.receipt === 'function'
                ? await opts.receipt(...args)
                : (opts.receipt ?? null);
            const observedAction = typeof opts.observedAction === 'function'
                ? await opts.observedAction(...args)
                : (opts.observedAction || selector.observedAction || null);
            const admissibilityProfile = typeof opts.admissibilityProfile === 'function'
                ? await opts.admissibilityProfile(...args)
                : (opts.admissibilityProfile ?? null);
            const presentedPacket = typeof opts.reliancePacket === 'function'
                ? await opts.reliancePacket(...args)
                : (opts.reliancePacket ?? opts.admissibility ?? null);
            const capability = typeof opts.capability === 'function'
                ? await opts.capability(...args)
                : (opts.capability ?? null);
            const out = await run({ selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket, capability }, () => fn(...args), { recordExecution: opts.recordExecution });
            if (!out.ok) {
                const refusal = out.refusal || out.authorization;
                const e = new Error(`EMILIA Gate refused (${refusal.reason})`);
                e.code = 'EMILIA_RECEIPT_REQUIRED';
                e.gate = refusal;
                throw e;
            }
            return out.result;
        };
    }
    async function reliancePacket({ authorization, execution = null, binding = null, admissibility = null } = {}) {
        // The admissibility block rides on the authorization decision's evidence when
        // a reliance packet was presented at check() time; an explicit `admissibility`
        // arg overrides it. buildReliancePacket fails closed on a non-'admissible'
        // block, so a do_not_rely verdict can never be laundered into rely here.
        const adm = admissibility
            ?? authorization?.evidence?.admissibility
            ?? authorization?.admissibility
            ?? null;
        return buildReliancePacket({
            decision: authorization,
            execution,
            evidence,
            manifest,
            binding: binding || execution?.execution_binding || null,
            admissibility: adm,
        });
    }
    /** Retention classification over this gate's evidence log (hot/cold/expired/legal-hold). */
    function retention(opts = {}) {
        return classifyRetention(evidence.all(), opts);
    }
    /** The auditor/SIEM export manifest for this gate's evidence log. */
    function retentionExport(opts = {}) {
        return buildRetentionExport(evidence.all(), opts);
    }
    return {
        check, run, recordExecution, route, wrapRoute: route, middleware, guard, reliancePacket, evidence,
        store: consumption, capabilityStore, keyRegistry: registry, retention, retentionExport,
    };
}
export function createTrustedActionFirewall(opts = {}) {
    const { manifest = createDefaultActionRiskManifest(), ...rest } = opts;
    return createGate({ ...rest, manifest });
}
/**
 * EG-1 conformance for an existing gate. The gate MUST have been built trusting
 * `harness.publicKey` (otherwise every valid receipt is rejected and the gate
 * cannot earn EG-1). Returns the EG-1 JSON report.
 * @param {object} [o]
 * @param {object} [o.gate]     an EMILIA Gate (createGate/createTrustedActionFirewall)
 * @param {object} [o.harness]  the harness whose key the gate trusts (createEg1Harness)
 * @param {object} [o.action] the high-risk action to exercise
 * @param {object} [o.selector] the manifest selector for that action
 */
export async function gateConformance({ gate, harness, action, selector = EG1_DEFAULT_SELECTOR } = {}) {
    if (!gate || typeof gate.run !== 'function') {
        throw new Error('gateConformance requires a gate built trusting harness.publicKey');
    }
    if (!harness)
        throw new Error('gateConformance requires the harness whose key the gate trusts');
    const act = action || harness.action;
    const invoke = makeGateInvoke(gate, { selector, action: act });
    return runEg1({ invoke, harness, action: act });
}
/**
 * Self-certify the reference gate: build a default Consequence Firewall that
 * trusts a fresh EG-1 harness key, then run all eight checks. This is the
 * canonical "EMILIA Gate earns EG-1" proof — runnable as a CLI (`eg1.mjs`),
 * shown on /gate, and the template an adopter copies for their integration.
 * @param {{now?: any}} [o]
 */
export async function gateConformanceSelfTest({ now } = {}) {
    const harness = createEg1Harness({ now });
    const gate = createTrustedActionFirewall({
        trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys,
        rpId: harness.rpId, allowedOrigins: harness.allowedOrigins,
        now, allowEphemeralStore: true,
    });
    return gateConformance({ gate, harness });
}
/**
 * CF-1 (Consequence Firewall) conformance for an existing gate. Runs the eight
 * EG-1 runtime checks plus the three CF-1 category checks: the action is
 * declared consequential by the manifest, a gate pinned to the WRONG issuer key
 * refuses a valid receipt, and the allowed run emits offline-verifiable reliance
 * evidence. The `gate` MUST trust `harness.publicKey`; `wrongGate` MUST trust a
 * DIFFERENT key (otherwise wrong_authority_refused cannot be demonstrated).
 * @param {object} [o]
 * @param {object} [o.gate]       an EMILIA Gate trusting harness.publicKey
 * @param {object} [o.wrongGate] a sibling gate trusting a different (wrong) key
 * @param {object} [o.harness]    from createEg1Harness()
 * @param {object} [o.manifest] the action-risk manifest (to resolve the requirement)
 * @param {object} [o.selector] the manifest selector for the action
 * @param {object} [o.action]   the high-risk action to exercise
 */
export async function cf1Conformance({ gate, wrongGate, harness, manifest = null, selector = EG1_DEFAULT_SELECTOR, action } = {}) {
    if (!gate || typeof gate.run !== 'function')
        throw new Error('cf1Conformance requires a gate built trusting harness.publicKey');
    if (!harness)
        throw new Error('cf1Conformance requires the harness whose key the gate trusts');
    const act = action || harness.action;
    const invoke = makeGateInvoke(gate, { selector, action: act });
    const wrongInvoke = (wrongGate && typeof wrongGate.run === 'function')
        ? makeGateInvoke(wrongGate, { selector, action: act }) : undefined;
    const requirement = manifest ? findActionRequirement(manifest, selector) : null;
    return runCf1({ invoke, wrongInvoke, harness, action: act, requirement });
}
/**
 * Self-certify the reference gate against CF-1: a default Trusted Action
 * Firewall trusting a fresh harness key, a sibling firewall trusting a DIFFERENT
 * key (for wrong_authority_refused), and the default action-risk manifest (for
 * consequential_action_declared). The canonical "reference gate earns CF-1"
 * proof — runnable as a CLI (`cf1.mjs`).
 * @param {{now?: any}} [o]
 */
export async function cf1ConformanceSelfTest({ now } = {}) {
    const harness = createEg1Harness({ now });
    const manifest = createDefaultActionRiskManifest();
    const gate = createTrustedActionFirewall({
        trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys,
        rpId: harness.rpId, allowedOrigins: harness.allowedOrigins,
        now, allowEphemeralStore: true,
    });
    const wrongHarness = createEg1Harness({ now });
    const wrongGate = createTrustedActionFirewall({
        trustedKeys: [wrongHarness.publicKey], approverKeys: wrongHarness.approverKeys,
        rpId: wrongHarness.rpId, allowedOrigins: wrongHarness.allowedOrigins,
        now, allowEphemeralStore: true,
    });
    return cf1Conformance({ gate, wrongGate, harness, manifest, selector: EG1_DEFAULT_SELECTOR, action: harness.action });
}
export default {
    createGate,
    createTrustedActionFirewall,
    runBreakGlass,
    receiptAssuranceTier,
    businessAuthorizationRequirement,
    verifyBusinessAuthorization,
    verifyAdmissibilityAgainstPinnedProfile,
    ADMISSIBILITY_VERDICTS,
    MemoryConsumptionStore,
    createEvidenceLog,
    createAtomicEvidenceLog,
    createMemoryAtomicEvidenceBackend,
    ASSURANCE_TIERS,
    DEFAULT_GATE_MANIFEST,
    HIGH_RISK_ACTION_PACKS,
    gateConformance,
    gateConformanceSelfTest,
    cf1Conformance,
    cf1ConformanceSelfTest,
    CF1_VERSION,
    CF1_CHECKS,
    runCf1,
    createEg1Harness,
    runEg1,
    createKeyRegistry,
    asKeyRegistry,
    classifyRetention,
    buildRetentionExport,
    createDefaultActionControlManifest,
    findActionControl,
    validateActionControlManifest,
    createRuntimeMonitor,
    RUNTIME_MONITOR_VERSION,
    RUNTIME_MONITOR_MODES,
    RUNTIME_INVARIANTS,
    FORMAL_RUNTIME_BRIDGE_VERSION,
    FORMAL_RUNTIME_SPEC,
    FORMAL_RUNTIME_CONFIG,
    FORMAL_RUNTIME_INVARIANT_MAP,
    CAPABILITY_RECEIPT_VERSION,
    CAPABILITY_STATE_VERSION,
    CAPABILITY_SHARE_VERSION,
    CAPABILITY_SCOPE_PROFILE,
    CAPABILITY_CAID_SCOPE_PROFILE,
    CAPABILITY_STATE_DDL,
    CAPABILITY_SQL,
    capabilityBaseReceiptDigest,
    capabilityActionDigest,
    verifyCapabilityScope,
    mintCapabilityReceipt,
    verifyCapabilityReceipt,
    splitCapabilitySecret,
    reconstructCapabilitySecret,
    createMemoryCapabilityStore,
    createPostgresCapabilityStore,
    executeWithCapability,
    executeWithThreshold,
    reconcileCapabilityOperation,
    ZK_RANGE_RECEIPT_VERSION,
    ZK_RANGE_SCHEME,
    ZK_RANGE_BACKEND_PACKAGE,
    deriveZkRangeBases,
    loadBulletproofBackend,
    mintZkRangeReceipt,
    verifyZkRangeReceipt,
};
//# sourceMappingURL=index.js.map