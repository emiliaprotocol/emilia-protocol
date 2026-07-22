import { receiptChallenge } from '@emilia-protocol/require-receipt';
import { MemoryConsumptionStore } from './store.js';
import { canonicalEvidenceJson, createAtomicEvidenceLog, createEvidenceLog, createMemoryAtomicEvidenceBackend } from './evidence.js';
import { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest } from './action-packs.js';
import { createEg1Harness, runEg1 } from './eg1-conformance.js';
import { runCf1 } from './cf1-conformance.js';
import { createKeyRegistry, asKeyRegistry } from './key-registry.js';
import { classifyRetention, buildRetentionExport } from './retention.js';
import { createDefaultActionControlManifest, findActionControl, resolveActionControl, validateActionControlManifest } from './action-control-manifest.js';
import { createRuntimeMonitor } from './runtime-monitor.js';
import { capabilityBaseReceiptDigest, capabilityActionDigest, verifyCapabilityScope, mintCapabilityReceipt, verifyCapabilityReceipt, splitCapabilitySecret, reconstructCapabilitySecret, createMemoryCapabilityStore, createPostgresCapabilityStore, executeWithCapability, executeWithThreshold, reconcileCapabilityOperation } from './capability-receipt.js';
import { deriveZkRangeBases, loadBulletproofBackend, mintZkRangeReceipt, verifyZkRangeReceipt } from './zk-range-proof.js';
import { mintBreakGlassAuthorization, verifyBreakGlass, consumeBreakGlass, buildBreakGlassEvidence, runBreakGlass, BREAKGLASS_VERSION, BREAKGLASS_EVIDENCE_KIND } from './breakglass.js';
type Obj = Record<string, any>;
/** Shared shape for the `opts`/selector-bag argument accepted by route(), guard(),
 * requestGateInput(), run(), and runCapability(). Each field may be a literal value
 * or a `(req) => value` resolver function; see requestGateInput for resolution. */
interface GateCallOpts {
    selector?: any;
    action?: any;
    receipt?: any;
    observedAction?: any;
    admissibilityProfile?: any;
    reliancePacket?: any;
    admissibility?: any;
    capability?: any;
    recordExecution?: boolean;
}
export { MemoryConsumptionStore, canonicalEvidenceJson, createEvidenceLog, createAtomicEvidenceLog, createMemoryAtomicEvidenceBackend, };
export { createDurableConsumptionStore, createMemoryBackend, isSecureConsumptionStore, DURABLE_CONSUMPTION_VERSION, } from './store.js';
export { createDurableChallengeStore, challengeStorageKey, challengeBodyDigest, DURABLE_CHALLENGE_STORE_VERSION } from './challenge-store.js';
export { createKeyRegistry, asKeyRegistry } from './key-registry.js';
export { classifyRetention, buildRetentionExport, RETENTION_EXPORT_VERSION } from './retention.js';
export { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest };
export { ACTION_CONTROL_MANIFEST_VERSION, ACTION_CONTROL_SCHEMA_URL, ACTION_CONTROL_CONFORMANCE_LEVEL, ACTION_CONTROL_DEFAULTS, ACTION_CONTROL_EVIDENCE_PROFILES, ACTION_CONTROL_CONFORMANCE_CHECKS, toActionControl, createDefaultActionControlManifest, findActionControl, resolveActionControl, validateActionControlManifest, } from './action-control-manifest.js';
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
export { RECEIPT_PROGRAM_VERSION, RECEIPT_PROGRAM_CERTIFICATE_VERSION, RECEIPT_PROGRAM_SIGNATURE_ALGORITHM, createReceiptProgramKernel, verifyReceiptProgramCertificate, } from './receipt-program.js';
export { TRUST_PROGRAM_VERSION, TRUST_STAGE_RECEIPT_VERSION, validateTrustProgram, trustProgramDigest, verifyTrustStageReceipt, createMemoryTrustProgramStore, createTrustProgramKernel, } from './trust-program.js';
export { TRUST_PROGRAM_REVOCATION_TARGET_VERSION, deriveTrustProgramRevocationTargetObject, deriveTrustProgramRevocationTarget, verifyTrustProgramRevocation, applyTrustProgramRevocation, } from './trust-program-revocation.js';
export { REMEDY_PROGRAM_VERSION, createRemedyMemoryStore, createRemedyProgramKernel, } from './remedy-program.js';
export { ACTION_REMEDY_RECEIPT_VERSION, REMEDY_PROGRAM_RECEIPT_VERSION, ACTION_REMEDY_RECEIPT_DOMAIN, expectedRemedyProgramReceiptBindings, remedyProgramReceiptSigningBytes, issueRemedyProgramReceipt, signRemedyProgramReceipt, createRemedyProgramReceipt, verifyRemedyProgramReceipt, } from './remedy-program-receipt.js';
export { REMEDY_PROGRAM_PG_STORE_VERSION, REMEDY_PROGRAM_MAX_STATE_BYTES, REMEDY_PROGRAM_MAX_FORWARD_SKEW_MINUTES, REMEDY_PROGRAM_POSTGRES_SQL, createRemedyProgramPostgresStore, } from './remedy-program-postgres.js';
export { PROPOSAL_TO_EFFECT_VERSION, proposalToEffectConsumptionNonce, createProposalToEffect, } from './proposal-to-effect.js';
export declare const ASSURANCE_TIERS: string[];
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
export declare function verifyAdmissibilityAgainstPinnedProfile(pinned: any, presented: any): {
    ok: boolean;
    reason: string;
    pinned_hash: any;
    presented_hash: any;
    verdict: any;
} | {
    ok: boolean;
    reason: null;
    pinned_hash: any;
    presented_hash: any;
    verdict: any;
};
/**
 * The assurance tier a receipt has CRYPTOGRAPHICALLY EARNED.
 *
 * SECURITY: the credited tier is NEVER inferred from self-asserted payload
 * fields. A bare `quorum:{signers,threshold}` block or an `outcome:
 * 'allow_with_signoff'` string with no verifiable signature earns only
 * `software` — it will be refused `assurance_too_low` by any guard that needs
 * more. Fail-closed by construction.
 *
 * Two independent cryptographic proof shapes are accepted; a receipt earns the
 * HIGHEST tier any of them proves:
 *
 *  (a) Pinned assurance proof (`payload.assurance_proof`, EP-ASSURANCE-PROOF-v1):
 *      per-signer signatures verified against PINNED approver keys (opts.approverKeys)
 *      or a caller-supplied verifier (opts.verifyAssurance). This is the primary,
 *      strongest model — the verifier never trusts a key that travels inside the
 *      receipt. Delegated to require-receipt's receiptAssuranceTierFromProof.
 *
 *  (b) Embedded evidence (DoD audit fix): a full EP-QUORUM-v1
 *      document (payload.quorum) whose per-signer WebAuthn assertions verify via
 *      verifyQuorum (distinct humans + distinct keys + threshold + action-binding
 *      + window) earns `quorum`; a WebAuthn device signoff (payload.signoff =
 *      {context, webauthn}) that verifies against the approver's own key via
 *      verifyWebAuthnSignoff earns `class_a`. Quorum additionally requires an
 *      out-of-band organizational policy and identity-bound approver directory.
 *
 *      TRUST-LAUNDERING GUARD: an approver key carried INSIDE the receipt proves
 *      only that whoever minted the receipt also holds that key — it is NOT proof
 *      the relying party trusts that human. Crediting an elevated tier off such a
 *      key would collapse VERIFIED into ACCEPTED (any party can mint a fresh
 *      keypair, self-sign a signoff, and embed both). So path (b) elevates the
 *      tier ONLY when either: (i) the caller explicitly opts in with
 *      `allowEmbeddedApproverKeys:true` for a single Class-A integrity demo
 *      (DEFAULT OFF); or (ii) the embedded approver key that would earn the
 *      credit is present in the relying party's PINNED approver key set
 *      (opts.approverKeys). With no pin and no opt-in, path (b) may still VERIFY
 *      the signoff/quorum, but it does NOT elevate above `software`. Fail-closed.
 *
 * @param {object} doc  the EP-RECEIPT-v1 document
 * @param {object} [opts]
 * @param {object} [opts.approverKeys] pinned approver keys for path (a) and the
 *   path-(b) fallback: a receipt-embedded approver key elevates the tier only if
 *   it is one of these pinned keys (unless allowEmbeddedApproverKeys is set)
 * @param {boolean} [opts.allowEmbeddedApproverKeys=false] explicit opt-in where
 *   one unpinned embedded key may earn Class-A integrity. It never earns quorum.
 * @param {object} [opts.quorumPolicy] relying-party-pinned organizational rule
 * @param {function|null} [opts.verifyAssurance] custom assurance verifier for path (a)
 * @param {string|null} [opts.rpId]  bind embedded device assertions to this WebAuthn RP id (path b)
 * @param {string[]} [opts.allowedOrigins] exact WebAuthn origins accepted for embedded-evidence verification (path b)
 * @param {object} [opts.quorum_policy] legacy snake_case alias for opts.quorumPolicy
 * @param {boolean} [opts.detail] return a {tier, quorum, signoff} object instead of the string
 * @returns {'software'|'class_a'|'quorum'|object} the highest tier proven
 */
interface AssuranceQuorumDetail {
    valid: boolean;
    checks: Obj;
    policy_pinned: boolean;
    embedded_keys_trusted: boolean;
    approvers: string[];
    roles: {
        subject: string | null;
        role: string | null;
    }[];
    refusal: string | null;
}
interface AssuranceSignoffDetail {
    valid: boolean;
    checks: Obj;
    embedded_key_trusted: boolean;
    approver: string | null;
}
interface AssuranceTierDetail {
    tier: string;
    quorum: AssuranceQuorumDetail | null;
    signoff: AssuranceSignoffDetail | null;
}
interface ReceiptAssuranceOpts {
    approverKeys?: Obj;
    allowEmbeddedApproverKeys?: boolean;
    quorumPolicy?: Obj | null;
    quorum_policy?: Obj | null;
    verifyAssurance?: ((...args: any[]) => any) | null;
    rpId?: string | null;
    allowedOrigins?: readonly string[];
    detail?: boolean;
}
export declare function receiptAssuranceTier(doc: any, opts?: ReceiptAssuranceOpts): string | AssuranceTierDetail;
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
export declare function businessAuthorizationRequirement(requirement: any): {
    configured: boolean;
    ok: boolean;
    reason: string | null;
    policy_id: string | null;
    policy_hash: string | null;
    tenant_id: string | null;
    allowed_approvers: {
        subject: string | null;
        role: string | null;
    }[];
};
/**
 * Verify signed business-policy and tenant fields plus the cryptographically
 * credited human approvers against one action's relying-party pins.
 * @returns {{required:boolean, ok:boolean, reason:string|null, expected:object, evaluated:{policy_id:string|null, policy_hash:string|null, tenant_id:string|null, approvers:{subject:string, roles:string[]}[]}}}
 */
export declare function verifyBusinessAuthorization({ requirement, receipt, assurance, tierResult }?: {
    requirement?: any;
    receipt?: any;
    assurance?: any;
    tierResult?: any;
}): {
    ok: boolean;
    reason: string | null;
    required: boolean;
    expected: {
        configured: boolean;
        ok: boolean;
        reason: string | null;
        policy_id: string | null;
        policy_hash: string | null;
        tenant_id: string | null;
        allowed_approvers: {
            subject: string | null;
            role: string | null;
        }[];
    };
    evaluated: {
        policy_id: unknown;
        policy_hash: unknown;
        tenant_id: unknown;
        approvers: {
            subject: unknown;
            roles: string[];
        }[];
    };
};
/**
 * Create a gate.
 * @param {object} opts
 * @param {object} [opts.manifest]      EP-ACTION-RISK-MANIFEST-v0.1 (which actions are guarded, their tier)
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER issuer keys you trust
 * @param {number} [opts.maxAgeSec=900] reject receipts older than this
 * @param {object} [opts.store]         durable, ownership-fenced, permanent consumption store
 * @param {object} [opts.capabilityStore] Marvel capability budget store. A
 *   capability run reserves here before the effect and commits after it.
 * @param {string[]} [opts.capabilityTrustedIssuerKeys] pinned capability
 *   envelope issuer keys. Required when capabilityStore is configured.
 * @param {function|null} [opts.capabilityCaidResolver] relying-party-pinned resolver
 *   for `urn:emilia:scope:caid-set-v1`. Missing resolver fails CAID scope closed.
 * @param {boolean} [opts.allowEphemeralStore=false] explicit test/demo opt-in for in-memory state
 * @param {object} [opts.log]           evidence log (default in-memory, hash-chained)
 * @param {boolean} [opts.allowInlineKey=false] accept the receipt's own key (integrity, NOT trust)
 * @param {object} [opts.keyRegistry] a key registry (createKeyRegistry) for rotation + revocation;
 *   if given it supersedes trustedKeys — a receipt is verified only against keys valid (and not
 *   revoked) at its issuance time.
 * @param {object} [opts.approverKeys] PINNED approver keys ({ keyId: { public_key, key_class } }).
 *   Used both for the pinned assurance-proof path and to authorize receipt-embedded
 *   approver keys under the self-contained embedded-evidence path.
 * @param {boolean} [opts.allowEmbeddedApproverKeys=false] allow one embedded key
 *   to earn Class-A integrity in demos. Embedded keys never establish quorum.
 * @param {object} [opts.quorumPolicy] global relying-party-pinned quorum rule
 * @param {object} [opts.quorumPolicies] action_type -> pinned quorum rule
 * @param {string|null} [opts.rpId] WebAuthn relying-party identifier. Required for
 *   built-in Class-A or quorum assurance verification.
 * @param {string[]} [opts.allowedOrigins] exact WebAuthn origins accepted by the
 *   relying party. Required for built-in Class-A or quorum verification.
 * @param {function|null} [opts.verifyAdmissibilityPacket] trusted relying-party hook.
 *   Required whenever an admissibility profile is pinned. It must authenticate
 *   the presented packet or recompute the verdict and return the trusted block.
 * @param {boolean} [opts.strictEvidence=true] make the evidence log strict (fail on record errors)
 * @param {() => number} [opts.now] clock source (defaults to Date.now)
 * @param {object|null} [opts.approver_keys] legacy snake_case alias for opts.approverKeys
 * @param {function|null} [opts.verifyAssurance] caller-supplied assurance verifier (assurance-proof path a)
 * @param {object} [opts.requiredAdmissibilityProfile] gate-level pinned admissibility profile {id, profile_hash}
 * @param {object} [opts.runtimeMonitor] runtime invariant monitor (defaults to createRuntimeMonitor)
 */
interface CreateGateOptions {
    manifest?: Obj | null;
    trustedKeys?: readonly string[];
    maxAgeSec?: number;
    store?: any;
    log?: any;
    capabilityStore?: any;
    capabilityTrustedIssuerKeys?: string[];
    capabilityCaidResolver?: ((...args: any[]) => any) | null;
    allowInlineKey?: boolean;
    allowEphemeralStore?: boolean;
    strictEvidence?: boolean;
    now?: number | (() => number);
    keyRegistry?: any;
    approverKeys?: Obj;
    approver_keys?: Obj | null;
    verifyAssurance?: ((...args: any[]) => any) | null;
    rpId?: string | null;
    allowedOrigins?: readonly string[];
    quorumPolicy?: Obj | null;
    quorumPolicies?: Obj;
    requiredAdmissibilityProfile?: Obj | null;
    verifyAdmissibilityPacket?: ((...args: any[]) => any) | null;
    allowEmbeddedApproverKeys?: boolean;
    runtimeMonitor?: ReturnType<typeof createRuntimeMonitor> | null;
}
export declare function createGate({ manifest, trustedKeys, maxAgeSec, store, log, capabilityStore, capabilityTrustedIssuerKeys, capabilityCaidResolver, allowInlineKey, allowEphemeralStore, strictEvidence, now, keyRegistry, approverKeys, approver_keys, verifyAssurance, rpId, allowedOrigins, quorumPolicy, quorumPolicies, requiredAdmissibilityProfile, verifyAdmissibilityPacket, allowEmbeddedApproverKeys, runtimeMonitor }?: CreateGateOptions): {
    check: ({ selector, receipt, observedAction, consumptionMode, admissibilityProfile, reliancePacket: presentedPacket, admissibility, capability }?: {
        selector?: any;
        receipt?: any;
        observedAction?: any;
        consumptionMode?: string;
        admissibilityProfile?: any;
        reliancePacket?: any;
        admissibility?: any;
        capability?: any;
    }) => Promise<{
        allow: any;
        status: any;
        reason: any;
        action: any;
        requirement: any;
        evidence: any;
        challenge?: ReturnType<typeof receiptChallenge>;
        header?: string;
        _runtime_cycle_id?: any;
    }>;
    run: ({ selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket, admissibility, capability }: {
        selector?: any;
        receipt?: any;
        observedAction?: any;
        admissibilityProfile?: any;
        reliancePacket?: any;
        admissibility?: any;
        capability?: any;
    } | undefined, fn: any, opts?: GateCallOpts) => Promise<Awaited<ReturnType<({ selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket, admissibility, capability }: {
        selector?: any;
        receipt?: any;
        observedAction?: any;
        admissibilityProfile?: any;
        reliancePacket?: any;
        admissibility?: any;
        capability?: any;
    } | undefined, fn: any, opts?: GateCallOpts) => Promise<ReturnType<({ authorization, capability, reason, status, event }?: {
        authorization?: any;
        capability?: any;
        reason?: any;
        status?: number;
        event?: any;
    }) => {
        ok: false;
        status: any;
        body: any;
        authorization: any;
        refusal: any;
        capability: any;
        evidence: any;
        result?: undefined;
        execution?: undefined;
        packet?: undefined;
    }> | {
        ok: true;
        result: any;
        authorization: any;
        execution: any;
        packet: any;
        capability: any;
        status?: undefined;
        body?: undefined;
        refusal?: undefined;
        evidence?: undefined;
    } | {
        ok: false;
        status: any;
        body: any;
        authorization: any;
        refusal: any;
        capability: any;
        result?: undefined;
        execution?: undefined;
        packet?: undefined;
        evidence?: undefined;
    }>>> | {
        ok: false;
        status: any;
        body: any;
        authorization: any;
        result?: undefined;
        execution?: undefined;
        packet?: undefined;
    } | {
        ok: true;
        result: any;
        authorization: any;
        execution: any;
        packet: any;
        status?: undefined;
        body?: undefined;
    }>;
    recordExecution: ({ authorization, outcome, detail, observedAction, executionBinding }?: {
        authorization?: any;
        outcome?: string;
        detail?: any;
        observedAction?: any;
        executionBinding?: any;
    }) => Promise<any>;
    route: (handler: any, opts?: GateCallOpts) => (req: any, res: any) => Promise<any>;
    wrapRoute: (handler: any, opts?: GateCallOpts) => (req: any, res: any) => Promise<any>;
    middleware: (opts?: GateCallOpts) => (req: any, res: any) => Promise<any>;
    guard: (fn: any, opts?: GateCallOpts) => (...args: any[]) => Promise<any>;
    reliancePacket: ({ authorization, execution, binding, admissibility }?: {
        authorization?: any;
        execution?: any;
        binding?: any;
        admissibility?: any;
    }) => Promise<{
        '@version': string;
        product: string;
        verifier: string;
        verdict: string;
        summary: {
            action: any;
            receipt_id: any;
            subject: any;
            policy_id: any;
            policy_hash: any;
            tenant_id: any;
            approvers: any;
            required_tier: any;
            observed_tier: any;
            decision_hash: any;
            execution_hash: any;
            evidence_head: any;
            admissibility_verdict: string | null;
            admissibility_profile: {
                id: any;
                version: any;
            } | null;
            admissibility_profile_hash: string | null;
        };
        admissibility: {
            admissibility_profile: {
                id: any;
                version: any;
            } | null;
            profile_hash: string | null;
            verdict: string | null;
            verdict_recognized: boolean;
            admissible: boolean;
            replay_digest: string | null;
            challenge_id: any;
            challenge_digest: string | null;
        } | null;
        checks: {
            detail?: string | {
                [x: string]: any;
            } | undefined;
            id: any;
            ok: any;
        }[];
        manifest_version: any;
        limitations: string[];
    }>;
    evidence: any;
    store: any;
    capabilityStore: any;
    keyRegistry: any;
    retention: (opts?: {}) => {
        summary: {
            total: number;
            hot: number;
            cold: number;
            expired: number;
            legal_hold: number;
            unknown: number;
            hot_days: number;
            cold_days: number;
        };
        hot: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        cold: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        expired: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        legal_hold: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        unknown: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
    };
    retentionExport: (opts?: {}) => {
        '@version': string;
        generated_at: string;
        hot_days: number;
        cold_days: number;
        evidence_head: string | null;
        counts: {
            total: number;
            hot: number;
            cold: number;
            expired: number;
            legal_hold: number;
            unknown: number;
        };
        entries: {
            hash: string | null;
            at: string;
            kind: string | null;
        }[];
    };
};
export declare function createTrustedActionFirewall(opts?: CreateGateOptions): {
    check: ({ selector, receipt, observedAction, consumptionMode, admissibilityProfile, reliancePacket: presentedPacket, admissibility, capability }?: {
        selector?: any;
        receipt?: any;
        observedAction?: any;
        consumptionMode?: string;
        admissibilityProfile?: any;
        reliancePacket?: any;
        admissibility?: any;
        capability?: any;
    }) => Promise<{
        allow: any;
        status: any;
        reason: any;
        action: any;
        requirement: any;
        evidence: any;
        challenge?: ReturnType<typeof receiptChallenge>;
        header?: string;
        _runtime_cycle_id?: any;
    }>;
    run: ({ selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket, admissibility, capability }: {
        selector?: any;
        receipt?: any;
        observedAction?: any;
        admissibilityProfile?: any;
        reliancePacket?: any;
        admissibility?: any;
        capability?: any;
    } | undefined, fn: any, opts?: GateCallOpts) => Promise<Awaited<ReturnType<({ selector, receipt, observedAction, admissibilityProfile, reliancePacket: presentedPacket, admissibility, capability }: {
        selector?: any;
        receipt?: any;
        observedAction?: any;
        admissibilityProfile?: any;
        reliancePacket?: any;
        admissibility?: any;
        capability?: any;
    } | undefined, fn: any, opts?: GateCallOpts) => Promise<ReturnType<({ authorization, capability, reason, status, event }?: {
        authorization?: any;
        capability?: any;
        reason?: any;
        status?: number;
        event?: any;
    }) => {
        ok: false;
        status: any;
        body: any;
        authorization: any;
        refusal: any;
        capability: any;
        evidence: any;
        result?: undefined;
        execution?: undefined;
        packet?: undefined;
    }> | {
        ok: true;
        result: any;
        authorization: any;
        execution: any;
        packet: any;
        capability: any;
        status?: undefined;
        body?: undefined;
        refusal?: undefined;
        evidence?: undefined;
    } | {
        ok: false;
        status: any;
        body: any;
        authorization: any;
        refusal: any;
        capability: any;
        result?: undefined;
        execution?: undefined;
        packet?: undefined;
        evidence?: undefined;
    }>>> | {
        ok: false;
        status: any;
        body: any;
        authorization: any;
        result?: undefined;
        execution?: undefined;
        packet?: undefined;
    } | {
        ok: true;
        result: any;
        authorization: any;
        execution: any;
        packet: any;
        status?: undefined;
        body?: undefined;
    }>;
    recordExecution: ({ authorization, outcome, detail, observedAction, executionBinding }?: {
        authorization?: any;
        outcome?: string;
        detail?: any;
        observedAction?: any;
        executionBinding?: any;
    }) => Promise<any>;
    route: (handler: any, opts?: GateCallOpts) => (req: any, res: any) => Promise<any>;
    wrapRoute: (handler: any, opts?: GateCallOpts) => (req: any, res: any) => Promise<any>;
    middleware: (opts?: GateCallOpts) => (req: any, res: any) => Promise<any>;
    guard: (fn: any, opts?: GateCallOpts) => (...args: any[]) => Promise<any>;
    reliancePacket: ({ authorization, execution, binding, admissibility }?: {
        authorization?: any;
        execution?: any;
        binding?: any;
        admissibility?: any;
    }) => Promise<{
        '@version': string;
        product: string;
        verifier: string;
        verdict: string;
        summary: {
            action: any;
            receipt_id: any;
            subject: any;
            policy_id: any;
            policy_hash: any;
            tenant_id: any;
            approvers: any;
            required_tier: any;
            observed_tier: any;
            decision_hash: any;
            execution_hash: any;
            evidence_head: any;
            admissibility_verdict: string | null;
            admissibility_profile: {
                id: any;
                version: any;
            } | null;
            admissibility_profile_hash: string | null;
        };
        admissibility: {
            admissibility_profile: {
                id: any;
                version: any;
            } | null;
            profile_hash: string | null;
            verdict: string | null;
            verdict_recognized: boolean;
            admissible: boolean;
            replay_digest: string | null;
            challenge_id: any;
            challenge_digest: string | null;
        } | null;
        checks: {
            detail?: string | {
                [x: string]: any;
            } | undefined;
            id: any;
            ok: any;
        }[];
        manifest_version: any;
        limitations: string[];
    }>;
    evidence: any;
    store: any;
    capabilityStore: any;
    keyRegistry: any;
    retention: (opts?: {}) => {
        summary: {
            total: number;
            hot: number;
            cold: number;
            expired: number;
            legal_hold: number;
            unknown: number;
            hot_days: number;
            cold_days: number;
        };
        hot: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        cold: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        expired: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        legal_hold: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
        unknown: {
            hash: string | null;
            at: string | null;
            kind: string | null;
        }[];
    };
    retentionExport: (opts?: {}) => {
        '@version': string;
        generated_at: string;
        hot_days: number;
        cold_days: number;
        evidence_head: string | null;
        counts: {
            total: number;
            hot: number;
            cold: number;
            expired: number;
            legal_hold: number;
            unknown: number;
        };
        entries: {
            hash: string | null;
            at: string;
            kind: string | null;
        }[];
    };
};
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
export declare function gateConformance({ gate, harness, action, selector }?: {
    gate?: any;
    harness?: any;
    action?: any;
    selector?: any;
}): Promise<{
    standard: string;
    passed: boolean;
    badge: string;
    summary: {
        passed: number;
        total: number;
    };
    checks: any[];
    generated_at: string;
}>;
/**
 * Self-certify the reference gate: build a default Consequence Firewall that
 * trusts a fresh EG-1 harness key, then run all eight checks. This is the
 * canonical "EMILIA Gate earns EG-1" proof — runnable as a CLI (`eg1.mjs`),
 * shown on /gate, and the template an adopter copies for their integration.
 * @param {{now?: any}} [o]
 */
export declare function gateConformanceSelfTest({ now }?: {
    now?: any;
}): Promise<{
    standard: string;
    passed: boolean;
    badge: string;
    summary: {
        passed: number;
        total: number;
    };
    checks: any[];
    generated_at: string;
}>;
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
export declare function cf1Conformance({ gate, wrongGate, harness, manifest, selector, action }?: {
    gate?: any;
    wrongGate?: any;
    harness?: any;
    manifest?: any;
    selector?: any;
    action?: any;
}): Promise<{
    standard: string;
    passed: boolean;
    badge: string;
    summary: {
        passed: number;
        total: number;
    };
    eg1: {
        passed: boolean;
        summary: {
            passed: number;
            total: number;
        };
    };
    checks: {
        pass: boolean;
        observed: {
            [x: string]: any;
        };
        id: string;
        title: string;
    }[];
    generated_at: string;
}>;
/**
 * Self-certify the reference gate against CF-1: a default Trusted Action
 * Firewall trusting a fresh harness key, a sibling firewall trusting a DIFFERENT
 * key (for wrong_authority_refused), and the default action-risk manifest (for
 * consequential_action_declared). The canonical "reference gate earns CF-1"
 * proof — runnable as a CLI (`cf1.mjs`).
 * @param {{now?: any}} [o]
 */
export declare function cf1ConformanceSelfTest({ now }?: {
    now?: any;
}): Promise<{
    standard: string;
    passed: boolean;
    badge: string;
    summary: {
        passed: number;
        total: number;
    };
    eg1: {
        passed: boolean;
        summary: {
            passed: number;
            total: number;
        };
    };
    checks: {
        pass: boolean;
        observed: {
            [x: string]: any;
        };
        id: string;
        title: string;
    }[];
    generated_at: string;
}>;
declare const _default: {
    createGate: typeof createGate;
    createTrustedActionFirewall: typeof createTrustedActionFirewall;
    runBreakGlass: typeof runBreakGlass;
    receiptAssuranceTier: typeof receiptAssuranceTier;
    businessAuthorizationRequirement: typeof businessAuthorizationRequirement;
    verifyBusinessAuthorization: typeof verifyBusinessAuthorization;
    verifyAdmissibilityAgainstPinnedProfile: typeof verifyAdmissibilityAgainstPinnedProfile;
    ADMISSIBILITY_VERDICTS: readonly string[];
    MemoryConsumptionStore: typeof MemoryConsumptionStore;
    createEvidenceLog: typeof createEvidenceLog;
    createAtomicEvidenceLog: typeof createAtomicEvidenceLog;
    createMemoryAtomicEvidenceBackend: typeof createMemoryAtomicEvidenceBackend;
    ASSURANCE_TIERS: string[];
    DEFAULT_GATE_MANIFEST: Readonly<{
        '@version': string;
        actions: {
            id: string;
            label: string;
            action_type: string;
            risk?: string;
            receipt_required: boolean;
            assurance_class?: string;
            match: {
                protocol: string;
                tool: string;
            };
            why?: string;
            execution_binding?: {
                required_fields: string[];
                caid_selector?: {
                    field: string;
                };
            };
            business_authorization?: Record<string, any>;
        }[];
    }>;
    HIGH_RISK_ACTION_PACKS: readonly {
        id: string;
        label: string;
        action_type: string;
        risk?: string;
        receipt_required: boolean;
        assurance_class?: string;
        match: {
            protocol: string;
            tool: string;
        };
        why?: string;
        execution_binding?: {
            required_fields: string[];
            caid_selector?: {
                field: string;
            };
        };
        business_authorization?: Record<string, any>;
    }[];
    gateConformance: typeof gateConformance;
    gateConformanceSelfTest: typeof gateConformanceSelfTest;
    cf1Conformance: typeof cf1Conformance;
    cf1ConformanceSelfTest: typeof cf1ConformanceSelfTest;
    CF1_VERSION: string;
    CF1_CHECKS: readonly {
        id: string;
        title: string;
    }[];
    runCf1: typeof runCf1;
    createEg1Harness: typeof createEg1Harness;
    runEg1: typeof runEg1;
    createKeyRegistry: typeof createKeyRegistry;
    asKeyRegistry: typeof asKeyRegistry;
    classifyRetention: typeof classifyRetention;
    buildRetentionExport: typeof buildRetentionExport;
    createDefaultActionControlManifest: typeof createDefaultActionControlManifest;
    findActionControl: typeof findActionControl;
    resolveActionControl: typeof resolveActionControl;
    validateActionControlManifest: typeof validateActionControlManifest;
    createRuntimeMonitor: typeof createRuntimeMonitor;
    RUNTIME_MONITOR_VERSION: string;
    RUNTIME_MONITOR_MODES: Readonly<{
        NORMAL: "normal";
        DEGRADED: "degraded";
        LOCKDOWN: "lockdown";
    }>;
    RUNTIME_INVARIANTS: Readonly<{
        CONSUME_ONCE: "ConsumeOnceSafety";
        WRITE_BYPASS: "WriteBypassSafety";
        SIGNOFF_BINDING: "SignoffBindingMatch";
    }>;
    FORMAL_RUNTIME_BRIDGE_VERSION: string;
    FORMAL_RUNTIME_SPEC: string;
    FORMAL_RUNTIME_CONFIG: string;
    FORMAL_RUNTIME_INVARIANT_MAP: readonly (Readonly<{
        runtime: "ConsumeOnceSafety";
        formal: "ConsumeOnceSafety";
        transition: "consumptionCommitted";
    }> | Readonly<{
        runtime: "WriteBypassSafety";
        formal: "WriteBypassSafety";
        transition: "beginExecution";
    }> | Readonly<{
        runtime: "SignoffBindingMatch";
        formal: "SignoffBindingMatch";
        transition: "recordDecision";
    }>)[];
    CAPABILITY_RECEIPT_VERSION: string;
    CAPABILITY_STATE_VERSION: string;
    CAPABILITY_SHARE_VERSION: string;
    CAPABILITY_SCOPE_PROFILE: string;
    CAPABILITY_CAID_SCOPE_PROFILE: string;
    CAPABILITY_STATE_DDL: string;
    CAPABILITY_SQL: Readonly<{
        register: "INSERT INTO ep_capability_state (capability_id, budget_amount, currency, expires_at, capability_fingerprint) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(ep_capability_state.capability_fingerprint, EXCLUDED.capability_fingerprint) WHERE ep_capability_state.budget_amount = EXCLUDED.budget_amount AND ep_capability_state.currency = EXCLUDED.currency AND ep_capability_state.expires_at = EXCLUDED.expires_at";
        readState: "SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at FROM ep_capability_state WHERE capability_id = $1 FOR UPDATE";
        readOperation: "SELECT operation_id, capability_id, action_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, reconciled_at FROM ep_capability_operations WHERE operation_id = $1 FOR UPDATE";
        insertOperation: "INSERT INTO ep_capability_operations (operation_id, capability_id, action_digest, amount, currency, status, reservation_token, reserved_at) VALUES ($1, $2, $3, $4, $5, 'reserved', $6, $7)";
        reserveState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND budget_amount - consumed_amount - reserved_amount >= $2";
        commitOperation: "UPDATE ep_capability_operations SET status = 'committed', outcome = $3, committed_at = $4 WHERE operation_id = $1 AND capability_id = $2 AND status = 'reserved' AND reservation_token = $5";
        reconcileOperation: "UPDATE ep_capability_operations SET reconciliation_outcome = $3, reconciliation_evidence_digest = $4, reconciled_at = $5 WHERE operation_id = $1 AND capability_id = $2 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL";
        commitState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2";
    }>;
    capabilityBaseReceiptDigest: typeof capabilityBaseReceiptDigest;
    capabilityActionDigest: typeof capabilityActionDigest;
    verifyCapabilityScope: typeof verifyCapabilityScope;
    mintCapabilityReceipt: typeof mintCapabilityReceipt;
    verifyCapabilityReceipt: typeof verifyCapabilityReceipt;
    splitCapabilitySecret: typeof splitCapabilitySecret;
    reconstructCapabilitySecret: typeof reconstructCapabilitySecret;
    createMemoryCapabilityStore: typeof createMemoryCapabilityStore;
    createPostgresCapabilityStore: typeof createPostgresCapabilityStore;
    executeWithCapability: typeof executeWithCapability;
    executeWithThreshold: typeof executeWithThreshold;
    reconcileCapabilityOperation: typeof reconcileCapabilityOperation;
    ZK_RANGE_RECEIPT_VERSION: string;
    ZK_RANGE_SCHEME: string;
    ZK_RANGE_BACKEND_PACKAGE: string;
    deriveZkRangeBases: typeof deriveZkRangeBases;
    loadBulletproofBackend: typeof loadBulletproofBackend;
    mintZkRangeReceipt: typeof mintZkRangeReceipt;
    verifyZkRangeReceipt: typeof verifyZkRangeReceipt;
};
export default _default;
//# sourceMappingURL=index.d.ts.map