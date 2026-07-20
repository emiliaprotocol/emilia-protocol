import { RELIANCE_VERDICTS } from '@emilia-protocol/verify/reliance';
export declare const ASSURANCE_PACKAGE_VERSION = "EP-ASSURANCE-PACKAGE-v1";
export declare const ASSURANCE_REPERFORMANCE_VERSION = "EP-ASSURANCE-REPERFORMANCE-v1";
export { RELIANCE_VERDICTS };
/**
 * The reliance control catalog: every reliance verdict maps to the control
 * objective it exercises. A `rely` shows the control PASSING; every do_not_rely_*
 * shows the control OPERATING (it refused a non-admissible action). Denials are
 * the control working, not the control failing.
 */
export declare const RELIANCE_CONTROL_CATALOG: Readonly<{
    'RC-1': {
        objective: string;
        verdicts: string[];
    };
    'RC-2': {
        objective: string;
        verdicts: string[];
    };
    'RC-3': {
        objective: string;
        verdicts: string[];
    };
    'RC-4': {
        objective: string;
        verdicts: string[];
    };
    'RC-5': {
        objective: string;
        verdicts: string[];
    };
    'RC-6': {
        objective: string;
        verdicts: string[];
    };
}>;
/**
 * Bundle N automated reliance decisions + the evidence each relied on into one
 * portable, content-addressed assurance package. Does NOT re-perform (that is the
 * assurer's independent step); it packages faithfully, including the verdict the
 * org's runtime CLAIMED, so drift is checkable later.
 *
 * @param {Array<object>} decisions  each: { decision_id, action, receipt, quorum?,
 *   authority_proof?, revocation_state?, consumption?, stated_verdict? }
 * @param {object} [opts]
 * @param {object} [opts.profile]       the pinned EP-RELIANCE-PROFILE-v1 the org operated under
 * @param {object} [opts.organization] { id, name } (no PHI)
 * @param {number|Function} [opts.now]
 * @returns {object} EP-ASSURANCE-PACKAGE-v1
 */
export declare function buildAssurancePackage(decisions?: any[], { profile, organization, now, }?: {
    profile?: Record<string, any> | null;
    organization?: Record<string, any> | null;
    now?: number | (() => number);
}): {
    package_digest: string;
    '@version': string;
    organization: any;
    reliance_profile: any;
    profile_hash: string | null;
    control_catalog: Readonly<{
        'RC-1': {
            objective: string;
            verdicts: string[];
        };
        'RC-2': {
            objective: string;
            verdicts: string[];
        };
        'RC-3': {
            objective: string;
            verdicts: string[];
        };
        'RC-4': {
            objective: string;
            verdicts: string[];
        };
        'RC-5': {
            objective: string;
            verdicts: string[];
        };
        'RC-6': {
            objective: string;
            verdicts: string[];
        };
    }>;
    decisions: {
        decision_id: any;
        action: any;
        policy_hash: any;
        stated_verdict: any;
        evidence: {
            receipt: any;
            quorum: any;
            authority_proof: any;
            revocation_state: any;
            consumption: any;
        };
    }[];
    exception_history: {
        decision_id: any;
        stated_verdict: any;
        control_id: any;
    }[];
    counts: {
        decisions: number;
        stated_admissible: number;
        stated_refused: number;
        stated_unknown: number;
    };
    assembled_at: string;
};
/**
 * INDEPENDENT re-performance. Recompute every reliance verdict offline from the
 * packaged evidence under the package's pinned profile and AUDITOR-supplied keys,
 * trusting nothing the package asserts. Detect drift (recomputed ≠ stated), map
 * to control objectives, and emit an auditor-style workpaper. Conclusion fields
 * are ALWAYS null: the assurer concludes, not this tool.
 *
 * @param {object} pkg  an EP-ASSURANCE-PACKAGE-v1
 * @param {object} opts
 * @param {object} [opts.approverKeys]  auditor-pinned approver keys (out of band)
 * @param {string|null} [opts.logPublicKey]  auditor-pinned transparency-log key
 * @param {string|null} [opts.rpId]
 * @param {string[]} [opts.allowedOrigins]
 * @param {object} [opts.revokerKeys]
 * @param {(key:object)=>boolean} [opts.isConsumed] auditor-owned consumption lookup
 * @param {number|string|Date|Function} [opts.now]  reliance-evaluation clock (pin for determinism)
 * @returns {object} EP-ASSURANCE-REPERFORMANCE-v1
 */
export declare function reperformAssurancePackage(pkg: any, { approverKeys, logPublicKey, rpId, allowedOrigins, revokerKeys, isConsumed, now, }?: {
    approverKeys?: Record<string, any>;
    logPublicKey?: string | null;
    rpId?: string | null;
    allowedOrigins?: string[];
    revokerKeys?: Record<string, any>;
    isConsumed?: (key: any) => boolean;
    now?: number | (() => number);
}): {
    '@version': string;
    product: string;
    package_digest: string;
    stated_package_digest: any;
    package_digest_verified: boolean;
    profile_hash: any;
    generated_at: string;
    honesty: {
        reperforms: string;
        does_not_establish: string[];
        status: string;
    };
    population: {
        decisions: any;
        admissible: number;
        refused: number;
        drift: number;
        relied_on_inadmissible_evidence: any;
        by_recomputed_verdict: any;
        by_control: any;
    };
    control_catalog: Readonly<{
        'RC-1': {
            objective: string;
            verdicts: string[];
        };
        'RC-2': {
            objective: string;
            verdicts: string[];
        };
        'RC-3': {
            objective: string;
            verdicts: string[];
        };
        'RC-4': {
            objective: string;
            verdicts: string[];
        };
        'RC-5': {
            objective: string;
            verdicts: string[];
        };
        'RC-6': {
            objective: string;
            verdicts: string[];
        };
    }>;
    results: any;
    reperformance_digest: string | null;
    conclusion: {
        supportable: null;
        opinion: null;
        signed_off_by: null;
    };
};
/** Render a plain-text auditor workpaper. Refuses to print a filled conclusion. */
export declare function renderAssuranceWorkpaper(doc: any): string;
//# sourceMappingURL=assurance-package.d.ts.map