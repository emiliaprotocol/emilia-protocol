import { RELIANCE_PROFILE_VERSION, RELIANCE_VERDICTS } from '@emilia-protocol/verify/reliance';
type Obj = Record<string, any>;
export { RELIANCE_VERDICTS, RELIANCE_PROFILE_VERSION };
/**
 * Create a reliance kernel bound to one relying-party profile.
 *
 * @param {object} [cfg]
 * @param {object} [cfg.profile]      the pinned EP-RELIANCE-PROFILE-v1
 * @param {object} [cfg.log]          an evidence log (createEvidenceLog); one is created if absent
 * @param {boolean} [cfg.strictEvidence=true]  fail closed if the evidence log sink fails
 * @returns {{ check: Function, evidence: object }}
 */
export declare function createRelianceKernel({ profile, log, strictEvidence, }?: {
    profile?: Obj;
    log?: Obj;
    strictEvidence?: boolean;
}): {
    check: (input?: Obj, opts?: Obj) => Promise<{
        allow: boolean;
        status: number;
        verdict: any;
        reasons: any;
        checks: any;
        challenge: {
            status: number;
            error: string;
            verdict: any;
            reasons: any[];
            required_assurance: any;
            required_authority: boolean;
            required_evidence: any;
            header: {
                name: string;
                value: any;
            };
        } | null;
        decision: any;
    }>;
    evidence: {
        durable: boolean;
        persisted: boolean;
        strict: boolean;
        forkAware: boolean;
        atomicAppend: boolean;
        record(entry: any): Promise<any>;
        all(): Record<string, any>[];
        verify(): {
            ok: boolean;
            at: any;
            reason: string;
            length?: undefined;
            head?: undefined;
        } | {
            ok: boolean;
            length: number;
            head: string | null;
            at?: undefined;
            reason?: undefined;
        };
    } | Obj;
};
declare const relianceKernelApi: {
    createRelianceKernel: typeof createRelianceKernel;
};
export default relianceKernelApi;
//# sourceMappingURL=reliance-kernel.d.ts.map