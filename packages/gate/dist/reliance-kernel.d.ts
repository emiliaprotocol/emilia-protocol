import { type RelianceRefusalContext, type RelianceRefusalSigner } from './reliance-refusal-bridge.js';
import { RELIANCE_PROFILE_VERSION, RELIANCE_VERDICTS } from '@emilia-protocol/verify/reliance';
type Obj = Record<string, any>;
export interface RelianceRefusalRuntime {
    signer: RelianceRefusalSigner;
    /**
     * Supplies deployment-owned bindings that the verifier cannot safely invent:
     * the compiled program identity, exact CAID/action digest, failed requirement
     * ids, evidence/challenge digests, nonce, and validity window.
     */
    context(args: {
        input: Obj;
        options: Obj;
        profile: Obj | undefined;
        result: Obj;
        decision: Obj;
        challenge: Obj;
    }): Omit<RelianceRefusalContext, 'decision'> | Promise<Omit<RelianceRefusalContext, 'decision'>>;
}
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
export declare function createRelianceKernel({ profile, log, strictEvidence, refusal, }?: {
    profile?: Obj;
    log?: Obj;
    strictEvidence?: boolean;
    refusal?: RelianceRefusalRuntime;
}): {
    check: (input?: Obj, opts?: Obj) => Promise<{
        allow: boolean;
        status: number;
        verdict: string;
        reasons: string[];
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
        };
        decision: null;
        refusal_statement?: undefined;
        refusal_statement_digest?: undefined;
        refusal_statement_recorded?: undefined;
    } | {
        allow: boolean;
        status: number;
        verdict: any;
        reasons: any;
        checks: any;
        challenge: {
            refusal_statement: Obj | null;
            refusal_statement_digest: string | null;
            refusal_statement_error: string | null;
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
        refusal_statement: Obj | null;
        refusal_statement_digest: string | null;
        refusal_statement_recorded: boolean;
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