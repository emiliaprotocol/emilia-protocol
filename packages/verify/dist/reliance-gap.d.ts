type Obj = Record<string, any>;
interface GapOptions {
    now?: number | string | Date;
    evaluatedAt?: number | string | Date;
    version?: string;
    cli?: string;
    [key: string]: any;
}
export declare const RELIANCE_GAP_REPORT_VERSION = "EP-RELIANCE-GAP-REPORT-v1";
export declare const RELIANCE_GAP_MULTI_VERSION = "EP-RELIANCE-GAP-MULTI-v1";
/** The evidence slots the reliance kernel consumes. Anything else is foreign. */
export declare const KERNEL_EVIDENCE_TYPES: readonly string[];
/**
 * The honest closed limitations list. ALWAYS present in every report,
 * including a `rely`. A scope limit is substance, never a hedge.
 */
export declare const RELIANCE_GAP_LIMITATIONS: readonly string[];
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
export declare function buildRelianceGapReport(packet: Obj, profile: Obj, opts?: GapOptions): Obj;
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
export declare function buildMultiPartyRelianceGapReport(packet: Obj, profiles: any[], opts?: GapOptions): Obj;
export {};
//# sourceMappingURL=reliance-gap.d.ts.map