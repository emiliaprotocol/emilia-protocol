export declare const AUTONOMY_CONTROL_PLANE_VERSION = "EP-GATE-AUTONOMY-CONTROL-PLANE-PROFILE-v1";
export declare const AUTONOMY_ROOT_EVIDENCE_TYPE = "ep-root-objective";
export declare const AUTONOMY_FITNESS_EVIDENCE_TYPE = "agent-fitness-report";
type JsonRecord = Record<string, any>;
export declare class AutonomyControlPlaneValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
export interface CompiledAutonomyControlPlane {
    version: typeof AUTONOMY_CONTROL_PLANE_VERSION;
    profile_digest: string;
    control_plane_id: string;
    programs: JsonRecord[];
    claim_boundary: string;
}
export declare function compileAutonomyControlPlaneProfile(value: unknown): CompiledAutonomyControlPlane;
export {};
//# sourceMappingURL=autonomy-control-plane-profile.d.ts.map