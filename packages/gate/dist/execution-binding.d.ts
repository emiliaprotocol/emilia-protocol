export declare const EXECUTION_BINDING_VERSION = "EP-GATE-EXECUTION-BINDING-v1";
export declare function canonicalize(v: any): any;
export declare function hashCanonical(v: any): string;
export declare function materialFieldsFor(requirement: any): any[];
/**
 * Verifies that the signed claim and the executor-observed mutation fields
 * match for the action pack. The executor must pass `observedAction` from the
 * system of record, not from the agent request body.
 */
export declare function verifyExecutionBinding({ requirement, receipt, observedAction }?: {
    requirement?: any;
    receipt?: any;
    observedAction?: any;
}): {
    ok: boolean;
    required: boolean;
    required_fields: never[];
    signed_hash: null;
    observed_hash: null;
    '@version'?: undefined;
    missing_signed_fields?: undefined;
    missing_observed_fields?: undefined;
    invalid_signed_fields?: undefined;
    invalid_observed_fields?: undefined;
    mismatched_fields?: undefined;
    note?: undefined;
} | {
    '@version': string;
    ok: boolean;
    required: boolean;
    required_fields: any[];
    missing_signed_fields: PropertyKey[];
    missing_observed_fields: PropertyKey[];
    invalid_signed_fields: PropertyKey[];
    invalid_observed_fields: PropertyKey[];
    mismatched_fields: PropertyKey[];
    signed_hash: string | null;
    observed_hash: string | null;
    note: string;
};
declare const _default: {
    EXECUTION_BINDING_VERSION: string;
    canonicalize: typeof canonicalize;
    hashCanonical: typeof hashCanonical;
    materialFieldsFor: typeof materialFieldsFor;
    verifyExecutionBinding: typeof verifyExecutionBinding;
};
export default _default;
//# sourceMappingURL=execution-binding.d.ts.map