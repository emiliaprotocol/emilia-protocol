export declare const MAX_JSON_DEPTH = 64;
export interface StrictJsonResult {
    ok: boolean;
    reason?: string;
}
export declare function strictJsonGate(raw: unknown): StrictJsonResult;
declare const strictJson: {
    strictJsonGate: typeof strictJsonGate;
    MAX_JSON_DEPTH: number;
};
export default strictJson;
//# sourceMappingURL=strict-json.d.ts.map