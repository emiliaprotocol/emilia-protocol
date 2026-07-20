export declare const MAX_JSON_DEPTH = 64;
export interface StrictJsonSuccess {
    ok: true;
}
export interface StrictJsonFailure {
    ok: false;
    reason: string;
}
export type StrictJsonResult = StrictJsonSuccess | StrictJsonFailure;
export declare function strictJsonGate(raw: unknown): StrictJsonResult;
declare const strictJson: {
    strictJsonGate: typeof strictJsonGate;
    MAX_JSON_DEPTH: number;
};
export default strictJson;
//# sourceMappingURL=strict-json.d.ts.map