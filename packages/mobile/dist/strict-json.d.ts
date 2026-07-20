export declare const MAX_JSON_DEPTH = 64;
type JsonResult = {
    ok: boolean;
    reason?: string;
};
export declare function strictJsonGate(raw: any): JsonResult;
declare const _default: {
    strictJsonGate: typeof strictJsonGate;
    MAX_JSON_DEPTH: number;
};
export default _default;
//# sourceMappingURL=strict-json.d.ts.map