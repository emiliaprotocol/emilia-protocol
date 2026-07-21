export declare const MAX_JSON_DEPTH = 64;
export declare function strictJsonGate(raw: any): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
declare const _default: {
    strictJsonGate: typeof strictJsonGate;
    MAX_JSON_DEPTH: number;
};
export default _default;
//# sourceMappingURL=strict-json.d.ts.map