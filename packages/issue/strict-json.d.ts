export declare const MAX_JSON_DEPTH = 64;
export declare function canonicalizeStrictJson(value: unknown): string;
export declare function isStrictCanonicalJson(value: unknown): boolean;
export declare function strictJsonGate(raw: unknown):
  | { ok: true }
  | { ok: false; reason: string };
