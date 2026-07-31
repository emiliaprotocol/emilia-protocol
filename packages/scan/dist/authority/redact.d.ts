import type { SecretDescriptor } from './types.js';
export declare function describeSecret(key: unknown, value: unknown): SecretDescriptor;
export declare function safeValue(key: unknown, value: unknown): string;
export declare function describeEnv(env: unknown): SecretDescriptor[];
export declare function redactText(text: unknown): string;
export declare function sanitizeForReport(value: unknown, key?: string, seen?: WeakSet<object>): unknown;
export declare function sanitizeArgs(args: unknown): string[];
//# sourceMappingURL=redact.d.ts.map