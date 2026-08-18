export declare const PROTECTED_ACTION_REGISTRY_VERSION = "EP-PROTECTED-ACTION-REGISTRY-v1";
type ProtectedHandler = (parameters: unknown, authorization: unknown) => unknown | Promise<unknown>;
type ProtectedValidator = (parameters: unknown) => boolean;
export type ProtectedActionRegistry = Readonly<{
    register(action: string, validate: ProtectedValidator, handler: ProtectedHandler): ProtectedActionRegistry;
    seal(): ProtectedActionRegistry;
    describe(): Readonly<{
        version: typeof PROTECTED_ACTION_REGISTRY_VERSION;
        sealed: boolean;
        actions: readonly string[];
    }>;
}>;
export type PreparedProtectedAction = Readonly<{
    ok: true;
    parameters: unknown;
    handler: ProtectedHandler;
}> | Readonly<{
    ok: false;
    reason: string;
}>;
/** Internal strict-JSON snapshot used to freeze the local adapter selector. */
export declare function snapshotProtectedActionValue(value: unknown): unknown;
/** Create a registry that can be populated only before trusted-startup sealing. */
export declare function createProtectedActionRegistry(): ProtectedActionRegistry;
/**
 * Internal Gate preflight. This is intentionally not re-exported by the
 * package root: public callers can inspect a handler-free manifest, not obtain
 * or redirect handlers.
 */
export declare function prepareProtectedActionInvocation(registry: unknown, action: unknown, parameters: unknown): PreparedProtectedAction;
export {};
//# sourceMappingURL=protected-action-registry.d.ts.map