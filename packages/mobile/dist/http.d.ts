type AnyRecord = Record<string, any>;
/**
 * Fetch-compatible transport for the native reference applications.
 * Authentication is provided by the deployment and never inferred from JSON.
 * @param {{
 *   controller?: *,
 *   enrollmentService?: *,
 *   authenticate?: (request: Request) => *,
 *   resolveEnrollmentIdentity?: (input: { caller: *, approver_id: * }) => *,
 *   enrollmentConfig?: *,
 *   maxBodyBytes?: number,
 *   routePrefix?: string,
 * }} [options]
 */
export declare function createMobileHttpHandler({ controller, enrollmentService, authenticate, resolveEnrollmentIdentity, enrollmentConfig, maxBodyBytes, routePrefix, }?: AnyRecord): (request: Request) => Promise<Response>;
declare const _default: {
    createMobileHttpHandler: typeof createMobileHttpHandler;
};
export default _default;
//# sourceMappingURL=http.d.ts.map