/**
 * System-of-record controller for government mobile approval flows.
 *
 * The requester supplies only references and ceremony routing. The protected
 * action and human presentation are resolved by the government system of
 * record, so an agent cannot choose the bytes a human is asked to approve.
 * @param {{
 *   service?: *,
 *   profiles?: Map<string, *>,
 *   resolveRequest?: (input: *) => *,
 *   authorize?: (input: *) => *,
 *   registerChallenge?: ((input: *) => *) | null,
 * }} [options]
 */
type AnyRecord = Record<string, any>;
export declare function createGovernmentMobileController({ service, profiles, resolveRequest, authorize, registerChallenge, }?: AnyRecord): AnyRecord;
declare const _default: {
    createGovernmentMobileController: typeof createGovernmentMobileController;
};
export default _default;
//# sourceMappingURL=government.d.ts.map