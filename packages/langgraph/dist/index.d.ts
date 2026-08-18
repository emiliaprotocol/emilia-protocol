type AnyRecord = Record<string, any>;
export type LangGraphActionRequest = {
    action: string;
    args: Record<string, any>;
};
export type LangGraphHumanInterrupt = {
    action_request: LangGraphActionRequest;
    config: {
        allow_ignore: boolean;
        allow_respond: boolean;
        allow_edit: boolean;
        allow_accept: boolean;
    };
    description?: string;
};
export type LangGraphHumanResponse = {
    type: 'accept' | 'ignore' | 'response' | 'edit';
    args: null | string | LangGraphActionRequest;
};
export type LangGraphOccurrence = {
    /** Trusted LangGraph runtime identity, never model-supplied content. */
    threadId: string;
    /** Trusted interrupt identity within the thread. */
    interruptId: string;
};
/** Test and single-process operations helper. Not a production control. */
export declare function _resetLangGraphConsumption(): void;
/**
 * Derive the exact receipt action for an interrupt or edited request.
 * The occurrence comes from the trusted runtime so identical sibling actions
 * cannot share authority.
 */
export declare function bindLangGraphAction(request: LangGraphActionRequest, occurrence: LangGraphOccurrence, actionFor?: (action: string, args: Record<string, any>) => string): string;
export declare function createLangGraphApprovalAdapter(opts?: AnyRecord): AnyRecord;
declare const langGraphExports: {
    bindLangGraphAction: typeof bindLangGraphAction;
    createLangGraphApprovalAdapter: typeof createLangGraphApprovalAdapter;
    _resetLangGraphConsumption: typeof _resetLangGraphConsumption;
};
export default langGraphExports;
//# sourceMappingURL=index.d.ts.map