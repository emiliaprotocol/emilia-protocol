type AnyRecord = Record<string, any>;
/** Reset the consumed-receipt set. Test/ops helper — not a production control. */
export declare function _resetConsumed(): void;
/**
 * Build a receipt gate for OpenAI Agents human-in-the-loop tool approvals.
 *
 * @param {object} opts
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER issuer public keys you trust.
 * @param {boolean} [opts.allowInlineKey=false] also accept a receipt's own inline
 *   key (proves integrity, NOT trust — leave OFF in production).
 * @param {number} [opts.maxAgeSec=900] reject receipts older than this.
 * @param {(toolName:string, args:any)=>string} [opts.actionFor] REQUIRED — maps a
 *   tool call to the canonical EP action_type the receipt must be bound to.
 * @param {{reserve:(id:string)=>Promise<boolean>|boolean,
 *   commit:(id:string)=>Promise<boolean>|boolean,
 *   release:(id:string)=>Promise<boolean>|boolean}} [opts.store]
 * @returns {{
 *   decide: (interruption:any, receipt:object|null|undefined) => Promise<{decision:'approve'|'reject', action:string|null, toolName:string|null, callId:string|null, reason:string, receipt_id?:string, subject?:string}>,
 *   resolve: (runResult:any, ctx?:{receipts?:object|Map|Array, state?:any}) => Promise<{approved:Array, rejected:Array, decisions:Array}>
 * }}
 */
export declare function requireReceiptForOpenAIAgent(opts?: AnyRecord): AnyRecord;
declare const openaiAgentsExports: {
    requireReceiptForOpenAIAgent: typeof requireReceiptForOpenAIAgent;
    _resetConsumed: typeof _resetConsumed;
};
export default openaiAgentsExports;
//# sourceMappingURL=index.d.ts.map