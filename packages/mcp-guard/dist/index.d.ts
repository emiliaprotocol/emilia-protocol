/**
 * @emilia-protocol/mcp-guard — EP-MCP MIDDLEWARE (reference implementation).
 *
 * Wraps an MCP server's tool-call handler so that *irreversible* tool calls are
 * forced through accountability before they execute, while everything else passes
 * straight through untouched.
 *
 *   reversible / read-only tool  → pass through (no overhead)
 *   irreversible tool, no proof  → legacy refusal object (the demand hook)
 *   irreversible tool, gated     → consent → Class-A signoff → EP-RECEIPT-v1
 *                                  emitted + a provenance entry appended → run
 *
 * Framework-agnostic: it wraps the function the MCP server already calls to
 * dispatch a tool (e.g. `handleTool(name, args)` behind CallToolRequestSchema).
 * Nothing here is MCP-transport-specific; it works with any tool-dispatch shape.
 *
 * Honesty / status:
 *   - This is a REFERENCE IMPLEMENTATION, experimental. It exercises the control
 *     flow, the 402 demand hook, the EP-RECEIPT-v1 emission shape, and the
 *     provenance ledger purely in-process with pluggable adapters.
 *   - The EP CORE is FROZEN. This package NEVER mints, mutates, re-canonicalizes,
 *     or re-signs an EP-RECEIPT-v1. Receipt issuance and consent/signoff are
 *     delegated to caller-supplied adapters (an EP host, @emilia-protocol/issue,
 *     a WebAuthn authenticator, etc.). The "provenance entry" is an ADDITIVE
 *     composite that BUNDLES references to existing v1 receipts — it is not a new
 *     wire format for receipts and changes nothing about Core.
 *   - To exercise end-to-end against a LIVE signer you must supply real adapters
 *     (`issueReceipt`, `requestConsent`, `requestClassASignoff`); see README
 *     "What needs a live MCP host / signer to exercise".
 *
 * Agent identity is carried as a CLAIM (scoped, attestable) — this package does
 * not assert EP proves strong agent identity. Liability attestation names an
 * accountable owner; it is evidence, not a legal determination.
 *
 * Verification reuses @emilia-protocol/require-receipt — NO new trust
 * assumptions. The demand hook fails CLOSED.
 */
type AnyRecord = Record<string, any>;
/** "sha256:<hex>" over canonical JSON — the project-wide hash format. */
export declare function hashObject(obj: any): string;
/**
 * Bind an MCP tool call to the exact material argument object. A receipt for
 * `payment.release` with one amount or destination cannot authorize another.
 * Control carriers under `__ep` / `emilia_receipt` are deliberately excluded;
 * they transport the proof and are not tool inputs.
 */
export declare function bindToolAction(name: string, args?: AnyRecord, baseAction?: string): string;
export declare const GUARD_DECISIONS: Readonly<{
    ALLOW: "allow";
    ALLOW_WITH_SIGNOFF: "allow_with_signoff";
    DENY: "deny";
}>;
/**
 * Decide whether a tool call is irreversible and therefore must be gated.
 *
 * Resolution order:
 *   1. Per-call escalation:      args.__ep?.irreversible === true
 *      (agent/tool-call metadata may only make a call stricter, never downgrade
 *      trusted server annotations or policy)
 *   2. Trusted tool annotation:  annotations[name].irreversible
 *      (MCP destructiveHint can escalate; readOnlyHint is advisory by default)
 *   3. Policy function:          policy(name, args) → boolean
 *   4. Default:                  treated as irreversible. New or misspelled
 *      tools cannot silently bypass the guard; explicitly mark trusted read-only
 *      tools with `irreversible: false` or set `defaultIrreversible: false` only
 *      when a complete external classifier is guaranteed.
 *
 * @param {string} name  tool name
 * @param {object} args  tool arguments
 * @param {object} opts  { annotations, policy, defaultIrreversible }
 * @returns {{ irreversible: boolean, reason: string }}
 */
export declare function classifyToolCall(name: string, args?: AnyRecord, opts?: AnyRecord): AnyRecord;
/**
 * Build the legacy refusal object an MCP tool can return verbatim. Same
 * problem-details shape as require-receipt's challenge, framed for a
 * tool result so a well-behaved agent knows exactly what to bring and retry.
 */
export declare function refusal(action: string, reason: string, extra?: AnyRecord): AnyRecord;
/**
 * Verify "no irreversible tool call without a valid receipt".
 *
 * Verifies the presented receipt OFFLINE via require-receipt (pinned issuer
 * keys, freshness, action binding, allowed outcomes). Returns either
 * `{ ok: true, verified }` or `{ ok: false, refusal }` — the refusal is the
 * legacy MCP object. FAILS CLOSED: anything missing/invalid → refusal.
 * This low-level function does not consume the receipt; middleware that can
 * execute an effect MUST use `withMcpGuard`, which composes verification with
 * atomic reserve/commit semantics.
 *
 * @param {object} p
 * @param {string} p.action            canonical action bound into the receipt
 * @param {object} p.args              tool arguments (carrier for the receipt)
 * @param {object} [p.meta]            MCP _meta (header-style carrier)
 * @param {object} p.verifyOpts        require-receipt options including pinned
 *   issuer keys and, for Class-A/quorum, rpId, allowedOrigins, quorumPolicy,
 *   and the relying party's approver keys.
 * @returns {{ok:true, verified:object} | {ok:false, refusal:object}}
 */
export declare function demandReceipt({ action, args, meta, verifyOpts }: AnyRecord): AnyRecord;
export declare class ProvenanceLedger {
    entries: AnyRecord[];
    constructor();
    /** sha256: of the previous entry, "" for genesis. */
    get headHash(): any;
    /**
     * Append an entry that REFERENCES a v1 receipt for an executed irreversible
     * tool call. Stores only references + the verified summary, never a re-signed
     * receipt.
     * @param {{tool:string, action:string, actionDigest:string,
     *   receiptRef:{receipt_id?:string, receipt_hash?:string},
     *   verified?:{outcome?:string, subject?:any, signer?:any}|null,
     *   agentClaim?:any, liability?:any, at?:string}} entry
     * @returns {object} the appended entry (with its own entry_hash)
     */
    append({ tool, action, actionDigest, receiptRef, verified, agentClaim, liability, at }: AnyRecord): AnyRecord;
    /**
     * Re-verify the append-only chain offline. Does NOT re-verify the underlying
     * v1 receipts (that is the verifier's job via require-receipt); it only proves
     * the ledger is internally consistent and untampered. Returns the first
     * break, fail-closed.
     */
    verifyChain(): AnyRecord;
}
/**
 * @typedef {Object} McpGuardOptions
 * @property {(name:string, args:object)=>boolean} [policy]
 *   Returns true if a tool is irreversible. Used when no annotation/override.
 * @property {Object.<string, {irreversible?:boolean, action?:string|((args,extra)=>string),
 *   readOnlyHint?:boolean, destructiveHint?:boolean, assuranceClass?:string,
 *   assurance_class?:string, agent_claim?:any, liability?:any,
 *   onSignoffRequired?:any}>} [annotations]
 *   Per-tool flags. `action` is the canonical action bound into the receipt.
 *   `assuranceClass`/`assurance_class` set the required receipt tier;
 *   `agent_claim`/`liability` seed the provenance-ledger entry.
 * @property {boolean} [defaultIrreversible=true]
 *   How to classify a tool with no annotation/policy answer.
 * @property {boolean} [trustReadOnlyHints=false]
 *   Opt-in downgrade for MCP readOnlyHint. False by default because hints are
 *   presenter-authored metadata, not enforcement policy.
 * @property {(name:string, args:object, extra:object)=>string} [action]
 *   Global fallback to choose the action family when an annotation has none.
 *   The guard always appends an exact digest of the material tool arguments.
 * @property {object} [verifyOpts]
 *   Offline verifier policy. Class-A requires pinned rpId + allowedOrigins;
 *   quorum requires a relying-party-pinned quorumPolicy and approver keys.
 *   Passed to require-receipt: { trustedKeys, maxAgeSec, allowedOutcomes, allowInlineKey }.
 * @property {(ctx:object)=>Promise<{approved:boolean, reason?:string, by?:string}>} [requestConsent]
 *   ADAPTER. Obtain end-user/operator consent for an irreversible action.
 *   No-op default REFUSES (fail closed) unless requireSignoff is false.
 * @property {(ctx:object)=>Promise<{approved:boolean, reason?:string, signoff?:object, approver?:string}>} [requestClassASignoff]
 *   ADAPTER. Obtain a Class-A (WebAuthn/hardware) human signoff. Needs a live
 *   authenticator. No-op default REFUSES (fail closed).
 * @property {(ctx:object)=>Promise<{receipt:object, receipt_id?:string}>} [issueReceipt]
 *   ADAPTER. Emit an EP-RECEIPT-v1 for the approved action. Delegated to an EP
 *   host or `@emilia-protocol/issue`. This package never signs a receipt itself.
 * @property {ProvenanceLedger} [ledger]  shared ledger; one is created if absent.
 * @property {boolean} [enforceDemand=true]
 *   If true, an irreversible call that arrives WITH a receipt is verified by the
 *   demand hook and runs without re-gating (the agent already did the loop).
 *   If it arrives WITHOUT a receipt, it is routed through consent→signoff→issue.
 * @property {{reserve:Function, commit:Function, release:Function}} [store]
 *   Ownership-fenced one-time consumption store. The process-local default is
 *   for demos only; fleets provide one shared durable store.
 * @property {(name:string)=>object|undefined} [getAnnotations]
 *   Optional resolver for untrusted MCP metadata. Only destructiveHint may
 *   escalate by default; it cannot override local action/policy annotations.
 */
/**
 * Wrap an MCP tool-call handler with EP accountability.
 *
 * @param {(name:string, args:object, extra?:object)=>Promise<any>} handler
 *   The MCP server's existing tool dispatcher. `extra` may carry MCP `_meta`.
 * @param {McpGuardOptions} options
 * @returns {(name:string, args:object, extra?:object)=>Promise<any>} guarded dispatcher
 */
export declare function withMcpGuard(handler: (...args: any[]) => any, options?: AnyRecord): any;
/**
 * Wrap an MCP dispatcher with the live v1 enforcement loop from
 * @emilia-protocol/sdk's `client.requireReceipt()`.
 *
 * This is the tiny adoption path for tool authors who want the system-of-record
 * guarantee, not just a demand-side 402 proof check: irreversible calls are
 * classified here, but the SDK performs create → signoff → consume → mutate →
 * execution-attest. If consume fails, the handler is never called.
 *
 * Required option:
 *   client: an object with `requireReceipt(params, mutate)` (EPClient).
 *
 * Per-tool annotations may include:
 *   actionType, targetResourceId, afterState, beforeState, amount, currency,
 *   riskFlags, approverId, executingSystem, onSignoffRequired, executionId.
 * Values may be constants or functions of (args, extra).
 */
export declare function withMcpReceiptGuard(handler: (...args: any[]) => any, options?: AnyRecord): any;
declare const _default: {
    withMcpGuard: typeof withMcpGuard;
    withMcpReceiptGuard: typeof withMcpReceiptGuard;
    demandReceipt: typeof demandReceipt;
    refusal: typeof refusal;
    classifyToolCall: typeof classifyToolCall;
    bindToolAction: typeof bindToolAction;
    ProvenanceLedger: typeof ProvenanceLedger;
    hashObject: typeof hashObject;
    GUARD_DECISIONS: Readonly<{
        ALLOW: "allow";
        ALLOW_WITH_SIGNOFF: "allow_with_signoff";
        DENY: "deny";
    }>;
};
export default _default;
//# sourceMappingURL=index.d.ts.map