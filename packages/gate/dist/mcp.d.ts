/**
 * EMILIA Gate — MCP drop-in. The lowest-friction place to put the firewall:
 * agents already live at the MCP tool-call boundary, and a single wrapper turns
 * a dangerous MCP tool into a receipt-required one.
 *
 *   import { createTrustedActionFirewall } from '@emilia-protocol/gate';
 *   import { gateMcpTool } from '@emilia-protocol/gate/mcp';
 *   const gate = createTrustedActionFirewall({ trustedKeys: [ISSUER], store: sharedConsumptionStore });
 *
 *   server.tool('release_payment',
 *     gateMcpTool(gate, { tool: 'release_payment' }, async (args) => actuallyPay(args)));
 *
 * A guarded call with no valid, sufficiently-assured, non-replayed receipt
 * returns a structured MCP error (isError) carrying the Receipt-Required
 * challenge, so the agent knows to go get a human/quorum to authorize THIS exact
 * action. On success the tool runs and an execution proof + reliance packet are
 * attached under `_emilia`.
 *
 * Receipt resolution order (override with opts.receipt): args._emilia_receipt,
 * args.emilia_receipt, then a base64 string in args._emilia_receipt_b64.
 */
type Obj = Record<string, any>;
type GateMcpToolOptions = {
    tool?: string;
    protocol?: string;
    action?: string;
    observedAction?: Obj | ((args: Obj, extra: any) => any);
    receipt?: Obj | ((args: Obj) => any);
};
/**
 * Wrap a single MCP tool handler so it runs only behind a passing gate check.
 * @param {object} gate     an EMILIA Gate (createGate/createTrustedActionFirewall)
 * @param {object} o
 * @param {string} [o.tool]   the MCP tool name (matched against the manifest)
 * @param {string} [o.protocol='mcp']
 * @param {string} [o.action] explicit action_type (else resolved by the manifest from {protocol,tool})
 * @param {object|function} [o.observedAction] the system-of-record facts to bind (default: the tool args)
 * @param {object|function} [o.receipt] override receipt resolution
 * @param {function} handler the real tool implementation (args, extra) => result
 * @returns {function} a gated MCP tool handler
 */
export declare function gateMcpTool(gate: any, o: GateMcpToolOptions | undefined, handler: any): (args: {} | undefined, extra: any) => Promise<any>;
/**
 * Convenience: wrap a map of { toolName: handler } in one call. Tools not named
 * in the manifest still pass through the gate (which lets non-guarded tools run).
 */
export declare function gateMcpTools(gate: any, handlers?: {}, opts?: {}): {};
declare const _default: {
    gateMcpTool: typeof gateMcpTool;
    gateMcpTools: typeof gateMcpTools;
};
export default _default;
//# sourceMappingURL=mcp.d.ts.map