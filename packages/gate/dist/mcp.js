// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
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
import { parseReceiptCarrier } from '@emilia-protocol/require-receipt';
function resolveReceipt(args, opts) {
    if (typeof opts.receipt === 'function')
        return opts.receipt(args);
    if (opts.receipt)
        return opts.receipt;
    if (args && typeof args === 'object') {
        if (args._emilia_receipt)
            return args._emilia_receipt;
        if (args.emilia_receipt)
            return args.emilia_receipt;
        if (typeof args._emilia_receipt_b64 === 'string') {
            return parseReceiptCarrier(args._emilia_receipt_b64);
        }
    }
    return null;
}
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
export function gateMcpTool(gate, o = {}, handler) {
    if (!gate || typeof gate.run !== 'function')
        throw new Error('gateMcpTool requires an EMILIA Gate (with .run)');
    if (typeof handler !== 'function')
        throw new Error('gateMcpTool requires a tool handler function');
    const { tool, protocol = 'mcp', action } = o;
    if (!tool)
        throw new Error('gateMcpTool requires { tool }');
    const refused = (reason, body = null) => ({
        isError: true,
        content: [{
                type: 'text',
                text: `EMILIA Gate refused "${tool}": ${reason}. `
                    + 'This is a high-risk action; present a valid, sufficiently-assured, unused human/quorum receipt.',
            }],
        _emilia: {
            gate: 'refused',
            status: 428,
            reason,
            challenge: body,
        },
    });
    return async function gatedTool(args = {}, extra) {
        const selector = { protocol, tool, ...(action ? { action_type: action } : {}) };
        let receipt;
        let observedAction;
        try {
            receipt = resolveReceipt(args, o);
            observedAction = typeof o.observedAction === 'function'
                ? o.observedAction(args, extra)
                : (o.observedAction ?? args);
        }
        catch {
            return refused('receipt_boundary_failed');
        }
        const out = await gate.run({ selector, receipt, observedAction }, () => handler(args, extra));
        if (!out.ok) {
            return refused(out.authorization.reason, out.body);
        }
        const result = out.result;
        // Attach the proof without clobbering a structured tool result.
        if (result && typeof result === 'object' && !Array.isArray(result)) {
            return { ...result, _emilia: { gate: 'allowed', execution: out.execution, reliance: out.packet } };
        }
        return { result, _emilia: { gate: 'allowed', execution: out.execution, reliance: out.packet } };
    };
}
/**
 * Convenience: wrap a map of { toolName: handler } in one call. Tools not named
 * in the manifest still pass through the gate (which lets non-guarded tools run).
 */
export function gateMcpTools(gate, handlers = {}, opts = {}) {
    const wrapped = {};
    for (const [tool, handler] of Object.entries(handlers)) {
        wrapped[tool] = gateMcpTool(gate, { ...opts, tool }, handler);
    }
    return wrapped;
}
export default { gateMcpTool, gateMcpTools };
//# sourceMappingURL=mcp.js.map