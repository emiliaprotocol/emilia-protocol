/**
 * @emilia-protocol/openai-agents — type declarations.
 * @license Apache-2.0
 */

/** A single per-interruption decision. */
export interface ReceiptDecision {
  decision: 'approve' | 'reject';
  /** Canonical EP action_type this tool call maps to (via actionFor), or null. */
  action: string | null;
  /** The OpenAI tool name from the interruption, or null. */
  toolName: string | null;
  /** The tool-call id (function_call.callId or hosted id), or null. */
  callId: string | null;
  /** Machine-readable reason for the decision. */
  reason: string;
  /** Present when a valid receipt was consumed. */
  receipt_id?: string;
  /** The receipt subject (the named accountable human), when valid. */
  subject?: string;
}

export interface ResolveResult {
  /** Interruptions that were approved (and state.approve called). */
  approved: unknown[];
  /** Interruptions that were rejected (and state.reject called). */
  rejected: unknown[];
  /** All per-interruption decisions, in order. */
  decisions: ReceiptDecision[];
}

export interface RequireReceiptForOpenAIAgentOptions {
  /** base64url SPKI-DER issuer public keys you trust. */
  trustedKeys?: string[];
  /** Also accept a receipt's own inline key (integrity, NOT trust). Default false. */
  allowInlineKey?: boolean;
  /** Reject receipts older than this many seconds. Default 900. */
  maxAgeSec?: number;
  /** REQUIRED. Map a tool call to the canonical EP action_type the receipt must bind. */
  actionFor: (toolName: string, args: unknown) => string;
}

export interface OpenAIAgentReceiptGate {
  /** Decide a single interruption against a single receipt. */
  decide(interruption: unknown, receipt: object | null | undefined): ReceiptDecision;
  /** Resolve all pending tool-approval interruptions on a run result. */
  resolve(
    runResult: { interruptions?: unknown[]; state?: unknown },
    ctx?: {
      receipts?: Record<string, object> | Map<string, object> | object[];
      state?: unknown;
    },
  ): Promise<ResolveResult>;
}

export function requireReceiptForOpenAIAgent(
  opts: RequireReceiptForOpenAIAgentOptions,
): OpenAIAgentReceiptGate;

/** Reset the process-local consumed-receipt set. Test/ops helper. */
export function _resetConsumed(): void;

declare const _default: {
  requireReceiptForOpenAIAgent: typeof requireReceiptForOpenAIAgent;
  _resetConsumed: typeof _resetConsumed;
};
export default _default;
