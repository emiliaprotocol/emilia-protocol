/**
 * @emilia-protocol/langchain — guard LangChain.js tools with EMILIA Protocol.
 * @license Apache-2.0
 *
 * Two ways to gate a LangChain tool:
 *
 *  1. requireReceiptForLangChainTool(tool, { action | actionFor, trustedKeys })
 *     — the RECOMMENDED, offline path. A high-risk tool call runs only when it
 *     arrives with a valid EMILIA authorization receipt (EP-RECEIPT-v1) bound to
 *     the exact action: missing -> refused, valid -> runs, replay -> refused,
 *     forged -> refused (RR-1). Verification is offline Ed25519 over canonical
 *     JSON via @emilia-protocol/require-receipt's makeReceiptGate — zero network,
 *     no vendor in the loop. This is the lane that makes the approval *portable
 *     evidence* an auditor can check without trusting you.
 *
 *  2. guardAction / withGuard — the LEGACY hosted precheck path. It can inspect
 *     a remote policy decision, but withGuard always refuses execution because
 *     a hosted boolean or callback is not exact-action authority. Kept only for
 *     migration compatibility; use (1) for execution.
 *
 * Necessary-not-sufficient: the gate composes with — never replaces — the
 * resource owner's own checks.
 *
 * See: draft-schrock-ep-authorization-receipts, draft-schrock-ep-enforcement-point.
 */

// Monorepo: import the sibling package by relative path (same convention as
// @emilia-protocol/openai-agents and @emilia-protocol/gate). When installed from
// npm, the published build resolves the bare "@emilia-protocol/require-receipt"
// specifier; both point at the same canonical makeReceiptGate.
import { makeReceiptGate } from '../../require-receipt/gate.js';
import { bindExecutorAction, bindToolAction, snapshotToolArguments } from '../../require-receipt/index.js';
// Optional OpenTelemetry emission, loaded LAZILY and never declared as a
// dependency. Resolution failure turns telemetry off; it never breaks the
// authorization path.
type OtelAuthorizationModule = typeof import('../../otel-authorization/index.js');
let otelAuthorizationModule: Promise<OtelAuthorizationModule | null> | null = null;
function loadOtelAuthorization(): Promise<OtelAuthorizationModule | null> {
  if (!otelAuthorizationModule) {
    otelAuthorizationModule = import('../../otel-authorization/index.js').catch(() => null);
  }
  return otelAuthorizationModule;
}

type Obj = Record<string, any>;
type Tool = any;

// ── (1) Offline receipt gate — the recommended path ──────────────────────────

/** Process-local atomic receipt state shared across gates in this process. */
const consumed = new Map<string, string>();
const sharedStore = {
  ownershipFenced: true,
  async reserve(id: string): Promise<boolean> {
    if (consumed.has(id)) return false;
    consumed.set(id, 'reserved');
    return true;
  },
  async commit(id: string): Promise<boolean> {
    if (consumed.get(id) !== 'reserved') throw new Error('reservation_not_owned');
    consumed.set(id, 'committed');
    return true;
  },
  async release(id: string): Promise<boolean> {
    if (consumed.get(id) !== 'reserved') throw new Error('reservation_not_owned');
    consumed.delete(id);
    return true;
  },
};

/** Reset consumed receipts. Test/ops helper — not a production control. */
export function _resetConsumed() {
  consumed.clear();
}

/**
 * Pull the receipt a caller attached to this tool invocation. The receipt is
 * out-of-band call metadata, so by default we read it from the LangChain
 * RunnableConfig (`config.configurable.emiliaReceipt`) and fall back to the
 * input object. Override with opts.getReceipt(input, config) for custom transport.
 */
function defaultGetReceipt(input: any, config: any): any {
  const fromConfig =
    config?.configurable?.emiliaReceipt ??
    config?.configurable?.emilia_receipt;
  if (fromConfig != null) return fromConfig;
  if (input && typeof input === 'object') {
    return input.emiliaReceipt ?? input.emilia_receipt ?? null;
  }
  return null;
}

/**
 * Wrap a LangChain tool so EVERY execution entry point requires a valid,
 * action-bound EMILIA receipt before the underlying tool runs: `.invoke()`,
 * `.call()`, `.batch()`, `.stream()`, and the raw `.func` / `._call` bodies.
 * Gating `.invoke()` alone is not enough: langchain-core reaches the same
 * effect through several Runnable methods, and any one of them left bound to
 * the raw target is an ungated path to the tool. Every other method is bound to
 * the proxy, so an internal `this.invoke(...)` also lands on the gate.
 * Preserves the tool's identity, name, description, and schema (thin Proxy;
 * works with StructuredTool, DynamicStructuredTool, or anything exposing
 * `.invoke(input, config)`).
 *
 * @template {{invoke?: (input:any, config?:any, ...rest:any[]) => any}} T
 * @param {T} tool a tool exposing `.invoke(input, config?)`
 * @param {object} opts
 * @param {string} [opts.action] canonical base action_type. The wrapper always
 *   adds a digest of the actual tool name and complete executor-side input.
 * @param {(input:any)=>string} [opts.actionFor] derive the base action_type from
 *   the call input. Exact input binding remains automatic and cannot be disabled.
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER issuer keys you trust.
 * @param {boolean} [opts.allowInlineKey=false] also accept the receipt's own key
 *   (proves integrity, NOT issuer trust) — demo only.
 * @param {number} [opts.maxAgeSec=900]
 * @param {(input:any, config:any)=>(object|null|undefined)} [opts.getReceipt]
 * @param {{reserve:(id:string)=>Promise<boolean>|boolean,
 *   commit:(id:string)=>Promise<boolean>|boolean,
 *   release:(id:string)=>Promise<boolean>|boolean}} [opts.store]
 * @returns {T}
 */
export function requireReceiptForLangChainTool(tool: Tool, opts: Obj = {}): Tool {
  const {
    action,
    actionFor,
    trustedKeys = [],
    allowInlineKey = false,
    maxAgeSec = 900,
    getReceipt = defaultGetReceipt,
    store = sharedStore,
    otelAuthorization,
    ...gateOptions
  } = opts;

  if (typeof actionFor !== 'function' && (typeof action !== 'string' || !action)) {
    throw new TypeError('requireReceiptForLangChainTool: provide opts.action (string) or opts.actionFor (input)=>action_type');
  }
  const originalInvoke = typeof tool?.invoke === 'function' ? tool.invoke : null;
  if (!originalInvoke) {
    throw new Error('requireReceiptForLangChainTool: tool must expose an .invoke(input, config) method');
  }

  // Derive the action exactly once per invocation. Evaluating a caller-supplied
  // mapper twice creates a TOCTOU surface if it is stateful or nondeterministic.
  const gates = new Map();
  const gateFor = (boundAction: string): any => {
    if (!gates.has(boundAction)) {
      // gateOptions is spread FIRST: the derived exact action and the
      // consumption store are not caller-overridable.
      gates.set(boundAction, makeReceiptGate({
        ...gateOptions,
        trustedKeys,
        allowInlineKey,
        maxAgeSec,
        action: boundAction,
        store,
      }));
    }
    return gates.get(boundAction);
  };

  /**
   * Emit gen_ai.tool.authorization.* for one gated LangChain tool execution.
   *
   * LangChain 1.0's HumanInTheLoopMiddleware slot is a boolean: the wrapped tool
   * either runs or refuses, and no approver, signature or scope travels with the
   * decision. This wrapper drives that boolean from an action-bound
   * EP-RECEIPT-v1, so an allow backed by a consumed receipt is
   * authorized_in_scope at grade independently_verifiable, and every other
   * outcome is self_attested.
   *
   * Emission never changes the wrapper's behaviour: a refusal is still thrown,
   * an allow still returns the tool's result.
   */
  const emitAuthorizationAttributes = async (
    allowed: boolean,
    receiptBound: boolean,
    boundAction: string,
    consumed: { receiptId?: string; receipt?: any } | null,
    reason: string,
  ): Promise<void> => {
    if (!otelAuthorization) return;
    const otel = await loadOtelAuthorization();
    if (!otel) return;
    const evidence: Obj = { action_digest: boundAction };
    if (receiptBound && consumed?.receipt && typeof consumed.receiptId === 'string' && consumed.receiptId !== '') {
      let receiptDigest: string | null = null;
      try { receiptDigest = bindExecutorAction('receipt', consumed.receipt); } catch { receiptDigest = null; }
      if (receiptDigest) {
        evidence.evidence_digest = receiptDigest;
        evidence.evidence_format = 'application/vnd.emilia.receipt.v1+json';
        evidence.evidence_locator = `emilia-receipt:${consumed.receiptId}`;
      }
    }
    // Without a digest there is nothing another party can check, so the honest
    // report is auto_approved at self_attested rather than a grade we cannot back.
    const bound = receiptBound && typeof evidence.evidence_digest === 'string';
    try {
      await otel.emitToolAuthorization(
        otelAuthorization,
        otel.mapLangChainDecision(allowed, bound, evidence as any),
        { runtime: 'langchain', tool_name: tool?.name, action: boundAction, reason },
      );
    } catch {
      // Telemetry failure is never an authorization failure.
    }
  };

  const bindingError = (): Error & { emilia?: any } => {
    const err = new Error('EMILIA blocked tool call: action_binding_invalid') as Error & { emilia?: any };
    err.emilia = { status: 428, reason: 'action_binding_invalid' };
    return err;
  };

  /**
   * The single gated execution path. Every entry point the tool exposes routes
   * through here, so the receipt requirement cannot be sidestepped by calling a
   * different Runnable method.
   *
   * @param input      the executor-side call input (hashed into the action)
   * @param config     the RunnableConfig used to locate the receipt
   * @param execute    runs the ORIGINAL, unproxied implementation on the exact
   *                   snapshot that was hashed
   */
  const gatedExecution = async (
    input: any,
    config: any,
    execute: (executionInput: any) => any,
  ): Promise<any> => {
    const receipt = getReceipt(input, config);
    let executionInput: any;
    try {
      executionInput = snapshotToolArguments(input);
    } catch {
      throw bindingError();
    }
    /** @type {string | null | undefined} */
    let baseAction = action;
    if (actionFor) {
      try {
        baseAction = actionFor(snapshotToolArguments(executionInput));
      } catch {
        baseAction = null;
      }
    }
    let boundAction: string;
    try {
      if (typeof baseAction !== 'string' || !baseAction) throw new TypeError('action_binding_invalid');
      boundAction = bindToolAction(tool?.name || 'langchain.tool', executionInput, baseAction);
    } catch {
      throw bindingError();
    }
    const gate = gateFor(boundAction);
    const r = await gate.run(receipt, {}, async () => execute(executionInput));
    if (!r.ok) {
      const reason = r.body?.rejected?.reason || (r.body?.required ? 'receipt_required' : 'refused');
      await emitAuthorizationAttributes(false, false, boundAction, null, reason);
      const err = new Error(`EMILIA blocked "${boundAction}": ${reason}`) as Error & { emilia?: any };
      err.emilia = { status: r.status, reason, body: r.body };
      throw err;
    }
    await emitAuthorizationAttributes(true, true, boundAction, { receiptId: r.receiptId, receipt }, 'valid_action_bound_receipt');
    return r.result;
  };

  const gatedInvoke = async (input: any, config: any, ...rest: any[]): Promise<any> =>
    gatedExecution(input, config, (executionInput) =>
      originalInvoke.call(tool, executionInput, config, ...rest));

  // langchain-core implements .call() as a thin wrapper over this.invoke, so it
  // routes straight to the gated invoke: exactly one gated execution, no second
  // trip through the raw target.
  const gatedCall = async (input: any, config: any, ...rest: any[]): Promise<any> =>
    gatedInvoke(input, config, ...rest);

  // .batch() takes one receipt per element. LangChain accepts either one config
  // for the whole batch or one per input; both are honored here. There is no
  // returnExceptions escape hatch: a refusal for any element propagates, so a
  // partially authorized batch never runs the unauthorized part silently.
  const gatedBatch = async (inputs: any, config?: any, ...rest: any[]): Promise<any[]> => {
    if (!Array.isArray(inputs)) throw bindingError();
    const configFor = (i: number): any => (Array.isArray(config) ? config[i] : config);
    return Promise.all(inputs.map((input, i) => gatedInvoke(input, configFor(i), ...rest)));
  };

  // .stream() resolves to the underlying stream only after the gate has cleared
  // and consumed the receipt; the original (unproxied) stream then runs inside
  // the gate, so the effect happens exactly once.
  const gatedStream = async (input: any, config: any, ...rest: any[]): Promise<any> => {
    const originalStream = tool.stream;
    return gatedExecution(input, config, (executionInput) =>
      originalStream.call(tool, executionInput, config, ...rest));
  };

  // .func / ._call are the raw tool bodies that StructuredTool and
  // DynamicStructuredTool expose as ordinary properties. Reaching them through
  // the proxy must not skip the gate. The original body runs inside the gate so
  // its return shape is preserved exactly.
  const gatedRawBody = (name: 'func' | '_call') =>
    async (input: any, second: any, ...rest: any[]): Promise<any> => {
      const original = tool[name];
      return gatedExecution(input, second, (executionInput) =>
        original.call(tool, executionInput, second, ...rest));
    };

  return new Proxy(tool, {
    get(t, prop, receiver) {
      // .invoke is required and validated above, so it is always gated.
      if (prop === 'invoke') return gatedInvoke;
      // The remaining entry points are gated only when the target actually has
      // them, so the proxy never invents a method and duck-typing is preserved.
      // typeof t !== 'function' keeps Function.prototype.call out of this branch
      // for the rare callable-with-.invoke target.
      if (prop === 'call' && typeof t !== 'function' && typeof t.call === 'function') return gatedCall;
      if (prop === 'batch' && typeof t.batch === 'function') return gatedBatch;
      if (prop === 'stream' && typeof t.stream === 'function') return gatedStream;
      if (prop === 'func' && typeof t.func === 'function') return gatedRawBody('func');
      if (prop === '_call' && typeof t._call === 'function') return gatedRawBody('_call');
      const value = Reflect.get(t, prop, receiver);
      // Bind to the RECEIVER, not the raw target: any other method that reaches
      // the effect through `this.invoke` (transform, streamEvents, streamLog,
      // pipe outputs, ...) then resolves to the gated invoke instead of the
      // ungated original.
      return typeof value === 'function' ? value.bind(receiver) : value;
    },
  });
}

/** Lower-level: get the underlying makeReceiptGate for advanced orchestration. */
export function makeLangChainReceiptGate(opts: Obj = {}): Obj {
  const { action, actionFor, toolName, input, store = sharedStore, ...gateOptions } = opts;
  if (typeof actionFor !== 'function' && (typeof action !== 'string' || !action)) {
    throw new TypeError('makeLangChainReceiptGate: provide opts.action or opts.actionFor');
  }
  if (typeof toolName !== 'string' || !toolName || !Object.prototype.hasOwnProperty.call(opts, 'input')) {
    throw new TypeError('makeLangChainReceiptGate: opts.toolName and opts.input are required for exact binding');
  }
  const baseAction = typeof actionFor === 'function' ? actionFor(input) : action;
  const boundAction = bindToolAction(toolName, input, baseAction);
  // The derived exact action and the store are not caller-overridable.
  return makeReceiptGate({ ...gateOptions, action: boundAction, store });
}

// ── (2) Legacy hosted policy gate — kept for back-compat ─────────────────────

const DEFAULT_GATE = 'https://www.emiliaprotocol.ai/api/trust/gate';

/**
 * LEGACY: ask a hosted EMILIA gate whether an action may proceed. The decision
 * is the operator's word, not offline-verifiable evidence — prefer
 * requireReceiptForLangChainTool for irreversible actions.
 * @param {object} [opts]
 * @param {string} [opts.actor]
 * @param {string} [opts.action]
 * @param {object} [opts.context]
 * @param {string} [opts.gateUrl]
 * @param {typeof fetch} [opts.fetchImpl]
 */
export async function guardAction({ actor, action, context = {}, gateUrl = DEFAULT_GATE, fetchImpl }: Obj = {}): Promise<Obj> {
  if (!action) throw new Error('guardAction: `action` is required');
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) throw new Error('guardAction: no fetch implementation available; pass { fetchImpl }');

  let res;
  let raw;
  try {
    res = await doFetch(gateUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ actor, action, context }),
    });
    raw = await res.json().catch(() => ({}));
  } catch {
    return { allow: false, deny: true, signoffRequired: false, reason: 'gate_unavailable', raw: {} };
  }

  const decision = String(raw.decision || raw.verdict || '');
  const httpOk = res?.ok === true
    || (res?.ok === undefined && Number.isInteger(res?.status) && res.status >= 200 && res.status < 300);
  const signoffRequired = raw.signoff_required === true
    || decision === 'allow_with_signoff'
    || decision === 'signoff_required'
    || decision === 'review';
  const allow = httpOk && decision === 'allow' && raw.allowed !== false && !signoffRequired;
  const deny = !allow && !signoffRequired;
  const reason = raw.reason || (!httpOk ? 'gate_unavailable' : (!allow && !signoffRequired ? 'unrecognized_gate_decision' : undefined));
  return { allow, deny, signoffRequired, reason, raw };
}

/**
 * LEGACY hosted-gate wrapper. It is now precheck-only and always refuses
 * execution because a hosted boolean or application callback is not portable,
 * exact-action execution authority. Use requireReceiptForLangChainTool.
 */
export function withGuard(tool: Tool, opts: Obj = {}): Tool {
  const { action, actor, context, onSignoff, gateUrl, fetchImpl } = opts;
  if (!action) throw new Error('withGuard: opts.action is required');

  const originalInvoke = typeof tool?.invoke === 'function' ? tool.invoke : null;
  if (!originalInvoke) throw new Error('withGuard: tool must expose an .invoke(input) method');

  const run = async (input: any, ...rest: any[]): Promise<any> => {
    const decision = await guardAction({
      actor: actor || tool?.name || 'langchain-agent',
      action,
      context: typeof context === 'function' ? context(input) : (context || { input }),
      gateUrl,
      fetchImpl,
    });
    if (decision.signoffRequired) {
      if (typeof onSignoff === 'function') {
        try { await onSignoff(decision, input); } catch { /* notification failure stays closed */ }
      }
      throw new Error(`EMILIA blocked legacy hosted signoff for "${action}": use requireReceiptForLangChainTool with an exact-action receipt`);
    }
    const suffix = decision.reason ? `: ${decision.reason}` : '';
    throw new Error(`EMILIA blocked legacy hosted gate execution for "${action}"${suffix}; use requireReceiptForLangChainTool`);
  };

  // Every entry point refuses, not just .invoke. A legacy hosted decision is
  // never execution authority, so .call/.batch/.stream/.func/._call must not
  // reach the raw target either.
  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === 'invoke') return run;
      if (prop === 'call' && typeof target !== 'function' && typeof target.call === 'function') return run;
      if (prop === 'batch' && typeof target.batch === 'function') return run;
      if (prop === 'stream' && typeof target.stream === 'function') return run;
      if (prop === 'func' && typeof target.func === 'function') return run;
      if (prop === '_call' && typeof target._call === 'function') return run;
      const value = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(receiver) : value;
    },
  });
}

export default {
  requireReceiptForLangChainTool,
  makeLangChainReceiptGate,
  _resetConsumed,
  guardAction,
  withGuard,
};
