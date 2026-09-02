/**
 * @emilia-protocol/langgraph
 * @license Apache-2.0
 *
 * A security adapter for LangGraph's documented HumanInterrupt / HumanResponse
 * protocol, including the Agent Inbox UI. The UI is a delivery surface, not an
 * authority source. This adapter binds a pinned issuer's receipt to the exact
 * action, arguments, thread, and interrupt occurrence before a graph may resume.
 *
 * The critical edit rule is explicit: editing action A creates action A-prime.
 * Authority for A never authorizes A-prime. An edit therefore returns
 * `reauthorize` until a fresh receipt bound to A-prime is supplied.
 */
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

const localStates = new Map<string, 'reserved' | 'committed'>();
const localStore = {
  durable: false,
  ownershipFenced: true,
  async reserve(id: string): Promise<boolean> {
    if (localStates.has(id)) return false;
    localStates.set(id, 'reserved');
    return true;
  },
  async commit(id: string): Promise<boolean> {
    if (localStates.get(id) !== 'reserved') throw new Error('reservation_not_owned');
    localStates.set(id, 'committed');
    return true;
  },
  async release(id: string): Promise<boolean> {
    if (localStates.get(id) !== 'reserved') throw new Error('reservation_not_owned');
    localStates.delete(id);
    return true;
  },
};

/** Test and single-process operations helper. Not a production control. */
export function _resetLangGraphConsumption(): void {
  localStates.clear();
}

function validId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512;
}

function boundOccurrence(occurrence: LangGraphOccurrence): string | null {
  if (!validId(occurrence?.threadId) || !validId(occurrence?.interruptId)) return null;
  // JSON tuple encoding is injective. Delimiter concatenation would collide for
  // ("a:b", "c") and ("a", "b:c").
  const encoded = JSON.stringify([occurrence.threadId, occurrence.interruptId]);
  return encoded.length <= 512 ? encoded : null;
}

function snapshotActionRequest(value: unknown): LangGraphActionRequest | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const request = value as AnyRecord;
  if (!validId(request.action)) return null;
  try {
    const args = snapshotToolArguments(request.args);
    if (!args || typeof args !== 'object' || Array.isArray(args)) return null;
    return { action: request.action, args };
  } catch {
    return null;
  }
}

function snapshotInterrupt(value: unknown): LangGraphHumanInterrupt | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const input = value as AnyRecord;
  const actionRequest = snapshotActionRequest(input.action_request);
  const config = input.config;
  if (!actionRequest || !config || typeof config !== 'object' || Array.isArray(config)) return null;
  for (const field of ['allow_ignore', 'allow_respond', 'allow_edit', 'allow_accept']) {
    if (typeof config[field] !== 'boolean') return null;
  }
  return {
    action_request: actionRequest,
    config: {
      allow_ignore: config.allow_ignore,
      allow_respond: config.allow_respond,
      allow_edit: config.allow_edit,
      allow_accept: config.allow_accept,
    },
    ...(typeof input.description === 'string' ? { description: input.description } : {}),
  };
}

function oneResponse(value: unknown): LangGraphHumanResponse | null {
  const candidate = Array.isArray(value)
    ? (value.length === 1 ? value[0] : null)
    : value;
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
  const response = candidate as AnyRecord;
  if (!['accept', 'ignore', 'response', 'edit'].includes(response.type)) return null;
  return { type: response.type, args: response.args ?? null } as LangGraphHumanResponse;
}

function responseAllowed(interrupt: LangGraphHumanInterrupt, response: LangGraphHumanResponse): boolean {
  return response.type === 'accept' ? interrupt.config.allow_accept
    : response.type === 'edit' ? interrupt.config.allow_edit
      : response.type === 'response' ? interrupt.config.allow_respond
        : interrupt.config.allow_ignore;
}

function sameInterrupt(current: unknown, frozen: LangGraphHumanInterrupt): boolean {
  const snap = snapshotInterrupt(current);
  return snap !== null && JSON.stringify(snap) === JSON.stringify(frozen);
}

function sameResponse(current: unknown, frozen: LangGraphHumanResponse): boolean {
  const snap = oneResponse(current);
  if (!snap || snap.type !== frozen.type) return false;
  if (snap.type === 'edit') {
    const left = snapshotActionRequest(snap.args);
    const right = snapshotActionRequest(frozen.args);
    return left !== null && right !== null && JSON.stringify(left) === JSON.stringify(right);
  }
  // Accept resumes only the trusted frozen interrupt. Client-supplied accept
  // args are intentionally non-authoritative and never reach execution.
  return true;
}

/**
 * Derive the exact receipt action for an interrupt or edited request.
 * The occurrence comes from the trusted runtime so identical sibling actions
 * cannot share authority.
 */
export function bindLangGraphAction(
  request: LangGraphActionRequest,
  occurrence: LangGraphOccurrence,
  actionFor?: (action: string, args: Record<string, any>) => string,
): string {
  const occurrenceBinding = boundOccurrence(occurrence);
  if (!occurrenceBinding) {
    throw new TypeError('runtime_occurrence_invalid');
  }
  const frozen = snapshotActionRequest(request);
  if (!frozen) throw new TypeError('action_request_invalid');
  const mapperArgs = snapshotToolArguments(frozen.args);
  const base = actionFor ? actionFor(frozen.action, mapperArgs) : `langgraph.action.${frozen.action}`;
  if (!validId(base)) throw new TypeError('action_binding_invalid');
  return bindToolAction(
    frozen.action,
    frozen.args,
    base,
    occurrenceBinding,
  );
}

export function createLangGraphApprovalAdapter(opts: AnyRecord = {}): AnyRecord {
  const { actionFor, store = localStore, otelAuthorization, ...gateOptions } = opts;
  if (actionFor !== undefined && typeof actionFor !== 'function') {
    throw new TypeError('createLangGraphApprovalAdapter: actionFor must be a function');
  }
  const gates = new Map<string, AnyRecord>();
  const gateFor = (action: string): AnyRecord => {
    let gate = gates.get(action);
    if (!gate) {
      // The derived exact action and consumption store are not caller-overridable.
      gate = makeReceiptGate({ ...gateOptions, action, store });
      gates.set(action, gate);
    }
    return gate;
  };

  /**
   * Resolve one documented Agent Inbox response. Only `resume` carries execution
   * authority. `pass` is non-authorizing conversation/control flow.
   */
  async function resolveInner(
    interruptInput: unknown,
    responseInput: unknown,
    receipt: AnyRecord | null | undefined,
    occurrence: LangGraphOccurrence,
  ): Promise<AnyRecord> {
    const interrupt = snapshotInterrupt(interruptInput);
    const response = oneResponse(responseInput);
    if (!interrupt) return { decision: 'reject', reason: 'interrupt_invalid', action: null };
    if (!response) return { decision: 'reject', reason: 'response_invalid', action: null };
    if (!responseAllowed(interrupt, response)) {
      return { decision: 'reject', reason: 'response_type_not_allowed', action: null };
    }

    if (response.type === 'ignore' || response.type === 'response') {
      if (response.type === 'ignore' && response.args !== null) {
        return { decision: 'reject', reason: 'response_invalid', action: null };
      }
      if (response.type === 'response' && typeof response.args !== 'string') {
        return { decision: 'reject', reason: 'response_invalid', action: null };
      }
      return {
        decision: 'pass',
        reason: 'non_authorizing_human_response',
        action: null,
        response,
      };
    }

    const request = response.type === 'edit'
      ? snapshotActionRequest(response.args)
      : interrupt.action_request;
    if (!request) return { decision: 'reject', reason: 'edited_action_invalid', action: null };

    let action: string;
    try {
      action = bindLangGraphAction(request, occurrence, actionFor);
    } catch (error: any) {
      return { decision: 'reject', reason: error?.message || 'action_binding_invalid', action: null };
    }

    if (response.type === 'edit' && !receipt) {
      return {
        decision: 'reauthorize',
        reason: 'fresh_receipt_required_for_edit',
        action,
        action_request: request,
      };
    }
    if (!receipt) {
      return { decision: 'reject', reason: 'no_receipt_for_interrupt', action };
    }

    const gate = gateFor(action);
    const checked = await gate.check(receipt);
    if (!checked.ok) {
      const gateReason = checked.body?.rejected?.reason
        || (checked.body?.required ? 'receipt_required' : 'invalid_receipt');
      return {
        decision: response.type === 'edit' && gateReason === 'action_mismatch' ? 'reauthorize' : 'reject',
        reason: response.type === 'edit' && gateReason === 'action_mismatch'
          ? 'fresh_receipt_required_for_edit'
          : gateReason,
        action,
        ...(response.type === 'edit' ? { action_request: request } : {}),
      };
    }

    // Freeze, verify, reserve, and then re-read before durable consumption.
    // Mutable UI/runtime objects can drift across the await in gate.check().
    if (!sameInterrupt(interruptInput, interrupt) || !sameResponse(responseInput, response)) {
      try { await gate.release(checked.receiptId); } catch { /* fail closed */ }
      return { decision: 'reject', reason: 'request_drifted_before_consumption', action };
    }

    try {
      // Spend before returning a response that can resume execution.
      await gate.commit(checked.receiptId);
    } catch {
      return { decision: 'reject', reason: 'consumption_commit_failed', action };
    }

    // A mutation during commit crosses the indeterminate authority boundary.
    // The receipt stays spent, but the graph must not resume.
    if (!sameInterrupt(interruptInput, interrupt) || !sameResponse(responseInput, response)) {
      return { decision: 'reject', reason: 'request_drifted_after_consumption', action };
    }

    const authorizedResponse: LangGraphHumanResponse = response.type === 'accept'
      ? { type: 'accept', args: interrupt.action_request }
      : { type: 'edit', args: request };
    return {
      decision: 'resume',
      reason: response.type === 'edit'
        ? 'fresh_authority_for_edited_action'
        : 'valid_action_bound_receipt',
      action,
      receipt_id: checked.receiptId,
      subject: checked.subject,
      response: authorizedResponse,
    };
  }

  /**
   * Emit gen_ai.tool.authorization.* for one resolved interrupt, then hand the
   * caller the unchanged decision.
   *
   * LangGraph's HumanInTheLoopMiddleware slot is the richest of the four this
   * repository adapts: the human's response type distinguishes `accept` from
   * `edit`, which is the only place `edited_then_approved` can be reported
   * honestly rather than inferred. `ignore` and free-text `response` are
   * non-authorizing, so they are reported as no_authorization_step, not as an
   * approval.
   *
   * Emission never changes the decision and never throws into the graph.
   */
  async function resolve(
    interruptInput: unknown,
    responseInput: unknown,
    receipt: AnyRecord | null | undefined,
    occurrence: LangGraphOccurrence,
  ): Promise<AnyRecord> {
    const decision = await resolveInner(interruptInput, responseInput, receipt, occurrence);
    if (!otelAuthorization) return decision;
    const otel = await loadOtelAuthorization();
    if (!otel) return decision;

    const responseType = decision?.response?.type
      ?? (responseInput && typeof responseInput === 'object'
        ? (responseInput as AnyRecord).type
        : undefined);

    let receiptDigest: string | null = null;
    if (decision?.decision === 'resume' && receipt) {
      try { receiptDigest = bindExecutorAction('receipt', receipt); } catch { receiptDigest = null; }
    }

    const evidence: AnyRecord = {
      action_digest: typeof decision?.action === 'string' ? decision.action : null,
    };
    if (receiptDigest && typeof decision?.receipt_id === 'string' && decision.receipt_id !== '') {
      evidence.evidence_digest = receiptDigest;
      evidence.evidence_format = 'application/vnd.emilia.receipt.v1+json';
      evidence.evidence_locator = `emilia-receipt:${decision.receipt_id}`;
    }

    try {
      await otel.emitToolAuthorization(
        otelAuthorization,
        otel.mapLangGraphDecision(decision?.decision, responseType, evidence as any),
        {
          runtime: 'langgraph',
          decision: decision?.decision,
          reason: decision?.reason,
          response_type: responseType,
        },
      );
    } catch {
      // Telemetry failure is never an authorization failure.
    }
    return decision;
  }

  return { resolve };
}

const langGraphExports = {
  bindLangGraphAction,
  createLangGraphApprovalAdapter,
  _resetLangGraphConsumption,
};
export default langGraphExports;
