/**
 * @emilia-protocol/openai-agents — make an OpenAI agent's approval portable.
 * @license Apache-2.0
 *
 * The OpenAI Agents SDK already has a human-in-the-loop primitive: a tool marked
 * `needsApproval` pauses the run, and the pending approvals surface as
 * `RunToolApprovalItem`s in `result.interruptions`. You resolve each one with
 * `result.state.approve(item)` / `result.state.reject(item)` and re-run the agent
 * with the same state.
 *
 * That approval is a transient, in-process boolean. The moment the run resumes it
 * is gone — there is no portable evidence that a *named* human accountably
 * authorized *this exact* tool call, nothing an auditor (or an insurer, or a
 * counterparty) can verify later without trusting OpenAI, your app, or a mutable
 * log.
 *
 * This adapter closes that gap. It does NOT replace OpenAI's approval step — it
 * drives it. For each pending interruption it requires a valid EMILIA
 * authorization receipt (EP-RECEIPT-v1) cryptographically bound (via action_type)
 * to that exact tool call:
 *
 *   - no receipt for the interruption  -> state.reject(item)  (the tool stays blocked)
 *   - valid, action-bound receipt      -> state.approve(item) (the tool runs)
 *   - replayed receipt (already used)  -> state.reject(item)
 *   - tampered / invalid receipt       -> state.reject(item)
 *
 * Verification is offline Ed25519 over canonical JSON via
 * @emilia-protocol/require-receipt's verifyEmiliaReceipt. Zero network. The
 * decision is necessary-not-sufficient: it composes with — never substitutes for —
 * the resource owner's own checks.
 *
 * The adapter is unit-testable WITHOUT @openai/agents: it reads the documented
 * interruption shape and calls the documented state methods, both passed in.
 *
 * See: draft-schrock-ep-authorization-receipts, draft-schrock-ep-enforcement-point
 * (individual Internet-Drafts, not RFCs).
 */
// Declared dependency: @emilia-protocol/require-receipt (see package.json). In
// this monorepo there is no workspace symlink, so we import the sibling package
// by relative path — the same convention @emilia-protocol/gate uses. When this
// package is installed from npm, the published build resolves the bare
// "@emilia-protocol/require-receipt" specifier; both point at the same module.
// The canonical makeReceiptGate encodes verify + target binding + reserve→
// commit/release replay safety + sanitized {reason} rejections in one place.
import { makeReceiptGate } from '../require-receipt/gate.js';

/** Process-local set of consumed receipt_ids (replay defense). Per-process only.
 *  Shared across every per-action gate so one receipt is spent at most once. */
const consumed = new Set();
const sharedStore = { has: (id) => consumed.has(id), add: (id) => consumed.add(id) };

/** Reset the consumed-receipt set. Test/ops helper — not a production control. */
export function _resetConsumed() {
  consumed.clear();
}

/**
 * Read the tool name from an OpenAI Agents RunToolApprovalItem.
 * The SDK exposes `.name` on the item and also `.rawItem.name`.
 */
function interruptionToolName(interruption) {
  return (
    interruption?.name ??
    interruption?.rawItem?.name ??
    null
  );
}

/**
 * Read the tool-call arguments from an interruption.
 * The Agents SDK stores arguments as a JSON *string* on function_call rawItems
 * (`interruption.arguments` / `rawItem.arguments`). We parse when possible and
 * otherwise return the raw value so `actionFor` can decide.
 */
function interruptionArgs(interruption) {
  const raw =
    interruption?.arguments ??
    interruption?.rawItem?.arguments ??
    undefined;
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== 'string') return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

/** Stable id for a tool call: function_call uses callId; hosted tools use id. */
function interruptionCallId(interruption) {
  return (
    interruption?.rawItem?.callId ??
    interruption?.rawItem?.id ??
    interruption?.callId ??
    interruption?.id ??
    null
  );
}

function isApprovalInterruption(interruption) {
  // Faithful to the SDK: items are of type "tool_approval_item". Be lenient for
  // synthetic / minimal items in tests that still carry a tool name.
  if (!interruption || typeof interruption !== 'object') return false;
  if (interruption.type && interruption.type !== 'tool_approval_item') return false;
  return interruptionToolName(interruption) != null;
}

/**
 * Build a receipt gate for OpenAI Agents human-in-the-loop tool approvals.
 *
 * @param {object} opts
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER issuer public keys you trust.
 * @param {boolean} [opts.allowInlineKey=false] also accept a receipt's own inline
 *   key (proves integrity, NOT trust — leave OFF in production).
 * @param {number} [opts.maxAgeSec=900] reject receipts older than this.
 * @param {(toolName:string, args:any)=>string} opts.actionFor REQUIRED — maps a
 *   tool call to the canonical EP action_type the receipt must be bound to.
 * @returns {{
 *   decide: (interruption:any, receipt:object|null|undefined) => {decision:'approve'|'reject', action:string|null, toolName:string|null, callId:string|null, reason:string, receipt_id?:string, subject?:string},
 *   resolve: (runResult:any, ctx:{receipts?:object|Map|Array, state?:any}) => Promise<{approved:Array, rejected:Array, decisions:Array}>
 * }}
 */
export function requireReceiptForOpenAIAgent(opts = {}) {
  const {
    trustedKeys = [],
    allowInlineKey = false,
    maxAgeSec = 900,
    actionFor,
  } = opts;

  if (typeof actionFor !== 'function') {
    throw new TypeError('requireReceiptForOpenAIAgent: opts.actionFor (toolName, args) => action_type is required');
  }

  // One canonical gate per bound action. The action_type IS the binding (the
  // verifier matches the receipt's claim.action_type to it), so callId is NOT
  // folded into the gate's action — doing so would break verification against a
  // receipt minted for the bare action. All gates share one consumed store so a
  // receipt is spent at most once across calls; the compound receipt_id#callId
  // key (below) is the belt-and-suspenders cross-call defense.
  const gates = new Map();
  const gateFor = (action) => {
    let gate = gates.get(action);
    if (!gate) {
      gate = makeReceiptGate({ action, trustedKeys, allowInlineKey, maxAgeSec, store: sharedStore });
      gates.set(action, gate);
    }
    return gate;
  };

  // Track the reservation a decide() approval holds, so resolve() can commit it
  // (on a driven approve) or release it (rollback) — keyed by receipt_id.
  const pending = new Map();

  /**
   * Decide a single interruption against a single receipt.
   *
   * The decision NEVER carries the raw verifier output — only an allowlisted,
   * sanitized shape ({decision, action, toolName, callId, reason} plus, on the
   * approve path only, receipt_id + the accountable subject). A rejection never
   * leaks the signer, the verifier's `detail`, or any other library internals.
   *
   * Consume-on-approve: when `decide` returns an `approve`, it marks the
   * receipt_id consumed (replay defense) — and ONLY then. A reject (including a
   * replayed or invalid receipt) never consumes anything, so a blocked approval
   * stays retryable with a fresh, valid receipt. Replay is still checked here,
   * before any approval, so a receipt can satisfy at most one interruption.
   */
  function decide(interruption, receipt) {
    const toolName = interruptionToolName(interruption);
    const callId = interruptionCallId(interruption);
    const args = interruptionArgs(interruption);
    // Bind the receipt to THIS tool call. actionFor SHOULD incorporate the
    // specific call identity (callId or a hash of args) so a single receipt
    // cannot be reused across distinct tool calls — see the README note.
    const action = toolName != null ? actionFor(toolName, args) : null;

    const base = { action, toolName, callId };

    if (!isApprovalInterruption(interruption)) {
      return { decision: 'reject', ...base, reason: 'not_a_tool_approval_interruption' };
    }
    if (!receipt) {
      return { decision: 'reject', ...base, reason: 'no_receipt_for_interruption' };
    }

    // The action_type is the binding — the gate verifies the receipt against it.
    // callId is NOT passed as a target (that would change the verified binding);
    // it is only used for the compound cross-call replay key below.
    const gate = gateFor(action);

    // Belt-and-suspenders cross-call defense: refuse if the SAME receipt was
    // already used for a DIFFERENT call. We can only check this once we know the
    // receipt_id, so peek at it from the receipt before the gate runs.
    const receiptId = receipt?.payload?.receipt_id;
    const callKey = receiptId && callId != null ? `${receiptId}#${callId}` : null;

    // gate.check verifies (sanitized reason), enforces action binding + trust,
    // and reserves the receipt (one-time consumption / replay safety).
    const c = gate.check(receipt);
    if (!c.ok) {
      // Map the gate's sanitized refusal to this adapter's decision vocabulary.
      // The gate uses `replay_refused`; this API has long exposed `receipt_replayed`.
      const reason = c.body?.rejected?.reason || 'invalid_receipt';
      if (reason === 'replay_refused') {
        return { decision: 'reject', ...base, reason: 'receipt_replayed', receipt_id: receiptId };
      }
      return { decision: 'reject', ...base, reason };
    }

    // The gate cleared verify + bare-receipt_id replay. Now apply the compound
    // call-scoped guard: if this exact receipt already drove a DIFFERENT call,
    // refuse and release the reservation the gate just took.
    if (callKey && consumed.has(callKey)) {
      gate.release(c.receiptId);
      return { decision: 'reject', ...base, reason: 'receipt_replayed', receipt_id: c.receiptId };
    }

    // Record the reservation so resolve() can commit (driven approve) or release
    // (rollback). decide() reserves but does NOT commit — a standalone approve
    // that is never driven leaves the receipt retryable, matching prior behavior.
    pending.set(c.receiptId, { gate, callKey });

    return {
      decision: 'approve',
      ...base,
      reason: 'valid_action_bound_receipt',
      receipt_id: c.receiptId,
      subject: c.subject,
    };
  }

  /**
   * Look up the receipt a caller supplied for a given interruption. Accepts:
   *   - a Map / plain object keyed by callId OR tool name
   *   - an array of receipts (matched by claim.action_type for this tool call)
   */
  function lookupReceipt(receipts, interruption) {
    if (receipts == null) return null;
    const callId = interruptionCallId(interruption);
    const toolName = interruptionToolName(interruption);

    if (receipts instanceof Map) {
      if (callId != null && receipts.has(callId)) return receipts.get(callId);
      if (toolName != null && receipts.has(toolName)) return receipts.get(toolName);
      return null;
    }
    if (Array.isArray(receipts)) {
      const args = interruptionArgs(interruption);
      const action = toolName != null ? actionFor(toolName, args) : null;
      return receipts.find((r) => r?.payload?.claim?.action_type === action) ?? null;
    }
    if (typeof receipts === 'object') {
      if (callId != null && callId in receipts) return receipts[callId];
      if (toolName != null && toolName in receipts) return receipts[toolName];
      return null;
    }
    return null;
  }

  /**
   * Resolve EVERY pending tool-approval interruption on a run result, driving the
   * SDK's own approve/reject. Returns the decisions; the run is then resumed by
   * the caller via `run(agent, state)` (kept out of this adapter so it stays
   * testable without OpenAI).
   *
   * @param {object} runResult an Agents-SDK RunResult / StreamedRunResult with
   *   `.interruptions` (RunToolApprovalItem[]) and `.state` (RunState).
   * @param {object} ctx
   * @param {object|Map|Array} [ctx.receipts] caller-supplied receipts (see lookupReceipt).
   * @param {object} [ctx.state] override the state object to drive (defaults to runResult.state).
   */
  async function resolve(runResult, ctx = {}) {
    const interruptions = runResult?.interruptions ?? [];
    const state = ctx.state ?? runResult?.state ?? null;
    const receipts = ctx.receipts;

    const approved = [];
    const rejected = [];
    const decisions = [];

    // Release the reservation decide() took when the approval is not actually
    // driven (no approve() to call, or approve() threw) — keeps it retryable.
    const releasePending = (d) => {
      if (!d.receipt_id) return;
      const p = pending.get(d.receipt_id);
      if (p) {
        p.gate.release(d.receipt_id);
        pending.delete(d.receipt_id);
      }
    };

    // Finalize one-time consumption for a driven approve: commit in the gate and
    // also record the compound call-scoped key for the cross-call replay guard.
    const commitPending = (d) => {
      if (!d.receipt_id) return;
      const p = pending.get(d.receipt_id);
      if (p) {
        p.gate.commit(d.receipt_id); // moves receipt_id into the shared store
        if (p.callKey) consumed.add(p.callKey);
        pending.delete(d.receipt_id);
      }
    };

    for (const interruption of interruptions) {
      const receipt = lookupReceipt(receipts, interruption);
      const d = decide(interruption, receipt);
      decisions.push(d);
      if (d.decision === 'approve') {
        // decide() RESERVED the receipt for this approve. Drive the SDK's
        // approval now; commit (spend) only if approve() succeeds. If approve()
        // is missing or throws, release the reservation so the (un-driven)
        // approval stays retryable — a receipt is spent only when it drives one.
        if (state && typeof state.approve === 'function') {
          try {
            state.approve(interruption);
            commitPending(d);
            approved.push(interruption);
          } catch (err) {
            releasePending(d);
            d.decision = 'reject';
            d.reason = 'approve_failed';
            rejected.push(interruption);
            if (state && typeof state.reject === 'function') {
              state.reject(interruption, { message: `EMILIA: approve_failed` });
            }
          }
        } else {
          // No approve() to drive -> do not spend the receipt.
          releasePending(d);
          approved.push(interruption);
        }
      } else {
        rejected.push(interruption);
        if (state && typeof state.reject === 'function') {
          state.reject(interruption, { message: `EMILIA: ${d.reason}` });
        }
      }
    }

    return { approved, rejected, decisions };
  }

  return { decide, resolve };
}

const openaiAgentsExports = { requireReceiptForOpenAIAgent, _resetConsumed };
export default openaiAgentsExports;
