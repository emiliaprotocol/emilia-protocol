/**
 * EMILIA Gate — robot/actuator edge sidecar (reference).
 * @license Apache-2.0
 *
 * The Consequence Firewall at the actuator boundary, for the physical world.
 * A human (or quorum) PRE-AUTHORIZES a bounded on-the-loop envelope once
 * (PIP-013): effect class, target set, allowed actions, bounds (e.g. reach),
 * and a time window, retaining a halt/revoke authority. Each individual motion
 * command is then verified at the edge — OFFLINE, no cloud, no per-command
 * human, and (unlike a per-action receipt) WITHOUT consuming the envelope.
 * Out-of-envelope, malformed, expired, or revoked → the actuator does not move.
 *
 * Fail-closed contract (mirrors lib/grace/curtailment checkOrderWithinEnvelope):
 *   - an envelope constraint the gate cannot parse or does not understand is a
 *     refusal at authorization time, never an unlimited default;
 *   - every command field the envelope constrains must be present, of the
 *     right type, and finite; a missing or malformed value is a refusal, never
 *     a skipped check;
 *   - command fields the envelope does not name are refused unless the
 *     envelope lists them in `allowed_command_fields`;
 *   - the receipt is read exactly once into a frozen, data-only copy; the
 *     signature is verified over that copy and the envelope is parsed from
 *     that same copy, so a getter or Proxy cannot swap a wider payload in
 *     after verification;
 *   - every signed time bound (window.not_before, window.not_after, and the
 *     receipt's expires_at) is enforced on every command, in milliseconds,
 *     through the gate's single injected clock, which authorization uses too;
 *   - the gate clock may not run backwards: the gate keeps the highest reading
 *     it has used (authorization and permit) and refuses any lower reading, so
 *     setting the clock back cannot re-open an expired envelope;
 *   - revoke() latches a gate-level halt. While halted, permit refuses and
 *     authorizeEnvelope refuses every receipt, so loading another valid signed
 *     envelope cannot lift a human halt; only the separately named clearHalt()
 *     does. A revoked receipt_id stays refused on this gate even after
 *     clearHalt(). The halt is in-memory, unsigned, and per-process;
 *   - every refusal, from authorizeEnvelope and from permit, is a return value
 *     with a specific reason code, never a thrown exception.
 *
 * Why a sidecar, not the model: it sits before the actuator, so a compromised or
 * confused planner still cannot move hardware outside the authorized envelope.
 */
import { types } from 'node:util';
import { verifyEmiliaReceipt } from '../../packages/require-receipt/index.js';

/** Command fields with gate-defined semantics. `allowed_command_fields` may not re-declare them. */
const CORE_COMMAND_FIELDS = new Set(['action', 'target', 'reach_cm']);
/** Scope keys the gate understands. Any other key is a constraint it cannot enforce. */
const KNOWN_SCOPE_KEYS = new Set(['effect_class', 'target_set', 'allowed_actions', 'bounds', 'window', 'allowed_command_fields']);
const KNOWN_BOUND_KEYS = new Set(['max_reach_cm']);
const KNOWN_WINDOW_KEYS = new Set(['not_before', 'not_after']);
/** Receipt snapshot limits, matching the strict canonical JSON profile the verifier signs over. */
const MAX_RECEIPT_DEPTH = 64;
const MAX_RECEIPT_NODES = 100_000;

type Refusal = { allow: false, reason: string, field?: string };
type Permit = { allow: true, reason: 'within_envelope', command: Readonly<Record<string, unknown>> };

const refuse = (reason: string, field?: string): Refusal => (field === undefined ? { allow: false, reason } : { allow: false, reason, field });

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isFiniteNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

/** A non-empty array of distinct non-empty strings, copied; null when malformed. */
function stringSet(v: unknown): string[] | null {
  if (!Array.isArray(v) || v.length === 0) return null;
  const out: string[] = [];
  for (const item of v) {
    if (!isNonEmptyString(item) || out.includes(item)) return null;
    out.push(item);
  }
  return out;
}

class ReceiptReadError extends Error {
  code: string;
  constructor(code: string) { super(code); this.code = code; }
}

/**
 * Read an untrusted receipt exactly once into a deep, frozen, data-only copy.
 * Only plain objects, dense arrays, strings, booleans, null, and finite numbers
 * are copied. Proxies, class instances, accessors, symbol keys, and any other
 * value are refused with a reason, and no accessor is ever invoked: values are
 * taken from own data property descriptors. Verification and enforcement then
 * both run on this copy, so they see identical bytes.
 */
function snapshotReceipt(receipt: unknown): { ok: true, receipt: any } | { ok: false, reason: string } {
  if (receipt === null || typeof receipt !== 'object') return { ok: false, reason: 'envelope_malformed_receipt' };
  let nodes = 0;
  const copy = (v: unknown, depth: number): unknown => {
    if (++nodes > MAX_RECEIPT_NODES || depth > MAX_RECEIPT_DEPTH) throw new ReceiptReadError('envelope_receipt_too_deep');
    if (v === null || typeof v === 'string' || typeof v === 'boolean') return v;
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new ReceiptReadError('envelope_receipt_non_data_value');
      return v;
    }
    if (typeof v !== 'object') throw new ReceiptReadError('envelope_receipt_non_data_value');
    if (types.isProxy(v)) throw new ReceiptReadError('envelope_receipt_non_plain_object');
    const isArray = Array.isArray(v);
    if (!isArray && !isPlainObject(v)) throw new ReceiptReadError('envelope_receipt_non_plain_object');
    if (isArray && Object.getPrototypeOf(v) !== Array.prototype) throw new ReceiptReadError('envelope_receipt_non_plain_object');
    const keys = Reflect.ownKeys(v as object);
    const out: any = isArray ? [] : {};
    for (const key of keys) {
      if (typeof key === 'symbol') throw new ReceiptReadError('envelope_receipt_symbol_field');
      const desc = Object.getOwnPropertyDescriptor(v, key);
      if (!desc || !('value' in desc)) throw new ReceiptReadError('envelope_receipt_accessor_field');
      if (isArray && key === 'length') continue;
      if (isArray && String(Number(key)) !== key) throw new ReceiptReadError('envelope_receipt_non_plain_object');
      // defineProperty, not assignment, so a `__proto__` member stays an own data member.
      Object.defineProperty(out, key, { value: copy(desc.value, depth + 1), enumerable: true, writable: false, configurable: false });
    }
    if (isArray && out.length !== keys.length - 1) throw new ReceiptReadError('envelope_receipt_non_plain_object'); // sparse
    return Object.freeze(out);
  };
  try {
    return { ok: true, receipt: copy(receipt, 0) };
  } catch (err) {
    if (err instanceof ReceiptReadError) return { ok: false, reason: err.code };
    if (err instanceof RangeError) return { ok: false, reason: 'envelope_receipt_too_deep' };
    return { ok: false, reason: 'envelope_receipt_unreadable' };
  }
}

/**
 * Validate the signed scope and copy it into an immutable envelope. Returns a
 * reason code when any constraint is missing, malformed, or not understood.
 */
function parseScope(scope: unknown): { ok: true, scope: any } | { ok: false, reason: string } {
  if (!isPlainObject(scope)) return { ok: false, reason: 'envelope_malformed_scope' };
  for (const key of Object.keys(scope)) {
    if (!KNOWN_SCOPE_KEYS.has(key)) return { ok: false, reason: 'envelope_unsupported_constraint' };
  }

  if (scope.effect_class !== undefined && !isNonEmptyString(scope.effect_class)) {
    return { ok: false, reason: 'envelope_malformed_effect_class' };
  }

  // An envelope that does not name its actions would authorize every action.
  const allowedActions = stringSet(scope.allowed_actions);
  if (!allowedActions) return { ok: false, reason: 'envelope_malformed_allowed_actions' };

  let targetSet: string[] | null = null;
  if (scope.target_set !== undefined) {
    targetSet = stringSet(scope.target_set);
    if (!targetSet) return { ok: false, reason: 'envelope_malformed_target_set' };
  }

  let maxReachCm: number | null = null;
  if (scope.bounds !== undefined) {
    if (!isPlainObject(scope.bounds)) return { ok: false, reason: 'envelope_malformed_bounds' };
    for (const key of Object.keys(scope.bounds)) {
      if (!KNOWN_BOUND_KEYS.has(key)) return { ok: false, reason: 'envelope_unsupported_bound' };
    }
    const max = scope.bounds.max_reach_cm;
    if (max !== undefined) {
      if (!isFiniteNumber(max) || max < 0 || Object.is(max, -0)) return { ok: false, reason: 'envelope_malformed_bounds' };
      maxReachCm = max;
    }
  }

  // A window without an end would authorize forever.
  const w = scope.window;
  if (!isPlainObject(w)) return { ok: false, reason: 'envelope_malformed_window' };
  for (const key of Object.keys(w)) {
    if (!KNOWN_WINDOW_KEYS.has(key)) return { ok: false, reason: 'envelope_malformed_window' };
  }
  if (!isFiniteNumber(w.not_after)) return { ok: false, reason: 'envelope_malformed_window' };
  if (w.not_before !== undefined && (!isFiniteNumber(w.not_before) || w.not_before > w.not_after)) {
    return { ok: false, reason: 'envelope_malformed_window' };
  }

  let extraFields: string[] = [];
  if (scope.allowed_command_fields !== undefined) {
    const fields = stringSet(scope.allowed_command_fields);
    if (!fields || fields.some((f) => CORE_COMMAND_FIELDS.has(f))) {
      return { ok: false, reason: 'envelope_malformed_allowed_command_fields' };
    }
    extraFields = fields;
  }

  return {
    ok: true,
    scope: Object.freeze({
      effect_class: scope.effect_class ?? null,
      allowed_actions: Object.freeze(allowedActions),
      target_set: targetSet ? Object.freeze(targetSet) : null,
      max_reach_cm: maxReachCm,
      window: Object.freeze({ not_before: w.not_before ?? null, not_after: w.not_after }),
      allowed_command_fields: Object.freeze(extraFields),
    }),
  };
}

/**
 * Read the command exactly once into a frozen data-only snapshot. Accessors,
 * symbol keys, non-plain objects, and Proxy traps that throw are refused, so
 * the value that is checked is the value that actuates.
 */
function snapshotCommand(command: unknown): { ok: true, snap: Record<string, unknown> } | { ok: false, reason: string, field?: string } {
  try {
    if (!isPlainObject(command)) return { ok: false, reason: 'command_not_plain_object' };
    const snap: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(command)) {
      if (typeof key === 'symbol') return { ok: false, reason: 'command_symbol_field' };
      const desc = Object.getOwnPropertyDescriptor(command, key);
      if (!desc || !('value' in desc)) return { ok: false, reason: 'command_accessor_field', field: key };
      snap[key] = desc.value;
    }
    return { ok: true, snap: Object.freeze(snap) };
  } catch {
    return { ok: false, reason: 'command_unreadable' };
  }
}

export class EdgeActuatorGate {
  trustedKeys: string[];
  now: number | (() => number);
  envelope: any;
  /** Gate-level halt latched by revoke(). Private: only clearHalt() lifts it; no load does. */
  #halted: boolean;
  /** receipt_ids revoked on this gate. Never cleared, not even by clearHalt(). */
  #revokedReceiptIds: Set<string>;
  /** Highest gate-clock reading used so far (ms); a lower later reading is refused. */
  #clockHighWaterMs: number;

  constructor({ trustedKeys = [] as string[], now = Date.now as number | (() => number) } = {}) {
    this.trustedKeys = trustedKeys;
    this.now = now;
    this.envelope = null;
    this.#halted = false;
    this.#revokedReceiptIds = new Set();
    this.#clockHighWaterMs = -Infinity;
  }

  /** True while a human halt is latched (read-only; lift it with clearHalt()). */
  get halted(): boolean { return this.#halted; }

  /**
   * The gate's single clock, in milliseconds. Refuses a reading that is not a
   * finite number, or that is below the highest reading this gate has already
   * used, and records every accepted reading. Never throws.
   */
  private readClock(): { ok: true, ms: number } | { ok: false, reason: 'clock_unavailable' | 'clock_regressed' } {
    let ms: unknown;
    try { ms = typeof this.now === 'function' ? this.now() : this.now; } catch { ms = NaN; }
    if (!isFiniteNumber(ms)) return { ok: false, reason: 'clock_unavailable' };
    if (ms < this.#clockHighWaterMs) return { ok: false, reason: 'clock_regressed' };
    this.#clockHighWaterMs = ms;
    return { ok: true, ms };
  }

  /**
   * Verify + load a bounded authorization envelope (one human signoff, many
   * edge-verified acts). Fail-closed; every refusal is `{ ok: false, reason }`,
   * never a thrown exception.
   */
  authorizeEnvelope(receipt: unknown): { ok: false, reason: string } | { ok: true, envelope: any } {
    try {
      return this.loadEnvelope(receipt);
    } catch {
      return { ok: false, reason: 'envelope_internal_error' };
    }
  }

  private loadEnvelope(receipt: unknown): { ok: false, reason: string } | { ok: true, envelope: any } {
    // A latched halt refuses every load, valid or not; only clearHalt() lifts it.
    if (this.#halted) return { ok: false, reason: 'gate_halted' };
    // One read of the caller's object. Everything below uses `doc`, never `receipt`.
    const read = snapshotReceipt(receipt);
    if (!read.ok) return { ok: false, reason: read.reason };
    const doc = read.receipt;

    const clock = this.readClock();
    if (!clock.ok) return { ok: false, reason: `envelope_${clock.reason}` };
    const nowMs = clock.ms;
    const v = verifyEmiliaReceipt(doc, {
      trustedKeys: this.trustedKeys,
      maxAgeSec: 0, // envelope validity is its own window, enforced on every command, not created_at age
      allowedOutcomes: ['allow_with_signoff', 'allow'],
      now: () => nowMs, // the same clock permit() uses
    });
    if (!v.ok) return { ok: false, reason: `envelope_${v.reason}` };

    const payload = doc.payload;
    const claim = isPlainObject(payload.claim) ? payload.claim : {};
    if (claim.action_type !== 'physical.envelope') return { ok: false, reason: 'not_an_envelope' };
    const receiptId = payload.receipt_id;
    if (!isNonEmptyString(receiptId)) return { ok: false, reason: 'envelope_malformed_receipt_id' };
    // A revoked receipt_id stays refused on this gate forever, even after clearHalt().
    if (this.#revokedReceiptIds.has(receiptId)) return { ok: false, reason: 'envelope_revoked' };
    const parsed = parseScope(claim.authorization_scope);
    if (!parsed.ok) return { ok: false, reason: parsed.reason };

    // The verifier already refused an expires_at it cannot parse or that has passed;
    // keep the same parsed instant so permit() enforces it on every command.
    let expiresAtMs: number | null = null;
    if (payload.expires_at !== undefined) {
      const t = Date.parse(payload.expires_at);
      if (!Number.isFinite(t)) return { ok: false, reason: 'envelope_receipt_expired' };
      expiresAtMs = t;
    }

    this.envelope = Object.freeze({
      scope: parsed.scope,
      window: parsed.scope.window,
      expires_at_ms: expiresAtMs,
      approver: claim.approver ?? null,
      receipt_id: receiptId,
    });
    return { ok: true, envelope: this.envelope };
  }

  /**
   * Halt authority: latch a gate-level halt. The active envelope (if any) is
   * dropped and its receipt_id is refused on this gate from now on. While
   * halted, permit() refuses with `revoked` and authorizeEnvelope() refuses
   * every receipt with `gate_halted`. Works with or without a loaded envelope.
   * In-memory, unsigned, this gate instance only.
   */
  revoke() {
    this.#halted = true;
    if (this.envelope) this.#revokedReceiptIds.add(this.envelope.receipt_id);
    this.envelope = null;
  }

  /**
   * Operator action that lifts a latched halt. It does not restore the revoked
   * envelope: the gate has no envelope until a new one loads, and a revoked
   * receipt_id is still refused. This is an in-process call; any code holding
   * the gate object can make it.
   */
  clearHalt() {
    this.#halted = false;
  }

  /** Offline per-command check against the active envelope. Fail-closed; never throws. */
  permit(command?: unknown): Refusal | Permit {
    if (this.#halted) return refuse('revoked');
    if (!this.envelope) return refuse('no_envelope');

    // Every signed time bound, in milliseconds, on the one gate clock. The usable
    // interval is half-open: not_before*1000 <= now < not_after*1000, and
    // now < expires_at (exclusive, as the receipt verifier treats it).
    const clock = this.readClock();
    if (!clock.ok) return refuse(clock.reason);
    const nowMs = clock.ms;
    const w = this.envelope.window;
    if (w.not_before !== null && nowMs < w.not_before * 1000) return refuse('before_window');
    if (nowMs >= w.not_after * 1000) return refuse('expired');
    if (this.envelope.expires_at_ms !== null && nowMs >= this.envelope.expires_at_ms) return refuse('receipt_expired');

    const read = snapshotCommand(command);
    if (!read.ok) return refuse(read.reason, read.field);
    const cmd = read.snap;
    const s = this.envelope.scope;

    const known = new Set<string>(['action', ...s.allowed_command_fields]);
    if (s.target_set) known.add('target');
    if (s.max_reach_cm !== null) known.add('reach_cm');
    for (const key of Object.keys(cmd)) {
      if (!known.has(key)) return refuse('unknown_command_field', key);
    }

    if (cmd.action === undefined) return refuse('missing_action');
    if (!isNonEmptyString(cmd.action)) return refuse('invalid_action');
    if (!s.allowed_actions.includes(cmd.action)) return refuse('action_not_in_envelope');

    if (s.target_set) {
      if (cmd.target === undefined) return refuse('missing_target');
      if (!isNonEmptyString(cmd.target)) return refuse('invalid_target');
      if (!s.target_set.includes(cmd.target)) return refuse('out_of_target_set');
    }

    if (s.max_reach_cm !== null) {
      const reach = cmd.reach_cm;
      if (reach === undefined) return refuse('missing_reach_cm');
      if (typeof reach !== 'number') return refuse('invalid_reach_cm_type');
      if (!Number.isFinite(reach)) return refuse('reach_cm_not_finite');
      if (Object.is(reach, -0)) return refuse('reach_cm_negative_zero');
      if (reach < 0) return refuse('reach_cm_negative');
      if (reach > s.max_reach_cm) return refuse('exceeds_bounds');
    }

    for (const field of s.allowed_command_fields) {
      const value = cmd[field];
      if (value === undefined) continue; // explicitly allowed, not constrained: may be omitted
      const scalar = typeof value === 'string' || typeof value === 'boolean'
        || (isFiniteNumber(value) && !Object.is(value, -0));
      if (!scalar) return refuse('invalid_extra_field_value', field);
    }

    return { allow: true, reason: 'within_envelope', command: cmd };
  }
}

/** A toy actuator that only moves when the edge gate permits — and records every decision. */
export class SimulatedArm {
  gate: EdgeActuatorGate;
  position: number;
  log: any[];

  constructor(gate: EdgeActuatorGate) { this.gate = gate; this.position = 0; this.log = []; }
  move(command: unknown) {
    const decision = this.gate.permit(command);
    this.log.push({ command, decision, at: undefined });
    if (!decision.allow) return { moved: false, reason: decision.reason };
    // Actuate from the checked snapshot, never by re-reading the caller's object.
    const reach = decision.command.reach_cm;
    if (typeof reach === 'number') this.position = reach;
    return { moved: true, position: this.position };
  }
}

export default { EdgeActuatorGate, SimulatedArm };
