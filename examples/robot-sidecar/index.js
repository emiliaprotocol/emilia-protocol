// Generated from index.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
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
 *   - every refusal is a return value `{ allow: false, reason }` with a
 *     specific reason code, never a thrown exception.
 *
 * Why a sidecar, not the model: it sits before the actuator, so a compromised or
 * confused planner still cannot move hardware outside the authorized envelope.
 */
import { verifyEmiliaReceipt } from '../../packages/require-receipt/index.js';
/** Command fields with gate-defined semantics. `allowed_command_fields` may not re-declare them. */
const CORE_COMMAND_FIELDS = new Set(['action', 'target', 'reach_cm']);
/** Scope keys the gate understands. Any other key is a constraint it cannot enforce. */
const KNOWN_SCOPE_KEYS = new Set(['effect_class', 'target_set', 'allowed_actions', 'bounds', 'window', 'allowed_command_fields']);
const KNOWN_BOUND_KEYS = new Set(['max_reach_cm']);
const KNOWN_WINDOW_KEYS = new Set(['not_before', 'not_after']);
const refuse = (reason, field) => (field === undefined ? { allow: false, reason } : { allow: false, reason, field });
function isPlainObject(v) {
    if (v === null || typeof v !== 'object' || Array.isArray(v))
        return false;
    const proto = Object.getPrototypeOf(v);
    return proto === Object.prototype || proto === null;
}
const isNonEmptyString = (v) => typeof v === 'string' && v.length > 0;
const isFiniteNumber = (v) => typeof v === 'number' && Number.isFinite(v);
/** A non-empty array of distinct non-empty strings, copied; null when malformed. */
function stringSet(v) {
    if (!Array.isArray(v) || v.length === 0)
        return null;
    const out = [];
    for (const item of v) {
        if (!isNonEmptyString(item) || out.includes(item))
            return null;
        out.push(item);
    }
    return out;
}
/**
 * Validate the signed scope and copy it into an immutable envelope. Returns a
 * reason code when any constraint is missing, malformed, or not understood.
 */
function parseScope(scope) {
    if (!isPlainObject(scope))
        return { ok: false, reason: 'envelope_malformed_scope' };
    for (const key of Object.keys(scope)) {
        if (!KNOWN_SCOPE_KEYS.has(key))
            return { ok: false, reason: 'envelope_unsupported_constraint' };
    }
    if (scope.effect_class !== undefined && !isNonEmptyString(scope.effect_class)) {
        return { ok: false, reason: 'envelope_malformed_effect_class' };
    }
    // An envelope that does not name its actions would authorize every action.
    const allowedActions = stringSet(scope.allowed_actions);
    if (!allowedActions)
        return { ok: false, reason: 'envelope_malformed_allowed_actions' };
    let targetSet = null;
    if (scope.target_set !== undefined) {
        targetSet = stringSet(scope.target_set);
        if (!targetSet)
            return { ok: false, reason: 'envelope_malformed_target_set' };
    }
    let maxReachCm = null;
    if (scope.bounds !== undefined) {
        if (!isPlainObject(scope.bounds))
            return { ok: false, reason: 'envelope_malformed_bounds' };
        for (const key of Object.keys(scope.bounds)) {
            if (!KNOWN_BOUND_KEYS.has(key))
                return { ok: false, reason: 'envelope_unsupported_bound' };
        }
        const max = scope.bounds.max_reach_cm;
        if (max !== undefined) {
            if (!isFiniteNumber(max) || max < 0 || Object.is(max, -0))
                return { ok: false, reason: 'envelope_malformed_bounds' };
            maxReachCm = max;
        }
    }
    // A window without an end would authorize forever.
    const w = scope.window;
    if (!isPlainObject(w))
        return { ok: false, reason: 'envelope_malformed_window' };
    for (const key of Object.keys(w)) {
        if (!KNOWN_WINDOW_KEYS.has(key))
            return { ok: false, reason: 'envelope_malformed_window' };
    }
    if (!isFiniteNumber(w.not_after))
        return { ok: false, reason: 'envelope_malformed_window' };
    if (w.not_before !== undefined && (!isFiniteNumber(w.not_before) || w.not_before > w.not_after)) {
        return { ok: false, reason: 'envelope_malformed_window' };
    }
    let extraFields = [];
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
function snapshotCommand(command) {
    try {
        if (!isPlainObject(command))
            return { ok: false, reason: 'command_not_plain_object' };
        const snap = Object.create(null);
        for (const key of Reflect.ownKeys(command)) {
            if (typeof key === 'symbol')
                return { ok: false, reason: 'command_symbol_field' };
            const desc = Object.getOwnPropertyDescriptor(command, key);
            if (!desc || !('value' in desc))
                return { ok: false, reason: 'command_accessor_field', field: key };
            snap[key] = desc.value;
        }
        return { ok: true, snap: Object.freeze(snap) };
    }
    catch {
        return { ok: false, reason: 'command_unreadable' };
    }
}
export class EdgeActuatorGate {
    trustedKeys;
    now;
    envelope;
    revoked;
    revokedReceiptIds;
    constructor({ trustedKeys = [], now = Date.now } = {}) {
        this.trustedKeys = trustedKeys;
        this.now = now;
        this.envelope = null;
        this.revoked = false;
        this.revokedReceiptIds = new Set();
    }
    /** Verify + load a bounded authorization envelope (one human signoff, many edge-verified acts). */
    authorizeEnvelope(receipt) {
        const v = verifyEmiliaReceipt(receipt, {
            trustedKeys: this.trustedKeys,
            maxAgeSec: 0, // envelope validity is its own window, enforced below — not created_at age
            allowedOutcomes: ['allow_with_signoff', 'allow'],
        });
        if (!v.ok)
            return { ok: false, reason: `envelope_${v.reason}` };
        const claim = receipt?.payload?.claim || {};
        if (claim.action_type !== 'physical.envelope')
            return { ok: false, reason: 'not_an_envelope' };
        const receiptId = receipt.payload?.receipt_id;
        if (!isNonEmptyString(receiptId))
            return { ok: false, reason: 'envelope_malformed_receipt_id' };
        // A halted envelope stays halted: re-presenting the same signed receipt does not lift the halt.
        if (this.revokedReceiptIds.has(receiptId))
            return { ok: false, reason: 'envelope_revoked' };
        const parsed = parseScope(claim.authorization_scope);
        if (!parsed.ok)
            return { ok: false, reason: parsed.reason };
        this.envelope = Object.freeze({
            scope: parsed.scope,
            window: parsed.scope.window,
            approver: claim.approver ?? null,
            receipt_id: receiptId,
        });
        this.revoked = false;
        return { ok: true, envelope: this.envelope };
    }
    /** Halt authority: the human can revoke the envelope at any time (in-memory, this gate instance only). */
    revoke() {
        this.revoked = true;
        if (this.envelope)
            this.revokedReceiptIds.add(this.envelope.receipt_id);
    }
    /** Offline per-command check against the active envelope. Fail-closed; never throws. */
    permit(command) {
        if (!this.envelope)
            return refuse('no_envelope');
        if (this.revoked)
            return refuse('revoked');
        let nowMs;
        try {
            nowMs = typeof this.now === 'function' ? this.now() : this.now;
        }
        catch {
            nowMs = NaN;
        }
        if (!isFiniteNumber(nowMs))
            return refuse('clock_unavailable');
        const nowSec = Math.floor(nowMs / 1000);
        const w = this.envelope.window;
        if (w.not_before !== null && nowSec < w.not_before)
            return refuse('before_window');
        if (nowSec > w.not_after)
            return refuse('expired');
        const read = snapshotCommand(command);
        if (!read.ok)
            return refuse(read.reason, read.field);
        const cmd = read.snap;
        const s = this.envelope.scope;
        const known = new Set(['action', ...s.allowed_command_fields]);
        if (s.target_set)
            known.add('target');
        if (s.max_reach_cm !== null)
            known.add('reach_cm');
        for (const key of Object.keys(cmd)) {
            if (!known.has(key))
                return refuse('unknown_command_field', key);
        }
        if (cmd.action === undefined)
            return refuse('missing_action');
        if (!isNonEmptyString(cmd.action))
            return refuse('invalid_action');
        if (!s.allowed_actions.includes(cmd.action))
            return refuse('action_not_in_envelope');
        if (s.target_set) {
            if (cmd.target === undefined)
                return refuse('missing_target');
            if (!isNonEmptyString(cmd.target))
                return refuse('invalid_target');
            if (!s.target_set.includes(cmd.target))
                return refuse('out_of_target_set');
        }
        if (s.max_reach_cm !== null) {
            const reach = cmd.reach_cm;
            if (reach === undefined)
                return refuse('missing_reach_cm');
            if (typeof reach !== 'number')
                return refuse('invalid_reach_cm_type');
            if (!Number.isFinite(reach))
                return refuse('reach_cm_not_finite');
            if (Object.is(reach, -0))
                return refuse('reach_cm_negative_zero');
            if (reach < 0)
                return refuse('reach_cm_negative');
            if (reach > s.max_reach_cm)
                return refuse('exceeds_bounds');
        }
        for (const field of s.allowed_command_fields) {
            const value = cmd[field];
            if (value === undefined)
                continue; // explicitly allowed, not constrained: may be omitted
            const scalar = typeof value === 'string' || typeof value === 'boolean'
                || (isFiniteNumber(value) && !Object.is(value, -0));
            if (!scalar)
                return refuse('invalid_extra_field_value', field);
        }
        return { allow: true, reason: 'within_envelope', command: cmd };
    }
}
/** A toy actuator that only moves when the edge gate permits — and records every decision. */
export class SimulatedArm {
    gate;
    position;
    log;
    constructor(gate) { this.gate = gate; this.position = 0; this.log = []; }
    move(command) {
        const decision = this.gate.permit(command);
        this.log.push({ command, decision, at: undefined });
        if (!decision.allow)
            return { moved: false, reason: decision.reason };
        // Actuate from the checked snapshot, never by re-reading the caller's object.
        const reach = decision.command.reach_cm;
        if (typeof reach === 'number')
            this.position = reach;
        return { moved: true, position: this.position };
    }
}
export default { EdgeActuatorGate, SimulatedArm };
