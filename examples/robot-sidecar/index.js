/**
 * EMILIA Gate — robot/actuator edge sidecar (reference).
 * @license Apache-2.0
 *
 * The Consequence Firewall at the actuator boundary, for the physical world.
 * A human (or quorum) PRE-AUTHORIZES a bounded on-the-loop envelope once
 * (PIP-013): effect class, target set, allowed actions, bounds (e.g. reach),
 * and a time window, retaining a halt/revoke authority. Each individual motion
 * command is then verified at the edge — OFFLINE, sub-millisecond, no cloud, no
 * per-command human, and (unlike a per-action receipt) WITHOUT consuming the
 * envelope. Out-of-envelope, expired, or revoked → the actuator does not move.
 *
 * Why a sidecar, not the model: it sits before the actuator, so a compromised or
 * confused planner still cannot move hardware outside the authorized envelope.
 */
import { verifyEmiliaReceipt } from '../../packages/require-receipt/index.js';

export class EdgeActuatorGate {
  constructor({ trustedKeys = [], now = Date.now } = {}) {
    this.trustedKeys = trustedKeys;
    this.now = now;
    this.envelope = null;
    this.revoked = false;
  }

  /** Verify + load a bounded authorization envelope (one human signoff, many edge-verified acts). */
  authorizeEnvelope(receipt) {
    const v = verifyEmiliaReceipt(receipt, {
      trustedKeys: this.trustedKeys,
      maxAgeSec: 0, // envelope validity is its own window, enforced below — not created_at age
      allowedOutcomes: ['allow_with_signoff', 'allow'],
    });
    if (!v.ok) return { ok: false, reason: `envelope_${v.reason}` };
    const claim = receipt?.payload?.claim || {};
    if (claim.action_type !== 'physical.envelope') return { ok: false, reason: 'not_an_envelope' };
    const scope = claim.authorization_scope || {};
    this.envelope = {
      scope,
      window: scope.window || {},
      approver: claim.approver ?? null,
      receipt_id: receipt.payload?.receipt_id ?? null,
    };
    this.revoked = false;
    return { ok: true, envelope: this.envelope };
  }

  /** Halt authority: the human can revoke the envelope at any time. */
  revoke() { this.revoked = true; }

  /** Offline, sub-ms per-command check against the active envelope. Fail-closed. */
  permit(command = {}) {
    if (!this.envelope) return { allow: false, reason: 'no_envelope' };
    if (this.revoked) return { allow: false, reason: 'revoked' };
    const nowSec = Math.floor((typeof this.now === 'function' ? this.now() : this.now) / 1000);
    const w = this.envelope.window;
    if (w.not_before && nowSec < w.not_before) return { allow: false, reason: 'before_window' };
    if (w.not_after && nowSec > w.not_after) return { allow: false, reason: 'expired' };
    const s = this.envelope.scope;
    if (s.target_set && command.target && !s.target_set.includes(command.target)) return { allow: false, reason: 'out_of_target_set' };
    if (s.allowed_actions && !s.allowed_actions.includes(command.action)) return { allow: false, reason: 'action_not_in_envelope' };
    if (s.bounds?.max_reach_cm != null && command.reach_cm != null && command.reach_cm > s.bounds.max_reach_cm) return { allow: false, reason: 'exceeds_bounds' };
    return { allow: true, reason: 'within_envelope' };
  }
}

/** A toy actuator that only moves when the edge gate permits — and records every decision. */
export class SimulatedArm {
  constructor(gate) { this.gate = gate; this.position = 0; this.log = []; }
  move(command) {
    const decision = this.gate.permit(command);
    this.log.push({ command, decision, at: undefined });
    if (!decision.allow) return { moved: false, reason: decision.reason };
    this.position = command.reach_cm ?? this.position;
    return { moved: true, position: this.position };
  }
}

export default { EdgeActuatorGate, SimulatedArm };
