// SPDX-License-Identifier: Apache-2.0
// Shared signoff binding predicates for GovGuard / FinGuard receipt timelines.

/**
 * A GovGuard/FinGuard audit_events row (or an equivalent in-memory replay of
 * one). `after_state` is the JSON blob written at that event; its shape
 * varies by event_type, so it is treated as a loosely-typed record here.
 */
export interface GuardAuditEvent {
  event_type: string;
  actor_id?: string | null;
  after_state?: Record<string, any> | null;
  [key: string]: any;
}

/** The after_state of a `guard.signoff.requested` event. */
export interface SignoffRequestState {
  signoff_id: string;
  approver_id?: string | null;
  quorum?: { approver_id?: string | null; [key: string]: any } | null;
  [key: string]: any;
}

/**
 * Return signoff-request states that were requested by the entity that created
 * the receipt. This prevents a leaked receipt id from becoming an approval
 * attachment point for a different actor.
 */
export function creatorBoundSignoffRequests(
  events: GuardAuditEvent[] | null | undefined,
  createdEvent: GuardAuditEvent | null | undefined,
): SignoffRequestState[] {
  const creatorId = createdEvent?.actor_id;
  if (!creatorId) return [];
  return (events || [])
    .filter((e) => e.event_type === 'guard.signoff.requested' && e.actor_id === creatorId)
    .map((e) => e.after_state)
    .filter((s): s is SignoffRequestState => Boolean(s?.signoff_id));
}

/** True when a decision event resolves one of the creator-bound requests. */
export function decisionMatchesRequest(
  decisionEvent: GuardAuditEvent | null | undefined,
  requestState: SignoffRequestState | null | undefined,
): boolean {
  const decidedSignoffId = decisionEvent?.after_state?.signoff_id;
  const decidedApproverId = decisionEvent?.after_state?.approver_id || decisionEvent?.actor_id || null;
  const requestedApproverId = requestState?.approver_id || requestState?.quorum?.approver_id || null;
  return decidedSignoffId === requestState?.signoff_id
    && (!requestedApproverId || decidedApproverId === requestedApproverId);
}

/**
 * Return approval/rejection events tied to creator-bound signoff requests and,
 * when present, each request's intended approver.
 */
export function boundSignoffDecisionEvents(
  events: GuardAuditEvent[] | null | undefined,
  createdEvent: GuardAuditEvent | null | undefined,
  eventType: string,
): GuardAuditEvent[] {
  const requests = creatorBoundSignoffRequests(events, createdEvent);
  return (events || [])
    .filter((e) => e.event_type === eventType)
    .filter((e) => requests.some((s) => decisionMatchesRequest(e, s)));
}

/**
 * Find the first approval/rejection event that is tied to a creator-bound
 * signoff request and, when present, the request's intended approver.
 */
export function findBoundSignoffDecision(
  events: GuardAuditEvent[] | null | undefined,
  createdEvent: GuardAuditEvent | null | undefined,
  eventType: string,
): GuardAuditEvent | null {
  return boundSignoffDecisionEvents(events, createdEvent, eventType)[0] || null;
}
