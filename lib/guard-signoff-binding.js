// SPDX-License-Identifier: Apache-2.0
// Shared signoff binding predicates for GovGuard / FinGuard receipt timelines.

/**
 * Return signoff-request states that were requested by the entity that created
 * the receipt. This prevents a leaked receipt id from becoming an approval
 * attachment point for a different actor.
 */
export function creatorBoundSignoffRequests(events, createdEvent) {
  const creatorId = createdEvent?.actor_id;
  if (!creatorId) return [];
  return (events || [])
    .filter((e) => e.event_type === 'guard.signoff.requested' && e.actor_id === creatorId)
    .map((e) => e.after_state)
    .filter((s) => s?.signoff_id);
}

/** True when a decision event resolves one of the creator-bound requests. */
export function decisionMatchesRequest(decisionEvent, requestState) {
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
export function boundSignoffDecisionEvents(events, createdEvent, eventType) {
  const requests = creatorBoundSignoffRequests(events, createdEvent);
  return (events || [])
    .filter((e) => e.event_type === eventType)
    .filter((e) => requests.some((s) => decisionMatchesRequest(e, s)));
}

/**
 * Find the first approval/rejection event that is tied to a creator-bound
 * signoff request and, when present, the request's intended approver.
 */
export function findBoundSignoffDecision(events, createdEvent, eventType) {
  return boundSignoffDecisionEvents(events, createdEvent, eventType)[0] || null;
}
