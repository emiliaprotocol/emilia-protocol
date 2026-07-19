// SPDX-License-Identifier: Apache-2.0
//
// Assurance-tier quorum for value-tiered actions. A 'dual' tier (e.g. payment
// >= $1M) must be authorized by TWO DISTINCT, individually-authorized humans —
// not one approval and not one human signing twice. This is the economic defense
// from the adversarial-economics model: a farmed trust score cannot manufacture
// distinct, separately-authorized Class-A approvers.
//
// Pure + injectable: the authority resolver is passed in, so the money-auth rule
// is exhaustively unit-testable without the consume route's DB harness. The
// resolver does the live, not-revoked authority check (revocation-at-execution).
// See docs/gov-readiness/ASSURANCE-TIER-ENFORCEMENT.md.

/** Required distinct, valid approvals for a value tier. dual -> 2, else 1. */
export function requiredApprovalsForTier(tier) {
  return tier === 'dual' ? 2 : 1;
}

/**
 * Count DISTINCT approvals that pass every gate:
 *   - assurance: Class-A when requiredAssurance === 'A';
 *   - not the initiator (self-approval guard);
 *   - distinct human (one approver counts once, however many times they signed);
 *   - backed by a valid, not-revoked authority (resolveAuthority(approval) -> {authorized}).
 *
 * @param {Array<{approver_id?:string, key_class?:string, role?:string}>} approvals
 * @param {{ initiatorId?:string|null, requiredAssurance?:string|null,
 *           resolveAuthority:(approval:object)=>Promise<{authorized:boolean}>}} opts
 * @returns {Promise<number>} distinct valid approver count
 */
export async function countDistinctValidApprovers(approvals, {
  initiatorId = null,
  requiredAssurance = null,
  resolveAuthority,
} = /** @type {any} */ ({})) {
  if (typeof resolveAuthority !== 'function') {
    throw new Error('countDistinctValidApprovers requires a resolveAuthority(approval) function');
  }
  const distinct = new Set();
  for (const a of approvals || []) {
    if (!a) continue;
    const keyClass = a.key_class || 'C';
    if (requiredAssurance === 'A' && keyClass !== 'A') continue;
    const approverId = a.approver_id || null;
    if (!approverId || approverId === initiatorId) continue;
    if (distinct.has(approverId)) continue;
    const authority = await resolveAuthority(a);
    if (authority && authority.authorized) distinct.add(approverId);
  }
  return distinct.size;
}
