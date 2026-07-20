// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-REGISTRY-v1 — public surface.
 *
 * Closes the chain the rest of the stack leaves open:
 *   identity -> ceremony -> AUTHORITY -> policy -> receipt -> admissibility
 *
 * Verification proves someone signed and a named human was present; this layer
 * proves that human was ENTITLED — in role, in scope, within limit, under the
 * pinned policy, at authorization time — and binds that entitlement into the
 * receipt so an offline verifier sees exactly which authority was relied on.
 */
export {
  AUTHORITY_REGISTRY_VERSION,
  AUTHORITY_VERDICTS,
  evaluateAuthorityVerdict,
  authorityResultCore,
  authorityResultHash,
  authorityBinding,
  normalizeAuthorityRecord,
} from './resolver.js';

export {
  computeRegistryHead,
  canonicalAuthorityEntry,
  buildRegistrySnapshot,
} from './registry-head.js';

export {
  snapshotStore,
  supabaseAuthorityStore,
  resolveAuthority,
} from './store.js';

export {
  AUTHORITY_PROOF_VERSION,
  signAuthorityProof,
  verifyAuthorityProofSignature,
  verifyAuthorityProof,
  authorityProofDigest,
} from './proof.js';

export {
  verifyAuthorityProofViaDocument,
} from './document-proof-join.js';

export {
  AUTHORITY_ENFORCEMENT_MODES,
  isAuthorityEnforcementMode,
  authorityAdmissibilityCode,
  applyAuthorityEnforcement,
} from './enforcement.js';

import { resolveAuthority } from './store.js';
import { authorityBinding } from './resolver.js';
import { applyAuthorityEnforcement } from './enforcement.js';

/**
 * The one call the mint/consume paths make. Resolves real scoped authority from
 * `store`, decides the staged-enforcement outcome, and returns the receipt
 * binding plus everything ops needs to log a shadow diff.
 *
 * @param {object} store       a store (supabaseAuthorityStore | snapshotStore)
 * @param {object} input       resolver input (organization_id, principal_id/approver_id,
 *                             action_type, amount, currency, policy_hash, issued_at, ...)
 * @param {{ isCritical?: boolean, mode?: string }} [opts]
 *   isCritical: whether this action fails closed under enforce_critical
 *   mode: one of AUTHORITY_ENFORCEMENT_MODES (server-pinned)
 * @returns {Promise<{ result, enforcement, binding }>}
 */
export async function resolveAndBindAuthority(store, input, { isCritical = false, mode = 'shadow' } = {}) {
  const result = await resolveAuthority(store, input);
  const enforcement = applyAuthorityEnforcement({ verdict: result.verdict, isCritical, mode });
  const binding = authorityBinding(result);
  return { result, enforcement, binding };
}
