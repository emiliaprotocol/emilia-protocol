// SPDX-License-Identifier: Apache-2.0
// Observe-scope guard for the control plane.
//
// The self-serve pilot bootstrap (POST /api/pilot/sandbox/provision) mints a
// real ep_live_ API key so anyone can run traffic through the guard in OBSERVE
// mode and pull a "what would have required approval" report. That key must
// never reach the CONTROL PLANE (minting SCIM provisioning tokens, configuring
// SSO connections, or any other tenant-administration surface): a public
// observe-mode credential that could stand up directory sync or federation is a
// privilege-escalation pivot, not a sandbox.
//
// Pilot keys are marked at mint with entity.metadata.scope === 'observe' (and
// metadata.pilot_sandbox === true). authenticateRequest() returns the full
// entity row as auth.entity (RPC resolve_authenticated_actor, migration 125),
// so the marker is visible to every route without a schema change. This guard
// is fail-closed on the marker: it refuses the marked scope and lets everything
// else through, so no real tenant is affected.

/**
 * @param {{ entity?: { metadata?: unknown } }} auth  the result of authenticateRequest()
 * @returns {boolean} true when this credential is an observe-mode pilot sandbox key
 */
export function isObserveScoped(auth) {
  const meta = auth && auth.entity && typeof auth.entity === 'object'
    ? auth.entity.metadata
    : null;
  if (!meta || typeof meta !== 'object') return false;
  return meta.scope === 'observe' || meta.pilot_sandbox === true;
}

/**
 * Fail-closed control-plane guard. Returns a 403 epProblem Response when the
 * caller is an observe-mode pilot key, or null when the caller may proceed.
 *
 * @param {object} auth  the result of authenticateRequest()
 * @param {(status:number, code:string, detail:string) => Response} epProblem
 * @returns {Response|null}
 */
export function refuseObserveScope(auth, epProblem) {
  if (isObserveScoped(auth)) {
    return epProblem(
      403,
      'observe_scope_forbidden',
      'This is an observe-mode pilot sandbox key. It can run actions through the gate and read its own report, but it cannot access the control plane (SSO, SCIM, or tenant administration).',
    );
  }
  return null;
}
