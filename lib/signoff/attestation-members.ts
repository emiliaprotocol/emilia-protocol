// SPDX-License-Identifier: Apache-2.0
/**
 * Bridge: reconstruct EP-QUORUM-v1 members from stored Class-A signoff evidence.
 *
 * The Class-A WebAuthn approve path
 * (app/api/v1/signoffs/[signoffId]/approve-webauthn/route.js) records, per
 * approver decision, everything an offline verifier needs: the canonical
 * authorization `context` and the WebAuthn assertion (authenticator_data /
 * client_data_json / signature). Paired with the approver's enrolled SPKI
 * public key (approver_credentials.public_key_spki), that reconstitutes the
 * exact EP-SIGNOFF-v1 object that verifyQuorum / quorumGate consume.
 *
 * The point: the quorum gate then verifies the SAME bytes with the SAME
 * fail-closed predicate that cross-language conformance (JS/Python/Go) covers —
 * it does NOT introduce a second verifier. (The live approve route validates
 * the assertion via @simplewebauthn at decision time; this re-derives the
 * portable EP-SIGNOFF object for the offline quorum check, which is what makes
 * the quorum independently checkable off any EP server.)
 */

/**
 * One stored Class-A decision → one quorum member.
 * @param {object} d
 * @param {string} d.role               roster role (e.g. 'authorizing_official')
 * @param {string} d.approver_public_key approver SPKI (base64url) from approver_credentials
 * @param {object} d.context            canonical authorization context (incl. action_hash, approver, issued_at)
 * @param {object} d.webauthn           { authenticator_data, client_data_json, signature } (base64url)
 * @returns {object} EP-QUORUM-v1 member
 */
export function decisionToMember({ role, approver_public_key, context, webauthn }) {
  return {
    role,
    approver_public_key,
    signoff: {
      '@type': 'ep.signoff',
      context,
      webauthn: {
        authenticator_data: webauthn.authenticator_data,
        client_data_json: webauthn.client_data_json,
        signature: webauthn.signature,
      },
    },
  };
}

/**
 * Map a list of stored Class-A decisions → quorum members. Skips any decision
 * missing its context or assertion (fail-safe: an incomplete record can never
 * count toward a quorum).
 * @param {Array<object>} decisions
 * @returns {Array<object>}
 */
export function attestationsToMembers(decisions) {
  return (decisions || [])
    .filter((d) => d && d.context && d.webauthn && d.approver_public_key)
    .map(decisionToMember);
}

/**
 * Build quorum members from raw `guard.signoff.approved` audit-event payloads.
 *
 * Each approved decision's `after_state` carries `{ context, webauthn:{...},
 * approver_id }` but NOT the approver's role or public key. The role comes from
 * the quorum policy roster (by approver id); the SPKI key comes from
 * `approver_credentials` (by credential id). This joins them. Fail-safe: any
 * decision we can't fully resolve (unknown approver, missing key, incomplete
 * assertion) is dropped — it cannot count toward the quorum.
 *
 * @param {object} policy                 EP-QUORUM-v1 policy (for the role roster)
 * @param {Array<object>} decisions        guard.signoff.approved after_state payloads
 * @param {Object<string,object>} credsByCredentialId  credential_id → { public_key_spki }
 * @returns {Array<object>} EP-QUORUM-v1 members
 */
export function decisionsToMembers(policy, decisions, credsByCredentialId = {}) {
  const roleByApprover = Object.fromEntries(
    ((policy && policy.approvers) || []).map((a) => [a.approver, a.role]),
  );
  return (decisions || [])
    .map((d) => {
      const credId = d && d.webauthn && d.webauthn.credential_id;
      const cred = credId ? credsByCredentialId[credId] : null;
      const approver = (d && d.approver_id) || (d && d.context && d.context.approver);
      return {
        role: roleByApprover[approver] ?? null,
        approver_public_key: cred ? cred.public_key_spki : null,
        context: d && d.context,
        webauthn: d && d.webauthn,
      };
    })
    .filter((m) => m.role && m.approver_public_key && m.context && m.webauthn)
    .map(decisionToMember);
}
