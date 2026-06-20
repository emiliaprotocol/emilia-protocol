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
