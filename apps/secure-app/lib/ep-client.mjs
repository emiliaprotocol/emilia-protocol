/**
 * EP Secure App — gate client.
 *
 * Talks to the EP signoff API: list pending signoffs, fetch the signing options
 * (the Authorization Context + challenge), and submit the device-key approval.
 * Injectable fetch so it is testable without a network.
 *
 * @license Apache-2.0
 */

function authHeaders(token) {
  return token ? { authorization: `Bearer ${token}` } : {};
}

/** List signoffs awaiting this approver. */
export async function fetchPendingSignoffs({ baseUrl, token, fetchImpl = fetch }) {
  const res = await fetchImpl(`${baseUrl}/api/v1/signoffs/pending`, { headers: authHeaders(token) });
  if (!res.ok) throw new Error(`pending fetch failed: HTTP ${res.status}`);
  return res.json();
}

/** Fetch the WebAuthn signing options + Authorization Context for one signoff. */
export async function fetchSignoffOptions({ baseUrl, challengeId, token, fetchImpl = fetch }) {
  const res = await fetchImpl(`${baseUrl}/api/v1/signoffs/${encodeURIComponent(challengeId)}/webauthn-options`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders(token) }, body: '{}',
  });
  if (!res.ok) throw new Error(`options fetch failed: HTTP ${res.status}`);
  return res.json();
}

/** Submit the device-key (Class-A) approval. */
export async function submitSignoff({ baseUrl, challengeId, attestation, token, fetchImpl = fetch }) {
  const res = await fetchImpl(`${baseUrl}/api/v1/signoffs/${encodeURIComponent(challengeId)}/approve-webauthn`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...authHeaders(token) },
    body: JSON.stringify(attestation),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`signoff submit failed: HTTP ${res.status} ${detail.slice(0, 200)}`);
  }
  return res.json();
}
