// SPDX-License-Identifier: Apache-2.0

export type OrcaCancellationResult = {
  outcome: 'cancelled' | 'ended' | 'unconfirmed';
  message: string;
};

/** Report only what the local cancellation endpoint actually confirms. */
export async function requestOrcaCancellation(
  attemptId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<OrcaCancellationResult> {
  const unconfirmed: OrcaCancellationResult = {
    outcome: 'unconfirmed',
    message: 'Could not confirm cancellation. Check OrcaRouter for any issued key.',
  };
  try {
    const response = await fetchImpl('/api/orcarouter/connect/cancel', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ attempt_id: attemptId }),
    });
    if (!response.ok) return unconfirmed;
    const body = await response.json();
    if (body?.cancelled === true) {
      return {
        outcome: 'cancelled',
        message: 'Authorization cancelled locally. Check OrcaRouter for any key already issued and revoke it if needed.',
      };
    }
    if (body?.cancelled === false) {
      return {
        outcome: 'ended',
        message: 'This authorization has already ended. Check OrcaRouter for any issued key.',
      };
    }
    return unconfirmed;
  } catch {
    return unconfirmed;
  }
}
