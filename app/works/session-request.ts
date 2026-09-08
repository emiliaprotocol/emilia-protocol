// SPDX-License-Identifier: Apache-2.0

/** null deliberately selects the Works-only HttpOnly session. An explicit key
 * never falls back to that session and is never mixed with its cookies. */
export function worksRequestAuth(apiKey: string | null): {
  headers: Record<string, string>; credentials: 'same-origin' | 'omit';
} {
  if (apiKey === null) return { headers: {}, credentials: 'same-origin' };
  if (!/^[A-Za-z0-9_-]{8,512}$/.test(apiKey)) throw new Error('works_credentials_invalid');
  return { headers: { authorization: `Bearer ${apiKey}` }, credentials: 'omit' };
}
