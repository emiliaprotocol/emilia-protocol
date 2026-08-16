// SPDX-License-Identifier: Apache-2.0
//
// Demand counts are evidence, not copy. Count only independently verified
// request events and never infer purchase intent from an information request.

const REQUESTER_DIGEST = /^hmac-sha256:[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export type DemandEvent = Readonly<{
  requester_digest: string;
  organization_domain: string;
  status: 'PENDING' | 'VERIFIED' | 'WITHDRAWN';
  test_event?: boolean;
}>;

export function countVerifiedIndependentDemand(
  events: readonly DemandEvent[],
  options: Readonly<{ ownerRequesterDigest?: string }> = {},
): Readonly<{ verified_requesters: number; verified_organizations: number }> {
  const requesters = new Set<string>();
  const organizations = new Set<string>();
  for (const event of events) {
    const domain = typeof event.organization_domain === 'string'
      ? event.organization_domain.trim().toLowerCase() : '';
    if (event.status !== 'VERIFIED'
        || event.test_event === true
        || !REQUESTER_DIGEST.test(event.requester_digest)
        || event.requester_digest === options.ownerRequesterDigest
        || !DOMAIN.test(domain)
        || domain === 'emiliaprotocol.ai'
        || domain.endsWith('.emiliaprotocol.ai')) continue;
    requesters.add(event.requester_digest);
    organizations.add(domain);
  }
  return Object.freeze({
    verified_requesters: requesters.size,
    verified_organizations: organizations.size,
  });
}
