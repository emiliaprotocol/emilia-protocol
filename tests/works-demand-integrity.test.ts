// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import { countVerifiedIndependentDemand } from '../lib/works/demand.ts';

describe('Authority Record demand integrity', () => {
  it('counts distinct verified requesters and organizations only', () => {
    const result = countVerifiedIndependentDemand([
      { requester_digest: 'hmac-sha256:' + 'a'.repeat(64), organization_domain: 'one.example', status: 'VERIFIED' },
      { requester_digest: 'hmac-sha256:' + 'a'.repeat(64), organization_domain: 'one.example', status: 'VERIFIED' },
      { requester_digest: 'hmac-sha256:' + 'b'.repeat(64), organization_domain: 'two.example', status: 'VERIFIED' },
      { requester_digest: 'hmac-sha256:' + 'c'.repeat(64), organization_domain: 'two.example', status: 'VERIFIED' },
      { requester_digest: 'hmac-sha256:' + 'd'.repeat(64), organization_domain: 'three.example', status: 'PENDING' },
    ]);
    expect(result).toEqual({ verified_requesters: 3, verified_organizations: 2 });
  });

  it('excludes EMILIA, the record owner, tests, unverified events, and malformed identities', () => {
    const OWNER = 'hmac-sha256:' + 'e'.repeat(64);
    const result = countVerifiedIndependentDemand([
      { requester_digest: OWNER, organization_domain: 'owner.example', status: 'VERIFIED' },
      { requester_digest: 'hmac-sha256:' + 'a'.repeat(64), organization_domain: 'emiliaprotocol.ai', status: 'VERIFIED' },
      { requester_digest: 'hmac-sha256:' + 'b'.repeat(64), organization_domain: 'test.example', status: 'VERIFIED', test_event: true },
      { requester_digest: 'bad', organization_domain: 'real.example', status: 'VERIFIED' },
      { requester_digest: 'hmac-sha256:' + 'c'.repeat(64), organization_domain: 'real.example', status: 'PENDING' },
    ], { ownerRequesterDigest: OWNER });
    expect(result).toEqual({ verified_requesters: 0, verified_organizations: 0 });
  });

  it('does not infer purchasing intent from a verified information request', () => {
    const result = countVerifiedIndependentDemand([
      { requester_digest: 'hmac-sha256:' + 'a'.repeat(64), organization_domain: 'one.example', status: 'VERIFIED' },
    ]);
    expect(result).toEqual({ verified_requesters: 1, verified_organizations: 1 });
    expect(result).not.toHaveProperty('buyers');
  });
});
