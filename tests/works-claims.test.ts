// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace claim model — the discipline is structural:
//   * VERIFIED requires a non-claimant source artifact reference.
//   * Expiry fails closed (effective status degrades to UNKNOWN).
//   * Malformed input returns typed errors, never throws.

import { describe, expect, it } from 'vitest';
import {
  effectiveClaimStatus,
  isClaimExpired,
  sourceSupportsVerified,
  transitionClaimStatus,
  validateClaim,
  type Claim,
} from '../lib/works/claims.ts';

const ARTIFACT_SOURCE = {
  kind: 'content_addressed_artifact',
  reference: 'https://example.com/repo/blob/abc/manifest.json',
  sha256: 'e011fb3538f973cfcea6d02df79500af1d7ab74ee85667b46790633063294058',
};

function baseClaim(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    statement: 'Reproduced the named suites at revision abc1234.',
    status: 'VERIFIED',
    scope: 'conformance/ at revision abc1234',
    source: ARTIFACT_SOURCE,
    observed_at: '2026-08-08T00:00:00Z',
    ...overrides,
  };
}

describe('validateClaim', () => {
  it('accepts a well-formed VERIFIED claim with a content-addressed source', () => {
    const result = validateClaim(baseClaim());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.claim.status).toBe('VERIFIED');
      expect(result.claim.source?.sha256).toBe(ARTIFACT_SOURCE.sha256);
    }
  });

  it('refuses VERIFIED without any source (VERIFIED-requires-source rule)', () => {
    const result = validateClaim(baseClaim({ source: null }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('verified_requires_source');
  });

  it('refuses VERIFIED backed only by the claimant', () => {
    const result = validateClaim(baseClaim({
      source: { kind: 'claimant', reference: 'mailto:someone@example.com' },
    }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('verified_requires_source');
  });

  it('accepts VERIFIED from an external signer', () => {
    const result = validateClaim(baseClaim({
      source: { kind: 'external_signer', reference: 'did:example:signer-1' },
    }));
    expect(result.ok).toBe(true);
  });

  it('requires sha256 on a content-addressed artifact source', () => {
    const result = validateClaim(baseClaim({
      source: { kind: 'content_addressed_artifact', reference: 'https://example.com/f' },
    }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('missing_source_hash');
  });

  it('requires a source for ASSERTED (claimant is acceptable)', () => {
    const missing = validateClaim(baseClaim({ status: 'ASSERTED', source: null }));
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.code).toBe('asserted_requires_source');

    const claimant = validateClaim(baseClaim({
      status: 'ASSERTED',
      source: { kind: 'claimant', reference: 'mailto:someone@example.com' },
    }));
    expect(claimant.ok).toBe(true);
  });

  it('allows UNKNOWN with no source', () => {
    const result = validateClaim(baseClaim({ status: 'UNKNOWN', source: null }));
    expect(result.ok).toBe(true);
  });

  it('refuses unknown status values, scores, and rankings', () => {
    for (const status of ['TRUSTED', 'A+', 5, null, 'verified']) {
      const result = validateClaim(baseClaim({ status }));
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe('invalid_claim_status');
    }
  });

  it('requires an exact scope', () => {
    const result = validateClaim(baseClaim({ scope: '   ' }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('invalid_claim_scope');
  });

  it('fails closed on malformed input without throwing', () => {
    for (const input of [null, undefined, 'claim', 42, [], { statement: 7 }]) {
      const result = validateClaim(input);
      expect(result.ok).toBe(false);
    }
  });

  it('rejects malformed timestamps', () => {
    expect(validateClaim(baseClaim({ observed_at: 'yesterday' })).ok).toBe(false);
    expect(validateClaim(baseClaim({ expires_at: 'soon' })).ok).toBe(false);
  });
});

describe('expiry', () => {
  const expired = () => {
    const result = validateClaim(baseClaim({ expires_at: '2026-01-01T00:00:00Z' }));
    if (!result.ok) throw new Error('fixture invalid');
    return result.claim;
  };

  it('detects an expired claim', () => {
    expect(isClaimExpired(expired(), '2026-08-08T00:00:00Z')).toBe(true);
    expect(isClaimExpired(expired(), '2025-12-31T00:00:00Z')).toBe(false);
  });

  it('degrades an expired VERIFIED claim to UNKNOWN (fail closed)', () => {
    expect(effectiveClaimStatus(expired(), '2026-08-08T00:00:00Z')).toBe('UNKNOWN');
    expect(effectiveClaimStatus(expired(), '2025-12-31T00:00:00Z')).toBe('VERIFIED');
  });

  it('treats an unparseable expiry as expired', () => {
    const claim = { ...expired(), expires_at: 'not-a-date' } as Claim;
    expect(isClaimExpired(claim)).toBe(true);
    expect(effectiveClaimStatus(claim)).toBe('UNKNOWN');
  });

  it('never expires a claim without expires_at', () => {
    const result = validateClaim(baseClaim());
    if (!result.ok) throw new Error('fixture invalid');
    expect(isClaimExpired(result.claim, '2999-01-01T00:00:00Z')).toBe(false);
  });
});

describe('transitionClaimStatus', () => {
  const asserted = () => {
    const result = validateClaim(baseClaim({
      status: 'ASSERTED',
      source: { kind: 'claimant', reference: 'mailto:someone@example.com' },
    }));
    if (!result.ok) throw new Error('fixture invalid');
    return result.claim;
  };

  it('upgrades ASSERTED to VERIFIED only with a qualifying source', () => {
    const withoutSource = transitionClaimStatus(asserted(), 'VERIFIED');
    expect(withoutSource.ok).toBe(false);
    if (!withoutSource.ok) expect(withoutSource.code).toBe('verified_requires_source');

    const withSource = transitionClaimStatus(asserted(), 'VERIFIED', {
      source: ARTIFACT_SOURCE as Claim['source'],
      observedAt: '2026-08-08T12:00:00Z',
    });
    expect(withSource.ok).toBe(true);
    if (withSource.ok) {
      expect(withSource.claim.status).toBe('VERIFIED');
      expect(withSource.claim.observed_at).toBe('2026-08-08T12:00:00Z');
    }
  });

  it('always allows downgrades', () => {
    const verified = validateClaim(baseClaim());
    if (!verified.ok) throw new Error('fixture invalid');
    const down = transitionClaimStatus(verified.claim, 'ASSERTED');
    expect(down.ok).toBe(true);
    const toUnknown = transitionClaimStatus(verified.claim, 'UNKNOWN', { source: null });
    expect(toUnknown.ok).toBe(true);
  });

  it('refuses invalid target statuses and never mutates the input', () => {
    const claim = asserted();
    const result = transitionClaimStatus(claim, 'BEST' as never);
    expect(result.ok).toBe(false);
    expect(claim.status).toBe('ASSERTED');
  });
});

describe('sourceSupportsVerified', () => {
  it('accepts artifact and signer sources, refuses claimant and null', () => {
    expect(sourceSupportsVerified(ARTIFACT_SOURCE as Claim['source'])).toBe(true);
    expect(sourceSupportsVerified({ kind: 'external_signer', reference: 'x' })).toBe(true);
    expect(sourceSupportsVerified({ kind: 'claimant', reference: 'x' })).toBe(false);
    expect(sourceSupportsVerified(null)).toBe(false);
  });
});
