// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import {
  authorityRecordDigest,
  buildAuthorityClaimProof,
  evaluateAuthorityRecordFreshness,
  normalizeGitHubRepositoryUrl,
  validateAuthorityClaimProof,
  validateAuthorityRecordProjection,
} from '../lib/works/authority-record.ts';

const SHA_A = `sha256:${'a'.repeat(64)}`;
const SHA_B = `sha256:${'b'.repeat(64)}`;
const REVISION_A = 'a'.repeat(40);
const REVISION_B = 'b'.repeat(40);

function record(overrides: Record<string, unknown> = {}) {
  return {
    '@version': 'EMILIA-AUTHORITY-RECORD-v1',
    record_id: 'authority-record-acme-agent',
    subject: {
      name: 'Acme Agent',
      builder_name: 'Acme Labs',
      repository_url: 'https://github.com/acme/agent',
    },
    provenance: {
      source_locator: 'https://github.com/acme/agent',
      watched_ref: 'refs/heads/main',
      resolved_revision: REVISION_A,
      artifact_digest: SHA_A,
      observed_at: '2026-08-13T20:00:00.000Z',
      expires_at: '2026-09-12T20:00:00.000Z',
      scanner: {
        name: '@emilia-protocol/scan',
        version: '0.1.0',
        profile_digest: SHA_B,
      },
    },
    surfaces: [
      {
        surface_id: 'github-merge',
        label: 'Merge a commit',
        action_class: 'code_change',
        consequence_class: 'code',
        evidence_status: 'OBSERVED',
        enforcement_status: 'NOT_ASSESSED',
      },
    ],
    owner_statement: null,
    claim_boundary:
      'versioned_public_authority_mapping_not_certification_not_safety_rating_not_complete_mediation',
    ...overrides,
  };
}

describe('Authority Record closed projection', () => {
  it('accepts a version-pinned, redacted record and normalizes exact fields', () => {
    const result = validateAuthorityRecordProjection(record());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.record.provenance.resolved_revision).toBe(REVISION_A);
    expect(result.record.surfaces).toHaveLength(1);
  });

  it('refuses unknown fields so raw findings and bypass details cannot leak into public bytes', () => {
    const hostile = record({
      raw_findings: [{ file: '.github/workflows/deploy.yml', bypass: 'use admin token' }],
    });
    expect(validateAuthorityRecordProjection(hostile)).toMatchObject({
      ok: false,
      code: 'authority_record_unknown_field',
    });

    const nested = record();
    (nested.surfaces[0] as any).exploit_instructions = 'call the unguarded endpoint';
    expect(validateAuthorityRecordProjection(nested)).toMatchObject({
      ok: false,
      code: 'authority_record_unknown_field',
    });
  });

  it('requires an explicit watched ref, immutable revision, artifact digest, scanner, and expiry', () => {
    for (const [field, value] of [
      ['watched_ref', 'main'],
      ['resolved_revision', 'moving-main'],
      ['artifact_digest', 'not-a-digest'],
      ['expires_at', '2026-08-13T20:00:00.000Z'],
    ] as const) {
      const candidate = record();
      (candidate.provenance as any)[field] = value;
      expect(validateAuthorityRecordProjection(candidate).ok, field).toBe(false);
    }
    const noScanner = record();
    delete (noScanner.provenance as any).scanner;
    expect(validateAuthorityRecordProjection(noScanner).ok).toBe(false);
  });

  it('admits only typed evidence labels and never a purchased verdict', () => {
    for (const status of ['EMILIA_APPROVED', 'SAFE', 'CERTIFIED', 'TRUSTED']) {
      const candidate = record();
      (candidate.surfaces[0] as any).evidence_status = status;
      expect(validateAuthorityRecordProjection(candidate).ok, status).toBe(false);
    }
  });

  it('fails closed across malformed repository, subject, provenance, scanner, surface, and owner shapes', () => {
    for (const repositoryUrl of [
      'not a URL',
      'http://github.com/acme/agent',
      'https://user:secret@github.com/acme/agent',
      'https://github.com/acme/agent/issues',
      'https://github.com/-invalid/agent',
    ]) {
      expect(normalizeGitHubRepositoryUrl(repositoryUrl), repositoryUrl).toBeNull();
    }

    const mutations: Array<(candidate: ReturnType<typeof record>) => void> = [
      (candidate) => { candidate.record_id = 'not a record id'; },
      (candidate) => { (candidate.subject as any).raw_owner_email = 'owner@acme.example'; },
      (candidate) => { delete (candidate.subject as any).builder_name; },
      (candidate) => { (candidate.subject as any).repository_url = 'https://gitlab.com/acme/agent'; },
      (candidate) => { candidate.provenance = null as any; },
      (candidate) => { (candidate.provenance as any).raw_checkout_path = '/private/repo'; },
      (candidate) => { delete (candidate.provenance as any).artifact_digest; },
      (candidate) => { (candidate.provenance as any).source_locator = 'https://github.com/acme/other'; },
      (candidate) => { (candidate.provenance as any).scanner = null; },
      (candidate) => { (candidate.provenance.scanner as any).private_key = 'secret'; },
      (candidate) => { (candidate.provenance.scanner as any).version = 'latest'; },
      (candidate) => { candidate.surfaces = []; },
      (candidate) => { delete (candidate.surfaces[0] as any).label; },
      (candidate) => { (candidate.surfaces[0] as any).action_class = 'anything'; },
      (candidate) => { candidate.owner_statement = 'approved' as any; },
      (candidate) => {
        candidate.owner_statement = { status: 'SELLER_ASSERTED', statement: 'Builder statement', raw: true } as any;
      },
      (candidate) => {
        candidate.owner_statement = { status: 'EMILIA_APPROVED', statement: 'Builder statement' } as any;
      },
    ];

    for (const mutate of mutations) {
      const candidate = record();
      mutate(candidate);
      expect(validateAuthorityRecordProjection(candidate).ok).toBe(false);
    }
  });

  it('produces one stable exact-byte digest independent of object insertion order', () => {
    const first = validateAuthorityRecordProjection(record());
    const reordered = validateAuthorityRecordProjection({
      claim_boundary:
        'versioned_public_authority_mapping_not_certification_not_safety_rating_not_complete_mediation',
      owner_statement: null,
      surfaces: record().surfaces,
      provenance: record().provenance,
      subject: record().subject,
      record_id: 'authority-record-acme-agent',
      '@version': 'EMILIA-AUTHORITY-RECORD-v1',
    });
    expect(first.ok && reordered.ok).toBe(true);
    if (!first.ok || !reordered.ok) return;
    expect(authorityRecordDigest(first.record)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(authorityRecordDigest(first.record)).toBe(authorityRecordDigest(reordered.record));
  });
});

describe('Authority Record freshness', () => {
  it('is CURRENT only when the watched ref resolves to the recorded immutable revision', () => {
    const parsed = validateAuthorityRecordProjection(record());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(evaluateAuthorityRecordFreshness(parsed.record, {
      kind: 'resolved', revision: REVISION_A,
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'CURRENT', observed_revision: REVISION_A, current_revision: REVISION_A,
    });
  });

  it('is STALE only on a successful unequal ref resolution', () => {
    const parsed = validateAuthorityRecordProjection(record());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(evaluateAuthorityRecordFreshness(parsed.record, {
      kind: 'resolved', revision: REVISION_B,
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toMatchObject({
      status: 'STALE', current_revision: REVISION_B,
    });
  });

  it('reports lookup failures honestly and does not manufacture staleness', () => {
    const parsed = validateAuthorityRecordProjection(record());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(evaluateAuthorityRecordFreshness(parsed.record, {
      kind: 'unavailable', reason: 'github_rate_limited',
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'UNAVAILABLE', reason: 'github_rate_limited',
    });
    expect(evaluateAuthorityRecordFreshness(parsed.record, {
      kind: 'indeterminate', reason: 'ambiguous_tag_target',
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'INDETERMINATE', reason: 'ambiguous_tag_target',
    });
  });

  it('marks the record EXPIRED independently of ref-resolution state', () => {
    const parsed = validateAuthorityRecordProjection(record());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(evaluateAuthorityRecordFreshness(parsed.record, {
      kind: 'resolved', revision: REVISION_A,
    }, Date.parse('2026-10-01T00:00:00.000Z'))).toEqual({ status: 'EXPIRED' });
  });

  it('does not accept an invalid resolved revision as current or stale', () => {
    const parsed = validateAuthorityRecordProjection(record());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(evaluateAuthorityRecordFreshness(parsed.record, {
      kind: 'resolved', revision: 'moving-main',
    }, Date.parse('2026-08-20T00:00:00.000Z'))).toEqual({
      status: 'INDETERMINATE', reason: 'resolved_revision_invalid',
    });
  });
});

describe('repository-control claim proof', () => {
  it('binds the invitation challenge to the exact record bytes and repository', () => {
    const parsed = validateAuthorityRecordProjection(record());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const digest = authorityRecordDigest(parsed.record);
    const proof = buildAuthorityClaimProof({
      challenge: `claim_${'c'.repeat(48)}`,
      recordDigest: digest,
      repositoryUrl: parsed.record.subject.repository_url,
      expiresAt: '2026-08-20T20:00:00.000Z',
    });
    expect(validateAuthorityClaimProof(proof, {
      challenge: `claim_${'c'.repeat(48)}`,
      recordDigest: digest,
      repositoryUrl: 'https://github.com/acme/agent',
      now: Date.parse('2026-08-19T00:00:00.000Z'),
    })).toEqual({ ok: true });
  });

  it('refuses substituted record bytes, repository, challenge, expiry, or extra fields', () => {
    const parsed = validateAuthorityRecordProjection(record());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const digest = authorityRecordDigest(parsed.record);
    const base = buildAuthorityClaimProof({
      challenge: `claim_${'c'.repeat(48)}`,
      recordDigest: digest,
      repositoryUrl: parsed.record.subject.repository_url,
      expiresAt: '2026-08-20T20:00:00.000Z',
    });
    const expected = {
      challenge: `claim_${'c'.repeat(48)}`,
      recordDigest: digest,
      repositoryUrl: 'https://github.com/acme/agent',
      now: Date.parse('2026-08-19T00:00:00.000Z'),
    };
    for (const hostile of [
      { ...base, challenge: `claim_${'d'.repeat(48)}` },
      { ...base, record_digest: SHA_A },
      { ...base, repository_url: 'https://github.com/attacker/fork' },
      { ...base, expires_at: '2026-08-18T00:00:00.000Z' },
      { ...base, approved: true },
    ]) {
      expect(validateAuthorityClaimProof(hostile, expected).ok).toBe(false);
    }
  });

  it('refuses to construct a claim proof from malformed caller input', () => {
    expect(() => buildAuthorityClaimProof({
      challenge: 'short',
      recordDigest: SHA_A,
      repositoryUrl: 'https://github.com/acme/agent',
      expiresAt: '2026-08-20T20:00:00.000Z',
    })).toThrow(TypeError);
  });
});
