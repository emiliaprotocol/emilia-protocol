// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  auditPreprintClaims,
  normalizeExtractedText,
} from '../scripts/check-preprint-sync.mjs';

const evidence = {
  failures: [],
  canonicalMarkdownSha256: 'a'.repeat(64),
  conformance: {
    suites: 21,
    vectors: 329,
    manifestSha256: 'b'.repeat(64),
  },
  tla: {
    states: '413,137',
    distinctStates: '45,342',
    invariants: 26,
    checker: 'TLC 2.19',
  },
  alloy: {
    assertions: 32,
    version: '6.2.0',
  },
  tamarin: {
    verified: 10,
    falsified: 2,
  },
  external: {
    commit: '7faba36010e7590727bebbc5b9dcceee60539b9b',
    suites: 16,
    vectors: 164,
    structuredCases: 353,
    rawParserCases: 6,
    hostilityCases: 359,
  },
  drafts: {
    'draft-schrock-ep-authorization-receipts': '07',
    'draft-schrock-ep-quorum': '03',
    'draft-schrock-ep-authorization-evidence-chain': '03',
    'draft-schrock-ep-evidence-record': '01',
  },
};

const composedBlock = `
executable_composed_reliance (exists-trace): verified
execution_requires_full_composition (all-traces): verified
caid_binds_family_and_material (all-traces): verified
initiator_cannot_self_approve (all-traces): verified
no_single_signer_fills_quorum (all-traces): verified
no_issuer_laundering (all-traces): verified
strict_registry_view_is_exact (all-traces): verified
no_cross_action_profile_or_audience_replay (all-traces): verified
execution_has_honest_approvals_or_prior_compromise (all-traces): verified
injective_execution_with_consumption (all-traces): verified
unchecked_composition_is_injective (all-traces): falsified
unchecked_registry_view_is_current (all-traces): falsified
`;

const sharedClaims = `
A cross-language conformance battery (21 suites, 329 vectors).
A conformance battery of 21 suites comprising 329 vectors.
The 21-suite / 329-vector conformance battery.
The ports show agreement across all 329 current vectors.
413,137 states (45,342 distinct) with no counterexample against 26 invariants.
four Alloy models (6.2.0, SAT4J), with 32 assertions.
Pinned commit 7faba36010e7590727bebbc5b9dcceee60539b9b.
The pinned 16-suite/164-vector clean-room bundle.
353 structured attacks plus 6 raw-parser refusals.
The 359-case hostility campaign.
draft-schrock-ep-authorization-receipts-07
draft-schrock-ep-quorum-03
draft-schrock-ep-authorization-evidence-chain-03
draft-schrock-ep-evidence-record-01
${composedBlock}
`;

const tex = `
% Canonical Markdown SHA-256: ${'a'.repeat(64)}
% conformance 21 suites / 329 vectors
% manifest_sha256=${'b'.repeat(64)}
${sharedClaims}
`;

const staging = `
Status: LOCALLY REPRODUCIBLE; NOT APPROVED TO POST.
Conformance 21 suites / 329 vectors.
10 composed obligations + 2 deliberate falsifications.
TLA+ 413,137 states / 26 invariants.
32 assertions across four CI-gated models at analyzer 6.2.0.
Rust external verifier / 164 vectors / 359 hostility cases.
npm run preprint:build
npm run check:preprint
npm run test:preprint
`;

const audit = (overrides = {}) => auditPreprintClaims({
  tex,
  pdfText: sharedClaims,
  staging,
  evidence,
  ...overrides,
});

describe('preprint evidence synchronization guard', () => {
  it('accepts synchronized source, PDF text, staging, and evidence', () => {
    assert.deepEqual(audit(), []);
  });

  it('rejects stale conformance totals in the source', () => {
    const staleTex = tex.replaceAll('21 suites', '18 suites').replaceAll('329 vectors', '251 vectors');
    assert.ok(
      audit({ tex: staleTex }).some((failure) =>
        /main\.tex claims 18 suites \/ 251 vectors/.test(failure)),
    );
  });

  it('rejects a stale standards revision even when the other claims are current', () => {
    assert.ok(audit({
      tex: tex.replaceAll(
        'draft-schrock-ep-authorization-receipts-07',
        'draft-schrock-ep-authorization-receipts-06',
      ),
    }).includes(
      'main.tex cites stale draft-schrock-ep-authorization-receipts-06; evidence is draft-schrock-ep-authorization-receipts-07',
    ));
  });

  it('rejects a PDF whose claim text was not rebuilt from the synchronized source', () => {
    assert.ok(
      audit({
        pdfText: sharedClaims.replaceAll('329 vectors', '251 vectors'),
      }).some((failure) => /main\.pdf claims 21 suites \/ 251 vectors/.test(failure)),
    );
  });

  it('rejects stale canonical Markdown and manifest fingerprints', () => {
    const staleMarkers = tex
      .replace(`% Canonical Markdown SHA-256: ${'a'.repeat(64)}`, `% Canonical Markdown SHA-256: ${'c'.repeat(64)}`)
      .replace(`manifest_sha256=${'b'.repeat(64)}`, `manifest_sha256=${'d'.repeat(64)}`);
    const failures = audit({ tex: staleMarkers });
    assert.ok(failures.includes('main.tex canonical Markdown SHA-256 marker is missing or stale'));
    assert.ok(failures.includes('main.tex conformance manifest_sha256 marker is missing or stale'));
  });

  it('normalizes PDF ligatures and page whitespace deterministically', () => {
    assert.equal(normalizeExtractedText('veri\uFB01ed\n\n  claims'), 'verified claims');
  });
});
