// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';

const readJson = (relative) => JSON.parse(fs.readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8'));
const context = readJson('public/.well-known/emilia-context.json');
const manifest = readJson('conformance/conformance-manifest.json');
const external = readJson('conformance/external/rust-cleanroom-jdieselny.v1.json');
const securityCase = readJson('security/security-case.json');
const llms = fs.readFileSync(new URL('../public/llms.txt', import.meta.url), 'utf8');
const llmsFull = fs.readFileSync(new URL('../public/llms-full.txt', import.meta.url), 'utf8');

describe('EMILIA-REPO-CONTEXT-v1', () => {
  it('takes current conformance counts from the executable manifest', () => {
    expect(context.current_evidence.cross_language_conformance.suites).toBe(manifest.totals.suites);
    expect(context.current_evidence.cross_language_conformance.vectors).toBe(manifest.totals.vectors);
    expect(context.current_evidence.cross_language_conformance.relationship).toBe('same_team_ports');
  });

  it('keeps the external result pinned to the bundle it actually ran', () => {
    expect(context.external_implementation.conformance.vectors).toBe(external.conformance.vectors);
    expect(context.external_implementation.conformance.current_vectors).toBe(manifest.totals.vectors);
    expect(context.external_implementation.conformance.relation_to_current_bundle)
      .toBe(external.conformance.vectors === manifest.totals.vectors
        ? 'current_vector_set'
        : 'time_pinned_prior_vector_set');
    expect(context.external_implementation.construction_evidence.strict_clean_room_acceptance).toBe(false);
  });

  it('takes security-claim status from the resolved machine-verifiable case', () => {
    expect(context.current_evidence.security_case.status).toBe('passed');
    expect(context.current_evidence.security_case.claims).toBe(securityCase.claim_count);
    expect(context.security_claims).toHaveLength(securityCase.claim_count);
  });

  it('makes the machine-policy versus human-authorization boundary explicit', () => {
    expect(context.canonical_definitions.some((entry) =>
      entry.term === 'machine policy decision versus human authorization')).toBe(true);
    expect(llmsFull).toContain('machine policy decision versus human authorization');
  });

  it('exposes both concise and machine-readable discovery targets', () => {
    expect(llms).toContain('/llms-full.txt');
    expect(llms).toContain('/.well-known/emilia-context.json');
    expect(context.excluded_as_current_authority.join(' ')).toContain('standards/archive/**');
  });
});
