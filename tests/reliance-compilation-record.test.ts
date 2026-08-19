// SPDX-License-Identifier: Apache-2.0
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { defineAdmissibilityProfile } from '../lib/evidence/admissibility-profiles.js';
import {
  RELIANCE_PROGRAM_SOURCE_VERSION,
  RELIANCE_PROGRAM_V2_VERSION,
  compileRelianceProgram,
  signRelianceProgram,
} from '../packages/gate/reliance-program.js';
import {
  RELIANCE_COMPILATION_CLAIM_BOUNDARY,
  RELIANCE_COMPILATION_LIMITATIONS,
  RELIANCE_COMPILATION_RECORD_VERSION,
  RELIANCE_COMPILER_PROFILE,
  createRelianceProgramCompilationRecord,
  renderRelianceProgramCompilationRecord,
  verifyRelianceProgramCompilationRecord,
} from '../packages/gate/reliance-compilation-record.js';
import { hashCanonical } from '../packages/gate/execution-binding.js';
import {
  TRUST_PROGRAM_V2_VERSION,
  trustProgramV2Digest,
} from '../packages/gate/trust-program.js';

type JsonRecord = Record<string, any>;

const D = (character: string) => `sha256:${character.repeat(64)}`;
const profile = defineAdmissibilityProfile({
  id: 'rp:institution:payment-review:v1',
  authored_by: 'Synthetic institutional relying party',
  version: 1,
  requires: [{ evidence: 'human_authorization', max_staleness_sec: 300 }],
});

function fixture() {
  const keys = generateKeyPairSync('ed25519');
  const source = {
    '@version': RELIANCE_PROGRAM_SOURCE_VERSION,
    program_id: 'rp.institution.synthetic.1',
    version: 1,
    relying_party: { id: 'org:synthetic-institution', key_id: 'rp-key-1' },
    root_caid: `caid:1:finance.vendor-bank-change.1:jcs-sha256:${'A'.repeat(43)}`,
    action_digest: D('a'),
    valid_from: '2026-08-19T12:00:00Z',
    expires_at: '2026-08-20T12:00:00Z',
    stages: [{
      stage_id: 'institutional-review',
      depends_on: [],
      rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
      profiles: [{
        profile_id: profile.id,
        profile_hash: profile.profile_hash,
        evaluation_max_age_sec: 300,
        revocation_required: true,
      }],
    }],
    execution: {
      depends_on: ['institutional-review'],
      consequence_mode: 'action-escrow',
      capability_template_digest: null,
      escrow_profile_digest: D('e'),
    },
  };
  const signed = signRelianceProgram(source, keys.privateKey);
  const compiled = compileRelianceProgram(signed, {
    trustedKeys: {
      'rp-key-1': {
        relying_party_id: source.relying_party.id,
        public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    profiles: [profile],
  });
  return { compiled, signed };
}

function redigest(record: JsonRecord): JsonRecord {
  const changed = structuredClone(record);
  delete changed.record_digest;
  return {
    ...changed,
    record_digest: `sha256:${hashCanonical(changed)}`,
  };
}

describe('institution-readable Reliance Program compilation record', () => {
  it('binds the exact institutional source, action, compiler target, and mapping trace', () => {
    const { compiled } = fixture();
    const record = createRelianceProgramCompilationRecord(compiled);

    expect(record['@version']).toBe(RELIANCE_COMPILATION_RECORD_VERSION);
    expect(record.source).toEqual({
      digest: compiled.source_digest,
      relying_party_id: 'org:synthetic-institution',
    });
    expect(record.output).toMatchObject({
      program_digest: compiled.program_digest,
      root_caid: compiled.program.root_caid,
      action_digest: D('a'),
      stage_count: 1,
      requirement_count: 1,
      consequence_mode: 'action-escrow',
    });
    expect(record.trace).toEqual(compiled.trace);
    expect(record.limitations).toEqual([...RELIANCE_COMPILATION_LIMITATIONS]);
    expect(record.claim_boundary).toBe(RELIANCE_COMPILATION_CLAIM_BOUNDARY);
    expect(Object.isFrozen(record)).toBe(true);
    expect(Object.isFrozen(record.trace[0])).toBe(true);
  });

  it('is deterministic and verifies against an independently supplied compilation', () => {
    const { compiled } = fixture();
    const first = createRelianceProgramCompilationRecord(compiled);
    const second = createRelianceProgramCompilationRecord(structuredClone(compiled));
    expect(second).toEqual(first);
    expect(verifyRelianceProgramCompilationRecord(first, compiled)).toEqual({
      valid: true,
      reason: null,
      record_digest: first.record_digest,
      source_digest: compiled.source_digest,
      program_digest: compiled.program_digest,
    });
  });

  it('records the registered hybrid compiler and Trust Program versions without changing the mapping', () => {
    const { compiled } = fixture();
    const hybrid = structuredClone(compiled) as JsonRecord;
    hybrid.version = RELIANCE_PROGRAM_V2_VERSION;
    hybrid.program['@version'] = TRUST_PROGRAM_V2_VERSION;
    hybrid.program_digest = trustProgramV2Digest(hybrid.program);

    const record = createRelianceProgramCompilationRecord(hybrid);
    expect(record.compiler).toEqual({
      profile: RELIANCE_COMPILER_PROFILE,
      compiled_artifact_version: RELIANCE_PROGRAM_V2_VERSION,
      target_program_version: TRUST_PROGRAM_V2_VERSION,
    });
    expect(record.trace).toEqual(compiled.trace);
    expect(verifyRelianceProgramCompilationRecord(record, hybrid))
      .toMatchObject({ valid: true, reason: null });
  });

  it('rejects digest tampering, rehashed substitution, unknown fields, and corrupt compiler output', () => {
    const { compiled } = fixture();
    const record = createRelianceProgramCompilationRecord(compiled) as JsonRecord;

    const tampered = structuredClone(record);
    tampered.output.action_digest = D('b');
    expect(verifyRelianceProgramCompilationRecord(tampered, compiled))
      .toMatchObject({ valid: false, reason: 'record_digest_mismatch' });

    expect(verifyRelianceProgramCompilationRecord(redigest(tampered), compiled))
      .toMatchObject({ valid: false, reason: 'record_compilation_mismatch' });

    const extended = structuredClone(record);
    extended.authorized = true;
    expect(verifyRelianceProgramCompilationRecord(extended, compiled))
      .toEqual({ valid: false, reason: 'record_schema_invalid', record_digest: null });

    const corruptCompiled = structuredClone(compiled);
    corruptCompiled.program.action_digest = D('c');
    expect(() => createRelianceProgramCompilationRecord(corruptCompiled))
      .toThrowError(/digest does not match/);
  });

  it('renders the same bounded record for a human reviewer without source or evidence bodies', () => {
    const { compiled, signed } = fixture();
    const record = createRelianceProgramCompilationRecord(compiled);
    const markdown = renderRelianceProgramCompilationRecord(record);

    expect(markdown).toContain('# Reliance Program compilation record');
    expect(markdown).toContain('`org:synthetic-institution`');
    expect(markdown).toContain('`institutional-review/admissibility-01`');
    expect(markdown).toContain(`\`${profile.id}\``);
    expect(markdown).toContain('does not establish policy truth');
    expect(markdown).not.toContain(signed.signature.value);
    expect(markdown).not.toContain('human_authorization');
  });
});
