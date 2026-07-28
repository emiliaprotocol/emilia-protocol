// SPDX-License-Identifier: Apache-2.0
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  defineAdmissibilityProfile,
  evaluateAdmissibilityProfile,
} from '../lib/evidence/admissibility-profiles.js';
import {
  RELIANCE_PROGRAM_SOURCE_VERSION,
  compileRelianceProgram,
  createAdmissibilityProfileTrustAdapter,
  signRelianceProgram,
} from '../packages/gate/reliance-program.js';

const D = (character: string) => `sha256:${character.repeat(64)}`;
const profile = defineAdmissibilityProfile({
  id: 'rp:admissibility:human-review:v1',
  authored_by: 'Synthetic health-plan relying party',
  version: 1,
  requires: [{ evidence: 'human_authorization', max_staleness_sec: 900 }],
});

describe('Reliance Program and Admissibility Profile composition', () => {
  it('uses the existing evaluator under the RP-pinned profile and refuses missing evidence', async () => {
    const keys = generateKeyPairSync('ed25519');
    const source = {
      '@version': RELIANCE_PROGRAM_SOURCE_VERSION,
      program_id: 'rp.payer.synthetic.1',
      version: 1,
      relying_party: { id: 'payer:synthetic', key_id: 'rp-key-1' },
      root_caid: `caid:1:health.prior-authorization-determination.1:jcs-sha256:${'A'.repeat(43)}`,
      action_digest: D('a'),
      valid_from: '2026-07-28T12:00:00Z',
      expires_at: '2026-07-29T12:00:00Z',
      stages: [{
        stage_id: 'licensed-review', depends_on: [],
        rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
        profiles: [{
          profile_id: profile.id,
          profile_hash: profile.profile_hash,
          evaluation_max_age_sec: 300,
          revocation_required: true,
        }],
      }],
      execution: {
        depends_on: ['licensed-review'], consequence_mode: 'action-escrow',
        capability_template_digest: null, escrow_profile_digest: D('e'),
      },
    };
    const signed = signRelianceProgram(source, keys.privateKey);
    const compiled = compileRelianceProgram(signed, {
      trustedKeys: {
        'rp-key-1': {
          relying_party_id: 'payer:synthetic',
          public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        },
      },
      profiles: [profile],
    });
    const requirement = compiled.program.stages[0].requirements[0];
    const binding = {
      instance_id: 'instance:pas-001', program_digest: compiled.program_digest,
      program_version: 1, root_caid: compiled.program.root_caid,
      action_digest: compiled.program.action_digest, stage_id: 'licensed-review',
      requirement_id: requirement.requirement_id, policy_digest: profile.profile_hash,
      predecessor_receipt_digests: [],
    };
    const adapter = createAdmissibilityProfileTrustAdapter({
      profile,
      evaluate: evaluateAdmissibilityProfile,
      now: '2026-07-28T12:10:00Z',
      project: () => ({
        subjects: ['reviewer:licensed-001'], key_fingerprints: [D('f')],
        issued_at: '2026-07-28T12:09:00Z', expires_at: '2026-07-28T12:20:00Z',
        revocation_checked_at: '2026-07-28T12:09:30Z',
      }),
    });
    const makeArtifact = (items: unknown[]) => ({
      evidence_id: `evidence:${items.length}`, binding, evidence: { bundle: { items } },
    });
    const accepted = await adapter({
      artifact: makeArtifact([{
        evidence: 'human_authorization', digest: D('c'), signature_valid: true,
        issued_at: '2026-07-28T12:09:00Z', revoked: false,
        action_digest: compiled.program.action_digest,
      }]),
      requirement,
      program: compiled.program,
    });
    expect(accepted).toMatchObject({ valid: true, policy_digest: profile.profile_hash });
    expect(await adapter({ artifact: makeArtifact([]), requirement, program: compiled.program }))
      .toMatchObject({ valid: false, reason: 'admissibility_missing_evidence' });
  });
});
