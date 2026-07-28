// SPDX-License-Identifier: Apache-2.0
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  RELIANCE_PROGRAM_SOURCE_VERSION,
  signRelianceProgram,
} from '../packages/gate/reliance-program.js';

const schema = JSON.parse(readFileSync(
  new URL('../public/schemas/ep-reliance-program.schema.json', import.meta.url),
  'utf8',
));
const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
const D = (character: string) => `sha256:${character.repeat(64)}`;

function source(): any {
  return {
    '@version': RELIANCE_PROGRAM_SOURCE_VERSION,
    program_id: 'rp.schema.reference.1',
    version: 1,
    relying_party: { id: 'rp:reference', key_id: 'rp-key-1' },
    root_caid: `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`,
    action_digest: D('a'),
    valid_from: '2026-07-28T12:00:00Z',
    expires_at: '2026-07-29T12:00:00Z',
    stages: [{
      stage_id: 'authorization',
      depends_on: [],
      rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
      profiles: [{
        profile_id: 'rp:admissibility:authorization:v1',
        profile_hash: D('b'),
        evaluation_max_age_sec: 300,
        revocation_required: true,
      }],
    }],
    execution: {
      depends_on: ['authorization'],
      consequence_mode: 'receipt-program',
      capability_template_digest: D('c'),
      escrow_profile_digest: null,
    },
  };
}

describe('EP Reliance Program JSON schema', () => {
  it('accepts the implementation-emitted signed envelope', () => {
    const keys = generateKeyPairSync('ed25519');
    expect(validate(signRelianceProgram(source(), keys.privateKey))).toBe(true);
  });

  it('refuses extension fields and ambiguous consequence ownership', () => {
    const keys = generateKeyPairSync('ed25519');
    const extra = structuredClone(signRelianceProgram(source(), keys.privateKey));
    extra.source.surprise = true;
    expect(validate(extra)).toBe(false);

    const ambiguous = source();
    ambiguous.execution.escrow_profile_digest = D('d');
    const unsignedEnvelope = {
      '@version': 'EP-RELIANCE-PROGRAM-v1',
      source: ambiguous,
      source_digest: D('e'),
      signature: { algorithm: 'Ed25519', key_id: 'rp-key-1', value: 'A'.repeat(86) },
    };
    expect(validate(unsignedEnvelope)).toBe(false);
  });
});

