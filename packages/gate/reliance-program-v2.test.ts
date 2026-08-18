// SPDX-License-Identifier: Apache-2.0
//
// EP-RELIANCE-PROGRAM-v2 / EP-RELIANCE-PROGRAM-SOURCE-v2 -- hostile matrix for
// the hybrid relying-party program source. Package-root node:test file
// importing the compatibility shim './reliance-program.js' (which re-exports
// ./dist/reliance-program.js), matching this package's convention;
// packages/gate/reliance-program.test.js keeps covering v1 and is untouched.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import { hashCanonical } from './execution-binding.js';
import { TRUST_PROGRAM_V2_VERSION } from './trust-program.js';
import {
  RELIANCE_PROGRAM_SOURCE_VERSION,
  RELIANCE_PROGRAM_VERSION,
  RELIANCE_PROGRAM_SOURCE_V2_VERSION,
  RELIANCE_PROGRAM_V2_VERSION,
  RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS,
  RelianceProgramValidationError,
  compileRelianceProgram,
  compileRelianceProgramV2,
  relianceProgramSourceV2Digest,
  signRelianceProgram,
  signRelianceProgramV2,
  verifyRelianceProgram,
  verifyRelianceProgramV2,
  verifyRelianceProgramEnvelope,
} from './reliance-program.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (character: string) => `sha256:${character.repeat(64)}`;
const C = (character: string) => `caid:1:health.prior-authorization-determination.1:jcs-sha256:${character.repeat(43)}`;
const KEY_ID = 'rp-key-1';
const RP_ID = 'payer:example-health-plan';

function profile(id = 'rp:admissibility:human-review:v1') {
  const body = {
    id,
    version: 1,
    authored_by: 'Example Health Plan',
    requires: [{ evidence: 'human_authorization', max_staleness_sec: 900 }],
    verdicts: ['unverifiable', 'conflicted', 'stale', 'missing_evidence', 'admissible'],
  };
  return { ...body, profile_hash: `sha256:${hashCanonical(body)}` };
}

const PROFILE_HASH = profile().profile_hash;

function source(version: string = RELIANCE_PROGRAM_SOURCE_V2_VERSION) {
  return {
    '@version': version,
    program_id: 'rp.payer.pas-adverse-determination.1',
    version: 1,
    relying_party: { id: RP_ID, key_id: KEY_ID },
    root_caid: C('A'),
    action_digest: D('1'),
    valid_from: '2026-07-28T12:00:00Z',
    expires_at: '2026-07-29T12:00:00Z',
    stages: [
      {
        stage_id: 'licensed-review',
        depends_on: [],
        rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
        profiles: [{
          profile_id: 'rp:admissibility:human-review:v1',
          profile_hash: PROFILE_HASH,
          evaluation_max_age_sec: 300,
          revocation_required: true,
        }],
      },
    ],
    execution: {
      depends_on: ['licensed-review'],
      consequence_mode: 'action-escrow',
      capability_template_digest: null,
      escrow_profile_digest: D('e'),
    },
  };
}

function issuerFixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
  return {
    ed,
    keys: {
      ed: { privateKey: ed.privateKey, publicKey: edPubB64u },
      pq: { secretKey: pq.secretKey, publicKey: pqPubB64u },
    },
    hybridPin: {
      [KEY_ID]: { relying_party_id: RP_ID, public_key: edPubB64u, pq_public_key: pqPubB64u },
    },
    classicalPin: { [KEY_ID]: { relying_party_id: RP_ID, public_key: edPubB64u } },
  };
}

async function signed() {
  const issuer = issuerFixture();
  const envelope = await signRelianceProgramV2(source(), issuer.keys) as any;
  return { issuer, envelope };
}

describe('EP-RELIANCE-PROGRAM-v2 hybrid relying-party source', () => {
  it('valid v2 roundtrip: signs, verifies, and compiles to a v2 Trust Program', async () => {
    const { issuer, envelope } = await signed();
    assert.equal(envelope['@version'], RELIANCE_PROGRAM_V2_VERSION);
    assert.equal(envelope.source['@version'], RELIANCE_PROGRAM_SOURCE_V2_VERSION);
    assert.deepEqual(envelope.proof.required_algorithms, [...RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS]);
    assert.deepEqual(
      envelope.proof.signatures.map((s: any) => s.alg),
      [...RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS],
    );
    assert.equal(envelope.source_digest, relianceProgramSourceV2Digest(envelope.source));

    const verified = await verifyRelianceProgramV2(envelope, { trustedKeys: issuer.hybridPin });
    assert.deepEqual(verified, {
      valid: true,
      reason: null,
      source_digest: envelope.source_digest,
      relying_party_id: RP_ID,
      key_id: KEY_ID,
    });

    const compiled = await compileRelianceProgramV2(envelope, {
      trustedKeys: issuer.hybridPin,
      profiles: [profile()],
    });
    assert.equal(compiled.version, RELIANCE_PROGRAM_V2_VERSION);
    assert.equal(compiled.program['@version'], TRUST_PROGRAM_V2_VERSION);
    assert.deepEqual(compiled.trace, [{
      stage_id: 'licensed-review',
      requirement_id: 'admissibility-01',
      profile_id: 'rp:admissibility:human-review:v1',
      profile_hash: PROFILE_HASH,
    }]);
  });

  it('v1-refuses-v2: the SYNC v1 verifier refuses structurally, never a crash and never partial credit', async () => {
    const { issuer, envelope } = await signed();
    // No await: verifyRelianceProgram remains synchronous and untouched. A v2
    // envelope carries no `signature` member for it to inspect at all.
    const result = verifyRelianceProgram(envelope, { trustedKeys: issuer.classicalPin });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'envelope_schema_invalid');
    assert.throws(
      () => compileRelianceProgram(envelope, { trustedKeys: issuer.classicalPin, profiles: [profile()] }),
      RelianceProgramValidationError,
    );
  });

  it('the router keeps the exact v1 verdict for a v1 envelope and hybrid-checks a v2 one', async () => {
    const issuer = issuerFixture();
    const v1 = signRelianceProgram(source(RELIANCE_PROGRAM_SOURCE_VERSION), issuer.ed.privateKey);
    assert.equal(v1['@version'], RELIANCE_PROGRAM_VERSION);
    const routedV1 = await verifyRelianceProgramEnvelope(v1, {
      trustedKeys: {
        [KEY_ID]: { relying_party_id: RP_ID, public_key: issuer.keys.ed.publicKey },
      },
    });
    assert.equal(routedV1.valid, true);

    const v2 = await signRelianceProgramV2(source(), issuer.keys);
    const routedV2 = await verifyRelianceProgramEnvelope(v2, { trustedKeys: issuer.hybridPin });
    assert.equal(routedV2.valid, true);
  });

  it('a key_id pinned WITHOUT the ML-DSA half never satisfies a v2 pin', async () => {
    const { issuer, envelope } = await signed();
    const result = await verifyRelianceProgramV2(envelope, { trustedKeys: issuer.classicalPin });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'relying_party_identity_mismatch');
  });

  it('stripped leg: dropping the ML-DSA signature refuses, never a classical-only pass', async () => {
    const { issuer, envelope } = await signed();
    const stripped = {
      ...envelope,
      proof: {
        ...envelope.proof,
        signatures: envelope.proof.signatures.filter((s: any) => s.alg !== 'ML-DSA-65'),
      },
    };
    const result = await verifyRelianceProgramV2(stripped, { trustedKeys: issuer.hybridPin });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'signature_leg_missing');
  });

  it('narrowed set: claiming required_algorithms=["Ed25519"] is refused structurally AND cryptographically', async () => {
    const { issuer, envelope } = await signed();
    const narrowed = {
      ...envelope,
      proof: {
        ...envelope.proof,
        required_algorithms: ['Ed25519'],
        signatures: envelope.proof.signatures.filter((s: any) => s.alg === 'Ed25519'),
      },
    };
    assert.equal(
      (await verifyRelianceProgramV2(narrowed, { trustedKeys: issuer.hybridPin })).reason,
      'algorithm_set_unsupported',
    );

    // Independently: the surviving Ed25519 signature does not verify over the
    // bytes rebuilt from the REGISTERED set, because the set is inside them.
    const setIntact = {
      ...narrowed,
      proof: { ...narrowed.proof, required_algorithms: [...RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS] },
    };
    assert.equal(
      (await verifyRelianceProgramV2(setIntact, { trustedKeys: issuer.hybridPin })).reason,
      'signature_leg_missing',
    );
  });

  it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
    const { issuer, envelope } = await signed();
    const tampered = {
      ...envelope,
      proof: {
        ...envelope.proof,
        signatures: envelope.proof.signatures.map((s: any) => (
          s.alg === 'ML-DSA-65' ? { ...s, sig: crypto.randomBytes(16).toString('base64url') } : s
        )),
      },
    };
    const result = await verifyRelianceProgramV2(tampered, { trustedKeys: issuer.hybridPin });
    assert.equal(result.valid, false);
    assert.ok(String(result.reason).includes('signature_invalid'));
  });

  it('Ed448-masquerade: a non-Ed25519 SPKI pinned as the classical half is refused, never verified', async () => {
    const { issuer, envelope } = await signed();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const masqueraded = { ...envelope, proof: { ...envelope.proof, public_key: ed448PubB64u } };
    const pin = {
      [KEY_ID]: {
        relying_party_id: RP_ID,
        public_key: ed448PubB64u,
        pq_public_key: issuer.hybridPin[KEY_ID].pq_public_key,
      },
    };
    const result = await verifyRelianceProgramV2(masqueraded, { trustedKeys: pin });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'relying_party_key_untrusted');
  });

  it('an absent ML-DSA backend is pq_backend_unavailable, never a pass on the Ed25519 leg', async () => {
    const { issuer, envelope } = await signed();
    const result = await verifyRelianceProgramV2(envelope, {
      trustedKeys: issuer.hybridPin,
      mldsaBackend: {},
    });
    assert.equal(result.valid, false);
    assert.ok(String(result.reason).includes('pq_backend_unavailable'));
  });

  it('a tampered source is caught by the independently recomputed digest', async () => {
    const { issuer, envelope } = await signed();
    const tampered = structuredClone(envelope);
    tampered.source.action_digest = D('9');
    const result = await verifyRelianceProgramV2(tampered, { trustedKeys: issuer.hybridPin });
    assert.equal(result.reason, 'source_digest_mismatch');
  });

  it('a v1-marked source cannot be signed or verified under the v2 profile', async () => {
    const issuer = issuerFixture();
    await assert.rejects(
      signRelianceProgramV2(source(RELIANCE_PROGRAM_SOURCE_VERSION), issuer.keys),
      RelianceProgramValidationError,
    );
    const envelope = await signRelianceProgramV2(source(), issuer.keys) as any;
    const downgraded = structuredClone(envelope);
    downgraded.source['@version'] = RELIANCE_PROGRAM_SOURCE_VERSION;
    assert.equal(
      (await verifyRelianceProgramV2(downgraded, { trustedKeys: issuer.hybridPin })).reason,
      'source_schema_invalid',
    );
  });

  it('never throws on hostile input', async () => {
    for (const bad of [null, undefined, '', 42, [], { '@version': RELIANCE_PROGRAM_V2_VERSION }]) {
      assert.equal((await verifyRelianceProgramV2(bad, { trustedKeys: {} })).valid, false);
      assert.equal((await verifyRelianceProgramEnvelope(bad, { trustedKeys: {} })).valid, false);
    }
  });
});
