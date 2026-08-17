// SPDX-License-Identifier: Apache-2.0
//
// EP-AGENT-RECORD-OBSERVATION-v2 hybrid verifier test.
//
// Builds a REAL Ed25519 (operator config key) + ML-DSA-65 signed agent-record
// observation, then asserts the fail-closed predicate. The hostile half is the
// point: leg stripping both ways, set narrowing (structural + independent
// crypto.verify over the narrowed bytes), set widening, duplicate/relabelled/
// swapped legs, PQ key substitution, tamper-after-signing, the v1 verifier
// refusing a v2 record, and a v1 byte-identity regression.
//
// The PQ leg runs for real: this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { vi } from 'vitest';

import { canonicalize } from '@/lib/canonical-json';
import {
  AGENT_RECORD_RETENTION_MS,
  AGENT_RECORD_V2_VERSION,
  AGENT_RECORD_V2_REQUIRED_ALGORITHMS,
  agentRecordV2SignedPayload,
  signAgentRecordObservation,
  signAgentRecordObservationV2,
  verifyAgentRecordObservation,
  verifyAgentRecordObservationV2,
} from './core';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const RECORD_ID = `agent_record_${'a'.repeat(40)}`;
const BOND_ID = '11111111-1111-4111-8111-111111111111';
const BOND_DIGEST = `sha256:${'b'.repeat(64)}`;
const SOURCE_DIGEST = `sha256:${'c'.repeat(64)}`;
const ACTION_DIGEST = `sha256:${'d'.repeat(64)}`;
const REFUSED_AT = '2026-08-02T20:00:00.000Z';
const OBSERVED_AT = '2026-08-02T20:01:00.000Z';
const RETENTION_EXPIRES_AT = new Date(Date.parse(OBSERVED_AT) + AGENT_RECORD_RETENTION_MS).toISOString();
const NOW = Date.parse(OBSERVED_AT);

const input = () => ({
  recordId: RECORD_ID,
  bondId: BOND_ID,
  bondDigest: BOND_DIGEST,
  sourceArtifactDigest: SOURCE_DIGEST,
  actionDigest: ACTION_DIGEST,
  refusalDigest: SOURCE_DIGEST,
  refusedAt: REFUSED_AT,
  observedAt: OBSERVED_AT,
  retentionExpiresAt: RETENTION_EXPIRES_AT,
});

const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');

const clone = <T>(v: T): T => structuredClone(v);

async function buildV2() {
  return signAgentRecordObservationV2(input(), { secretKey: pqSecretB64u, publicKey: pqPubB64u });
}
function pins(obs: any) {
  return { pqPublicKeys: { [obs.proof.pq_key_id]: obs.proof.pq_public_key }, now: NOW };
}

describe('EP-AGENT-RECORD-OBSERVATION-v2 hybrid', () => {
  beforeEach(() => {
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', crypto.randomBytes(32).toString('base64'));
    vi.stubEnv('EP_COMMIT_SIGNING_KEYS', '');
  });
  afterEach(() => { vi.unstubAllEnvs(); });

  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid observation verifies under both pinned keys', async () => {
    const obs = await buildV2();
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res).toMatchObject({ verified: true, within_retention: true, record_id: RECORD_ID });
    expect(res.checks.legs_present).toBe(true);
    expect(res.checks.signature_valid).toBe(true);
  });

  it('the committed bytes carry the required algorithm set + v2 marker', async () => {
    const obs = await buildV2();
    const bytes = agentRecordV2SignedPayload(obs.record).toString('utf8');
    expect(bytes).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
    expect(bytes).toContain(`"@version":"${AGENT_RECORD_V2_VERSION}"`);
  });

  // --- v1 / v2 compatibility --------------------------------------------------

  it('the v1 verifier refuses a v2 observation cleanly (does not accept, does not throw)', async () => {
    const obs = await buildV2();
    const res = verifyAgentRecordObservation(obs, NOW);
    expect(res.verified).toBe(false);
    expect(obs['@version']).not.toBe('EP-AGENT-RECORD-OBSERVATION-v1');
    expect(typeof res.reason).toBe('string');
  });

  it('the v1 verifier still accepts a v1 observation, unchanged (byte-identity regression)', () => {
    const v1 = signAgentRecordObservation(input());
    expect(v1['@version']).toBe('EP-AGENT-RECORD-OBSERVATION-v1');
    expect(verifyAgentRecordObservation(v1, NOW)).toMatchObject({ verified: true, within_retention: true });
  });

  it('the v2 verifier refuses a v1 observation on the version marker', async () => {
    const v1 = signAgentRecordObservation(input());
    const res = await verifyAgentRecordObservationV2(v1, { now: NOW });
    expect(res!.verified).toBe(false);
    expect(res!.checks.version).toBe(false);
  });

  // --- anti-stripping ---------------------------------------------------------

  it('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const obs = clone(await buildV2());
    obs.proof.signatures = obs.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.legs_present).toBe(false);
    expect(res!.checks.signature_valid).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const obs = clone(await buildV2());
    obs.proof.signatures = obs.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.legs_present).toBe(false);
  });

  it('SET NARROWING fails BOTH structurally and cryptographically', async () => {
    const obs = clone(await buildV2());
    obs.proof.required_algorithms = ['Ed25519'];
    obs.proof.signatures = obs.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.algorithm_set).toBe(false);

    // The surviving Ed25519 signature was made over bytes committing to the FULL
    // set, so it cannot verify over the narrowed bytes.
    const narrowedBytes = Buffer.from(canonicalize({
      '@version': AGENT_RECORD_V2_VERSION,
      record: obs.record,
      required_algorithms: ['Ed25519'],
    }), 'utf8');
    const edPub = crypto.createPublicKey({ key: Buffer.from(obs.proof.public_key, 'base64url'), format: 'der', type: 'spki' });
    const survivingSig = Buffer.from(obs.proof.signatures[0].sig, 'base64url');
    expect(crypto.verify(null, narrowedBytes, edPub, survivingSig)).toBe(false);
  });

  it('SET WIDENING: an extra algorithm refuses', async () => {
    const obs = clone(await buildV2());
    obs.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.algorithm_set).toBe(false);
  });

  it('DUPLICATE ALGORITHM refuses', async () => {
    const obs = clone(await buildV2());
    obs.proof.signatures = [obs.proof.signatures[0], obs.proof.signatures[0]];
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.legs_present).toBe(false);
  });

  it('ALGORITHM RELABELLING: Ed25519 leg called Ed448 refuses', async () => {
    const obs = clone(await buildV2());
    obs.proof.signatures = obs.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.legs_present).toBe(false);
  });

  it('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
    const obs = clone(await buildV2());
    const pqLeg = obs.proof.signatures.find((s: any) => s.alg === 'ML-DSA-65');
    obs.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.signature_valid).toBe(false);
  });

  // --- pinning ----------------------------------------------------------------

  it('an unpinned ML-DSA key confers nothing', async () => {
    const obs = await buildV2();
    const res = await verifyAgentRecordObservationV2(obs, { now: NOW });
    expect(res!.verified).toBe(false);
    expect(res!.checks.pq_key_pinned).toBe(false);
  });

  it('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const obs = await buildV2();
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyAgentRecordObservationV2(obs, {
      pqPublicKeys: { [obs.proof.pq_key_id]: Buffer.from(other.publicKey).toString('base64url') },
      now: NOW,
    });
    expect(res!.verified).toBe(false);
    expect(res!.checks.pq_key_pinned).toBe(false);
  });

  it('ED SUBSTITUTION: a v2 record verified under a different operator config key refuses', async () => {
    const obs = await buildV2();
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', crypto.randomBytes(32).toString('base64'));
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.operator_key_pinned).toBe(false);
  });

  // --- binding / domain -------------------------------------------------------

  it('TAMPERED AFTER SIGNING: editing the record breaks the binding of BOTH legs', async () => {
    const obs = clone(await buildV2());
    obs.record.bond.bond_digest = `sha256:${'f'.repeat(64)}`;
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.signature_valid).toBe(false);
  });

  it('DOMAIN: a structurally invalid record refuses', async () => {
    const obs = clone(await buildV2());
    obs.record.source.profile = 'EP-ACTION-REFUSAL-STATEMENT-v0';
    const res = await verifyAgentRecordObservationV2(obs, pins(obs));
    expect(res!.verified).toBe(false);
    expect(res!.checks.record_valid).toBe(false);
  });

  it('a v2 record outside its retention window verifies but is not within_retention', async () => {
    const obs = await buildV2();
    const res = await verifyAgentRecordObservationV2(obs, {
      ...pins(obs),
      now: Date.parse(RETENTION_EXPIRES_AT) + 1,
    });
    expect(res!.verified).toBe(true);
    expect(res!.within_retention).toBe(false);
    expect(res!.reason).toBe('agent_record_expired');
  });

  // --- fail-closed backend ----------------------------------------------------

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const obs = await buildV2();
    const res = await verifyAgentRecordObservationV2(obs, {
      ...pins(obs),
      mldsaBackendLoader: async () => null,
    });
    expect(res!.verified).toBe(false);
    expect(res!.checks.signature_valid).toBe(false);
    expect(res!.reason).toMatch(/pq_backend_unavailable/);
  });

  // --- fail-closed on junk ----------------------------------------------------

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyAgentRecordObservationV2(junk as any, { now: NOW });
      expect(res!.verified).toBe(false);
    }
  });
});
