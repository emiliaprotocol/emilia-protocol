// SPDX-License-Identifier: Apache-2.0
//
// EP-APPROVAL-v1 DaVinci PAS packet, hybrid (Ed25519 + ML-DSA-65) profile:
// hostile matrix for verifyDavinciPasConsequencePacketV2 / Any.
//
// This suite targets the SIGNATURE/SHAPE layer the PQ hybrid migration
// actually changed -- version marker, set-shaped proof, anti-stripping bytes,
// and the async hybrid verify path -- not the FHIR PAS binding validator
// (unchanged, owned by lib/health/davinci-pas-binding.ts, covered by
// tests/davinci-pas-consequence-control.test.ts). The packet built here is
// synthetic: fields outside the signature/shape layer (binding.action, caid,
// action_digest) are dummy values that legitimately fail the FHIR binding
// check ('packet_binding_invalid' etc.), which is expected and asserted
// explicitly below, never silently ignored. The PQ leg runs for real.
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../lib/canonical-json.js';
import {
  DAVINCI_PAS_ACTION_TYPE,
  DAVINCI_PAS_BINDING_TYPE,
  DAVINCI_PAS_IG_VERSION,
  DAVINCI_PAS_MEDICAL_RAIL,
  DAVINCI_PAS_PROFILE_ID,
} from '../lib/health/davinci-pas-binding.js';
import {
  DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION,
  DAVINCI_PAS_CONSEQUENCE_PACKET_V2_VERSION,
  DAVINCI_PAS_CONSEQUENCE_V2_REQUIRED_ALGORITHMS,
  DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
  DAVINCI_PAS_CONSEQUENCE_LIMITATIONS,
  verifyDavinciPasConsequencePacket,
  verifyDavinciPasConsequencePacketV2,
  verifyDavinciPasConsequencePacketAny,
} from '../lib/health/davinci-pas-consequence-control.js';
import { signAgile, type AgileSignature } from '@emilia-protocol/verify/pq-signature-agility';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const CLAIM_PROFILE = 'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim|2.2.1';
const RESPONSE_PROFILE = 'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse|2.2.1';
const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const DIGEST_C = `sha256:${'c'.repeat(64)}`;
const RELYING_PARTY_ID = 'rp:pas-hybrid-test';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const PIN = {
  relying_party_id: RELYING_PARTY_ID,
  key_id: 'pas:packet:hybrid',
  public_key_spki_b64u: edPubB64u,
  pq_key_id: 'pas:packet:hybrid:pq',
  pq_public_key_b64u: pqPubB64u,
};

function packetBody(version: string) {
  const eventDigests = [DIGEST_A, DIGEST_B];
  return {
    '@version': version,
    profile_id: DAVINCI_PAS_CONSEQUENCE_PROFILE_ID,
    relying_party_id: RELYING_PARTY_ID,
    tenant_id: 'org:hybrid-test',
    operation_id: 'operation:hybrid-test-001',
    generated_at: '2026-08-17T12:00:00.000Z',
    caid: 'caid:synthetic-dummy',
    action_digest: DIGEST_C,
    proposal_digest: DIGEST_A,
    binding: {
      '@type': DAVINCI_PAS_BINDING_TYPE,
      profile_id: DAVINCI_PAS_PROFILE_ID,
      ig: {
        package: 'hl7.fhir.us.davinci-pas',
        version: DAVINCI_PAS_IG_VERSION,
        fhir_release: 'R4',
        claim_profile: CLAIM_PROFILE,
        claim_response_profile: RESPONSE_PROFILE,
      },
      rail: DAVINCI_PAS_MEDICAL_RAIL,
      action: { action_type: DAVINCI_PAS_ACTION_TYPE },
      action_digest: DIGEST_C,
      caid: 'caid:synthetic-dummy',
    },
    binding_digest: DIGEST_B,
    decision: 'EXECUTED',
    reconciliation_required: false,
    retry_safe: false,
    event_count: 2,
    event_digests: eventDigests,
    event_root: digest(eventDigests),
    prepared_event_digest: DIGEST_A,
    terminal_event_digest: DIGEST_B,
    limitations: [...DAVINCI_PAS_CONSEQUENCE_LIMITATIONS],
  };
}

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

/** Mirrors davinci-pas-consequence-control.ts's private SIGNATURE_DOMAIN_V2. */
const SIGNATURE_DOMAIN_V2 = `${DAVINCI_PAS_CONSEQUENCE_PACKET_V2_VERSION}:SIGNATURE\0`;

async function buildV2Packet({
  requiredAlgorithms = [...DAVINCI_PAS_CONSEQUENCE_V2_REQUIRED_ALGORITHMS],
  omitLeg,
}: { requiredAlgorithms?: readonly string[]; omitLeg?: 'Ed25519' | 'ML-DSA-65' } = {}) {
  const body = packetBody(DAVINCI_PAS_CONSEQUENCE_PACKET_V2_VERSION);
  const packetDigest = digest(body);
  const bytes = Buffer.from(`${SIGNATURE_DOMAIN_V2}${canonicalize({
    packet_digest: packetDigest,
    required_algorithms: requiredAlgorithms,
    body,
  })}`);
  const ed25519Sig = crypto.sign(null, bytes, ed.privateKey).toString('base64url');
  const mldsaSignature = await signAgile(new Uint8Array(bytes), {
    alg: 'ML-DSA-65',
    private_key: Buffer.from(pq.secretKey).toString('base64url'),
    key_id: PIN.pq_key_id,
  });
  let signatures: AgileSignature[] = [
    { alg: 'Ed25519', sig: ed25519Sig, key_id: PIN.key_id },
    mldsaSignature,
  ];
  if (omitLeg) signatures = signatures.filter((s) => s.alg !== omitLeg);
  return {
    ...body,
    packet_digest: packetDigest,
    proof: {
      profile: DAVINCI_PAS_CONSEQUENCE_PACKET_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      signatures,
    },
  };
}

// Reasons that legitimately fail on this synthetic (non-FHIR-real) packet;
// the hostile matrix below asserts the SIGNATURE/SHAPE-layer reasons it
// controls are absent (or, for negative cases, exactly the expected one is
// present), while tolerating these unrelated binding-validation reasons.
const TOLERATED_FHIR_REASONS = new Set([
  'packet_binding_invalid',
  'packet_caid_invalid',
  'packet_action_digest_invalid',
  'packet_operation_mismatch',
  'packet_binding_digest_invalid',
  'packet_tenant_invalid',
]);

describe('DaVinci PAS consequence packet -- hybrid v2', () => {
  it('valid v2 roundtrip: the hybrid signature and shape layer accept a genuine dual-signed packet', async () => {
    const packet = await buildV2Packet();
    const result = await verifyDavinciPasConsequencePacketV2(packet, PIN);
    const nonFhirReasons = result.reasons.filter((r) => !TOLERATED_FHIR_REASONS.has(r));
    expect(nonFhirReasons).toEqual([]);
  });

  it('routes a v2 packet to the hybrid verifier via verifyDavinciPasConsequencePacketAny', async () => {
    const packet = await buildV2Packet();
    const viaAny = await verifyDavinciPasConsequencePacketAny(packet, PIN);
    const direct = await verifyDavinciPasConsequencePacketV2(packet, PIN);
    expect(viaAny).toEqual(direct);
  });

  it('v1 verifier refuses a v2 packet on the version marker before inspecting any signature', () => {
    const packet = { ...packetBody(DAVINCI_PAS_CONSEQUENCE_PACKET_V2_VERSION), packet_digest: 'sha256:' + '0'.repeat(64), proof: { bogus: true } };
    const result = verifyDavinciPasConsequencePacket(packet, {
      relying_party_id: RELYING_PARTY_ID,
      key_id: PIN.key_id,
      public_key_spki_b64u: edPubB64u,
    });
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('packet_profile_invalid');
  });

  it('v2 verifier refuses a v1 packet on the version marker', async () => {
    const packet = { ...packetBody(DAVINCI_PAS_CONSEQUENCE_PACKET_VERSION), packet_digest: 'sha256:' + '0'.repeat(64), proof: { alg: 'Ed25519', key_id: 'x', signature_b64u: 'a'.repeat(86) } };
    const result = await verifyDavinciPasConsequencePacketV2(packet, PIN);
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('packet_profile_invalid');
  });

  it('stripped leg: dropping the ML-DSA-65 signature refuses (never a pass on the classical leg alone)', async () => {
    const packet = await buildV2Packet({ omitLeg: 'ML-DSA-65' });
    const result = await verifyDavinciPasConsequencePacketV2(packet, PIN);
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('packet_proof_invalid');
  });

  it('stripped leg: dropping the Ed25519 signature refuses', async () => {
    const packet = await buildV2Packet({ omitLeg: 'Ed25519' });
    const result = await verifyDavinciPasConsequencePacketV2(packet, PIN);
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('packet_proof_invalid');
  });

  it('narrowed set: required_algorithms=[Ed25519] changes the signed bytes so the surviving Ed25519 leg no longer verifies', async () => {
    const packet = await buildV2Packet({ requiredAlgorithms: ['Ed25519'], omitLeg: 'ML-DSA-65' });
    const result = await verifyDavinciPasConsequencePacketV2(packet, PIN);
    expect(result.valid).toBe(false);
    // Structural refusal (algorithm set no longer matches the registered
    // pair) fires before the signature is even attempted.
    expect(result.reasons).toContain('packet_proof_invalid');
  });

  it('wrong-length signature: a truncated Ed25519 signature refuses as a signature failure, not a crash', async () => {
    const packet = await buildV2Packet();
    packet.proof.signatures = packet.proof.signatures.map((s: AgileSignature) => (
      s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, 10) } : s
    ));
    const result = await verifyDavinciPasConsequencePacketV2(packet, PIN);
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('packet_signature_invalid');
  });

  it('Ed448-masquerade: a non-Ed25519 key presented for the Ed25519 leg is refused, never silently accepted', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const packet = await buildV2Packet();
    const badPin = {
      ...PIN,
      public_key_spki_b64u: ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    };
    const result = await verifyDavinciPasConsequencePacketV2(packet, badPin);
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('packet_signature_invalid');
  });

  it('key substitution: an unpinned ML-DSA-65 public key is refused even with a structurally valid signature set', async () => {
    const packet = await buildV2Packet();
    const otherPq = ml_dsa65.keygen(crypto.randomBytes(32));
    const badPin = { ...PIN, pq_public_key_b64u: Buffer.from(otherPq.publicKey).toString('base64url') };
    const result = await verifyDavinciPasConsequencePacketV2(packet, badPin);
    expect(result.valid).toBe(false);
    expect(result.reasons).toContain('packet_signature_invalid');
  });
});
