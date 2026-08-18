// SPDX-License-Identifier: Apache-2.0
//
// EP-LOSS-EXPERIENCE-FEED-v2 hybrid adoption test: signRiskBodyV2 /
// verifyRiskBodyV2 (EP-RISK-HYBRID-v2) wired in additively via
// signLossExperienceFeedV2 / verifyLossExperienceFeedV2. Hostile matrix per
// docs/protocol/pq-hybrid-program.md: stripped leg, narrowed set,
// wrong-length signature, Ed448 masquerade, v1-refuses-v2, valid v2
// roundtrip.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
  LOSS_EXPERIENCE_FEED_V2_VERSION,
  signLossExperienceFeed,
  signLossExperienceFeedV2,
  verifyLossExperienceFeed,
  verifyLossExperienceFeedV2,
} from './loss-experience-feed.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (character: string) => `sha256:${character.repeat(64)}`;
const PROGRAM = { program_id: 'rp.payer.pas.1', version: 3, source_digest: D('1'), program_digest: D('2') };

function material() {
  const pair = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(9));
  return {
    signer: {
      issuer_id: 'carrier:example',
      key_id: 'carrier-key-v2',
      private_key: pair.privateKey,
      pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
    },
    trusted_keys: {
      'carrier-key-v2': {
        issuer_id: 'carrier:example',
        public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
      },
    },
  };
}

function input() {
  return {
    feed_id: 'loss-feed:2026-07-v2',
    reporting_party_id: 'carrier:example',
    relying_party_id: 'payer:example',
    program: PROGRAM,
    period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
    census_digest: D('3'),
    taxonomy_digest: D('a'),
    source_inventory_digest: D('4'),
    records: [],
    issued_at: '2026-08-01T01:00:00Z',
    expires_at: '2026-09-01T01:00:00Z',
    timestamp_anchor: null,
    claim_boundary: LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
  };
}

function verifyOptions(m: ReturnType<typeof material>) {
  return {
    trusted_keys: m.trusted_keys,
    now: '2026-08-02T00:00:00Z',
    expected_program: PROGRAM,
    expected_census_digest: D('3'),
    expected_taxonomy_digest: D('a'),
    expected_relying_party_id: 'payer:example',
    expected_action_classes: ['health.prior-authorization'],
  };
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

test('a real hybrid feed verifies under both pinned keys', async () => {
  const m = material();
  const feed: any = await signLossExperienceFeedV2(input(), m.signer);
  assert.equal(feed['@version'], LOSS_EXPERIENCE_FEED_V2_VERSION);
  const verified: any = await verifyLossExperienceFeedV2(feed, verifyOptions(m) as any);
  assert.equal(verified.accepted, true, verified.reason ?? '');
  assert.equal(verified.verified, true);
});

test('the v1 verifier refuses a v2 feed cleanly on the version marker', async () => {
  const m = material();
  const feed: any = await signLossExperienceFeedV2(input(), m.signer);
  const verified: any = verifyLossExperienceFeed(feed, verifyOptions(m) as any);
  assert.equal(verified.accepted, false);
});

test('the v1 verifier still accepts a v1 feed, unchanged', () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const feed = signLossExperienceFeed(input(), v1Signer);
  const verified: any = verifyLossExperienceFeed(feed, {
    ...verifyOptions(m),
    trusted_keys: { [v1Signer.key_id]: { issuer_id: v1Signer.issuer_id, public_key: m.trusted_keys[m.signer.key_id].public_key } },
  } as any);
  assert.equal(verified.accepted, true, verified.reason ?? '');
});

test('the v2 verifier refuses a v1 feed on the version marker', async () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const feed = signLossExperienceFeed(input(), v1Signer);
  const verified: any = await verifyLossExperienceFeedV2(feed, verifyOptions(m) as any);
  assert.equal(verified.accepted, false);
});

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const m = material();
  const feed: any = await signLossExperienceFeedV2(input(), m.signer);
  const stripped = { ...feed, proof: { ...feed.proof, signatures: feed.proof.signatures.filter((s: any) => s.alg === 'Ed25519') } };
  const verified: any = await verifyLossExperienceFeedV2(stripped, verifyOptions(m) as any);
  assert.equal(verified.accepted, false);
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const m = material();
  const feed: any = await signLossExperienceFeedV2(input(), m.signer);
  const stripped = { ...feed, proof: { ...feed.proof, signatures: feed.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65') } };
  const verified: any = await verifyLossExperienceFeedV2(stripped, verifyOptions(m) as any);
  assert.equal(verified.accepted, false);
});

test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails', async () => {
  const m = material();
  const feed: any = await signLossExperienceFeedV2(input(), m.signer);
  const narrowed = {
    ...feed,
    proof: {
      ...feed.proof,
      required_algorithms: ['Ed25519'],
      signatures: feed.proof.signatures.filter((s: any) => s.alg === 'Ed25519'),
    },
  };
  const verified: any = await verifyLossExperienceFeedV2(narrowed, verifyOptions(m) as any);
  assert.equal(verified.accepted, false);
});

test('WRONG-LENGTH SIGNATURE: a truncated ML-DSA signature refuses', async () => {
  const m = material();
  const feed: any = await signLossExperienceFeedV2(input(), m.signer);
  const tampered = {
    ...feed,
    proof: {
      ...feed.proof,
      signatures: feed.proof.signatures.map((s: any) => (
        s.alg === 'ML-DSA-65' ? { ...s, sig: s.sig.slice(0, -8) } : s
      )),
    },
  };
  const verified: any = await verifyLossExperienceFeedV2(tampered, verifyOptions(m) as any);
  assert.equal(verified.accepted, false);
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
  const m = material();
  const feed = await signLossExperienceFeedV2(input(), m.signer);
  const ed448 = generateKeyPairSync('ed448');
  const verified: any = await verifyLossExperienceFeedV2(feed, {
    ...verifyOptions(m),
    trusted_keys: {
      [m.signer.key_id]: {
        issuer_id: m.signer.issuer_id,
        public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: m.trusted_keys[m.signer.key_id].pq_public_key,
      },
    },
  } as any);
  assert.equal(verified.accepted, false);
});

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const m = material();
  const feed = await signLossExperienceFeedV2(input(), m.signer);
  const verified: any = await verifyLossExperienceFeedV2(feed, { ...verifyOptions(m), mldsaBackendLoader: async () => null } as any);
  assert.equal(verified.accepted, false);
});
