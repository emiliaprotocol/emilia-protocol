// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AGENT_RECORD_CLAIM_BOUNDARY,
  AGENT_RECORD_RETENTION_MS,
  AgentRecordCoreError,
  signAgentRecordObservation,
  verifyAgentRecordObservation,
} from './core';

const RECORD_ID = `agent_record_${'a'.repeat(40)}`;
const BOND_ID = '11111111-1111-4111-8111-111111111111';
const BOND_DIGEST = `sha256:${'b'.repeat(64)}`;
const SOURCE_DIGEST = `sha256:${'c'.repeat(64)}`;
const ACTION_DIGEST = `sha256:${'d'.repeat(64)}`;
const REFUSED_AT = '2026-08-02T20:00:00.000Z';
const OBSERVED_AT = '2026-08-02T20:01:00.000Z';
const RETENTION_EXPIRES_AT = new Date(
  Date.parse(OBSERVED_AT) + AGENT_RECORD_RETENTION_MS,
).toISOString();
const ED25519_PKCS8_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function rawPublicKey(seed: Buffer): string {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .subarray(12)
    .toString('base64');
}

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

describe('Agent Record observation core', () => {
  beforeEach(() => {
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', crypto.randomBytes(32).toString('base64'));
    vi.stubEnv('EP_COMMIT_SIGNING_KEYS', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('operator-signs the exact factual bindings and verifies with configured trust', () => {
    const observation = signAgentRecordObservation(input());

    expect(observation).toMatchObject({
      '@version': 'EP-AGENT-RECORD-OBSERVATION-v1',
      record: {
        record_id: RECORD_ID,
        bond: { bond_id: BOND_ID, bond_digest: BOND_DIGEST },
        source: {
          profile: 'EP-ACTION-REFUSAL-STATEMENT-v1',
          artifact_digest: SOURCE_DIGEST,
        },
        action: { action_digest: ACTION_DIGEST },
        refusal: { refusal_digest: SOURCE_DIGEST, refused_at: REFUSED_AT },
        observed_at: OBSERVED_AT,
        retention_expires_at: RETENTION_EXPIRES_AT,
        claim_boundary: AGENT_RECORD_CLAIM_BOUNDARY,
      },
      signature: {
        algorithm: 'Ed25519',
        key_id: 'ep-signing-key-1',
        key_source: 'operator-commit-signing-key',
      },
    });
    expect(verifyAgentRecordObservation(observation, Date.parse(OBSERVED_AT))).toMatchObject({
      verified: true,
      within_retention: true,
      status_checked: false,
      reason: null,
      record_id: RECORD_ID,
    });
  });

  it('verifies a retained observation after the current operator key and id rotate', () => {
    const seedA = crypto.randomBytes(32);
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', seedA.toString('base64'));
    vi.stubEnv('EP_AGENT_RECORD_SIGNING_KEY_ID', 'agent-record-key-a');
    const observationA = signAgentRecordObservation(input());
    expect(observationA.signature.key_id).toBe('agent-record-key-a');

    vi.stubEnv('EP_COMMIT_SIGNING_KEY', crypto.randomBytes(32).toString('base64'));
    vi.stubEnv('EP_AGENT_RECORD_SIGNING_KEY_ID', 'agent-record-key-b');
    vi.stubEnv('EP_COMMIT_SIGNING_KEYS', JSON.stringify({
      'agent-record-key-a': rawPublicKey(seedA),
    }));
    const observationB = signAgentRecordObservation(input());
    expect(observationB.signature.key_id).toBe('agent-record-key-b');
    expect(verifyAgentRecordObservation(
      observationB,
      Date.parse(OBSERVED_AT),
    )).toMatchObject({ verified: true, within_retention: true, status_checked: false });

    expect(verifyAgentRecordObservation(
      observationA,
      Date.parse(OBSERVED_AT),
    )).toMatchObject({
      verified: true,
      within_retention: true,
      status_checked: false,
      reason: null,
      record_id: RECORD_ID,
    });
  });

  it('contains only the bounded public allowlist and no identity, credential, or action payload', () => {
    const observation = signAgentRecordObservation(input());

    expect(Object.keys(observation).sort()).toEqual(['@version', 'record', 'signature']);
    expect(Object.keys(observation.record).sort()).toEqual([
      'action',
      'bond',
      'claim_boundary',
      'observed_at',
      'record_id',
      'refusal',
      'retention_expires_at',
      'source',
    ]);
    expect(Object.keys(observation.record.source).sort()).toEqual([
      'artifact_digest',
      'profile',
    ]);
    expect(JSON.stringify(observation)).not.toMatch(
      /adoption_id|session_id|owner_token|credential_id|candidate_url|source_url|arena_share_id|arena_share_|\/arena\/|\/api\/arena\/refusals|webauthn|prompt|ip_address|raw_action|action_parameters|agent_label|score|rank|marketplace/i,
    );
  });

  it('rejects a dereferenceable Arena source added to the signed public shape', () => {
    const observation: any = structuredClone(signAgentRecordObservation(input()));
    observation.record.source.arena_share_id = `arena_share_${'e'.repeat(40)}`;

    expect(verifyAgentRecordObservation(observation, Date.parse(OBSERVED_AT))).toMatchObject({
      verified: false,
      reason: 'agent_record_observation_invalid',
    });
  });

  it.each([
    ['record id', (value: any) => { value.record.record_id = `agent_record_${'f'.repeat(40)}`; }],
    ['bond', (value: any) => { value.record.bond.bond_digest = `sha256:${'1'.repeat(64)}`; }],
    ['source', (value: any) => { value.record.source.artifact_digest = `sha256:${'2'.repeat(64)}`; }],
    ['action', (value: any) => { value.record.action.action_digest = `sha256:${'3'.repeat(64)}`; }],
    ['refusal', (value: any) => { value.record.refusal.refusal_digest = `sha256:${'4'.repeat(64)}`; }],
    ['retention', (value: any) => { value.record.retention_expires_at = '2027-08-01T20:01:00.000Z'; }],
    ['operator key id', (value: any) => { value.signature.key_id = 'unsafe/key'; }],
  ])('refuses %s substitution or mutation', (_name, mutate) => {
    const observation: any = structuredClone(signAgentRecordObservation(input()));
    mutate(observation);

    expect(verifyAgentRecordObservation(observation, Date.parse(OBSERVED_AT))).toMatchObject({
      verified: false,
      within_retention: false,
      status_checked: false,
    });
  });

  it('rejects an embedded public-key substitution instead of trusting artifact key material', () => {
    const attacker = crypto.generateKeyPairSync('ed25519');
    const observation: any = structuredClone(signAgentRecordObservation(input()));
    observation.signature.public_key = attacker.publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64url');

    expect(verifyAgentRecordObservation(observation, Date.parse(OBSERVED_AT))).toMatchObject({
      verified: false,
      reason: 'agent_record_observation_invalid',
    });
  });

  it('ends public retention at the first instant 365 days after observation', () => {
    const observation = signAgentRecordObservation(input());

    expect(verifyAgentRecordObservation(
      observation,
      Date.parse(RETENTION_EXPIRES_AT) - 1,
    )).toMatchObject({ verified: true, within_retention: true, status_checked: false });
    expect(verifyAgentRecordObservation(
      observation,
      Date.parse(RETENTION_EXPIRES_AT),
    )).toMatchObject({
      verified: true,
      within_retention: false,
      status_checked: false,
      reason: 'agent_record_expired',
    });
  });

  it('fails closed in production when the stable operator key is absent', () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('EP_COMMIT_SIGNING_KEY', '');

    expect(() => signAgentRecordObservation(input())).toThrowError(
      expect.objectContaining<Partial<AgentRecordCoreError>>({
        code: 'agent_record_operator_key_unavailable',
      }),
    );
  });

  it.each([
    'unsafe/key',
    `k${'a'.repeat(64)}`,
    'constructor',
  ])('refuses unsafe current operator key id %s', (keyId) => {
    vi.stubEnv('EP_AGENT_RECORD_SIGNING_KEY_ID', keyId);

    expect(() => signAgentRecordObservation(input())).toThrowError(
      expect.objectContaining<Partial<AgentRecordCoreError>>({
        code: 'agent_record_operator_key_id_invalid',
      }),
    );
  });
});
