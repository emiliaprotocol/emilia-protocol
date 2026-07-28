// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  compileRelianceProgram,
  signRelianceProgram,
  verifyRelianceProgram,
} from '@emilia-protocol/gate/reliance-program';

type JsonRecord = Record<string, any>;
type Mutation = {
  op: 'add' | 'remove' | 'replace';
  path: string;
  value?: unknown;
};

const suite = JSON.parse(readFileSync(
  new URL('../conformance/vectors/reliance-programs.v1.json', import.meta.url),
  'utf8',
)) as JsonRecord;

const fixtureDefinitions = new Map<string, JsonRecord>(
  suite.fixtures.map((fixture: JsonRecord) => [fixture.id, fixture]),
);

function readFixture(fixtureId: string): JsonRecord {
  const definition = fixtureDefinitions.get(fixtureId);
  if (!definition) throw new Error(`unknown fixture ${fixtureId}`);
  return JSON.parse(readFileSync(
    new URL(`../${definition.path}`, import.meta.url),
    'utf8',
  ));
}

function privateKeyFromSeed(hexByte: string): crypto.KeyObject {
  return crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(hexByte.repeat(32), 'hex'),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
}

const privateKeys = new Map<string, crypto.KeyObject>();
const trustedKeys: Record<string, {
  relying_party_id: string;
  public_key: string;
}> = {};

for (const fixture of suite.fixtures as JsonRecord[]) {
  const source = readFixture(fixture.id);
  const privateKey = privateKeyFromSeed(fixture.owner_key_seed_hex_byte);
  privateKeys.set(source.relying_party.key_id, privateKey);
  trustedKeys[source.relying_party.key_id] = {
    relying_party_id: source.relying_party.id,
    public_key: crypto.createPublicKey(privateKey)
      .export({ type: 'spki', format: 'der' })
      .toString('base64url'),
  };
}

function sign(source: JsonRecord): JsonRecord {
  const privateKey = privateKeys.get(source.relying_party?.key_id);
  if (!privateKey) {
    throw new Error(`no test key for ${String(source.relying_party?.key_id)}`);
  }
  return signRelianceProgram(source, privateKey) as JsonRecord;
}

function compile(envelope: JsonRecord, profiles = suite.profiles): JsonRecord {
  return compileRelianceProgram(envelope, {
    trustedKeys,
    profiles,
  }) as JsonRecord;
}

function decodePointerSegment(segment: string): string {
  return segment.replace(/~1/g, '/').replace(/~0/g, '~');
}

function applyMutation(target: unknown, mutation: Mutation): void {
  if (!mutation.path.startsWith('/')) {
    throw new Error(`mutation path must be a JSON Pointer: ${mutation.path}`);
  }
  const segments = mutation.path.slice(1).split('/').map(decodePointerSegment);
  let parent = target as any;
  for (const segment of segments.slice(0, -1)) {
    if (parent === null || typeof parent !== 'object' || !(segment in parent)) {
      throw new Error(`mutation path does not exist: ${mutation.path}`);
    }
    parent = parent[segment];
  }
  const finalSegment = segments.at(-1)!;
  if (mutation.op === 'add' && Array.isArray(parent) && finalSegment === '-') {
    parent.push(structuredClone(mutation.value));
    return;
  }
  if (mutation.op === 'remove') {
    if (Array.isArray(parent)) {
      parent.splice(Number(finalSegment), 1);
    } else {
      delete parent[finalSegment];
    }
    return;
  }
  parent[finalSegment] = structuredClone(mutation.value);
}

function mutate<T>(value: T, mutations: Mutation[]): T {
  const changed = structuredClone(value);
  for (const mutation of mutations) applyMutation(changed, mutation);
  return changed;
}

function expectCompiledMapping(
  source: JsonRecord,
  envelope: JsonRecord,
  compiled: JsonRecord,
): void {
  expect(envelope['@version']).toBe('EP-RELIANCE-PROGRAM-v1');
  expect(envelope.source).toEqual(source);
  expect(envelope.source_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(envelope.signature).toEqual({
    algorithm: 'Ed25519',
    key_id: source.relying_party.key_id,
    value: expect.stringMatching(/^[A-Za-z0-9_-]{86}$/),
  });
  expect(Object.keys(envelope).sort()).toEqual([
    '@version',
    'signature',
    'source',
    'source_digest',
  ]);

  expect(compiled.version).toBe('EP-RELIANCE-PROGRAM-v1');
  expect(compiled.source_digest).toBe(envelope.source_digest);
  expect(compiled.relying_party_id).toBe(source.relying_party.id);
  expect(compiled.program_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(compiled.claim_boundary).toContain('does not prove');

  const program = compiled.program;
  expect(program['@version']).toBe('EP-GATE-TRUST-PROGRAM-PROFILE-v1');
  expect(program.program_id).toBe(source.program_id);
  expect(program.version).toBe(source.version);
  expect(program.root_caid).toBe(source.root_caid);
  expect(program.action_digest).toBe(source.action_digest);
  expect(program.valid_from).toBe(source.valid_from);
  expect(program.expires_at).toBe(source.expires_at);
  expect(program.execution).toEqual(source.execution);
  expect(program.stages).toHaveLength(source.stages.length);

  let traceIndex = 0;
  for (const [stageIndex, sourceStage] of source.stages.entries()) {
    const compiledStage = program.stages[stageIndex];
    expect(compiledStage.stage_id).toBe(sourceStage.stage_id);
    expect(compiledStage.depends_on).toEqual(sourceStage.depends_on);
    expect(compiledStage.rule).toEqual(sourceStage.rule);
    expect(compiledStage.requirements).toHaveLength(sourceStage.profiles.length);

    for (const [profileIndex, pin] of sourceStage.profiles.entries()) {
      const requirement = compiledStage.requirements[profileIndex];
      expect(requirement).toEqual({
        requirement_id: `admissibility-${String(profileIndex + 1).padStart(2, '0')}`,
        evidence_type: 'ep-admissibility-evaluation',
        verifier_profile: 'ep-admissibility-profile:v1',
        policy_digest: pin.profile_hash,
        max_age_sec: pin.evaluation_max_age_sec,
        revocation_required: pin.revocation_required,
      });
      expect(compiled.trace[traceIndex]).toEqual({
        stage_id: sourceStage.stage_id,
        requirement_id: requirement.requirement_id,
        profile_id: pin.profile_id,
        profile_hash: pin.profile_hash,
      });
      traceIndex += 1;
    }
  }
  expect(compiled.trace).toHaveLength(traceIndex);
}

describe('Reliance Program fixture catalog', () => {
  it('is complete, closed over its declared coverage, and explicitly claim-limited', () => {
    expect(suite.suite).toBe('EP-RELIANCE-PROGRAM-CONFORMANCE-v1');
    expect(suite.source_version).toBe('EP-RELIANCE-PROGRAM-SOURCE-v1');
    expect(suite.envelope_version).toBe('EP-RELIANCE-PROGRAM-v1');
    expect(suite.compiled_version).toBe('EP-GATE-TRUST-PROGRAM-PROFILE-v1');
    expect(suite.fixture_count).toBe(suite.fixtures.length);
    expect(suite.profile_count).toBe(suite.profiles.length);
    expect(suite.vector_count).toBe(suite.vectors.length);

    const covered = new Set<string>(
      suite.vectors.flatMap((vector: JsonRecord) => vector.covers),
    );
    expect([...covered].sort()).toEqual([...suite.required_coverage].sort());
    expect(suite.claim_limitations.join(' ')).toContain('not payer-live');
    expect(suite.claim_limitations.join(' ')).toContain('synthetic');
    expect(suite.claim_limitations.join(' ')).toContain('PHI-free');
  });

  it('keeps all public source fixtures synthetic, customer-owned, and PHI-free', () => {
    const prohibited = [
      '"patient"',
      '"member"',
      '"claim"',
      '"diagnosis"',
      '"procedure"',
      '"date_of_birth"',
      '"npi"',
      '"name"',
      '"address"',
      '"fhir_resource"',
    ];
    for (const fixture of suite.fixtures as JsonRecord[]) {
      const source = readFixture(fixture.id);
      expect(source['@version']).toBe('EP-RELIANCE-PROGRAM-SOURCE-v1');
      expect(source.relying_party.id).toMatch(/^org:synthetic-/);
      expect(source.relying_party.key_id).toMatch(/^key:synthetic-/);
      const serialized = JSON.stringify(source).toLowerCase();
      for (const token of prohibited) expect(serialized).not.toContain(token);
    }
  });

  it('pins every referenced profile body by both customer identifier and hash', () => {
    const catalog = new Map<string, JsonRecord>(
      suite.profiles.map((profile: JsonRecord) => [profile.id, profile]),
    );
    for (const fixture of suite.fixtures as JsonRecord[]) {
      const source = readFixture(fixture.id);
      for (const stage of source.stages) {
        for (const pin of stage.profiles) {
          const profile = catalog.get(pin.profile_id);
          expect(profile, `${fixture.id}:${pin.profile_id}`).toBeDefined();
          expect(profile!.profile_hash).toBe(pin.profile_hash);
          expect(profile!.authored_by).toBe(source.relying_party.id);
        }
      }
    }
  });
});

describe('Reliance Program source signing and compilation', () => {
  for (const fixture of suite.fixtures as JsonRecord[]) {
    it(`signs, verifies, and compiles ${fixture.id}`, () => {
      const source = readFixture(fixture.id);
      const envelope = sign(source);
      const verified = verifyRelianceProgram(envelope, { trustedKeys }) as JsonRecord;
      expect(verified).toMatchObject({
        valid: true,
        reason: null,
        source_digest: envelope.source_digest,
        relying_party_id: source.relying_party.id,
        key_id: source.relying_party.key_id,
      });
      expectCompiledMapping(source, envelope, compile(envelope));
    });
  }
});

describe('EP-RELIANCE-PROGRAM-CONFORMANCE-v1 hostile mutations', () => {
  for (const vector of suite.vectors as JsonRecord[]) {
    it(vector.id, () => {
      const source = readFixture(vector.fixture);
      if (vector.phase === 'positive') {
        const envelope = sign(source);
        expect((verifyRelianceProgram(envelope, { trustedKeys }) as JsonRecord).valid)
          .toBe(vector.expect.accepted);
        expect(() => compile(envelope)).not.toThrow();
        return;
      }
      if (vector.phase === 'sign_source') {
        expect(() => sign(mutate(source, vector.mutations))).toThrow();
        return;
      }
      if (vector.phase === 'verify_envelope') {
        const hostileEnvelope = mutate(sign(source), vector.mutations);
        const result = verifyRelianceProgram(hostileEnvelope, { trustedKeys }) as JsonRecord;
        expect(result.valid).toBe(vector.expect.accepted);
        return;
      }
      if (vector.phase === 'verify_trust_config') {
        const hostileTrust = mutate(trustedKeys, vector.mutations);
        const result = verifyRelianceProgram(sign(source), {
          trustedKeys: hostileTrust,
        }) as JsonRecord;
        expect(result.valid).toBe(vector.expect.accepted);
        return;
      }
      if (vector.phase === 'compile_source') {
        const hostileEnvelope = sign(mutate(source, vector.mutations));
        expect(() => compile(hostileEnvelope)).toThrow();
        return;
      }
      if (vector.phase === 'compile_profile_catalog') {
        const hostileProfiles = mutate(suite.profiles, vector.mutations);
        expect(() => compile(sign(source), hostileProfiles)).toThrow();
        return;
      }
      throw new Error(`unknown vector phase ${String(vector.phase)}`);
    });
  }
});
