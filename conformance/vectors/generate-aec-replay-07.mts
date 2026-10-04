// SPDX-License-Identifier: Apache-2.0
//
// Writes the frozen AEC -07 replay fixture: a replay record made by the
// RELEASED -07 evaluator (EP-AEC-EVALUATOR-07-v1, as shipped in the published
// npm package @emilia-protocol/verify 6.0.0), together with the inputs that
// produced it. The -08 replay migration tests replay this record; they do not
// edit an -08 record into a "-07" one.
//
//   aec-replay-07.v1.json         inputs, producer provenance, record summary
//   aec-replay-07.v1.record.json  the record, exactly as 6.0.0 serialized it
//                                 (RFC 8785 bytes, no trailing newline); its
//                                 SHA-256 is the replay digest 6.0.0 reported
//   aec-replay-07.v1.SHA256SUMS   SHA-256 of both files
//
// The inputs are taken unchanged from the frozen vector
// accept_pinned_human_receipt in aec-role.v1.json (a real Class-A WebAuthn
// Trust Receipt with its pinned RP profile and verification time), checked by
// the built-in ep-receipt verifier, with the requirement
// packages/verify/aec-current-profile.test.ts uses for that vector. The
// requirement evaluates SATISFIED.
//
// Regeneration needs the published package and nothing from this repository's
// evaluator. The tarball's npm integrity is checked before it is unpacked:
//
//   npm pack @emilia-protocol/verify@6.0.0 --pack-destination <dir>
//   node conformance/vectors/generate-aec-replay-07.mjs --tarball <dir>/emilia-protocol-verify-6.0.0.tgz
//
// `--check` without `--tarball` needs no package: it proves the fixture's
// inputs still equal the source vector, the record file is canonical and is
// what the fixture describes, and the checksum file matches. `--check` with
// `--tarball` also re-runs 6.0.0 and requires byte-identical output.
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalizeStrictJson } from '../../packages/verify/strict-json.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = 'aec-replay-07.v1.json';
const RECORD = 'aec-replay-07.v1.record.json';
const SUMS = 'aec-replay-07.v1.SHA256SUMS';
const SOURCE = 'aec-role.v1.json';
const SOURCE_VECTOR = 'accept_pinned_human_receipt';

// The published release that implements EP-AEC-EVALUATOR-07-v1, as the npm
// registry reports it (npm view @emilia-protocol/verify@6.0.0 dist).
const PRODUCER = {
  package: '@emilia-protocol/verify',
  version: '6.0.0',
  npm_integrity: 'sha512-47L+T0rzZ6vyQHnd+rvdQJvBsRWab0XdK6wOsueCgmy6gIxNWuRpIDy1JhzUTfhGWootI+01rFwLT0SxnJvQ5A==',
  npm_shasum: '05fd162c85f0d8248f353e53c78b92b80efcdbcd',
  published: '2026-09-28T13:24:43.580Z',
  algorithm_revision: 'EP-AEC-EVALUATOR-07-v1',
};

const sha256hex = (bytes: string | Buffer) => crypto.createHash('sha256').update(bytes).digest('hex');
const ascii = (value: unknown) => `${JSON.stringify(value, null, 2).replace(/[\u007f-￿]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)}\n`;

function inputsFromSource() {
  const suite = JSON.parse(readFileSync(resolve(here, SOURCE), 'utf8'));
  const vector = suite.vectors.find((v: any) => v.id === SOURCE_VECTOR);
  if (!vector || vector.expect?.valid !== true) throw new Error(`${SOURCE}#${SOURCE_VECTOR} is missing or no longer an accepting vector`);
  return {
    requirement: {
      '@version': 'EP-AEC-REQUIREMENT-v1', requirement_id: 'payment-evidence@1', expression: 'ep-receipt',
      freshness_sec: {}, role_constraints: [], required_bindings: [],
    },
    native_verifiers: {
      'ep-receipt': {
        profile: { id: 'native-receipt', revision: '1', native_format_revision: 'Trust-Receipt' },
        trustSnapshot: { policy: vector.policies_by_type['ep-receipt'] },
      },
    },
    chain: vector.aec_chain,
    expected_action: vector.aec_chain.action,
    verification_time: vector.verification_time,
  };
}

function fixtureText(inputs: ReturnType<typeof inputsFromSource>, recordBytes: string) {
  const record = JSON.parse(recordBytes);
  return ascii({
    '@version': 'EP-AEC-REPLAY-FIXTURE-v1',
    fixture: 'aec-replay-07.v1',
    frozen: true,
    description: 'A replay record made by the released AEC -07 evaluator over real evidence, kept as stored. The -08 evaluator must report it UNSUPPORTED_REVISION without modifying it, and re-evaluation under -08 must produce a new, separately identified record.',
    producer: PRODUCER,
    source: {
      vectors: `conformance/vectors/${SOURCE}`,
      vector_id: SOURCE_VECTOR,
      requirement_from: 'packages/verify/aec-current-profile.test.ts (AEC07 built-in ep-receipt)',
    },
    regeneration: 'node conformance/vectors/generate-aec-replay-07.mjs --tarball <npm pack of @emilia-protocol/verify@6.0.0>',
    inputs,
    record: {
      file: RECORD,
      encoding: 'RFC 8785 canonical JSON exactly as serialized by the producer; no trailing newline',
      replay_digest: `sha256:${sha256hex(recordBytes)}`,
      algorithm_revision: record.algorithm_revision,
      evaluator_profile_digest: record.evaluator_profile_digest,
      satisfied: record.satisfied,
    },
    producer_self_replay: { matches: true },
  });
}

function sumsText(fixture: string, recordBytes: string) {
  return `${sha256hex(fixture)}  ${FIXTURE}\n${sha256hex(recordBytes)}  ${RECORD}\n`;
}

async function produce(tarball: string) {
  const bytes = readFileSync(tarball);
  const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
  if (integrity !== PRODUCER.npm_integrity) throw new Error(`${tarball} is not the published ${PRODUCER.package}@${PRODUCER.version} (integrity ${integrity})`);
  const work = mkdtempSync(join(tmpdir(), 'aec-replay-07-'));
  try {
    execFileSync('tar', ['-xzf', tarball, '-C', work]);
    const root = join(work, 'package');
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    if (manifest.name !== PRODUCER.package || manifest.version !== PRODUCER.version) throw new Error('unexpected package manifest');
    const aec = await import(pathToFileURL(join(root, 'evidence-chain.js')).href);
    const strict = await import(pathToFileURL(join(root, 'strict-json.js')).href);
    if (aec.AEC_EVALUATOR_REVISION !== PRODUCER.algorithm_revision) throw new Error(`package evaluator is ${aec.AEC_EVALUATOR_REVISION}`);
    const inputs = inputsFromSource();
    const evaluator = aec.createAuthorizationChainEvaluator({ requirement: inputs.requirement, nativeVerifiers: inputs.native_verifiers });
    const acceptance = () => ({ expectedAction: inputs.expected_action, verificationTime: inputs.verification_time });
    const result = await evaluator.evaluate(inputs.chain, acceptance());
    if (result.satisfied !== true) throw new Error(`the -07 evaluator did not satisfy the requirement: ${JSON.stringify(result.reasons)}`);
    const recordBytes: string = strict.canonicalizeStrictJson(result.replay);
    if (`sha256:${sha256hex(recordBytes)}` !== result.replay_digest) throw new Error('record bytes do not hash to the reported replay digest');
    if (result.replay.algorithm_revision !== PRODUCER.algorithm_revision) throw new Error('record does not carry the -07 revision');
    // The producer accepts its own record: re-verifying the evidence under the
    // same pins reproduces the complete record digest.
    const self = await evaluator.replay(inputs.chain, JSON.parse(recordBytes), acceptance());
    if (self.matches !== true) throw new Error('the -07 evaluator does not match its own record');
    return { inputs, recordBytes };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

const args = process.argv.slice(2);
const tarballAt = args.indexOf('--tarball');
const tarball = tarballAt >= 0 ? args[tarballAt + 1] : null;
if (tarballAt >= 0 && !tarball) throw new Error('--tarball needs a path');

if (args.includes('--check')) {
  const recordBytes = readFileSync(resolve(here, RECORD), 'utf8');
  if (!/^[\x20-\x7e]*$/.test(recordBytes)) throw new Error(`${RECORD} is not printable ASCII without a newline`);
  if (canonicalizeStrictJson(JSON.parse(recordBytes)) !== recordBytes) throw new Error(`${RECORD} is not canonical`);
  const fixture = fixtureText(inputsFromSource(), recordBytes);
  if (readFileSync(resolve(here, FIXTURE), 'utf8') !== fixture) throw new Error(`${FIXTURE} differs from its source vector or its record`);
  if (readFileSync(resolve(here, SUMS), 'utf8') !== sumsText(fixture, recordBytes)) throw new Error(`${SUMS} does not match`);
  if (tarball) {
    const fresh = await produce(tarball);
    if (fresh.recordBytes !== recordBytes) throw new Error(`${PRODUCER.package}@${PRODUCER.version} no longer reproduces ${RECORD}`);
  }
  console.log(`${FIXTURE}: frozen -07 replay fixture and ${SUMS} match (record sha256:${sha256hex(recordBytes)}${tarball ? `, reproduced by ${PRODUCER.package}@${PRODUCER.version}` : ''})`);
} else {
  if (!tarball) throw new Error(`regeneration needs --tarball <npm pack of ${PRODUCER.package}@${PRODUCER.version}>`);
  const { inputs, recordBytes } = await produce(tarball);
  const fixture = fixtureText(inputs, recordBytes);
  writeFileSync(resolve(here, RECORD), recordBytes);
  writeFileSync(resolve(here, FIXTURE), fixture);
  writeFileSync(resolve(here, SUMS), sumsText(fixture, recordBytes));
  console.log(`wrote ${FIXTURE} and ${RECORD} (record sha256:${sha256hex(recordBytes)})`);
}
