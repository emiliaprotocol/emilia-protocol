// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildExecutionSessionV3,
  buildPostBuildChallengesV3,
  loadPinnedKitV3,
  sha256V3,
  validateResultRowsV3,
  verifyCleanRoomSubmissionV3,
} from '../scripts/verify-clean-room-submission-v3.mts';
import { evaluateExternalImplementationV3 } from '../scripts/evaluate-external-implementation-v3.mts';

function writeJson(target: string, value: unknown): void {
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
}

function buildReferenceRunner(target: string, script: string): void {
  execFileSync(path.resolve('node_modules/.bin/esbuild'), [
    script,
    '--bundle',
    '--platform=node',
    '--format=esm',
    `--outfile=${target}`,
  ]);
  fs.chmodSync(target, 0o555);
}

function writeExpectationCopyRunner(target: string): void {
  fs.writeFileSync(target, `#!/usr/bin/env node
const fs = require('node:fs');
const suite = JSON.parse(fs.readFileSync(process.argv.at(-1), 'utf8'));
const rows = suite.vectors.map((vector) => ({
  handle: vector.handle,
  result: { ...vector.expect },
}));
process.stdout.write(JSON.stringify(rows));
`);
  fs.chmodSync(target, 0o555);
}

function writePublishedVectorTableRunner(target: string): void {
  const table: Record<string, any> = {};
  for (const contract of loadPinnedKitV3().contracts) {
    const session = buildExecutionSessionV3(contract);
    for (const vector of session.executionSuite.vectors) {
      const binding = session.bindings.get(vector.handle)!;
      const result = { ...binding.expected };
      if (typeof result.reason_contains === 'string') {
        result.reasons = [result.reason_contains];
        delete result.reason_contains;
      }
      table[`${session.executionSuite.suite.id}\n${JSON.stringify(vector.input)}`] = result;
    }
  }
  fs.writeFileSync(target, `#!/usr/bin/env node
const fs = require('node:fs');
const table = ${JSON.stringify(table)};
const suite = JSON.parse(fs.readFileSync(process.argv.at(-1), 'utf8'));
const rows = suite.vectors.map((vector) => ({
  handle: vector.handle,
  result: table[suite.suite.id + '\\n' + JSON.stringify(vector.input)] || { valid: false },
}));
process.stdout.write(JSON.stringify(rows));
`);
  fs.chmodSync(target, 0o555);
}

function writeInputMutationRunner(target: string): void {
  fs.writeFileSync(target, `#!/usr/bin/env node
const fs = require('node:fs');
const target = process.argv.at(-1);
fs.chmodSync(target, 0o644);
fs.appendFileSync(target, ' ');
process.stdout.write('[]');
`);
  fs.chmodSync(target, 0o555);
}

function writeEntrypointMutationRunner(target: string): void {
  fs.writeFileSync(target, `#!/usr/bin/env node
const fs = require('node:fs');
fs.chmodSync(process.argv[1], 0o755);
fs.appendFileSync(process.argv[1], '\\n// changed after launch\\n');
process.stdout.write('[]');
`);
  fs.chmodSync(target, 0o555);
}

function writeEnvironmentGuardRunner(target: string, delegate: string): void {
  fs.writeFileSync(target, `#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
if (Object.hasOwn(process.env, 'EP_CLEAN_ROOM_TEST_SECRET')) process.exit(91);
const result = spawnSync(${JSON.stringify(delegate)}, process.argv.slice(2), {
  env: process.env,
  stdio: ['ignore', 'inherit', 'inherit'],
});
process.exit(result.status ?? 1);
`);
  fs.chmodSync(target, 0o555);
}

function submissionFor(runnerPath: string, kit = loadPinnedKitV3()): any {
  return {
    '@version': 'EP-CLEAN-ROOM-SUBMISSION-v3',
    implementation: {
      implementation_id: 'outside-verifier',
      organization: 'Outside Implementers LLC',
      team_id: 'team:outside-implementers',
      language: 'Synthetic',
      version: '1.0.0',
      source_repository: 'https://example.test/outside-verifier.git',
      source_commit: 'a'.repeat(40),
      source_tree_oid: 'b'.repeat(40),
      source_tree_path: '.',
      license_spdx: 'Apache-2.0',
      build_instructions: 'Build the separately maintained verifier.',
      dependencies: [],
    },
    runner: {
      protocol: 'EP-CONFORMANCE-FILE-RUNNER-v3',
      artifact_sha256: sha256V3(fs.readFileSync(runnerPath)),
      fixed_arguments: [],
    },
    kit: {
      vector_bundle_sha256: kit.bundleSha256,
      conformance_manifest_sha256: kit.sourceManifestSha256,
      conformance_manifest_claim_sha256: kit.sourceManifestClaimSha256,
      authority_document_execution_companion_sha256:
        kit.authorityExecutionCompanionSha256,
    },
    construction: {
      reference_source_access: 'none',
      emilia_affiliation: 'none',
      specification_inputs: ['emilia-clean-room-kit-v3'],
      statement:
        'The implementation was constructed from the source-free v3 kit without EMILIA reference implementation access.',
    },
  };
}

function git(repository: string, ...args: string[]): string {
  return execFileSync('git', ['-C', repository, ...args], { encoding: 'utf8' }).trim();
}

function commitRunnerRepository(repository: string): { head: string; tree: string } {
  git(repository, 'init', '-q');
  git(repository, 'config', 'user.name', 'Outside Implementer');
  git(repository, 'config', 'user.email', 'outside@example.test');
  git(repository, 'add', 'runner');
  git(repository, 'commit', '-qm', 'build runner');
  return {
    head: git(repository, 'rev-parse', 'HEAD'),
    tree: git(repository, 'rev-parse', 'HEAD^{tree}'),
  };
}

function signedAttestation(submission: any): { attestation: any; trusted: any } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const keyId = `attestor:${sha256V3(publicKeyDer).slice(0, 24)}`;
  const attestor = {
    key_id: keyId,
    organization: 'Independent Audit Cooperative',
    team_id: 'team:independent-audit',
  };
  const unsigned = {
    '@version': 'EP-CLEAN-ROOM-INDEPENDENT-ATTESTATION-v2',
    claim: {
      submission_sha256: sha256V3(Buffer.from(
        JSON.stringify(sortJson(submission)),
        'utf8',
      )),
      implementation_id: submission.implementation.implementation_id,
      implementation_organization: submission.implementation.organization,
      implementation_team_id: submission.implementation.team_id,
      source_commit: submission.implementation.source_commit,
      runner_artifact_sha256: submission.runner.artifact_sha256,
      vector_bundle_sha256: submission.kit.vector_bundle_sha256,
      conformance_manifest_sha256: submission.kit.conformance_manifest_sha256,
      authority_document_execution_companion_sha256:
        submission.kit.authority_document_execution_companion_sha256,
      reference_source_access: 'none',
      emilia_affiliation: 'none',
      reviewed_at: '2026-09-02T00:00:00.000Z',
      statement:
        'We independently reviewed the named construction record and attest only to that bounded review.',
    },
    attestor,
  };
  const canonical = JSON.stringify(sortJson(unsigned));
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKey);
  return {
    attestation: {
      ...unsigned,
      signature: {
        algorithm: 'Ed25519',
        value_base64url: signature.toString('base64url'),
      },
    },
    trusted: {
      '@version': 'EP-CLEAN-ROOM-TRUSTED-ATTESTORS-v2',
      keys: [{
        ...attestor,
        independent: true,
        public_key_spki_base64url: publicKeyDer.toString('base64url'),
      }],
    },
  };
}

function sortJson(value: any): any {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key])]));
}

function containsObjectKey(value: unknown, forbidden: string): boolean {
  if (Array.isArray(value)) return value.some((entry) => containsObjectKey(entry, forbidden));
  if (!value || typeof value !== 'object') return false;
  if (Object.hasOwn(value, forbidden)) return true;
  return Object.values(value).some((entry) => containsObjectKey(entry, forbidden));
}

describe('clean-room evaluator v3 oracle separation', () => {
  it('gives the runner execution-only inputs under fresh opaque handles', () => {
    const contract = loadPinnedKitV3().contracts.find((entry) =>
      entry.path.endsWith('/receipts.v1.json'));
    expect(contract).toBeDefined();

    const first = buildExecutionSessionV3(contract!);
    const second = buildExecutionSessionV3(contract!);
    const firstText = first.executionBytes.toString('utf8');
    const firstVector = first.executionSuite.vectors[0];

    expect(first.executionSuite['@version'])
      .toBe('EP-CLEAN-ROOM-EXECUTION-SUITE-v3');
    expect(first.executionSuite).not.toHaveProperty('source');
    expect(first.executionSuite.suite).not.toHaveProperty('profile');
    expect(Object.keys(firstVector).sort())
      .toEqual(['handle', 'input']);
    expect(firstVector.handle).toMatch(/^cr3_[A-Za-z0-9_-]{32}$/);
    expect(firstVector.input).not.toHaveProperty('id');
    expect(firstVector.input).not.toHaveProperty('description');
    expect(firstVector.input).not.toHaveProperty('reason');
    expect(firstVector.input).not.toHaveProperty('failure_class');
    expect(firstText).not.toContain('"expect"');
    expect(firstText).not.toContain('accept_minimal');
    expect(first.bindings.size).toBe(contract!.vectors);
    expect([...first.bindings.keys()]).not.toEqual([...second.bindings.keys()]);
  });

  it('removes every pinned vector identity and oracle field from all runner sessions', () => {
    for (const contract of loadPinnedKitV3().contracts) {
      const session = buildExecutionSessionV3(contract);
      const serialized = session.executionBytes.toString('utf8');

      for (const forbidden of [
        'expect',
        'expect_status',
        'description',
        'failure_class',
        'mutation',
      ]) {
        expect(containsObjectKey(session.executionSuite, forbidden), contract.path).toBe(false);
      }
      expect(session.executionSuite, contract.path).not.toHaveProperty('source');
      expect(session.executionSuite.suite, contract.path).not.toHaveProperty('profile');
      for (const vector of session.executionSuite.vectors) {
        expect(Object.keys(vector).sort(), contract.path).toEqual(['handle', 'input']);
      }
      for (const sourceId of contract.expectations.keys()) {
        expect(serialized, `${contract.path}: leaked ${sourceId}`)
          .not.toContain(JSON.stringify(sourceId));
      }
    }
  });

  it('keeps the currency assertion evaluator-side and requires computed status', () => {
    const contract = loadPinnedKitV3().contracts.find((entry) =>
      entry.path === 'conformance/vectors/currency.v2.json');
    expect(contract).toBeDefined();
    const session = buildExecutionSessionV3(contract!);

    for (const vector of session.executionSuite.vectors) {
      expect(vector.input.currency).toEqual({ args: vector.input.currency.args });
      expect(session.bindings.get(vector.handle)?.expected)
        .toEqual({
          currency_status: expect.stringMatching(/^(?:fresh|stale|unknown)$/),
        });
    }
    const oldAllTrueOracle = session.executionSuite.vectors.map((vector) => ({
      handle: vector.handle,
      result: { valid: true },
    }));
    expect(() => validateResultRowsV3(session, oldAllTrueOracle))
      .toThrow(/exact typed result differs/);
  });

  it('creates fresh post-build canonicalization cases with both outcomes', () => {
    const kit = loadPinnedKitV3();
    const first = buildPostBuildChallengesV3(kit);
    const second = buildPostBuildChallengesV3(kit);

    expect(first.bindings.size).toBe(64);
    expect([...first.bindings.values()].map((entry) => entry.expected.valid))
      .toContain(true);
    expect([...first.bindings.values()].map((entry) => entry.expected.valid))
      .toContain(false);
    const paired = new Map<string, boolean[]>();
    for (const vector of first.executionSuite.vectors) {
      const inputJson = vector.input.canonicalization.input_json;
      const outcomes = paired.get(inputJson) ?? [];
      outcomes.push(first.bindings.get(vector.handle)!.expected.valid);
      paired.set(inputJson, outcomes);
    }
    expect(paired.size).toBe(32);
    expect([...paired.values()].every((outcomes) =>
      JSON.stringify(outcomes.sort()) === JSON.stringify([false, true])))
      .toBe(true);
    expect(first.executionBytes).not.toEqual(second.executionBytes);
    expect(first.executionBytes.toString('utf8')).not.toContain('"expect"');

    const seed = Buffer.alloc(32, 0x5a);
    expect(buildPostBuildChallengesV3(kit, { seed }).executionBytes)
      .toEqual(buildPostBuildChallengesV3(kit, { seed }).executionBytes);
  });

  it('rejects the legacy expectation-copy oracle instead of certifying it', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-oracle-'));
    try {
      const runner = path.join(dir, 'runner');
      const manifestPath = path.join(dir, 'submission.json');
      writeExpectationCopyRunner(runner);
      writeJson(manifestPath, submissionFor(runner));

      expect(() => verifyCleanRoomSubmissionV3({
        manifestPath,
        runnerPath: runner,
      })).toThrow(/unsafe-local-execution acknowledgement is required/);
      expect(() => verifyCleanRoomSubmissionV3({
        manifestPath,
        runnerPath: runner,
        allowUnsafeLocalExecution: true,
      })).toThrow(/typed result fields differ|exact typed result differs/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a no-computation digest-order guess across the paired challenge', () => {
    const challenge = buildPostBuildChallengesV3(loadPinnedKitV3(), {
      seed: Buffer.alloc(32, 0x41),
    });
    const groups = new Map<string, any[]>();
    for (const vector of challenge.executionSuite.vectors) {
      const key = vector.input.canonicalization.input_json;
      const group = groups.get(key) ?? [];
      group.push(vector);
      groups.set(key, group);
    }
    const rows = [...groups.values()].flatMap((group) => {
      const guessedValidDigest = group
        .map((vector) => vector.input.canonicalization.expected_digest)
        .sort()[0];
      return group.map((vector) => ({
        handle: vector.handle,
        result: {
          valid: vector.input.canonicalization.expected_digest === guessedValidDigest,
        },
      }));
    });

    expect(() => validateResultRowsV3(challenge, rows))
      .toThrow(/post-build-canonical-pair-\d+-(?:valid|invalid)/);
  });

  it('rejects unknown, duplicate, and missing run-scoped handles', () => {
    const challenge = buildPostBuildChallengesV3(loadPinnedKitV3(), {
      seed: Buffer.alloc(32, 0x42),
    });
    const rows = challenge.executionSuite.vectors.map((vector) => ({
      handle: vector.handle,
      result: { ...challenge.bindings.get(vector.handle)!.expected },
    }));
    const unknown = structuredClone(rows);
    unknown[0].handle = `cr3_${'A'.repeat(32)}`;
    expect(() => validateResultRowsV3(challenge, unknown)).toThrow(/unknown handle/);

    const duplicate = structuredClone(rows);
    duplicate[1].handle = duplicate[0].handle;
    expect(() => validateResultRowsV3(challenge, duplicate)).toThrow(/duplicated handle/);
    expect(() => validateResultRowsV3(challenge, rows.slice(1)))
      .toThrow(/wrong result count/);
  });

  it('detects persistent execution-input and entrypoint mutations', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-mutation-'));
    try {
      const runner = path.join(dir, 'runner');
      const manifestPath = path.join(dir, 'submission.json');
      writeInputMutationRunner(runner);
      writeJson(manifestPath, submissionFor(runner));
      expect(() => verifyCleanRoomSubmissionV3({
        manifestPath,
        runnerPath: runner,
        allowUnsafeLocalExecution: true,
      }))
        .toThrow(/mutated the execution suite/);

      fs.chmodSync(runner, 0o755);
      writeEntrypointMutationRunner(runner);
      writeJson(manifestPath, submissionFor(runner));
      expect(() => verifyCleanRoomSubmissionV3({
        manifestPath,
        runnerPath: runner,
        allowUnsafeLocalExecution: true,
      }))
        .toThrow(/runner artifact is mutable|runner artifact hash mismatch/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a published-vector answer table with an unknown-case refusal default', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-table-'));
    try {
      const runner = path.join(dir, 'runner');
      const manifestPath = path.join(dir, 'submission.json');
      writePublishedVectorTableRunner(runner);
      writeJson(manifestPath, submissionFor(runner));

      expect(() => verifyCleanRoomSubmissionV3({
        manifestPath,
        runnerPath: runner,
        allowUnsafeLocalExecution: true,
      })).toThrow(/post-build-canonical-pair-\d+-valid/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('passes an honest evaluator over 335 pinned vectors and fresh challenges', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-valid-'));
    try {
      const runner = path.join(dir, 'runner');
      const manifestPath = path.join(dir, 'submission.json');
      const reportPath = path.join(dir, 'report.json');
      buildReferenceRunner(
        runner,
        path.resolve('conformance/runners/run-js-v3.mjs'),
      );
      writeJson(manifestPath, submissionFor(runner));

      const report = verifyCleanRoomSubmissionV3({
        manifestPath,
        runnerPath: runner,
        emitPath: reportPath,
        allowUnsafeLocalExecution: true,
      });
      expect(report.conformance).toMatchObject({
        status: 'pass',
        suites: 21,
        vectors: 335,
      });
      expect(report.post_build_challenge).toMatchObject({
        status: 'pass',
        suite: 'conformance/vectors/canonicalization.v1.json',
      });
      expect(report.post_build_challenge.cases).toBe(64);
      const disclosedChallenge = Buffer.from(
        report.post_build_challenge.execution_input_base64url,
        'base64url',
      );
      expect(sha256V3(disclosedChallenge))
        .toBe(report.post_build_challenge.execution_input_sha256);
      expect(JSON.parse(disclosedChallenge.toString('utf8')).vectors).toHaveLength(64);
      expect(report.post_build_challenge.normalized_results).toHaveLength(64);
      expect(report.post_build_challenge.generator_contract.pair_count).toBe(32);
      expect(Buffer.from(report.post_build_challenge.seed_base64url, 'base64url'))
        .toHaveLength(32);
      expect(report.suites.every((suite: any) =>
        Buffer.from(suite.randomization_seed_base64url, 'base64url').length === 32))
        .toBe(true);
      expect(report.input_separation).toMatchObject({
        expected_results_excluded_from_runner_input: true,
        catalogue_vector_ids_excluded_from_runner_input: true,
        currency_status_assertions_excluded_from_runner_input: true,
        handles: 'opaque_random_per_run',
        inherited_environment: false,
        runner_environment_variables: ['PATH', 'LANG', 'LC_ALL', 'TZ'],
      });
      expect(report.runner).toMatchObject({
        artifact_scope: 'entrypoint_file_only',
        fixed_argument_target_bytes_hashed: false,
        interpreter_and_dynamic_dependencies_hashed: false,
        entrypoint_path_toctou_excluded: false,
      });
      expect(JSON.parse(fs.readFileSync(reportPath, 'utf8')).report_sha256)
        .toBe(report.report_sha256);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('does not pass inherited credential variables to the runner', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-env-'));
    const previous = process.env.EP_CLEAN_ROOM_TEST_SECRET;
    try {
      const delegate = path.join(dir, 'delegate');
      const runner = path.join(dir, 'runner');
      const manifestPath = path.join(dir, 'submission.json');
      buildReferenceRunner(delegate, path.resolve('conformance/runners/run-js-v3.mjs'));
      writeEnvironmentGuardRunner(runner, delegate);
      writeJson(manifestPath, submissionFor(runner));
      process.env.EP_CLEAN_ROOM_TEST_SECRET = 'must-not-reach-runner';

      const report = verifyCleanRoomSubmissionV3({
        manifestPath,
        runnerPath: runner,
        allowUnsafeLocalExecution: true,
      });
      expect(report.conformance.status).toBe('pass');
      expect(report.input_separation.inherited_environment).toBe(false);
    } finally {
      if (previous === undefined) delete process.env.EP_CLEAN_ROOM_TEST_SECRET;
      else process.env.EP_CLEAN_ROOM_TEST_SECRET = previous;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('external evaluation uses a pinned tree export and excludes relative untracked helpers', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-external-'));
    try {
      const repository = path.join(dir, 'implementation');
      fs.mkdirSync(repository);
      const runner = path.join(repository, 'runner');
      buildReferenceRunner(runner, path.resolve('conformance/runners/run-js-v3.mjs'));
      const pins = commitRunnerRepository(repository);
      const manifest = submissionFor(runner);
      manifest.implementation.source_repository = repository;
      manifest.implementation.source_commit = pins.head;
      manifest.implementation.source_tree_oid = pins.tree;
      const signed = signedAttestation(manifest);
      const manifestPath = path.join(dir, 'submission.json');
      const attestationPath = path.join(dir, 'attestation.json');
      const trustedPath = path.join(dir, 'trusted.json');
      const reportPath = path.join(dir, 'report.json');
      writeJson(manifestPath, manifest);
      writeJson(attestationPath, signed.attestation);
      writeJson(trustedPath, signed.trusted);

      const report = evaluateExternalImplementationV3({
        manifestPath,
        sourcePath: repository,
        runnerPath: runner,
        attestationPath,
        trustedAttestorsPath: trustedPath,
        emitPath: reportPath,
        allowUnsafeLocalExecution: true,
      });
      expect(report.acceptance.accepted).toBe(true);
      expect(report.source_verification).toMatchObject({
        isolated_pinned_tree_export: true,
        untracked_source_files_included: false,
        tracked_files_outside_tree_scope_included: false,
        runner_dependency_closure_verified: false,
        fixed_argument_targets_pinned: false,
        entrypoint_path_toctou_excluded: false,
        network_sandbox: false,
        filesystem_read_sandbox: false,
      });

      fs.chmodSync(runner, 0o755);
      fs.writeFileSync(runner, '#!/bin/sh\nexec node "$(dirname "$0")/answers.mjs" "$@"\n');
      fs.chmodSync(runner, 0o555);
      git(repository, 'add', 'runner');
      git(repository, 'commit', '-qm', 'use generated helper');
      fs.writeFileSync(path.join(repository, 'answers.mjs'), 'throw new Error("untracked oracle loaded")\n');
      const secondPins = {
        head: git(repository, 'rev-parse', 'HEAD'),
        tree: git(repository, 'rev-parse', 'HEAD^{tree}'),
      };
      const secondManifest = submissionFor(runner);
      secondManifest.implementation.source_repository = repository;
      secondManifest.implementation.source_commit = secondPins.head;
      secondManifest.implementation.source_tree_oid = secondPins.tree;
      const secondSigned = signedAttestation(secondManifest);
      writeJson(manifestPath, secondManifest);
      writeJson(attestationPath, secondSigned.attestation);
      writeJson(trustedPath, secondSigned.trusted);

      expect(() => evaluateExternalImplementationV3({
        manifestPath,
        sourcePath: repository,
        runnerPath: runner,
        attestationPath,
        trustedAttestorsPath: trustedPath,
        emitPath: reportPath,
        allowUnsafeLocalExecution: true,
      })).toThrow(/runner failed/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
