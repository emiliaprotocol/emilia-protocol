// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildCleanRoomKitV2,
  collectCleanRoomKitV2Files,
} from '../scripts/build-clean-room-kit-v2.mts';
import {
  canonicalizeV2,
  loadPinnedKitV2,
  sha256V2,
  validateBundleDefinitionV2,
  validateResultRowsV2,
  verifyCleanRoomSubmissionV2,
  verifyIndependentAttestationV2,
  verifyRunnerArtifactV2,
  verifySubmissionManifestV2,
} from '../scripts/verify-clean-room-submission-v2.mts';

const repositoryRef = process.env.EP_CLEAN_ROOM_V2_REF || 'HEAD';

function writeJson(target: string, value: unknown): void {
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
}

function fixtureRunner(target: string): void {
  fs.writeFileSync(target, `#!/usr/bin/env node
const fs = require('node:fs');
const suite = JSON.parse(fs.readFileSync(process.argv.at(-1), 'utf8'));
const rows = suite.vectors.map((vector) => {
  const result = { ...vector.expect };
  if (typeof result.reason_contains === 'string') {
    const reason = result.reason_contains;
    delete result.reason_contains;
    result.reasons = [reason];
  }
  return { id: vector.id, result };
});
process.stdout.write(JSON.stringify(rows));
`);
  fs.chmodSync(target, 0o555);
}

function submissionFor(runnerPath: string, kit = loadPinnedKitV2()): any {
  return {
    '@version': 'EP-CLEAN-ROOM-SUBMISSION-v2',
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
      protocol: 'EP-CONFORMANCE-FILE-RUNNER-v2',
      artifact_sha256: sha256V2(fs.readFileSync(runnerPath)),
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
      specification_inputs: [
        'emilia-clean-room-kit-v2',
      ],
      statement:
        'The implementation was constructed from the source-free v2 kit without EMILIA reference implementation access.',
    },
  };
}

function signedAttestation(
  submission: any,
  options: {
    implementationOrganization?: string;
    implementationTeamId?: string;
    attestorOrganization?: string;
    attestorTeamId?: string;
  } = {},
): { attestation: any; trusted: any } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const keyId = `attestor:${sha256V2(publicKeyDer).slice(0, 24)}`;
  const attestor = {
    key_id: keyId,
    organization: options.attestorOrganization ?? 'Independent Audit Cooperative',
    team_id: options.attestorTeamId ?? 'team:independent-audit',
  };
  const unsigned = {
    '@version': 'EP-CLEAN-ROOM-INDEPENDENT-ATTESTATION-v2',
    claim: {
      submission_sha256: sha256V2(Buffer.from(canonicalizeV2(submission), 'utf8')),
      implementation_id: submission.implementation.implementation_id,
      implementation_organization:
        options.implementationOrganization ?? submission.implementation.organization,
      implementation_team_id:
        options.implementationTeamId ?? submission.implementation.team_id,
      source_commit: submission.implementation.source_commit,
      runner_artifact_sha256: submission.runner.artifact_sha256,
      vector_bundle_sha256: submission.kit.vector_bundle_sha256,
      conformance_manifest_sha256: submission.kit.conformance_manifest_sha256,
      authority_document_execution_companion_sha256:
        submission.kit.authority_document_execution_companion_sha256,
      reference_source_access: 'none',
      emilia_affiliation: 'none',
      reviewed_at: '2026-07-24T00:00:00.000Z',
      statement:
        'We independently reviewed the named construction record and attest only to that bounded review.',
    },
    attestor,
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizeV2(unsigned), 'utf8'),
    privateKey,
  );
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

describe('current-bundle clean-room v2', () => {
  it('pins the exact current 21-suite/332-vector manifest and rich Authority companion', () => {
    const kit = loadPinnedKitV2();
    expect(kit.bundle.totals).toEqual({ suites: 21, vectors: 332 });
    expect(kit.sourceManifestSha256)
      .toBe('5f8a6632dc1330138a222a91fea1702a39708088c9bbd3ec16f93474c103784d');
    expect(kit.sourceManifestClaimSha256)
      .toBe('37eaf29f4703ae3a79bd0a7bf6bbee0ab12c1e0bf1eb792caaa1c18d638b5e49');
    expect(kit.authorityExecutionCompanionSha256)
      .toBe('121a358459ffed223a41a79570cc5307693eaa89a59b3ad330710c5e2f286959');
    const authority = kit.contracts.find((entry) =>
      entry.path.endsWith('/authority-document-proof-join.v1.json'));
    expect(authority?.executionPath)
      .toBe('conformance/vectors/authority-document-proof-join.exec.v1.json');
    expect(authority?.expectations.size).toBe(26);
    expect(Object.keys(authority?.expectations.values().next().value ?? {}))
      .toContain('result_digest');
  });

  it('builds a deterministic source-free archive from the pinned allowlist', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-kit-'));
    try {
      const collected = collectCleanRoomKitV2Files(repositoryRef);
      expect(collected.files).toHaveLength(30);
      expect(collected.files.some((entry) =>
        /^(app|lib|packages|scripts|conformance\/runners)\//.test(entry.path)))
        .toBe(false);
      expect(collected.files.map((entry) => entry.path))
        .toContain('conformance/vectors/authority-document-proof-join.exec.v1.json');

      const first = buildCleanRoomKitV2({
        ref: repositoryRef,
        output: path.join(dir, 'first.tar.gz'),
      });
      const second = buildCleanRoomKitV2({
        ref: repositoryRef,
        output: path.join(dir, 'second.tar.gz'),
      });
      expect(first.archive.sha256).toBe(second.archive.sha256);
      expect(first.archive.reproducible).toBe(true);
      expect(first.reference_implementation_included).toBe(false);
      expect(first.source_files_included).toBe(false);
      expect(first.files).toEqual(second.files);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it('refuses boolean downgrades, missing, unknown, and duplicate vector IDs', () => {
    const contract = loadPinnedKitV2().contracts.find((entry) =>
      entry.path.endsWith('/revocation.exec.v2.json'));
    expect(contract).toBeDefined();
    const [id, expected] = contract!.expectations.entries().next().value;
    expect(() => validateResultRowsV2(contract!, [{ id, result: expected }]))
      .toThrow(/wrong result count/);

    const complete = [...contract!.expectations].map(([vectorId, result]) => ({
      id: vectorId,
      result,
    }));
    expect(validateResultRowsV2(contract!, complete)).toHaveLength(19);
    expect(() => validateResultRowsV2(contract!, complete.map((row, index) =>
      index === 0 ? { id: row.id, result: true } : row)))
      .toThrow(/typed result object/);
    expect(() => validateResultRowsV2(contract!, complete.slice(1)))
      .toThrow(/wrong result count|omitted/);
    expect(() => validateResultRowsV2(contract!, [
      ...complete.slice(0, -1),
      { id: 'unknown-vector', result: { valid: false } },
    ])).toThrow(/unknown vector id/);
    expect(() => validateResultRowsV2(contract!, [
      ...complete.slice(0, -1),
      complete[0],
    ])).toThrow(/duplicate vector id/);
  });

  it('refuses incomplete suite definitions and wrong manifest or companion hashes', () => {
    const kit = loadPinnedKitV2();
    expect(() => validateBundleDefinitionV2({
      ...kit.bundle,
      suites: kit.bundle.suites.slice(0, -1),
    })).toThrow(/21 suites|suite total/);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-pins-'));
    try {
      const runner = path.join(dir, 'runner');
      fixtureRunner(runner);
      const manifest = submissionFor(runner, kit);
      expect(() => verifySubmissionManifestV2({
        ...manifest,
        kit: {
          ...manifest.kit,
          conformance_manifest_sha256: '0'.repeat(64),
        },
      }, kit)).toThrow(/conformance manifest hash/);
      expect(() => verifySubmissionManifestV2({
        ...manifest,
        kit: {
          ...manifest.kit,
          authority_document_execution_companion_sha256: '0'.repeat(64),
        },
      }, kit)).toThrow(/Authority Document execution companion hash/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leaves acceptance false without a separate independent attestation', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-no-attestation-'));
    try {
      const runner = path.join(dir, 'runner');
      fixtureRunner(runner);
      const manifest = submissionFor(runner);
      expect(verifyIndependentAttestationV2(manifest, null, null)).toEqual({
        accepted: false,
        status: 'independent_attestation_missing',
      });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses unsigned and same-team construction claims', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-same-team-'));
    try {
      const runner = path.join(dir, 'runner');
      fixtureRunner(runner);
      const manifest = submissionFor(runner);
      const unsigned = signedAttestation(manifest);
      delete unsigned.attestation.signature;
      expect(() => verifyIndependentAttestationV2(
        manifest,
        unsigned.attestation,
        unsigned.trusted,
      )).toThrow(/unsigned/);

      const sameTeam = signedAttestation(manifest, {
        attestorOrganization: manifest.implementation.organization,
        attestorTeamId: manifest.implementation.team_id,
      });
      expect(() => verifyIndependentAttestationV2(
        manifest,
        sameTeam.attestation,
        sameTeam.trusted,
      )).toThrow(/same-team/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('accepts a valid separately signed independent fixture', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-valid-'));
    try {
      const runner = path.join(dir, 'runner');
      const manifestPath = path.join(dir, 'submission.json');
      const attestationPath = path.join(dir, 'attestation.json');
      const trustedPath = path.join(dir, 'trusted.json');
      const reportPath = path.join(dir, 'report.json');
      fixtureRunner(runner);
      const manifest = submissionFor(runner);
      const { attestation, trusted } = signedAttestation(manifest);
      writeJson(manifestPath, manifest);
      writeJson(attestationPath, attestation);
      writeJson(trustedPath, trusted);

      const report = verifyCleanRoomSubmissionV2({
        manifestPath,
        runnerPath: runner,
        attestationPath,
        trustedAttestorsPath: trustedPath,
        emitPath: reportPath,
      });
      expect(report.conformance).toMatchObject({
        status: 'pass',
        suites: 21,
        vectors: 332,
      });
      expect(report.acceptance).toMatchObject({
        accepted: true,
        status: 'independent_attestation_verified',
      });
      expect(JSON.parse(fs.readFileSync(reportPath, 'utf8')).report_sha256)
        .toBe(report.report_sha256);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('refuses mutable and tampered runner artifacts', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-runner-'));
    try {
      const runner = path.join(dir, 'runner');
      fixtureRunner(runner);
      const manifest = submissionFor(runner);
      fs.chmodSync(runner, 0o755);
      expect(() => verifyRunnerArtifactV2(manifest.runner, runner))
        .toThrow(/mutable/);

      fs.chmodSync(runner, 0o755);
      fs.appendFileSync(runner, '\n// tampered\n');
      fs.chmodSync(runner, 0o555);
      expect(() => verifyRunnerArtifactV2(manifest.runner, runner))
        .toThrow(/hash mismatch/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
