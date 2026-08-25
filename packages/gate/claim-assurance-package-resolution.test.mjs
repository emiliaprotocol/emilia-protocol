// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const gateRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(gateRoot, '../..');
const verifyRoot = path.join(repositoryRoot, 'packages/verify');

function pack(packageRoot, destination) {
  const report = JSON.parse(execFileSync('npm', [
    'pack', '--ignore-scripts', '--json', '--pack-destination', destination,
  ], { cwd: packageRoot, encoding: 'utf8' }));
  const entries = Array.isArray(report) ? report : Object.values(report ?? {});
  assert.equal(entries.length, 1, 'npm pack must return exactly one package');
  assert.equal(typeof entries[0]?.filename, 'string', 'npm pack report must name the tarball');
  return path.join(destination, entries[0].filename);
}

function extract(tarball, target) {
  fs.mkdirSync(target, { recursive: true });
  execFileSync('tar', ['-xzf', tarball, '--strip-components=1', '-C', target]);
}

test('packed Gate accepts an injected packed Verify evaluator in a blank consumer', () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'emilia-claim-assurance-consumer-'));
  try {
    const gateTarball = pack(gateRoot, temporaryRoot);
    const verifyTarball = pack(verifyRoot, temporaryRoot);
    const consumerRoot = path.join(temporaryRoot, 'consumer');
    const installedGate = path.join(consumerRoot, 'node_modules', '@emilia-protocol', 'gate');
    const installedVerify = path.join(consumerRoot, 'node_modules', '@emilia-protocol', 'verify');
    extract(gateTarball, installedGate);
    extract(verifyTarball, installedVerify);

    const gatePackage = JSON.parse(fs.readFileSync(path.join(installedGate, 'package.json'), 'utf8'));
    const verifyPackage = JSON.parse(fs.readFileSync(path.join(installedVerify, 'package.json'), 'utf8'));
    assert.equal(gatePackage.dependencies['@emilia-protocol/verify'], '3.20.3');
    assert.ok(gatePackage.exports['./claim-assurance']);
    assert.ok(verifyPackage.exports['./claim-assurance']);

    for (const relativePath of ['claim-assurance.js', 'dist/claim-assurance.d.ts']) {
      const bytes = fs.readFileSync(path.join(installedGate, relativePath), 'utf8');
      assert.doesNotMatch(
        bytes,
        /@emilia-protocol\/verify/u,
        `packed Gate ${relativePath} must not import Verify at runtime or for types`,
      );
    }

    fs.writeFileSync(path.join(consumerRoot, 'package.json'), JSON.stringify({ type: 'module' }));
    fs.writeFileSync(path.join(consumerRoot, 'consumer.mjs'), `
      import crypto from 'node:crypto';
      import {
        CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION,
        createClaimAssuranceAdmissibilityVerifier,
        validateClaimAssuranceAdmissibilityResult,
      } from '@emilia-protocol/gate/claim-assurance';
      import {
        CLAIM_ASSURANCE_PROFILE_VERSION,
        CLAIM_CASE_VERSION,
        claimAssuranceArtifactDigest,
        claimAssuranceProfileHash,
        evaluateClaimAssurance,
      } from '@emilia-protocol/verify/claim-assurance';

      const digest = (value) => 'sha256:' + crypto.createHash('sha256').update(value).digest('hex');
      const action = { action_type: 'finance.vendor_bank_change', vendor_id: 'vendor-1234' };
      const actionDigest = digest(JSON.stringify(action));
      const implementationDigest = 'sha256:' + '4'.repeat(64);
      const subjectDigest = 'sha256:' + '1'.repeat(64);
      const scopeDigest = 'sha256:' + '2'.repeat(64);
      const profile = {
        '@type': CLAIM_ASSURANCE_PROFILE_VERSION,
        profile_id: 'emilia.finance.vendor-account.v1',
        claim_type: 'finance.vendor-account',
        predicate: 'beneficiary-account-is-approved',
        requirements: [{
          requirement_id: 'bank-confirmation',
          evidence_role: 'BANK_CONFIRMATION',
          verifier: {
            verifier_id: 'reference.bank-confirmation',
            verifier_version: '1.0.0',
            implementation_digest: implementationDigest,
          },
          minimum_distinct_sources: 1,
          max_age_seconds: 300,
        }],
      };
      const profileHash = claimAssuranceProfileHash(profile);
      const artifact = { relationship: 'SUPPORTS', source_id: 'bank:reference' };
      const claimCase = {
        '@type': CLAIM_CASE_VERSION,
        subject_digest: subjectDigest,
        scope_digest: scopeDigest,
        claim: {
          claim_id: 'claim:vendor:1234',
          claim_type: profile.claim_type,
          predicate: profile.predicate,
          value: { beneficiary_account_digest: 'sha256:' + '5'.repeat(64) },
        },
        profile_id: profile.profile_id,
        profile_hash: profileHash,
        action_digest: actionDigest,
        as_of: '2026-08-23T12:00:00Z',
        evidence: [{
          evidence_id: 'evidence:1',
          role: 'BANK_CONFIRMATION',
          verifier: profile.requirements[0].verifier,
          binding: {
            subject_digest: subjectDigest,
            scope_digest: scopeDigest,
            claim_id: 'claim:vendor:1234',
            action_digest: actionDigest,
          },
          artifact,
          artifact_digest: claimAssuranceArtifactDigest(artifact),
        }],
      };
      const registration = {
        ...profile.requirements[0].verifier,
        verify(input) {
          return {
            verdict: 'VERIFIED',
            relationship: 'SUPPORTS',
            source_id: 'bank:reference',
            subject_digest: input.subject_digest,
            scope_digest: input.scope_digest,
            claim_id: input.claim.claim_id,
            observed_at: '2026-08-23T11:59:00Z',
            expires_at: '2026-08-23T12:04:00Z',
            artifact_digest: input.artifact_digest,
            reasons: [],
          };
        },
      };
      const bridge = createClaimAssuranceAdmissibilityVerifier({
        pinnedProfile: profile,
        pinnedProfileHash: profileHash,
        evaluateClaimAssurance,
        verifierRegistry: [registration],
        maxCaseAgeSec: 300,
        now: () => Date.parse('2026-08-23T12:00:01Z'),
      });
      const block = await bridge({
        pinned_profile: { id: profile.profile_id, profile_hash: profileHash },
        presented: {
          '@type': CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION,
          claim_case: claimCase,
        },
        observed_action: action,
      });
      if (block.verdict !== 'admissible' || block.authorizes_action !== false) {
        throw new Error('packed Claim Assurance bridge did not preserve its closed boundary');
      }
      if (validateClaimAssuranceAdmissibilityResult(block).ok !== true) {
        throw new Error('packed Claim Assurance subpath did not expose its closed validator');
      }
    `);
    execFileSync(process.execPath, [path.join(consumerRoot, 'consumer.mjs')], {
      cwd: consumerRoot,
      stdio: 'pipe',
    });

    fs.writeFileSync(path.join(consumerRoot, 'consumer.ts'), `
      import {
        createClaimAssuranceAdmissibilityVerifier,
        validateClaimAssuranceAdmissibilityResult,
        type ClaimAssuranceAdmissibilityOptions,
      } from '@emilia-protocol/gate/claim-assurance';
      import {
        claimAssuranceProfileHash,
        evaluateClaimAssurance,
        type ClaimAssuranceProfile,
        type EvidenceVerifierRegistration,
      } from '@emilia-protocol/verify/claim-assurance';
      declare const profile: ClaimAssuranceProfile;
      declare const registry: EvidenceVerifierRegistration[];
      const options: ClaimAssuranceAdmissibilityOptions = {
        pinnedProfile: profile,
        pinnedProfileHash: claimAssuranceProfileHash(profile),
        evaluateClaimAssurance,
        verifierRegistry: registry,
        maxCaseAgeSec: 300,
      };
      void createClaimAssuranceAdmissibilityVerifier(options);
      void validateClaimAssuranceAdmissibilityResult;
    `);
    fs.writeFileSync(path.join(consumerRoot, 'tsconfig.json'), JSON.stringify({
      compilerOptions: {
        target: 'ES2022',
        module: 'NodeNext',
        moduleResolution: 'NodeNext',
        strict: true,
        skipLibCheck: false,
        types: [],
        noEmit: true,
      },
      files: ['consumer.ts'],
    }));
    execFileSync(process.execPath, [
      path.join(repositoryRoot, 'node_modules', 'typescript', 'bin', 'tsc'),
      '-p', path.join(consumerRoot, 'tsconfig.json'),
    ], { cwd: consumerRoot, stdio: 'pipe' });
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
