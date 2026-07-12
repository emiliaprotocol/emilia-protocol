#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_OID = /^[0-9a-f]{40}$/;

export const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function fail(message) {
  throw new Error(`conformance case refused: ${message}`);
}

function strictJson(bytes, label) {
  const input = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(input);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
  const gate = strictParseGate(text);
  if (!gate.ok) fail(`${label}: ${gate.reason}`);
  try {
    return JSON.parse(text);
  } catch (error) {
    fail(`${label}: ${error.message}`);
  }
}

function same(left, right) {
  return canonicalize(left) === canonicalize(right);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function without(object, field) {
  const clone = structuredClone(object);
  delete clone[field];
  return clone;
}

function verifyCanonicalSelfHash(object, field, label) {
  assert(SHA256.test(object[field] || ''), `${label} has no valid ${field}`);
  const actual = sha256(Buffer.from(canonicalize(without(object, field)), 'utf8'));
  assert(actual === object[field], `${label} ${field} mismatch`);
}

function verifyInsertionOrderSelfHash(object, field, label) {
  assert(SHA256.test(object[field] || ''), `${label} has no valid ${field}`);
  const actual = sha256(Buffer.from(JSON.stringify(without(object, field)), 'utf8'));
  assert(actual === object[field], `${label} ${field} mismatch`);
}

function validateBaseManifest(manifest) {
  assert(manifest?.['@version'] === 'EP-CONFORMANCE-MANIFEST-v1', 'unsupported base manifest');
  verifyCanonicalSelfHash(manifest, 'manifest_sha256', 'base manifest');
  assert(
    manifest.claim_scope === 'same-team consistency over the frozen external clean-room bundle; not independent implementation evidence',
    'base manifest claim scope drifted',
  );
  assert(Array.isArray(manifest.suites) && manifest.suites.length > 0, 'base manifest has no suites');
  assert(Array.isArray(manifest.implementations) && manifest.implementations.length > 0, 'base manifest has no implementations');
  assert(manifest.totals?.suites === manifest.suites.length, 'base manifest suite total mismatch');
  assert(manifest.totals?.implementations === manifest.implementations.length, 'base manifest implementation total mismatch');
  assert(
    manifest.totals?.vectors === manifest.suites.reduce((sum, suite) => sum + suite.vectors, 0),
    'base manifest vector total mismatch',
  );
  const ids = new Set();
  for (const implementation of manifest.implementations) {
    assert(typeof implementation?.implementation_id === 'string' && !ids.has(implementation.implementation_id), 'base manifest implementation IDs must be unique');
    ids.add(implementation.implementation_id);
    assert(implementation.relationship === 'one_team_port', `${implementation.implementation_id} is not labeled as a one-team port`);
    assert(implementation.status === 'pass', `${implementation.implementation_id} did not pass`);
    assert(implementation.suites === manifest.totals.suites, `${implementation.implementation_id} suite total mismatch`);
    assert(implementation.vectors === manifest.totals.vectors, `${implementation.implementation_id} vector total mismatch`);
  }
  assert(typeof manifest.vector_bundle?.version === 'string', 'base manifest vector bundle version missing');
  assert(SHA256.test(manifest.vector_bundle?.sha256 || ''), 'base manifest vector bundle hash missing');
}

function validatePin(pin) {
  assert(pin?.['@version'] === 'EP-EXTERNAL-IMPLEMENTATION-PIN-v1', 'unsupported external implementation pin');
  assert(typeof pin.implementation?.implementation_id === 'string', 'external implementation ID missing');
  assert(typeof pin.implementation?.organization === 'string', 'external implementation organization missing');
  assert(GIT_OID.test(pin.source?.commit || ''), 'external source commit is not immutable');
  assert(GIT_OID.test(pin.source?.tree_oid || ''), 'external source tree is not immutable');
  assert(typeof pin.source?.repository === 'string' && typeof pin.source?.tree_path === 'string', 'external source locator missing');
  assert(typeof pin.hostility?.runner_name === 'string', 'external hostility runner pin missing');
  assert(SHA256.test(pin.hostility?.corpus_sha256 || ''), 'external hostility corpus hash missing');
  assert(pin.hostility?.required_status === 'pass', 'external hostility pin does not require pass');
  assert(typeof pin.construction_evidence?.third_party_attestation === 'boolean', 'third-party attestation status missing');
  assert(typeof pin.construction_evidence?.strict_clean_room_acceptance === 'boolean', 'strict clean-room status missing');
  assert(
    pin.construction_evidence.third_party_attestation === false
      && pin.construction_evidence.strict_clean_room_acceptance === false,
    'v1 pin cannot claim strict clean-room acceptance without a separately validated independent-attestation object',
  );
}

function validateExternalConformance(report, reportBytes, pin, pinBytes, manifest, expectedEvaluatorCommit) {
  assert(report?.['@version'] === 'EP-EXTERNAL-CONFORMANCE-EVALUATION-v1', 'unsupported external conformance report');
  verifyCanonicalSelfHash(report, 'report_sha256', 'external conformance report');
  assert(report.status === 'pass' && report.conformance?.status === 'pass', 'external conformance report did not pass');
  assert(same(report.implementation, pin.implementation), 'external implementation identity drifted from pin');
  assert(report.source?.verified === true, 'external source was not verified');
  assert(same(without(report.source, 'verified'), pin.source), 'external source drifted from pin');
  for (const [key, value] of Object.entries(pin.build || {})) {
    assert(same(report.build?.[key], value), `external build ${key} drifted from pin`);
  }
  assert(SHA256.test(report.build?.runner_sha256 || ''), 'external runner hash missing');
  for (const [key, value] of Object.entries(pin.construction_evidence || {})) {
    assert(same(report.construction_evidence?.[key], value), `construction evidence ${key} drifted from pin`);
  }
  assert(report.construction_evidence?.signature_verified === true, 'construction statement signature was not verified');
  assert(report.construction_evidence?.signed_result_status === 'verified', 'construction statement did not report verified');
  assert(report.evaluator?.repository === 'https://github.com/emiliaprotocol/emilia-protocol', 'external evaluator repository drifted');
  assert(GIT_OID.test(report.evaluator?.commit || ''), 'external evaluator commit missing');
  assert(report.evaluator.commit === expectedEvaluatorCommit, 'external report was produced for another evaluator commit');
  assert(report.evaluator?.pin_sha256 === sha256(pinBytes), 'external evaluator pin hash mismatch');
  assert(report.conformance?.bundle === manifest.vector_bundle.version, 'external vector bundle version differs from base manifest');
  assert(report.conformance?.bundle_sha256 === manifest.vector_bundle.sha256, 'external vector bundle hash differs from base manifest');
  assert(report.conformance?.suites === manifest.totals.suites, 'external suite total differs from base manifest');
  assert(report.conformance?.vectors === manifest.totals.vectors, 'external vector total differs from base manifest');
  assert(Array.isArray(report.suites) && report.suites.length === manifest.suites.length, 'external suite evidence is incomplete');
  const expectedSuites = new Map(manifest.suites.map((suite) => [suite.path, suite]));
  const seen = new Set();
  for (const suite of report.suites) {
    const expected = expectedSuites.get(suite?.path);
    assert(expected && !seen.has(suite.path), 'external suite evidence contains an unknown or duplicate suite');
    seen.add(suite.path);
    assert(suite.status === 'pass', `external suite ${suite.path} did not pass`);
    assert(suite.sha256 === expected.sha256 && suite.vectors === expected.vectors, `external suite ${suite.path} drifted from base manifest`);
  }
  return sha256(reportBytes);
}

function validateHostility(report, reportBytes, pin, expectedRunnerHash) {
  assert(report?.['@version'] === 'EP-DIFFERENTIAL-HOSTILITY-REPORT-v1', 'unsupported hostility report');
  verifyInsertionOrderSelfHash(report, 'report_sha256', 'external hostility report');
  assert(report.status === pin.hostility.required_status, 'external hostility report did not pass');
  assert(Array.isArray(report.divergences) && report.divergences.length === 0, 'external hostility report contains divergences');
  assert(report.corpus?.suite === pin.hostility.suite, 'external hostility suite drifted from pin');
  assert(report.corpus?.sha256 === pin.hostility.corpus_sha256, 'external hostility corpus drifted from pin');
  assert(report.corpus?.structured_cases === pin.hostility.structured_cases, 'external structured hostility count drifted from pin');
  assert(report.corpus?.raw_parser_cases === pin.hostility.raw_parser_cases, 'external raw-parser hostility count drifted from pin');
  assert(Array.isArray(report.implementations), 'external hostility implementation list missing');
  const matching = report.implementations.filter((implementation) => implementation?.name === pin.hostility.runner_name);
  assert(matching.length === 1 && matching[0].relationship === 'external-submission', 'pinned external runner is absent from hostility report');
  assert(matching[0].artifact_sha256 === expectedRunnerHash, 'hostility runner bytes differ from the conformance runner');
  return sha256(reportBytes);
}

export function assembleConformanceCase({
  manifestBytes,
  pinBytes,
  externalConformanceBytes,
  externalHostilityBytes,
  expectedEvaluatorCommit,
}) {
  assert(GIT_OID.test(expectedEvaluatorCommit || ''), 'expected evaluator commit must be a Git object ID');
  const normalizedManifestBytes = Buffer.from(manifestBytes);
  const normalizedPinBytes = Buffer.from(pinBytes);
  const normalizedConformanceBytes = Buffer.from(externalConformanceBytes);
  const normalizedHostilityBytes = Buffer.from(externalHostilityBytes);
  const manifest = strictJson(normalizedManifestBytes, 'base manifest');
  const pin = strictJson(normalizedPinBytes, 'external implementation pin');
  const externalConformance = strictJson(normalizedConformanceBytes, 'external conformance report');
  const externalHostility = strictJson(normalizedHostilityBytes, 'external hostility report');

  validateBaseManifest(manifest);
  validatePin(pin);
  const externalConformanceFileHash = validateExternalConformance(
    externalConformance,
    normalizedConformanceBytes,
    pin,
    normalizedPinBytes,
    manifest,
    expectedEvaluatorCommit,
  );
  const externalHostilityFileHash = validateHostility(
    externalHostility,
    normalizedHostilityBytes,
    pin,
    externalConformance.build.runner_sha256,
  );

  // EP-CONFORMANCE-CASE-v1 has no independent-attestation input. Its strict
  // counter is therefore locked to zero; a later schema must validate a
  // distinct attestor, current source binding, and independently pinned key.
  const strictAccepted = false;
  const strictRefusalReasons = [
    'no_independent_third_party_attestation',
    'current_source_not_strictly_clean_room_accepted',
  ];

  const result = {
    '@version': 'EP-CONFORMANCE-CASE-v1',
    claim_scope: 'one-team port consistency plus separately pinned external interoperability and hostility evidence; construction independence is reported without automatic promotion',
    evaluator: {
      repository: 'https://github.com/emiliaprotocol/emilia-protocol',
      commit: expectedEvaluatorCommit,
    },
    base_manifest: {
      path: 'conformance/clean-room/conformance-manifest.v1.json',
      file_sha256: sha256(normalizedManifestBytes),
      manifest_sha256: manifest.manifest_sha256,
      suites: manifest.totals.suites,
      vectors: manifest.totals.vectors,
      one_team_ports: manifest.totals.implementations,
    },
    external_implementations: [{
      implementation: pin.implementation,
      source: pin.source,
      pin: {
        path: 'conformance/external/rust-cleanroom-jdieselny.v1.json',
        file_sha256: sha256(normalizedPinBytes),
      },
      conformance: {
        report_file_sha256: externalConformanceFileHash,
        report_sha256: externalConformance.report_sha256,
        runner_sha256: externalConformance.build.runner_sha256,
        suites: externalConformance.conformance.suites,
        vectors: externalConformance.conformance.vectors,
        verdict: 'accepted',
      },
      hostility: {
        report_file_sha256: externalHostilityFileHash,
        report_sha256: externalHostility.report_sha256,
        runner_sha256: externalConformance.build.runner_sha256,
        corpus_sha256: externalHostility.corpus.sha256,
        structured_cases: externalHostility.corpus.structured_cases,
        raw_parser_cases: externalHostility.corpus.raw_parser_cases,
        verdict: 'accepted',
      },
      construction_evidence: {
        status: pin.construction_evidence.status,
        signature_verified: externalConformance.construction_evidence.signature_verified,
        third_party_attestation: pin.construction_evidence.third_party_attestation,
        strict_clean_room_verdict: strictAccepted ? 'accepted' : 'refused',
        refusal_reasons: strictRefusalReasons,
      },
    }],
    totals: {
      suites: manifest.totals.suites,
      vectors: manifest.totals.vectors,
      one_team_ports: manifest.totals.implementations,
      external_implementations_tested: 1,
      external_conformance_acceptances: 1,
      external_hostility_acceptances: 1,
      strict_external_clean_room_acceptances: strictAccepted ? 1 : 0,
      hostility_cases: externalHostility.corpus.structured_cases + externalHostility.corpus.raw_parser_cases,
    },
  };
  result.case_sha256 = sha256(Buffer.from(canonicalize(result), 'utf8'));
  return result;
}

function option(argv, name) {
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

function isMain() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMain()) {
  const argv = process.argv.slice(2);
  const manifestPath = option(argv, '--manifest');
  const pinPath = option(argv, '--pin');
  const externalConformancePath = option(argv, '--external-conformance');
  const externalHostilityPath = option(argv, '--external-hostility');
  const evaluatorCommit = option(argv, '--evaluator-commit');
  const emitPath = option(argv, '--emit');
  if (![manifestPath, pinPath, externalConformancePath, externalHostilityPath, evaluatorCommit, emitPath].every(Boolean)) {
    console.error('usage: assemble-conformance-case --manifest FILE --pin FILE --external-conformance FILE --external-hostility FILE --evaluator-commit SHA --emit FILE');
    process.exit(2);
  }
  const result = assembleConformanceCase({
    manifestBytes: fs.readFileSync(path.resolve(ROOT, manifestPath)),
    pinBytes: fs.readFileSync(path.resolve(ROOT, pinPath)),
    externalConformanceBytes: fs.readFileSync(path.resolve(ROOT, externalConformancePath)),
    externalHostilityBytes: fs.readFileSync(path.resolve(ROOT, externalHostilityPath)),
    expectedEvaluatorCommit: evaluatorCommit,
  });
  const target = path.resolve(ROOT, emitPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`CONFORMANCE CASE: PASS (${result.totals.suites} suites, ${result.totals.vectors} vectors, ${result.totals.external_implementations_tested} external implementation, ${result.totals.hostility_cases} hostility cases; strict external clean-room acceptances ${result.totals.strict_external_clean_room_acceptances}; sha256:${result.case_sha256})`);
}
