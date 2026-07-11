// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import { canonicalize } from '../packages/verify/index.js';
import { assembleConformanceCase, sha256 } from '../scripts/assemble-conformance-case.mjs';

const COMMIT = 'a'.repeat(40);
const manifestBytes = fs.readFileSync(new URL('../conformance/conformance-manifest.json', import.meta.url));
const pinBytes = fs.readFileSync(new URL('../conformance/external/rust-cleanroom-jdieselny.v1.json', import.meta.url));
const manifest = JSON.parse(manifestBytes);
const pin = JSON.parse(pinBytes);

function canonicalReport(object) {
  const result = structuredClone(object);
  result.report_sha256 = sha256(Buffer.from(canonicalize(result), 'utf8'));
  return Buffer.from(`${JSON.stringify(result, null, 2)}\n`);
}

function orderedReport(object) {
  const result = structuredClone(object);
  result.report_sha256 = sha256(Buffer.from(JSON.stringify(result), 'utf8'));
  return Buffer.from(`${JSON.stringify(result, null, 2)}\n`);
}

function externalConformance() {
  return canonicalReport({
    '@version': 'EP-EXTERNAL-CONFORMANCE-EVALUATION-v1',
    status: 'pass',
    implementation: pin.implementation,
    source: { ...pin.source, verified: true },
    build: { ...pin.build, runner_sha256: 'b'.repeat(64) },
    construction_evidence: {
      ...pin.construction_evidence,
      signature_verified: true,
      signed_result_status: 'verified',
      signed_vectors: 162,
      statement_digest: `sha256:${'c'.repeat(64)}`,
    },
    evaluator: {
      repository: 'https://github.com/emiliaprotocol/emilia-protocol',
      commit: COMMIT,
      pin_sha256: sha256(pinBytes),
    },
    conformance: {
      bundle: manifest.vector_bundle.version,
      bundle_sha256: manifest.vector_bundle.sha256,
      suites: manifest.totals.suites,
      vectors: manifest.totals.vectors,
      status: 'pass',
    },
    suites: manifest.suites.map((suite) => ({ ...suite, status: 'pass' })),
  });
}

function hostility() {
  return orderedReport({
    '@version': 'EP-DIFFERENTIAL-HOSTILITY-REPORT-v1',
    status: 'pass',
    corpus: {
      suite: pin.hostility.suite,
      seed: 'ep-hostility-v2-fixed',
      sha256: pin.hostility.corpus_sha256,
      structured_cases: pin.hostility.structured_cases,
      raw_parser_cases: pin.hostility.raw_parser_cases,
      categories: {},
    },
    implementations: [
      { name: 'javascript', relationship: 'one-team-port', dispatch: 'mixed' },
      { name: 'python', relationship: 'one-team-port', dispatch: 'mixed' },
      { name: 'go', relationship: 'one-team-port', dispatch: 'mixed' },
      { name: pin.hostility.runner_name, relationship: 'external-submission', dispatch: 'suite', artifact_sha256: 'b'.repeat(64) },
    ],
    divergences: [],
  });
}

function assemble(overrides = {}) {
  return assembleConformanceCase({
    manifestBytes,
    pinBytes,
    externalConformanceBytes: overrides.externalConformanceBytes || externalConformance(),
    externalHostilityBytes: overrides.externalHostilityBytes || hostility(),
    expectedEvaluatorCommit: COMMIT,
  });
}

describe('aggregate conformance case', () => {
  it('binds one-team ports and external evidence without promoting clean-room independence', () => {
    const result = assemble();
    expect(result.totals).toMatchObject({
      suites: 16,
      vectors: 163,
      one_team_ports: 3,
      external_implementations_tested: 1,
      external_conformance_acceptances: 1,
      external_hostility_acceptances: 1,
      strict_external_clean_room_acceptances: 0,
      hostility_cases: 359,
    });
    expect(result.external_implementations[0].construction_evidence).toMatchObject({
      third_party_attestation: false,
      strict_clean_room_verdict: 'refused',
      refusal_reasons: [
        'no_independent_third_party_attestation',
        'current_source_not_strictly_clean_room_accepted',
      ],
    });
    expect(result.external_implementations[0].hostility.runner_sha256)
      .toBe(result.external_implementations[0].conformance.runner_sha256);
    const unsigned = structuredClone(result);
    delete unsigned.case_sha256;
    expect(result.case_sha256).toBe(sha256(Buffer.from(canonicalize(unsigned), 'utf8')));
  });

  it('refuses a source substitution even when the attacker recomputes the report hash', () => {
    const report = JSON.parse(externalConformance());
    report.source.commit = 'd'.repeat(40);
    delete report.report_sha256;
    expect(() => assemble({ externalConformanceBytes: canonicalReport(report) }))
      .toThrow(/external source drifted from pin/);
  });

  it('refuses a hostility divergence even when the attacker recomputes the report hash', () => {
    const report = JSON.parse(hostility());
    report.divergences = [{ id: 'hostile-case', reason: 'hostile_input_accepted' }];
    delete report.report_sha256;
    expect(() => assemble({ externalHostilityBytes: orderedReport(report) }))
      .toThrow(/contains divergences/);
  });

  it('refuses hostility evidence produced by different runner bytes', () => {
    const report = JSON.parse(hostility());
    report.implementations.at(-1).artifact_sha256 = 'f'.repeat(64);
    delete report.report_sha256;
    expect(() => assemble({ externalHostilityBytes: orderedReport(report) }))
      .toThrow(/runner bytes differ from the conformance runner/);
  });

  it('refuses a report that upgrades the pinned construction-attestation status', () => {
    const report = JSON.parse(externalConformance());
    report.construction_evidence.third_party_attestation = true;
    report.construction_evidence.strict_clean_room_acceptance = true;
    delete report.report_sha256;
    expect(() => assemble({ externalConformanceBytes: canonicalReport(report) }))
      .toThrow(/construction evidence third_party_attestation drifted from pin/);
  });

  it('refuses promotion by editing only the pin flags', () => {
    const promotedPin = structuredClone(pin);
    promotedPin.construction_evidence.third_party_attestation = true;
    promotedPin.construction_evidence.strict_clean_room_acceptance = true;
    expect(() => assembleConformanceCase({
      manifestBytes,
      pinBytes: Buffer.from(`${JSON.stringify(promotedPin, null, 2)}\n`),
      externalConformanceBytes: externalConformance(),
      externalHostilityBytes: hostility(),
      expectedEvaluatorCommit: COMMIT,
    })).toThrow(/cannot claim strict clean-room acceptance/);
  });

  it('refuses evidence produced for a different evaluator commit', () => {
    expect(() => assembleConformanceCase({
      manifestBytes,
      pinBytes,
      externalConformanceBytes: externalConformance(),
      externalHostilityBytes: hostility(),
      expectedEvaluatorCommit: 'e'.repeat(40),
    })).toThrow(/produced for another evaluator commit/);
  });
});
