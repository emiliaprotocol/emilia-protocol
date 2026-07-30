// SPDX-License-Identifier: Apache-2.0
/**
 * Synthetic, executable coverage-reconciliation reference scenario.
 * Keys and populations are generated for the run and touch no production
 * system. The scenario demonstrates the shipped join and signature logic.
 */

import { generateKeyPairSync, type KeyObject } from 'node:crypto';

import {
  COVERAGE_REPORT_CLAIM_BOUNDARY,
  runCoverageReconciliation,
  signCoverageSourceInventory,
  type CoveragePopulationRecord,
} from '../packages/gate/coverage-reconciliation-runner.js';

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const caid = (character: string) => (
  `caid:1:health.medical-prior-authorization-review.1:jcs-sha256:${character.repeat(43)}`
);

function priorClosedMonth(now: Date) {
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const start = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() - 1, 1));
  return { start: start.toISOString(), end: end.toISOString() };
}

function publicKey(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

export function buildCoverageReferenceScenario(nowInput = new Date()) {
  const now = new Date(nowInput);
  if (!Number.isFinite(now.getTime())) throw new TypeError('reference scenario time invalid');
  const period = priorClosedMonth(now);
  const issuedAt = new Date(now.getTime() - 120_000).toISOString();
  const expiresAt = new Date(now.getTime() + 7 * 86_400_000).toISOString();
  const systemKey = generateKeyPairSync('ed25519');
  const receiptKey = generateKeyPairSync('ed25519');
  const reconcilerKey = generateKeyPairSync('ed25519');

  const systemRecords: CoveragePopulationRecord[] = [
    { record_id: 'pas:effect:PA-1001', caid: caid('A'), action_digest: digest('a'), classification: 'effect' },
    { record_id: 'pas:effect:PA-1002', caid: caid('B'), action_digest: digest('b'), classification: 'effect' },
    { record_id: 'pas:excluded:PA-1003', caid: caid('C'), action_digest: digest('c'), classification: 'excluded' },
    { record_id: 'pas:exception:PA-1004', caid: caid('D'), action_digest: digest('d'), classification: 'exception' },
  ];
  const receiptRecords: CoveragePopulationRecord[] = [
    { record_id: 'gate:receipt:PA-1001', caid: caid('A'), action_digest: digest('a'), classification: 'receipt' },
    { record_id: 'gate:receipt:PA-1005', caid: caid('E'), action_digest: digest('e'), classification: 'receipt' },
    { record_id: 'gate:indeterminate:PA-1006', caid: caid('F'), action_digest: digest('f'), classification: 'indeterminate' },
  ];
  const systemMapping = digest('3');
  const receiptMapping = digest('4');
  const systemArtifact = signCoverageSourceInventory({
    inventory_id: 'pas:sor:reference-period',
    inventory_kind: 'system_of_record',
    source_system_id: 'pas:reference-payer',
    source_operator_id: 'operator:pas-system-of-record',
    period,
    mapping_profile_digest: systemMapping,
    issued_at: issuedAt,
    expires_at: expiresAt,
  }, systemRecords, {
    issuer_id: 'operator:pas-system-of-record',
    key_id: 'key:pas-source:reference',
    private_key: systemKey.privateKey,
  });
  const receiptArtifact = signCoverageSourceInventory({
    inventory_id: 'gate:receipts:reference-period',
    inventory_kind: 'receipt_population',
    source_system_id: 'emilia-gate:reference-payer',
    source_operator_id: 'operator:emilia-gate',
    period,
    mapping_profile_digest: receiptMapping,
    issued_at: issuedAt,
    expires_at: expiresAt,
  }, receiptRecords, {
    issuer_id: 'operator:emilia-gate',
    key_id: 'key:gate-receipts:reference',
    private_key: receiptKey.privateKey,
  });
  const trustedKeys = {
    'key:pas-source:reference': {
      issuer_id: 'operator:pas-system-of-record',
      public_key: publicKey(systemKey.publicKey),
    },
    'key:gate-receipts:reference': {
      issuer_id: 'operator:emilia-gate',
      public_key: publicKey(receiptKey.publicKey),
    },
    'key:payer-reconciler:reference': {
      issuer_id: 'payer:reference',
      public_key: publicKey(reconcilerKey.publicKey),
    },
  };
  const result = runCoverageReconciliation({
    run_id: 'coverage-run:reference',
    attestation_id: 'coverage-attestation:reference',
    relying_party_id: 'payer:reference',
    program: {
      program_id: 'rp.payer.pas.reference.1',
      version: 1,
      source_digest: digest('1'),
      program_digest: digest('2'),
    },
    period,
    census_digest: digest('5'),
    system_of_record: { artifact: systemArtifact, records: systemRecords },
    receipt_population: { artifact: receiptArtifact, records: receiptRecords },
    generated_at: now.toISOString(),
    expires_at: expiresAt,
    timestamp_anchor: null,
  }, {
    trusted_keys: trustedKeys,
    now: now.toISOString(),
    system_of_record_pin: {
      source_system_id: 'pas:reference-payer',
      source_operator_id: 'operator:pas-system-of-record',
      mapping_profile_digest: systemMapping,
    },
    receipt_population_pin: {
      source_system_id: 'emilia-gate:reference-payer',
      source_operator_id: 'operator:emilia-gate',
      mapping_profile_digest: receiptMapping,
    },
  }, {
    issuer_id: 'payer:reference',
    key_id: 'key:payer-reconciler:reference',
    private_key: reconcilerKey.privateKey,
  }) as any;

  return Object.freeze({
    ok: true as const,
    reference_only: true as const,
    period,
    summary: result.report.joins,
    bypass: result.report.findings.effect_without_receipt[0],
    findings: result.report.findings,
    sources: {
      system_of_record: {
        operator_id: 'operator:pas-system-of-record',
        record_count: systemRecords.length,
        population_root: systemArtifact.population_root,
      },
      receipt_population: {
        operator_id: 'operator:emilia-gate',
        record_count: receiptRecords.length,
        population_root: receiptArtifact.population_root,
      },
    },
    report_hash: result.report_hash as string,
    attestation_body_digest: result.attestation.proof.body_digest as string,
    claim_boundary: COVERAGE_REPORT_CLAIM_BOUNDARY,
  });
}
