// SPDX-License-Identifier: Apache-2.0
/**
 * Runnable, revision-pinned CHAP to AEB composition profile.
 *
 * This runner proves a bounded interop claim. It does not claim CHAP adoption,
 * an independent CHAP implementation, or authority to execute an action.
 */
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalizeStrictJson } from '../../../packages/verify/strict-json.js';
import { digestAeb } from '../../../packages/verify/aeb-adapter-contract.js';
import {
  CHAP_AEB_ADAPTER_ID,
  CHAP_AEB_ADAPTER_VERSION,
  CHAP_AEB_CONFIG_VERSION,
  CHAP_CAID_MAPPER_ID,
  CHAP_CAID_MAPPING_VERSION,
  CHAP_PATCH_IMPLEMENTATION_SHA256,
  CHAP_REVIEW_PROFILE_SHA256,
  CHAP_SECURITY_SIGNED_PROFILE_SHA256,
  CHAP_SOURCE_COMMIT,
  CHAP_SOURCE_REPOSITORY,
  CHAP_TRUST_ROOT_VERSION,
  createChapActionDefinition,
  createChapAebAdapter,
} from '../../../packages/verify/aeb-chap-adapter.js';

/** @typedef {import('../../../packages/verify/dist/aeb-adapter-contract.js').AebPinnedProfile} AebPinnedProfile */
/** @typedef {import('../../../packages/verify/dist/aeb-chap-adapter.js').ChapAdapterConfig} ChapAdapterConfig */
/** @typedef {import('../../../packages/verify/dist/aeb-chap-adapter.js').ChapTrustRoot} ChapTrustRoot */

const HERE = dirname(fileURLToPath(import.meta.url));
const NOW = '2026-08-14T18:00:00.000Z';
const REVIEWER = 'human:alice@example.org';
const ACTION_TYPE = 'payment.transfer.1';
const FIXTURE_PRIVATE_KEY = crypto.createPrivateKey({
  key: Buffer.from(
    '302e020100300506032b657004220420752e048501f79628f66b7d9e93c52118e3feef74bd1167be95d901af360a9cb2',
    'hex',
  ),
  format: 'der',
  type: 'pkcs8',
});
const FIXTURE_PUBLIC_JWK = FIXTURE_PRIVATE_KEY.export({ format: 'jwk' });
if (FIXTURE_PUBLIC_JWK.kty !== 'OKP' || FIXTURE_PUBLIC_JWK.crv !== 'Ed25519'
    || typeof FIXTURE_PUBLIC_JWK.x !== 'string') {
  throw new TypeError('fixture public key is not Ed25519');
}

/** @type {Readonly<ChapAdapterConfig>} */
const CONFIG = Object.freeze({
  '@version': CHAP_AEB_CONFIG_VERSION,
  wire_profile: 'chap-jsonrpc-security-signed-1.0',
  evidence_role: 'human-authorization',
  subject: { id: REVIEWER, kind: /** @type {'human'} */ ('human'), native_id: REVIEWER },
  action_type: ACTION_TYPE,
  approve_binding_field: 'approved_artefact_digest',
  max_decision_age_seconds: 300,
  max_status_age_seconds: 300,
});

/** @type {Readonly<ChapTrustRoot>} */
const TRUST_ROOT = Object.freeze({
  '@version': CHAP_TRUST_ROOT_VERSION,
  use: 'chap-participant-signing-key',
  participant_id: REVIEWER,
  kid: 'alice-fixture-1',
  public_jwk: {
    kty: /** @type {'OKP'} */ (FIXTURE_PUBLIC_JWK.kty),
    crv: /** @type {'Ed25519'} */ (FIXTURE_PUBLIC_JWK.crv),
    x: FIXTURE_PUBLIC_JWK.x,
  },
  valid_from: '2026-08-14T00:00:00.000Z',
  valid_until: '2026-08-15T00:00:00.000Z',
  identity_binding: {
    method: 'conformance-fixture',
    evidence_digest: /** @type {`sha256:${string}`} */ (`sha256:${'a'.repeat(64)}`),
  },
});

const EXPECTED_ACTION = Object.freeze({
  action_type: ACTION_TYPE,
  native_action: {
    kind: 'payment.transfer',
    account: 'acct_9',
    amount: '100.00',
    currency: 'USD',
  },
});

const STATUS = Object.freeze({
  checked_at: NOW,
  expires_at: '2026-08-14T18:01:00.000Z',
  revocation_checked: true,
  revoked: false,
  consumed: false,
});

function signEnvelope(envelope, privateKey = FIXTURE_PRIVATE_KEY, kid = TRUST_ROOT.kid) {
  const unsigned = structuredClone(envelope);
  delete unsigned.sig;
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizeStrictJson(unsigned), 'utf8'),
    privateKey,
  ).toString('base64');
  return { ...unsigned, sig: `ed25519:${kid}:${signature}` };
}

function overrideEnvelope(id = '01K2AEBCHAP000000000000001') {
  return signEnvelope({
    jsonrpc: '2.0',
    id,
    method: 'decide.override',
    params: {
      workspace: 'wsp_payments',
      from: REVIEWER,
      to: 'service:coordinator@example.org',
      ts: NOW,
      task_id: 'tsk_payment_9',
      based_on_artefact: {
        kind: 'payment.transfer',
        account: 'acct_9',
        amount: '90.00',
        currency: 'USD',
      },
      diff: [{ op: 'replace', path: '/amount', value: '100.00' }],
      rationale: 'Approved the corrected amount.',
      tags: ['amount-corrected'],
    },
  });
}

function approveEnvelope(bound) {
  const params = {
    workspace: 'wsp_payments',
    from: REVIEWER,
    to: 'service:coordinator@example.org',
    ts: NOW,
    task_id: 'tsk_payment_9',
    comment: 'Approved.',
  };
  if (bound) params.approved_artefact_digest = digestAeb(EXPECTED_ACTION.native_action);
  return signEnvelope({
    jsonrpc: '2.0',
    id: bound ? '01K2AEBCHAP000000000000003' : '01K2AEBCHAP000000000000002',
    method: 'decide.approve',
    params,
  });
}

/** @returns {AebPinnedProfile} */
function mappingProfile() {
  return {
    version: CHAP_CAID_MAPPING_VERSION,
    definition: createChapActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:chap-human-decision-payment-transfer',
    mapper_id: CHAP_CAID_MAPPER_ID,
    resolver: {
      id: CHAP_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: CHAP_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'decision.comment',
        'decision.rationale',
        'decision.tags',
        'decision.task_id',
        'decision.workspace',
        'decision.timestamp',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function input(artifact, overrides = {}) {
  return {
    artifact,
    artifact_ref: `chap:decision:${artifact?.id ?? 'unknown'}`,
    status: STATUS,
    trust_roots: [TRUST_ROOT],
    adapter_config: CONFIG,
    expected_action: EXPECTED_ACTION,
    now: NOW,
    ...overrides,
  };
}

function check(id, description, passed, observed) {
  return { id, description, passed, observed };
}

function exactText(value, field) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256
      || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function exactInstant(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)
      || !Number.isFinite(Date.parse(value))) throw new TypeError('executed_at is invalid');
  return value;
}

function reportDigest(report) {
  return `sha256:${crypto.createHash('sha256').update(canonicalizeStrictJson(report)).digest('hex')}`;
}

export function runSuite(runner = {}) {
  const adapter = createChapAebAdapter({ config: CONFIG, trust_roots: [TRUST_ROOT] });
  const profile = mappingProfile();
  const override = overrideEnvelope();
  const acceptedOverride = adapter.verifyNative(input(override));
  const mappedOverride = adapter.mapAction({ ...input(override), profile, native: acceptedOverride });

  const plainApprove = adapter.verifyNative(input(approveEnvelope(false)));
  const boundApproveArtifact = approveEnvelope(true);
  const boundApprove = adapter.verifyNative(input(boundApproveArtifact));
  const mappedApprove = adapter.mapAction({ ...input(boundApproveArtifact), profile, native: boundApprove });

  const tampered = structuredClone(override);
  tampered.params.diff[0].value = '1000.00';
  const tamperedResult = adapter.verifyNative(input(tampered));

  const substitutedAction = structuredClone(EXPECTED_ACTION);
  substitutedAction.native_action.amount = '1000.00';
  const substitutedResult = adapter.verifyNative(input(override, { expected_action: substitutedAction }));

  const unsafePatch = structuredClone(override);
  unsafePatch.params.diff = [{ op: 'add', path: '/__proto__/polluted', value: true }];
  const unsafePatchResult = adapter.verifyNative(input(signEnvelope(unsafePatch)));

  const staleStatus = adapter.verifyNative(input(override, {
    status: { ...STATUS, checked_at: '2026-08-14T17:00:00.000Z' },
  }));
  const consumedStatus = adapter.verifyNative(input(override, {
    status: { ...STATUS, consumed: true },
  }));
  const replayAgain = adapter.verifyNative(input(override));

  const otherKeys = crypto.generateKeyPairSync('ed25519');
  const wrongSigner = signEnvelope({ ...override, sig: undefined }, otherKeys.privateKey, TRUST_ROOT.kid);
  const wrongSignerResult = adapter.verifyNative(input(wrongSigner));

  const checks = [
    check('CHAP-AEB-01', 'signed override verifies under the relying-party-pinned reviewer key',
      acceptedOverride.native_verification === 'VERIFIED' && acceptedOverride.acceptance === 'ACCEPTED',
      `${acceptedOverride.native_verification}/${acceptedOverride.acceptance}`),
    check('CHAP-AEB-02', 'override patch result maps to the exact expected action and CAID',
      mappedOverride.mapping === 'MATCH' && mappedOverride.action_digest === digestAeb(EXPECTED_ACTION),
      `${mappedOverride.mapping}/${mappedOverride.caid}`),
    check('CHAP-AEB-03', 'current plain approve remains indeterminate without an artifact binding',
      plainApprove.acceptance === 'INDETERMINATE'
        && plainApprove.reasons.includes('chap:approve_artifact_binding_missing'),
      `${plainApprove.acceptance}/${plainApprove.reasons.join(',')}`),
    check('CHAP-AEB-04', 'signature-covered approved_artefact_digest makes approve exact-action mappable',
      boundApprove.acceptance === 'ACCEPTED' && mappedApprove.mapping === 'MATCH',
      `${boundApprove.acceptance}/${mappedApprove.mapping}`),
    check('CHAP-AEB-05', 'post-signature patch tampering is rejected',
      tamperedResult.acceptance === 'REJECTED' && tamperedResult.reasons.includes('chap:signature_invalid'),
      `${tamperedResult.acceptance}/${tamperedResult.reasons.join(',')}`),
    check('CHAP-AEB-06', 'a valid decision cannot be substituted onto another action',
      substitutedResult.acceptance === 'REJECTED'
        && substitutedResult.reasons.includes('chap:approved_artifact_mismatch'),
      `${substitutedResult.acceptance}/${substitutedResult.reasons.join(',')}`),
    check('CHAP-AEB-07', 'prototype-polluting JSON Pointer segments are rejected',
      unsafePatchResult.acceptance === 'REJECTED' && unsafePatchResult.reasons.includes('chap:patch_invalid'),
      `${unsafePatchResult.acceptance}/${unsafePatchResult.reasons.join(',')}`),
    check('CHAP-AEB-08', 'a signer outside the pinned root cannot authenticate a decision',
      wrongSignerResult.acceptance === 'REJECTED' && wrongSignerResult.reasons.includes('chap:signature_invalid'),
      `${wrongSignerResult.acceptance}/${wrongSignerResult.reasons.join(',')}`),
    check('CHAP-AEB-09', 'stale status remains indeterminate rather than accepted',
      staleStatus.acceptance === 'INDETERMINATE', staleStatus.acceptance),
    check('CHAP-AEB-10', 'a consumed native decision is rejected',
      consumedStatus.acceptance === 'REJECTED' && consumedStatus.reasons.includes('evidence_consumed'),
      `${consumedStatus.acceptance}/${consumedStatus.reasons.join(',')}`),
    check('CHAP-AEB-11', 'the native replay identity is stable for the same signed decision',
      acceptedOverride.replay_unit === replayAgain.replay_unit,
      acceptedOverride.replay_unit),
  ];

  const passedCount = checks.filter((entry) => entry.passed).length;
  const runnerName = exactText(runner.runner_name ?? 'EMILIA reference runner', 'runner_name');
  const runnerAffiliation = exactText(runner.runner_affiliation ?? 'EMILIA Protocol', 'runner_affiliation');
  const runnerRevision = exactText(runner.runner_revision ?? 'working-tree', 'runner_revision');
  const executedAt = exactInstant(runner.executed_at ?? NOW);
  const base = {
    report_version: 'CHAP-AEB-CONFORMANCE-REPORT-v1',
    profile: 'CHAP-AEB-COMPOSITION-v1',
    passed: passedCount === checks.length,
    summary: { passed: passedCount, total: checks.length },
    runner: {
      runner_name: runnerName,
      runner_affiliation: runnerAffiliation,
      runner_revision: runnerRevision,
      executed_at: executedAt,
      execution_owner: 'runner-asserted',
      implementation_owner: 'EMILIA Protocol',
      independent_implementation: false,
    },
    source_pins: {
      repository: CHAP_SOURCE_REPOSITORY,
      commit: CHAP_SOURCE_COMMIT,
      review_profile_sha256: CHAP_REVIEW_PROFILE_SHA256,
      security_signed_profile_sha256: CHAP_SECURITY_SIGNED_PROFILE_SHA256,
      patch_implementation_sha256: CHAP_PATCH_IMPLEMENTATION_SHA256,
      wire_profile: CONFIG.wire_profile,
    },
    adapter: { id: CHAP_AEB_ADAPTER_ID, version: CHAP_AEB_ADAPTER_VERSION },
    result: {
      evidence_role: acceptedOverride.evidence_role,
      caid: mappedOverride.caid,
      action_digest: mappedOverride.action_digest,
      replay_unit: acceptedOverride.replay_unit,
    },
    checks,
    limitations: [
      'This run executes the EMILIA reference adapter, not an independent implementation.',
      'CHAP decide.override is exact-action mappable under this profile.',
      'Current plain decide.approve remains indeterminate unless its signature covers approved_artefact_digest.',
      'Integrity of a present CHAP record does not prove that every decision that should exist was emitted.',
      'A passing mapping does not authorize or execute the action.',
    ],
    implementation_status_markdown:
      `${runnerName} (${runnerAffiliation}) reproduced the EMILIA reference CHAP-to-AEB `
      + `composition at ${runnerRevision}: ${passedCount}/${checks.length} pinned checks passed. `
      + 'This was an external execution of the EMILIA reference runner, not an independent implementation.',
  };
  return { ...base, report_digest: reportDigest(base) };
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--emit') values.emit = true;
    else if (arg.startsWith('--')) {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new TypeError(`${arg} requires a value`);
      values[arg.slice(2)] = value;
      index += 1;
    } else throw new TypeError(`unknown argument: ${arg}`);
  }
  return values;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = runSuite({
    runner_name: args['runner-name'],
    runner_affiliation: args['runner-affiliation'],
    runner_revision: args['runner-revision'],
    executed_at: args['executed-at'],
  });
  if (args.emit || args.output) {
    const output = resolve(args.output ?? resolve(HERE, 'report.reference.json'));
    writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
