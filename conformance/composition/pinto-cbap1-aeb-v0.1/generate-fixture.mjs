// SPDX-License-Identifier: Apache-2.0
/** Rebuild the deterministic CBAP-1/COSE test fixture and Crossing Lab pins. */
import crypto from 'node:crypto';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sealCrossingLab } from '../../../packages/verify/dist/crossing-lab.js';
import {
  ADAPTER_ID,
  ADAPTER_VERSION,
  ARTIFACT_VERSION,
  EXPECTED_ABP_DIGEST,
  EXPECTED_ABP_DIGEST_BYTES,
  MAPPER_ID,
  NATIVE_PROTOCOL,
  PROFILE_DEFINITION,
  PROFILE_ID,
  RESOLVER_DESCRIPTOR,
  RESOLVER_DIGEST,
  computeProfileCaid,
  digestJson,
  encodeDeterministicCbor,
  hCbap1,
  makeCoseSign1ForFixture,
} from './workspace/adapter.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKSPACE = join(HERE, 'workspace');
const ZERO = `sha256:${'0'.repeat(64)}`;
const LAB_EVALUATOR_PUBLIC_SPKI = 'MCowBQYDK2VwAyEAc_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI';

/** @param {Array<[number, unknown]>} entries */
function cborMap(entries) {
  return new Map(entries);
}

// Published test-only keys. They carry no production identity or authority.
const KEYS = Object.freeze({
  issuer: Object.freeze({
    kid: 'issuer:cbap1',
    private_jwk: Object.freeze({
      crv: 'Ed25519',
      d: 'U7Aul-ZKIht1kle2BHbB9lUVqOUaGaUJlhYPVUAWXA0',
      x: 'TxU46WfTWvWB4szctxZz2jpGLoUUedHMRwfmpho-hlI',
      kty: 'OKP',
    }),
  }),
  forum: Object.freeze({
    kid: 'forum:cbap1',
    private_jwk: Object.freeze({
      crv: 'Ed25519',
      d: 'HnOFwTeD8VQKTa77MWL9LSnB-3QxFVKZEdKifabCjbk',
      x: 'zQ2OtunS3wb3l1VX2y1o39A1XRjbxByXZbDDAqcFz04',
      kty: 'OKP',
    }),
  }),
  executor: Object.freeze({
    kid: 'executor:cbap1',
    private_jwk: Object.freeze({
      crv: 'Ed25519',
      d: 'Z2F3gM5N7-BE9F1gsdQwR2piJuC8mARr-6hDBK7ReVQ',
      x: 'mhWCzGI70KHZAAM3EDBS8_aPoXaeHoZx5GUpvZaVVQ4',
      kty: 'OKP',
    }),
  }),
});

function epoch(value) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || milliseconds % 1_000 !== 0) throw new TypeError(`invalid whole-second instant ${value}`);
  return Math.floor(milliseconds / 1_000);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
}

function policy(uri, body) {
  const bytes = Buffer.from(`${JSON.stringify(body)}\n`, 'utf8');
  return Object.freeze({ uri, bytes, digest: sha256(bytes) });
}

function publicCoseKey(jwk) {
  return encodeDeterministicCbor(cborMap([
    [1, 1],
    [3, -19],
    [-1, 6],
    [-2, Buffer.from(jwk.x, 'base64url')],
  ])).toString('base64url');
}

function trustRoots() {
  return [
    { control_domain: 'domain:pinto-fixture:executor', kid: KEYS.executor.kid, public_key: publicCoseKey(KEYS.executor.private_jwk), role: 'executor' },
    { control_domain: 'domain:pinto-fixture:forum', kid: KEYS.forum.kid, public_key: publicCoseKey(KEYS.forum.private_jwk), role: 'forum' },
    { control_domain: 'domain:pinto-fixture:issuer', kid: KEYS.issuer.kid, public_key: publicCoseKey(KEYS.issuer.private_jwk), role: 'issuer' },
  ];
}

function authorizationTrustProfileDigest(roots) {
  return digestJson({
    '@version': 'PINTO-CBAP1-TRUST-PROFILE-v0.1',
    roles: roots.map(({ control_domain, kid, public_key, role }) => ({ control_domain, kid, public_key, role })),
  });
}

function buildNativeBundle() {
  const action = Object.freeze({
    account_ref: 'account:alice',
    action_type: 'account.suspend.1',
    policy_event_ref: 'policy-event:risk-2026-08-29-001',
  });
  const projected = computeProfileCaid(action);
  const actionDigest = Buffer.from(projected.action_digest.slice(7), 'hex');
  const authorizationId = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const nonce = Buffer.from('102132435465768798a9bacbdcedfe0f', 'hex');
  const notBefore = epoch('2026-08-29T12:00:00Z');
  const notAfter = epoch('2026-08-30T12:00:00Z');
  const verifiedAt = epoch('2026-08-29T12:01:00Z');
  const executedAt = epoch('2026-08-29T12:02:00Z');
  const filingDuration = 2_592_000;
  const horizon = epoch('2026-10-01T12:02:00Z');

  const standing = policy('https://forum.example/policies/standing/1', {
    profile: 'standing-policy-v1',
    eligible: ['materially-affected-party'],
  });
  const procedure = policy('https://forum.example/procedures/account-actions/1', {
    profile: 'account-action-contestation-v1',
    submission: 'authenticated-case',
  });
  const selection = policy('https://issuer.example/policies/forum-selection/1', {
    profile: 'issuer-selection-v1',
    provenance: 'unilateral',
  });
  const submissionReceipt = policy('https://forum.example/profiles/filing-receipt/1', {
    profile: 'filing-receipt-v1',
    dispositions: ['accepted', 'refused'],
  });
  const withdrawal = policy('https://forum.example/policies/withdrawal/1', {
    profile: 'forum-withdrawal-v1',
    continuity: 'historical-acknowledgement-retained',
  });
  const policies = [standing, procedure, selection, submissionReceipt, withdrawal]
    .sort((left, right) => Buffer.compare(left.digest, right.digest));

  const roots = trustRoots();
  const trustDigestString = authorizationTrustProfileDigest(roots);
  const trustDigest = Buffer.from(trustDigestString.slice(7), 'hex');
  const terms = cborMap([
    [1, authorizationId],
    [2, EXPECTED_ABP_DIGEST_BYTES],
    [3, trustDigest],
    [4, KEYS.issuer.kid],
    [5, [notBefore, notAfter]],
    [6, actionDigest],
    [7, ['https://forum.example/', 'https://forum.example/cases', KEYS.forum.kid]],
    [8, [standing.uri, standing.digest]],
    [9, [procedure.uri, procedure.digest]],
    [10, [1, filingDuration]],
    [11, [0]],
    [12, [selection.uri, selection.digest]],
    [13, [[3, 'https://transparency.example/contestability/00112233445566778899aabbccddeeff', horizon]]],
    [14, epoch('2026-08-29T11:30:00Z')],
    [15, horizon],
    [16, nonce],
  ]);
  const forumTerms = [
    terms.get(1), terms.get(2), terms.get(3), terms.get(4), terms.get(5),
    terms.get(6), terms.get(7), terms.get(8), terms.get(9), terms.get(10),
  ];
  const exactAcceptancePayload = cborMap([
    [1, 1],
    [2, 2],
    [3, hCbap1('agent-contestation-forum-terms-v1', forumTerms)],
    [4, epoch('2026-08-29T11:00:00Z')],
    [5, horizon],
    [6, [submissionReceipt.uri, submissionReceipt.digest]],
    [7, [withdrawal.uri, withdrawal.digest]],
    [8, epoch('2026-08-29T11:00:00Z')],
    [9, KEYS.forum.kid],
  ]);
  const exactAcceptanceCose = makeCoseSign1ForFixture(exactAcceptancePayload, KEYS.forum.kid, KEYS.forum.private_jwk);
  const cpoPayload = cborMap([
    [1, 1],
    [2, 1],
    [3, terms],
    [4, [0, sha256(exactAcceptanceCose)]],
    [5, []],
    [6, KEYS.issuer.kid],
  ]);
  const cpoCose = makeCoseSign1ForFixture(cpoPayload, KEYS.issuer.kid, KEYS.issuer.private_jwk);
  const cpoDigest = sha256(cpoCose);
  const authorizationPayload = cborMap([
    [1, 1],
    [2, 3],
    [3, authorizationId],
    [4, KEYS.issuer.kid],
    [5, 'agent:caseworker'],
    [6, actionDigest],
    [7, notBefore],
    [8, notAfter],
    [9, cpoDigest],
    [10, nonce],
  ]);
  const authorizationCose = makeCoseSign1ForFixture(authorizationPayload, KEYS.issuer.kid, KEYS.issuer.private_jwk);
  const authorizationDigest = sha256(authorizationCose);
  const verificationPayload = cborMap([
    [1, 1],
    [2, 4],
    [3, authorizationDigest],
    [4, authorizationId],
    [5, actionDigest],
    [6, cpoDigest],
    [7, 1],
    [8, verifiedAt],
    [9, nonce],
    [10, KEYS.executor.kid],
  ]);
  const verificationCose = makeCoseSign1ForFixture(verificationPayload, KEYS.executor.kid, KEYS.executor.private_jwk);
  const executionPayload = cborMap([
    [1, 1],
    [2, 5],
    [3, authorizationDigest],
    [4, sha256(verificationCose)],
    [5, authorizationId],
    [6, actionDigest],
    [7, 1],
    [8, executedAt],
    [9, nonce],
    [10, KEYS.executor.kid],
  ]);
  const executionCose = makeCoseSign1ForFixture(executionPayload, KEYS.executor.kid, KEYS.executor.private_jwk);
  const bundle = cborMap([
    [1, 1],
    [2, cpoCose],
    [3, exactAcceptanceCose],
    [4, authorizationCose],
    [5, verificationCose],
    [6, executionCose],
    [7, projected.action_bytes],
    [8, policies.map((entry) => [entry.digest, entry.bytes])],
  ]);
  const bundleBytes = encodeDeterministicCbor(bundle);
  const artifact = {
    '@version': ARTIFACT_VERSION,
    bundle_cbor: bundleBytes.toString('base64url'),
    bundle_sha256: `sha256:${sha256(bundleBytes).toString('hex')}`,
  };
  return { action, artifact, projected, roots, trustDigestString };
}

function registryEntry(kind, definition) {
  return { kind, version: '1', status: 'active', definition, definition_digest: ZERO };
}

function buildWorkspace(native) {
  const profile = {
    version: '0.1.0',
    definition: PROFILE_DEFINITION,
    registry_entry_ref: 'mapping:pinto:cbap1-account-suspension',
    mapper_id: MAPPER_ID,
    resolver: {
      id: RESOLVER_DESCRIPTOR.implementation,
      version: RESOLVER_DESCRIPTOR.version,
      implementation_digest: RESOLVER_DIGEST,
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
    profile_digest: ZERO,
  };
  const config = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:pinto-cbap1-lab',
    evaluator_keys: {
      'crossing-lab:self-test': { public_key: LAB_EVALUATOR_PUBLIC_SPKI },
    },
    registry: {
      '@version': 'EP-EVIDENCE-REGISTRY-v1',
      registry_id: 'registry:pinto-cbap1-lab',
      epoch: 1,
      entries: {
        'mapping:pinto:cbap1-account-suspension': registryEntry('mapping-profile', {
          profile_id: PROFILE_ID,
          native_protocol: NATIVE_PROTOCOL,
          claim_scope: 'historical-contestability-binding-only',
        }),
        'role:contestability-binding': registryEntry('evidence-role', {
          role: 'contestability-binding',
          subject_kinds: ['system'],
          authorization_semantics: false,
        }),
      },
      registry_digest: ZERO,
    },
    accepted_mappers: [MAPPER_ID],
    adapters: {
      [ADAPTER_ID]: {
        version: ADAPTER_VERSION,
        trust_roots: native.roots,
        config: {
          '@version': 'PINTO-CBAP1-ADAPTER-CONFIG-v0.1',
          authorization_trust_profile_digest: native.trustDigestString,
          cbap_profile: 'CBAP-1',
          claim_scope: 'historical-contestability-binding-only',
          expected_abp_digest: EXPECTED_ABP_DIGEST,
          source_txt_sha256: '6a879935dc516df39e7cb95fdc8c45f982165869981d93763746911826b0b052',
          subject_system_id: 'system:account-platform',
        },
        config_digest: ZERO,
        max_status_age_sec: 300,
      },
    },
    profiles: { [PROFILE_ID]: profile },
    requirements: {
      'requirement:historical-contestability-binding': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['contestability-binding'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  const hostile = { ...native.action, policy_event_ref: 'policy-event:substituted' };
  const status = {
    checked_at: '2026-08-29T23:59:00Z',
    expires_at: '2026-08-30T12:00:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    unavailable: false,
  };
  return {
    '@version': 'EMILIA-CROSSING-LAB-LOCAL-WORKSPACE-v1',
    adapter: {
      id: ADAPTER_ID,
      version: ADAPTER_VERSION,
      module: 'adapter.mjs',
      module_digest: ZERO,
    },
    artifact: 'artifact.json',
    artifact_digest: ZERO,
    config,
    evaluated_at: '2026-08-30T00:00:00Z',
    evaluation: {
      operation_id: 'operation:pinto-cbap1:historical-001',
      consumption_nonce: 'nonce:pinto-cbap1:aeb-001',
      initiator_id: 'reviewer:crossing-lab',
      executor_id: 'executor:historical-verifier',
      requirement_ref: 'requirement:historical-contestability-binding',
      profile_id: PROFILE_ID,
      artifact_ref: 'artifact:pinto-cbap1:001',
      caid: native.projected.caid,
      status,
      status_digest: ZERO,
    },
    expected_action: native.action,
    expected_action_digest: ZERO,
    hostile_expected_action: hostile,
    hostile_expected_action_digest: ZERO,
  };
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function materialize(target, flag) {
  mkdirSync(target, { recursive: true, mode: 0o700 });
  const native = buildNativeBundle();
  writeFileSync(join(target, 'artifact.json'), jsonBytes(native.artifact), { flag, mode: 0o600 });
  writeFileSync(join(target, 'workspace.json'), jsonBytes(buildWorkspace(native)), { flag, mode: 0o600 });
  sealCrossingLab(target);
}

function writeFixture() {
  materialize(WORKSPACE, 'wx');
  process.stdout.write('wrote and sealed deterministic Pinto CBAP-1 workspace\n');
}

function checkFixture() {
  const temporaryParent = mkdtempSync(join(tmpdir(), 'pinto-cbap1-fixture-'));
  const temporaryWorkspace = join(temporaryParent, 'workspace');
  try {
    mkdirSync(temporaryWorkspace, { mode: 0o700 });
    copyFileSync(join(WORKSPACE, 'adapter.mjs'), join(temporaryWorkspace, 'adapter.mjs'));
    materialize(temporaryWorkspace, 'wx');
    for (const name of ['adapter.mjs', 'artifact.json', 'workspace.json']) {
      const expected = readFileSync(join(WORKSPACE, name));
      const actual = readFileSync(join(temporaryWorkspace, name));
      if (!expected.equals(actual)) throw new Error(`${name} differs from deterministic regeneration`);
    }
  } finally {
    rmSync(temporaryParent, { recursive: true, force: true });
  }
  process.stdout.write('Pinto CBAP-1 deterministic fixture check passed\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2] ?? '--check';
  if (mode === '--write') writeFixture();
  else if (mode === '--check') checkFixture();
  else {
    process.stderr.write('usage: node generate-fixture.mjs [--write|--check]\n');
    process.exitCode = 1;
  }
}

export { buildNativeBundle, buildWorkspace };
