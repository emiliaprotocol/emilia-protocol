// SPDX-License-Identifier: Apache-2.0
/**
 * Runnable Workload Authorization Grant -00 to AEB token-issuance profile.
 *
 * This is an EMILIA reference implementation. An external execution
 * reproduces these pinned checks but is not an independent implementation.
 */
import crypto, { KeyObject } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  InMemoryAebConsumptionStore,
  digestAeb,
  type AebStatusInput,
} from '../../../packages/verify/aeb-adapter-contract.js';
import {
  WAG_AEB_ADAPTER_VERSION,
  WAG_AEB_CONFIG_VERSION,
  WAG_CAID_MAPPER_ID,
  WAG_CAID_MAPPING_VERSION,
  WAG_DRAFT_REVISION,
  WAG_DRAFT_SOURCE_COMMIT,
  WAG_DRAFT_SOURCE_SHA256,
  WAG_DRAFT_TXT_SHA256,
  WAG_GRANT_TYPE,
  WAG_TRUST_ROOT_VERSION,
  createWagActionDefinition,
  createWagAebAdapter,
  type WagAdapterConfig,
  type WagArtifact,
  type WagTrustRoot,
} from '../../../packages/verify/aeb-wag-adapter.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const REFERENCE_REPORT_PATH = resolve(HERE, 'report.reference.json');
const SOURCE_LOCK_PATH = resolve(ROOT, 'standards/observatory/wag-00-source-lock.v1.json');
const VECTOR_PATH = resolve(ROOT, 'conformance/vectors/wag-aeb.v1.json');
const PROFILE_PATH = resolve(ROOT, 'docs/protocol/wag-aeb-token-issuance-profile-v1.md');
const NOW_SECONDS = 1_800_000_000;
const NOW = new Date(NOW_SECONDS * 1000).toISOString();
const ISSUER = 'https://acme.agents.platform.example';
const SUBJECT = 'wimse://acme.agents.platform.example/agent/7f3d9a2e';
const AS_ISSUER = 'https://as.saas.example';
const TOKEN_ENDPOINT = 'https://as.saas.example/token';
const RESOURCE = 'https://api.saas.example/';
const ACTION_TYPE = 'oauth.access-token.issue.1';
const TEST_PRIVATE_JWK = {
  kty: 'EC',
  x: 'j4jkmhCCN0fBQlcdKW36JQLKmwKkeOas2IWrP8_7eC0',
  y: '6sF35gNnXwU8Sm8gAHg1dEeyM8t8m-vmpn8y3zsBoz8',
  crv: 'P-256',
  d: 'b2R174oHTPWtep7w3QAJvWGHX0yiJuGUNfEkwTFHMvM',
} as const;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Check = {
  id: string;
  category: 'source' | 'positive' | 'hostile' | 'replay' | 'boundary';
  description: string;
  passed: boolean;
  observed: Json;
};
type RunnerInput = {
  runner_name: string;
  runner_affiliation: string;
  runner_revision: string;
  executed_at: string;
};

function sortJson(value: any): Json {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sortJson(value[key])]),
    ) as Json;
  }
  return value as Json;
}

function canonical(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sha256(value: string | Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function fileSha256(path: string): string {
  return crypto.createHash('sha256').update(readFileSync(path)).digest('hex');
}

function exactText(value: string, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256
      || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function exactInstant(value: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)
      || !Number.isFinite(Date.parse(value))) throw new TypeError('executed_at is invalid');
  return value;
}

function spki(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function check(
  id: Check['id'],
  category: Check['category'],
  description: string,
  passed: boolean,
  observed: Json,
): Check {
  return { id, category, description, passed, observed };
}

const config: WagAdapterConfig = Object.freeze({
  '@version': WAG_AEB_CONFIG_VERSION,
  evidence_role: 'workload-authorization-grant',
  issuer: ISSUER,
  tenancy: 'acme',
  wimse_authority: 'acme.agents.platform.example',
  authorization_server_issuer: AS_ISSUER,
  token_endpoint: TOKEN_ENDPOINT,
  resource: RESOURCE,
  action_type: ACTION_TYPE,
  property_claims: ['ctx', 'groups', 'namespace', 'roles'],
  require_wimse_identifier: true,
  clock_skew_seconds: 5,
  max_grant_lifetime_seconds: 300,
  max_status_age_seconds: 120,
});

const trustRoot: WagTrustRoot = Object.freeze({
  '@version': WAG_TRUST_ROOT_VERSION,
  use: 'wag-per-tenancy-issuer-key',
  issuer: ISSUER,
  tenancy: 'acme',
  key_id: 'wag-demo-2026-08-13',
  algorithm: 'ES256',
  public_jwk: {
    kty: 'EC',
    crv: 'P-256',
    x: TEST_PRIVATE_JWK.x,
    y: TEST_PRIVATE_JWK.y,
  } as const,
});

const STATUS: AebStatusInput = Object.freeze({
  checked_at: NOW,
  expires_at: new Date(Date.parse(NOW) + 60_000).toISOString(),
  revocation_checked: true,
  revoked: false,
  consumed: false,
});

function mintGrant(overrides: Record<string, unknown> = {}, headerOverrides: Record<string, unknown> = {}): string {
  const header = { alg: 'ES256', kid: trustRoot.key_id, typ: 'JWT', ...headerOverrides };
  const claims = {
    iss: ISSUER,
    sub: SUBJECT,
    aud: [AS_ISSUER, TOKEN_ENDPOINT],
    exp: NOW_SECONDS + 300,
    iat: NOW_SECONDS,
    jti: '7d0f5a2b-93c8-4f0e-9c33-1b6a0e6d5f10',
    name: 'Support Triage Agent',
    namespace: 'acme/support',
    groups: ['support-eng'],
    roles: ['responder'],
    ctx: 'channel:C0123456789',
    ...overrides,
  };
  const signingInput = [header, claims]
    .map((value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url'))
    .join('.');
  const key = crypto.createPrivateKey({ key: TEST_PRIVATE_JWK, format: 'jwk' });
  const signature = crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), {
    key,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  return `${signingInput}.${signature}`;
}

function artifact(overrides: Partial<WagArtifact> = {}): WagArtifact {
  return { grant_type: WAG_GRANT_TYPE, assertion: mintGrant(), resource: RESOURCE, ...overrides };
}

function claimsFrom(value: WagArtifact): Record<string, any> {
  return JSON.parse(Buffer.from(value.assertion.split('.')[1], 'base64url').toString('utf8'));
}

function expectedAction(value: WagArtifact) {
  const claims = claimsFrom(value);
  return {
    action_type: ACTION_TYPE,
    authorization_server: { issuer: AS_ISSUER, token_endpoint: TOKEN_ENDPOINT },
    grant: {
      issuer: claims.iss,
      subject: claims.sub,
      jti: claims.jti,
      assertion_digest: digestAeb(value.assertion),
    },
    resource: value.resource,
    properties: {
      ctx: claims.ctx,
      groups: claims.groups,
      namespace: claims.namespace,
      roles: claims.roles,
    },
  };
}

function profile() {
  return {
    version: WAG_CAID_MAPPING_VERSION,
    definition: createWagActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:wag-token-issuance-v1',
    mapper_id: WAG_CAID_MAPPER_ID,
    resolver: {
      id: WAG_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: WAG_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE' as const,
      loss_policy: 'NO_MATERIAL_FIELD_LOSS' as const,
      omitted_material_fields: [],
      omitted_nonmaterial_fields: ['grant.aud', 'grant.exp', 'grant.iat', 'grant.name'],
    },
    profile_digest: digestAeb(null),
  };
}

function input(value: WagArtifact, action: unknown = expectedAction(value), status = STATUS) {
  return {
    artifact: value,
    artifact_ref: 'wag:reference-fixture',
    status,
    trust_roots: [trustRoot],
    adapter_config: config,
    expected_action: action,
    now: NOW,
  };
}

function buildResults() {
  const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
  const validArtifact = artifact();
  const validInput = input(validArtifact);
  const validNative = adapter.verifyNative(validInput);
  const validMapping = adapter.mapAction({ ...validInput, profile: profile(), native: validNative });
  const tenantKey = adapter.verifyNative({
    ...validInput,
    trust_roots: [{ ...trustRoot, tenancy: 'other' }],
  });

  function native(changed: WagArtifact, action: unknown = expectedAction(validArtifact), status = STATUS) {
    return adapter.verifyNative(input(changed, action, status));
  }
  const issuer = native(artifact({ assertion: mintGrant({ iss: 'https://other.agents.platform.example' }) }));
  const childArtifact = artifact({
    assertion: mintGrant({
      sub: 'wimse://acme.agents.platform.example/agent/child',
      jti: 'child-jti',
    }),
  });
  const childNative = native(childArtifact, expectedAction(childArtifact));
  const childMapping = adapter.mapAction({
    ...input(childArtifact),
    profile: profile(),
    native: childNative,
  });
  const subject = native(childArtifact, expectedAction(validArtifact));
  const audience = native(artifact({ assertion: mintGrant({ aud: ['https://evil.example'] }) }));
  const resource = native(artifact({ resource: 'https://other.saas.example/' }));
  const changedPropertiesArtifact = artifact({ assertion: mintGrant({ roles: ['admin'] }) });
  const changedPropertiesAction = expectedAction(changedPropertiesArtifact);
  changedPropertiesAction.properties.roles = ['responder'];
  const properties = native(changedPropertiesArtifact, changedPropertiesAction);
  const expired = native(artifact({ assertion: mintGrant({ exp: NOW_SECONDS - 10 }) }));
  const unavailable = native(validArtifact, expectedAction(validArtifact), { ...STATUS, unavailable: true });
  const downstream = native(validArtifact, {
    action_type: 'tool.invoke.1',
    tool: 'payments.transfer',
    parameters: { amount: '100.00', payee: 'acct_9' },
  });
  const wrapperReplay = adapter.verifyNative({ ...validInput, artifact_ref: 'wag:second-wrapper' });
  const store = new InMemoryAebConsumptionStore();
  const replayKey = `aeb-native:${digestAeb({
    relying_party_id: 'rp:wag-aeb-v1',
    replay_unit: validNative.replay_unit,
  })}`;
  const firstAdmission = store.reserve('aeb:wag-reference-1', [replayKey]);
  const secondAdmission = store.reserve('aeb:wag-reference-2', [replayKey]);
  return {
    validNative,
    validMapping,
    tenantKey,
    childNative,
    childMapping,
    issuer,
    subject,
    audience,
    resource,
    properties,
    expired,
    unavailable,
    downstream,
    wrapperReplay,
    firstAdmission,
    secondAdmission,
  };
}

function sourceLockCheck() {
  const source = JSON.parse(readFileSync(SOURCE_LOCK_PATH, 'utf8'));
  return source.draft === WAG_DRAFT_REVISION
    && `sha256:${source.published_txt.sha256}` === WAG_DRAFT_TXT_SHA256
    && source.source.commit === WAG_DRAFT_SOURCE_COMMIT
    && `sha256:${source.source.sha256}` === WAG_DRAFT_SOURCE_SHA256;
}

export function canonicalReportBytes(report: unknown): Buffer {
  return Buffer.from(canonical(report), 'utf8');
}

export function runSuite(inputValue: RunnerInput) {
  const runner = {
    name: exactText(inputValue.runner_name, 'runner_name'),
    affiliation: exactText(inputValue.runner_affiliation, 'runner_affiliation'),
    revision: exactText(inputValue.runner_revision, 'runner_revision'),
    executed_at: exactInstant(inputValue.executed_at),
    execution_owner: 'runner-asserted',
    implementation_owner: 'EMILIA Protocol',
    independent_implementation: false,
  };
  const result = buildResults();
  const checks: Check[] = [
    check('WAG-00-SOURCE-PIN', 'source', 'The adapter pins the exact reviewed WAG -00 source and published bytes.',
      sourceLockCheck(), { revision: WAG_DRAFT_REVISION, source_commit: WAG_DRAFT_SOURCE_COMMIT }),
    check('WAG-VALID-TOKEN-ISSUANCE', 'positive', 'A valid per-tenancy WAG grant maps to one exact token-issuance CAID.',
      result.validNative.native_verification === 'VERIFIED'
        && result.validNative.acceptance === 'ACCEPTED'
        && result.validMapping.mapping === 'MATCH',
      { acceptance: result.validNative.acceptance, mapping: result.validMapping.mapping, caid: result.validMapping.caid }),
    check('WAG-ISSUER-SUBSTITUTION', 'hostile', 'A different issuer cannot use the pinned tenancy key.',
      result.issuer.acceptance === 'REJECTED' && result.issuer.reasons.includes('wag:issuer_mismatch'),
      { acceptance: result.issuer.acceptance, reasons: result.issuer.reasons }),
    check('WAG-TENANT-KEY-SUBSTITUTION', 'hostile', 'A presenter cannot substitute a root from another tenancy.',
      result.tenantKey.acceptance === 'REJECTED'
        && result.tenantKey.reasons.includes('wag:constructor_pin_mismatch'),
      { acceptance: result.tenantKey.acceptance, reasons: result.tenantKey.reasons }),
    check('WAG-UNSEEN-SUBJECT-ACCEPT', 'positive', 'A newly seen signed subject under the allowlisted issuer is accepted without per-agent registration.',
      result.childNative.acceptance === 'ACCEPTED'
        && result.childMapping.mapping === 'MATCH'
        && result.childMapping.caid !== result.validMapping.caid,
      { acceptance: result.childNative.acceptance, mapping: result.childMapping.mapping, caid: result.childMapping.caid }),
    check('WAG-SUBJECT-SUBSTITUTION', 'hostile', 'A child or sibling agent identifier cannot inherit the pinned subject implicitly.',
      result.subject.acceptance === 'REJECTED'
        && result.subject.reasons.includes('wag:token_request_projection_mismatch'),
      { acceptance: result.subject.acceptance, reasons: result.subject.reasons }),
    check('WAG-AUDIENCE-SUBSTITUTION', 'hostile', 'The grant must address the pinned authorization server.',
      result.audience.acceptance === 'REJECTED' && result.audience.reasons.includes('wag:audience_mismatch'),
      { acceptance: result.audience.acceptance, reasons: result.audience.reasons }),
    check('WAG-RESOURCE-SUBSTITUTION', 'hostile', 'Changing the observed RFC 8707 target resource refuses the token request.',
      result.resource.acceptance === 'REJECTED' && result.resource.reasons.includes('wag:resource_mismatch'),
      { acceptance: result.resource.acceptance, reasons: result.resource.reasons }),
    check('WAG-PROPERTY-SUBSTITUTION', 'hostile', 'A material signed Property mismatch refuses rather than granting local permission.',
      result.properties.acceptance === 'REJECTED'
        && result.properties.reasons.includes('wag:token_request_projection_mismatch'),
      { acceptance: result.properties.acceptance, reasons: result.properties.reasons }),
    check('WAG-EXPIRED-GRANT', 'hostile', 'An expired grant is rejected under the pinned clock policy.',
      result.expired.acceptance === 'REJECTED' && result.expired.reasons.includes('wag:grant_expired'),
      { acceptance: result.expired.acceptance, reasons: result.expired.reasons }),
    check('WAG-STATUS-UNAVAILABLE', 'hostile', 'Unavailable current status yields INDETERMINATE, never a guessed acceptance.',
      result.unavailable.acceptance === 'INDETERMINATE',
      { acceptance: result.unavailable.acceptance, reasons: result.unavailable.reasons }),
    check('WAG-REPLAY-IDENTITY', 'replay', 'Wrapper changes do not change the native replay identity.',
      result.validNative.replay_unit === result.wrapperReplay.replay_unit,
      { replay_unit: result.validNative.replay_unit }),
    check('WAG-SECOND-TOKEN-ISSUANCE', 'replay', 'The AEB consumption store refuses a second reservation of the same WAG replay unit.',
      result.firstAdmission === true && result.secondAdmission === false,
      { first_reserved: result.firstAdmission, second_reserved: result.secondAdmission }),
    check('WAG-DOWNSTREAM-ACTION-NON-SUBSTITUTION', 'boundary', 'WAG alone is indeterminate for a downstream tool action.',
      result.downstream.acceptance === 'INDETERMINATE'
        && result.downstream.reasons.includes('wag:does_not_bind_downstream_action'),
      { acceptance: result.downstream.acceptance, reasons: result.downstream.reasons }),
    check('WAG-NOT-HUMAN-APPROVAL', 'boundary', 'The evidence subject and role remain workload-only.',
      result.validNative.subject.kind === 'workload'
        && result.validNative.evidence_role === 'workload-authorization-grant',
      { subject_kind: result.validNative.subject.kind, evidence_role: result.validNative.evidence_role }),
  ];
  const catalog = JSON.parse(readFileSync(VECTOR_PATH, 'utf8')) as { cases: { id: string }[] };
  const catalogIds = catalog.cases.map((entry) => entry.id).sort();
  const checkIds = checks.map((entry) => entry.id).sort();
  if (catalogIds.join('\0') !== checkIds.join('\0')) throw new Error('vector catalog and executable checks disagree');
  const reportBody: any = {
    '@version': 'WAG-AEB-COMPOSITION-REPORT-v1',
    profile: 'wag-aeb-v1',
    runner,
    pins: {
      wag_revision: WAG_DRAFT_REVISION,
      wag_source_commit: WAG_DRAFT_SOURCE_COMMIT,
      wag_published_txt_sha256: WAG_DRAFT_TXT_SHA256,
      wag_source_sha256: WAG_DRAFT_SOURCE_SHA256,
      aeb_adapter_version: WAG_AEB_ADAPTER_VERSION,
      mapping_version: WAG_CAID_MAPPING_VERSION,
      source_lock_sha256: `sha256:${fileSha256(SOURCE_LOCK_PATH)}`,
      profile_sha256: `sha256:${fileSha256(PROFILE_PATH)}`,
      vectors_sha256: `sha256:${fileSha256(VECTOR_PATH)}`,
    },
    checks,
    composition: {
      action_type: ACTION_TYPE,
      action_digest: result.validMapping.action_digest,
      caid: result.validMapping.caid,
      evidence_role: result.validNative.evidence_role,
      subject_kind: result.validNative.subject.kind,
      replay_unit: result.validNative.replay_unit,
      first_admission: result.firstAdmission ? 'RESERVED' : 'REFUSED',
      replay_admission: result.secondAdmission ? 'RESERVED' : 'REFUSED',
    },
    passed: checks.every((entry) => entry.passed),
    known_limits: [
      'This run executes the EMILIA reference implementation and is not an independent implementation.',
      'WAG -00 is an early exploratory individual draft and may change or be withdrawn.',
      'The WAG signature does not cover the RFC 8707 resource parameter. This profile binds the authorization-server-observed resource into the token-issuance CAID.',
      'One-time consumption is an EMILIA composition rule, not a WAG -00 conformance requirement.',
      'WAG proves a workload authorization grant. It does not prove human approval or authorize a downstream tool action by itself.',
      'A passing report is not IETF adoption, employer endorsement, certification, or production-readiness evidence.',
    ],
  };
  const passed = checks.filter((entry) => entry.passed).length;
  reportBody.implementation_status_markdown = `${runner.name} (${runner.affiliation}) reproduced the EMILIA WAG -00 to AEB token-issuance profile at ${runner.revision} on ${runner.executed_at}: ${passed}/${checks.length} checks passed against ${WAG_DRAFT_REVISION} (${WAG_DRAFT_TXT_SHA256}). The run verified per-tenancy issuer and key pinning, exact token-request projection, stable replay identity, second replay-unit reservation refusal, and downstream-action non-substitution. This is a reproduction of the EMILIA reference implementation, not an independent implementation, IETF adoption, or employer endorsement.`;
  reportBody.report_digest = sha256(canonicalReportBytes(reportBody));
  return reportBody;
}

export function signReport(report: any, privateKey: crypto.KeyLike, keyId: string) {
  const bytes = canonicalReportBytes(report);
  const privateKeyObject = privateKey instanceof KeyObject
    ? privateKey
    : crypto.createPrivateKey(privateKey);
  const publicKey = crypto.createPublicKey(privateKeyObject.export({ type: 'pkcs8', format: 'pem' }));
  return {
    report,
    signature: {
      alg: 'Ed25519',
      key_id: exactText(keyId, 'key_id'),
      public_key_spki_b64u: spki(publicKey),
      signed_report_b64u: bytes.toString('base64url'),
      value: crypto.sign(null, bytes, privateKeyObject).toString('base64url'),
    },
  };
}

export function verifyReportSignature(value: any): boolean {
  try {
    if (value?.signature?.alg !== 'Ed25519') return false;
    const bytes = canonicalReportBytes(value.report);
    const claimed = Buffer.from(value.signature.signed_report_b64u, 'base64url');
    if (!bytes.equals(claimed)) return false;
    const key = crypto.createPublicKey({
      key: Buffer.from(value.signature.public_key_spki_b64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, bytes, key, Buffer.from(value.signature.value, 'base64url'));
  } catch { return false; }
}

function argument(name: string): string | undefined {
  const at = process.argv.indexOf(name);
  return at === -1 ? undefined : process.argv[at + 1];
}

function main(): void {
  const report = runSuite({
    runner_name: argument('--runner-name') ?? 'EMILIA reference runner',
    runner_affiliation: argument('--runner-affiliation') ?? 'EMILIA Protocol',
    runner_revision: argument('--runner-revision') ?? 'repository-working-tree',
    executed_at: argument('--executed-at') ?? new Date().toISOString(),
  });
  const signingKeyPath = argument('--signing-key');
  const output = signingKeyPath
    ? signReport(report, readFileSync(resolve(signingKeyPath), 'utf8'), argument('--key-id') ?? 'runner:unspecified')
    : report;
  const outputPath = argument('--output');
  if (outputPath) {
    const resolved = resolve(outputPath);
    writeFileSync(resolved, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
    process.stdout.write(`${resolved}\n`);
  } else {
    process.stdout.write(`${report.implementation_status_markdown}\n`);
  }
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
