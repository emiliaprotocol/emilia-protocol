// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import {
  AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS,
  AEB_CROSSING_RECORD_VERSION,
  AEB_CROSSING_RECORD_V2_VERSION,
  AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION,
  BCR_CROSSING_MAPPING_PROFILE,
  WIMSE_OAUTH_CROSSING_MAPPING_PROFILE,
  crossingRecordContractDigest,
  crossingRecordV2AdmissionDomainDigest,
  crossingRecordV2ContractDigest,
  crossingLifecycleIndexV2AdmissionDomainDigest,
  crossingLifecycleIndexV2ContractDigest,
  crossingLifecycleIndexV2SignedBytes,
  aebCrossingEvaluationReference,
  issueAebCrossingLifecycleIndexV2,
  issueAebCrossingRecordV2,
  issueAebCrossingRecord,
  mapBcrCrossingAuthority,
  mapWimseOAuthCrossingAuthority,
  upgradeAebCrossingRecordV1ToLifecycleIndexV2,
  verifyAebCrossingLifecycleIndexV2,
  verifyAebCrossingRecord,
  verifyAebCrossingRecordV2,
} from "./dist/aeb-crossing-record.js";
import {
  AEB_EVALUATION_VERSION,
  AEB_EVALUATION_V2_VERSION,
  adapterPinDigest,
  aebEvaluationV2Digest,
  digestAeb,
  digestAebTyped,
  evaluateAebEvidence,
  issueAebEvaluationV2FromV1,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  verifyAebEvaluation,
  verifyAebEvaluationV2,
} from "./dist/aeb-adapter-contract.js";
import {
  loadDefaultAgilityMldsaBackend,
  signAgileSet,
} from "./dist/pq-signature-agility.js";

const ED_PRIVATE_JWK = {
  crv: "Ed25519",
  d: "EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y",
  x: "c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI",
  kty: "OKP",
} as const;
const ED_PUBLIC_JWK = {
  crv: "Ed25519",
  x: "c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI",
  kty: "OKP",
} as const;
const edPrivate = crypto.createPrivateKey({
  key: ED_PRIVATE_JWK,
  format: "jwk",
});
const edPublic = crypto.createPublicKey({ key: ED_PUBLIC_JWK, format: "jwk" });
const edPublicSpki = edPublic
  .export({ type: "spki", format: "der" })
  .toString("base64url");
const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x41));
const pqPublic = Buffer.from(pqPair.publicKey).toString("base64url");
const mldsaBackend = await loadDefaultAgilityMldsaBackend();

assert.ok(mldsaBackend, "real ML-DSA-65 backend must be available");

const NOW = "2026-08-19T05:00:00Z";
const ACTION = Object.freeze({
  caid: "caid:1:finance.vendor-account-change.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  action_digest: `sha256:${"11".repeat(32)}`,
});
const BOUNDARY = Object.freeze({
  relying_party_id: "rp:example-finance",
  audience: "erp:vendor-master",
  executor_id: "executor:erp-production",
  state_domain_id: "state-domain:finance-primary",
});
const REQUIREMENTS = Object.freeze({
  admission_digest: `sha256:${"22".repeat(32)}`,
  review_digest: `sha256:${"33".repeat(32)}`,
});
const CONFIGURATION_DIGESTS = Object.freeze([
  `sha256:${"44".repeat(32)}`,
  `sha256:${"55".repeat(32)}`,
]);
const EVALUATED_EVIDENCE_DIGESTS = Object.freeze([
  `sha256:${"66".repeat(32)}`,
  `sha256:${"77".repeat(32)}`,
]);
const ADMISSION_DIGEST = `sha256:${"88".repeat(32)}`;
const CONSUMPTION_DIGEST = `sha256:${"99".repeat(32)}`;
const EVALUATION_V2_DIGEST = `sha256:${"de".repeat(32)}`;

const SIGNERS = [
  { alg: "Ed25519", key_id: "crossing-ed", private_key: edPrivate },
  { alg: "ML-DSA-65", key_id: "crossing-pq", private_key: pqPair.secretKey },
] as const;
const VERIFICATION_KEYS = [
  { alg: "Ed25519", key_id: "crossing-ed", public_key: edPublicSpki },
  { alg: "ML-DSA-65", key_id: "crossing-pq", public_key: pqPublic },
] as const;

const ADMIT_AXES = Object.freeze({
  native_verification: "VERIFIED",
  rp_acceptance: "ACCEPTED",
  action_relation: "EXACT_MATCH",
  status: "CURRENT",
  replay: "FRESH",
  admission: "ADMIT",
  custody: "RESERVED",
  provider_commitment: "NOT_INVOKED",
  observed_effect: "NOT_OBSERVED",
  retry: "NOT_APPLICABLE",
  reconciliation: "NOT_APPLICABLE",
  reason_codes: [],
} as const);

function wimseAuthority(tokenDigest = `sha256:${"aa".repeat(32)}`) {
  const mapped = mapWimseOAuthCrossingAuthority({
    native_verification: "VERIFIED",
    rp_acceptance: "ACCEPTED",
    authorization_server: "https://as.example",
    subject: "spiffe://example/agent/accounting",
    token_id: "txn-token-123",
    token_digest: tokenDigest,
    mapping_profile_digest: `sha256:${"ab".repeat(32)}`,
    constraints_digest: `sha256:${"ac".repeat(32)}`,
    status: {
      value: "CURRENT",
      checked_at: NOW,
      source_head_digest: `sha256:${"ad".repeat(32)}`,
    },
    validity: {
      not_before: "2026-08-19T04:55:00Z",
      not_after: "2026-08-19T05:05:00Z",
    },
  });
  assert.equal(mapped.ok, true, JSON.stringify(mapped));
  return mapped.authority;
}

function bcrAuthority() {
  const mapped = mapBcrCrossingAuthority({
    native_verification: "VERIFIED",
    rp_acceptance: "ACCEPTED",
    issuer: "authority:finance-controller",
    subject: "agent:accounting-17",
    capability_id: "capability:vendor-master-7",
    generation: 3,
    receipt_digest: `sha256:${"ba".repeat(32)}`,
    mapping_profile_digest: `sha256:${"bb".repeat(32)}`,
    constraints_digest: `sha256:${"bc".repeat(32)}`,
    status: {
      value: "CURRENT",
      checked_at: NOW,
      source_head_digest: `sha256:${"bd".repeat(32)}`,
    },
    validity: {
      not_before: "2026-08-19T04:50:00Z",
      not_after: "2026-08-19T05:10:00Z",
    },
  });
  assert.equal(mapped.ok, true, JSON.stringify(mapped));
  return mapped.authority;
}

async function issue(
  authority = wimseAuthority(),
  overrides: Record<string, unknown> = {},
) {
  return issueAebCrossingRecord(
    {
      record_id: "crossing:finance:0001",
      operation_id: "operation:vendor-master:0001",
      issued_at: NOW,
      native_authority: authority,
      action: ACTION,
      boundary: BOUNDARY,
      requirements: REQUIREMENTS,
      admission_reference: { state: "PRESENT", digest: ADMISSION_DIGEST },
      lifecycle_records: {
        evaluation_digest: `sha256:${"ee".repeat(32)}`,
        consumption_digest: CONSUMPTION_DIGEST,
        provider_entry_digest: null,
      },
      evaluated_evidence_digests: EVALUATED_EVIDENCE_DIGESTS,
      configuration_digests: CONFIGURATION_DIGESTS,
      referee: ADMIT_AXES,
      ...overrides,
    },
    {
      signing_keys: [...SIGNERS],
      deterministic: true,
      mldsaBackend,
    },
  );
}

async function verify(record: unknown) {
  return verifyAebCrossingRecord(record, {
    verification_keys: [...VERIFICATION_KEYS],
    mldsaBackend,
  });
}

async function issueV2(
  overrides: Record<string, unknown> = {},
  contextOverrides: Record<string, unknown> = {},
) {
  const draft = {
    record_id: "crossing:finance:v2:0001",
    operation_id: "operation:vendor-master:v2:0001",
    issued_at: NOW,
    native_authority: wimseAuthority(),
    action: ACTION,
    boundary: BOUNDARY,
    requirements: REQUIREMENTS,
    admission_reference: { state: "PRESENT", digest: ADMISSION_DIGEST },
    lifecycle_records: {
      evaluation_digest: `sha256:${"ee".repeat(32)}`,
      consumption_digest: CONSUMPTION_DIGEST,
      provider_entry_digest: null,
    },
    evaluated_evidence_digests: EVALUATED_EVIDENCE_DIGESTS,
    configuration_digests: CONFIGURATION_DIGESTS,
    referee: ADMIT_AXES,
    ...overrides,
  };
  return issueAebCrossingRecordV2(
    draft,
    {
      action: ACTION,
      admission_domain: BOUNDARY,
      ...contextOverrides,
    },
    {
      signing_keys: [...SIGNERS],
      deterministic: true,
      mldsaBackend,
    },
  );
}

async function issueLifecycleIndex(
  overrides: Record<string, unknown> = {},
  contextOverrides: Record<string, unknown> = {},
) {
  const evaluation = {
    profile: AEB_EVALUATION_V2_VERSION,
    digest: EVALUATION_V2_DIGEST,
  } as const;
  return issueAebCrossingLifecycleIndexV2(
    {
      record_id: "crossing-lifecycle:finance:0001",
      operation_id: "operation:vendor-master:v2:0001",
      issued_at: NOW,
      action: ACTION,
      lifecycle: {
        evaluation,
        local_admission_digest: ADMISSION_DIGEST,
        authority_custody: {
          phase: "RESERVATION",
          digest: CONSUMPTION_DIGEST,
        },
        provider_entry_digest: null,
        effect_observation_digest: null,
        provider_outcome_digest: null,
        reconciliation_digest: null,
      },
      source_crossing_record: { version: null, digest: null },
      conversion: { status: "NATIVE", reason_codes: [] },
      execution_authorizing: false,
      ...overrides,
    },
    {
      action: ACTION,
      admission_domain: BOUNDARY,
      evaluation,
      ...contextOverrides,
    },
    {
      signing_keys: [...SIGNERS],
      deterministic: true,
      mldsaBackend,
    },
  );
}

// A real, signed AEB-EVALUATION-v1 fixture. The crossing verifier joins a
// supplied evaluation by digest, operation, CAID, action commitment, and the
// native-authority evidence digest of one evaluated leg.
const EVALUATION_ADAPTER_ID = "test:crossing-native";
const EVALUATION_PROFILE_ID = "test:crossing-mapping";
const EVALUATION_ARTIFACT_REF = "artifact:native-authority";
const EVALUATION_ARTIFACT = Object.freeze({
  root: "root:crossing-native",
  role: "native-authority",
  caid: ACTION.caid,
  action_digest: ACTION.action_digest,
  replay_id: "txn-token-123",
  subject: { id: "workload:accounting", kind: "workload" },
});
const EVALUATION_TOKEN_DIGEST = digestAeb(EVALUATION_ARTIFACT);
const UNRELATED_CAID =
  "caid:1:order.purchase.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

function evaluationStatus(overrides: Record<string, unknown> = {}) {
  return {
    checked_at: "2026-08-19T04:59:00Z",
    expires_at: "2026-08-19T06:00:00Z",
    revocation_checked: true,
    revoked: false,
    consumed: false,
    ...overrides,
  };
}

function evaluationAdapter() {
  return {
    id: EVALUATION_ADAPTER_ID,
    version: "1",
    verifyNative({ artifact, status, trust_roots }: any) {
      const trusted = trust_roots.includes(artifact.root);
      return {
        native_verification: trusted ? "VERIFIED" : "FAILED",
        acceptance: trusted ? "ACCEPTED" : "REJECTED",
        evidence_digest: digestAeb(artifact),
        status_digest: digestAeb({
          checked_at: status.checked_at,
          expires_at: status.expires_at,
          revocation_checked: status.revocation_checked,
          revoked: status.revoked,
          consumed: status.consumed,
          unavailable: status.unavailable === true,
        }),
        evidence_role: artifact.role,
        subject: artifact.subject,
        replay_unit: digestAeb({
          adapter: EVALUATION_ADAPTER_ID,
          replay_id: artifact.replay_id,
        }),
        reasons: trusted ? [] : ["native_trust_root_not_pinned"],
      };
    },
    mapAction({ artifact, native }: any) {
      return {
        mapping: native.native_verification === "VERIFIED" ? "MATCH" : "INDETERMINATE",
        caid: artifact.caid,
        action_digest: artifact.action_digest,
        reasons: [],
      };
    },
  };
}

function evaluationRegistryEntry(
  entryId: string,
  kind: string,
  definition: Record<string, unknown>,
) {
  const entry: Record<string, unknown> = {
    kind,
    version: "1",
    status: "active",
    definition,
  };
  entry.definition_digest = registryEntryDigest(entryId, entry as any);
  return entry;
}

function evaluationConfig() {
  const profile: Record<string, any> = {
    version: "crossing-mapping-v1",
    definition: { source: "crossing-record-test" },
    registry_entry_ref: "mapping:test:crossing",
    mapper_id: "mapper:test:crossing",
    resolver: {
      id: "resolver:test:crossing",
      version: "1",
      implementation_digest: digestAeb({ implementation: "resolver:test:crossing:1" }),
    },
    semantic_equivalence: {
      assertion: "EQUIVALENT_UNDER_PROFILE",
      loss_policy: "NO_MATERIAL_FIELD_LOSS",
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
  };
  profile.profile_digest = mappingProfileDigest(EVALUATION_PROFILE_ID, profile as any);
  const registry: Record<string, any> = {
    "@version": "EP-EVIDENCE-REGISTRY-v1",
    registry_id: "registry:crossing-test",
    epoch: 1,
    entries: {
      "mapping:test:crossing": evaluationRegistryEntry(
        "mapping:test:crossing",
        "mapping-profile",
        { profile_digest: profile.profile_digest },
      ),
      "role:native-authority": evaluationRegistryEntry(
        "role:native-authority",
        "evidence-role",
        { role: "native-authority", subject_kinds: ["workload"] },
      ),
    },
  };
  registry.registry_digest = unifiedRegistryDigest(registry as any);
  const pin: Record<string, any> = {
    version: "1",
    trust_roots: ["root:crossing-native"],
    config: { mode: "offline" },
    max_status_age_sec: 3600,
  };
  pin.config_digest = adapterPinDigest(EVALUATION_ADAPTER_ID, pin as any);
  return {
    "@version": "AEB-ADAPTER-v1",
    relying_party_id: BOUNDARY.relying_party_id,
    evaluator_keys: { "eval:crossing": { public_key: edPublicSpki } },
    registry,
    accepted_mappers: ["mapper:test:crossing"],
    adapters: { [EVALUATION_ADAPTER_ID]: pin },
    profiles: { [EVALUATION_PROFILE_ID]: profile },
    requirements: {
      "req:crossing": {
        "@version": "AEB-REQUIREMENT-v1",
        all_of: ["native-authority"],
        terms: [{ type: "one-time-consumption" }],
      },
    },
  } as any;
}

function evaluationFor(
  operationId: string,
  options: { caid?: string; status?: Record<string, unknown> } = {},
) {
  const config = evaluationConfig();
  const result = evaluateAebEvidence({
    config,
    adapters: { [EVALUATION_ADAPTER_ID]: evaluationAdapter() } as any,
    operation_id: operationId,
    consumption_nonce: `nonce:${operationId}`,
    initiator_id: "agent:accounting-17",
    requirement_ref: "req:crossing",
    caid: options.caid ?? ACTION.caid,
    legs: [
      {
        adapter_id: EVALUATION_ADAPTER_ID,
        profile_id: EVALUATION_PROFILE_ID,
        artifact_ref: EVALUATION_ARTIFACT_REF,
        artifact: EVALUATION_ARTIFACT,
        status: evaluationStatus(options.status) as any,
      },
    ],
    evaluated_at: NOW,
    signer: { key_id: "eval:crossing", private_key: edPrivate },
  });
  return { config, record: result.record };
}

function boundLifecycleRecords(evaluationRecord: unknown) {
  return {
    evaluation_digest: digestAeb(evaluationRecord),
    consumption_digest: CONSUMPTION_DIGEST,
    provider_entry_digest: null,
  };
}

async function signIndexBody(body: Record<string, any>) {
  return {
    "@version": AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION,
    body,
    signatures: await signAgileSet(
      crossingLifecycleIndexV2SignedBytes(body as any),
      [...SIGNERS] as any,
      { deterministic: true, mldsaBackend },
    ),
  };
}

test("both native mappings emit one carrier-neutral authority contract", () => {
  const wimse = wimseAuthority();
  const bcr = bcrAuthority();

  assert.equal(wimse.mapping_profile_id, WIMSE_OAUTH_CROSSING_MAPPING_PROFILE);
  assert.equal(bcr.mapping_profile_id, BCR_CROSSING_MAPPING_PROFILE);
  assert.deepEqual(Object.keys(wimse).sort(), Object.keys(bcr).sort());
  assert.notEqual(
    wimse.authority_instance_digest,
    bcr.authority_instance_digest,
  );
  assert.notEqual(wimse.replay_unit, bcr.replay_unit);
});

test("replay-unit derivation is byte-stable for the same native authority", () => {
  assert.equal(wimseAuthority().replay_unit, wimseAuthority().replay_unit);
  assert.equal(bcrAuthority().replay_unit, bcrAuthority().replay_unit);
  assert.equal(
    wimseAuthority().replay_unit,
    digestAebTyped(
      {
        authorization_server: "https://as.example",
        token_id: "txn-token-123",
      },
      `${WIMSE_OAUTH_CROSSING_MAPPING_PROFILE}:replay-unit`,
    ),
  );
});

test("a hybrid crossing record verifies offline under caller-pinned keys", async () => {
  const record = await issue();
  assert.equal(record["@version"], AEB_CROSSING_RECORD_VERSION);
  assert.deepEqual(
    record.body.signature_profile.required_algorithms,
    AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS,
  );
  assert.deepEqual(
    record.signatures.map((signature) => signature.alg),
    AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS,
  );
  const result = await verify(record);
  assert.equal(result.verified, true, JSON.stringify(result));
  assert.equal(result.checks.signature_set, true);
  assert.equal(result.checks.contract_digest, true);
  assert.equal(result.execution_authorizing, false);
});

test("different native authority systems produce different records accepted by the same verifier", async () => {
  const wimse = await issue(wimseAuthority());
  const bcr = await issue(bcrAuthority(), {
    record_id: "crossing:finance:0002",
  });
  assert.notDeepEqual(wimse.body.native_authority, bcr.body.native_authority);
  assert.notEqual(wimse.body.contract_digest, bcr.body.contract_digest);
  assert.equal((await verify(wimse)).verified, true);
  assert.equal((await verify(bcr)).verified, true);
});

test("the v1 contract digest remains compatible across relying-party labels", () => {
  const authority = wimseAuthority();
  const common = {
    native_authority: authority,
    action: ACTION,
    requirements: REQUIREMENTS,
  };
  const finance = crossingRecordContractDigest({
    ...common,
    boundary: BOUNDARY,
  });
  const attacker = crossingRecordContractDigest({
    ...common,
    boundary: {
      ...BOUNDARY,
      relying_party_id: "rp:attacker-controlled",
    },
  });
  assert.equal(finance, attacker);
  assert.equal(
    finance,
    "sha256:0d17ad047e432fd235d60ae06ab6f819691d90dc3b09ecf553b33d4d2c0472fc",
  );
});

test("v2 recomputes an explicit admission-domain commitment", async () => {
  const record = await issueV2();
  assert.equal(record["@version"], AEB_CROSSING_RECORD_V2_VERSION);
  assert.equal(
    record.body.admission_domain_digest,
    crossingRecordV2AdmissionDomainDigest(BOUNDARY),
  );
  assert.equal(
    record.body.contract_digest,
    crossingRecordV2ContractDigest(record.body),
  );
  const result = await verifyAebCrossingRecordV2(record, {
    verification_keys: [...VERIFICATION_KEYS],
    mldsaBackend,
  });
  assert.equal(result.verified, true, JSON.stringify(result));
  assert.equal(result.checks.admission_domain, true);
  assert.equal(result.execution_authorizing, false);
});

test("generic v2 issuance refuses action and admission-domain mismatch before signing", async () => {
  await assert.rejects(
    () =>
      issueV2({}, {
        action: { ...ACTION, action_digest: `sha256:${"01".repeat(32)}` },
      }),
    /action_mismatch/,
  );
  for (const [member, value] of [
    ["relying_party_id", "rp:other"],
    ["audience", "erp:other"],
    ["executor_id", "executor:other"],
    ["state_domain_id", "state-domain:other"],
  ] as const) {
    await assert.rejects(
      () =>
        issueV2({}, {
          admission_domain: { ...BOUNDARY, [member]: value },
        }),
      /admission_domain_mismatch/,
      member,
    );
  }
  await assert.rejects(
    () =>
      issueV2({}, {
        admission_domain: { ...BOUNDARY, region: "us-west" },
      }),
    /admission_domain_mismatch/,
  );
});

test("v2 refuses admission-domain, action, authority, and freshness substitution", async () => {
  const record = await issueV2();
  const mutations = [
    (value: typeof record) => { value.body.boundary.relying_party_id = "rp:other"; },
    (value: typeof record) => { value.body.boundary.audience = "erp:other"; },
    (value: typeof record) => { value.body.boundary.executor_id = "executor:other"; },
    (value: typeof record) => { value.body.boundary.state_domain_id = "state-domain:other"; },
    (value: typeof record) => { value.body.action.action_digest = `sha256:${"01".repeat(32)}`; },
    (value: typeof record) => { value.body.native_authority.authority_instance_digest = `sha256:${"02".repeat(32)}`; },
    (value: typeof record) => { value.body.native_authority.status.value = "STALE"; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(record);
    mutate(changed);
    const result = await verifyAebCrossingRecordV2(changed, {
      verification_keys: [...VERIFICATION_KEYS],
      mldsaBackend,
    });
    assert.equal(result.verified, false);
  }
});

test("v2 issuance never executes draft accessors to rewrite trusted action pins", async () => {
  const record = await issueV2();
  const { signature_profile, contract_digest, admission_domain_digest, ...draft } = record.body;
  const context = { action: { ...ACTION }, admission_domain: { ...BOUNDARY } };
  const replacement = { ...ACTION, action_digest: `sha256:${"01".repeat(32)}` };
  let reads = 0;
  Object.defineProperty(draft, "action", {
    enumerable: true,
    get() { reads++; Object.assign(context.action, replacement); return replacement; },
  });
  await assert.rejects(() => issueAebCrossingRecordV2(draft, context, {
    signing_keys: [...SIGNERS], mldsaBackend,
  }));
  assert.equal(reads, 0);
  assert.deepEqual(context.action, ACTION);
});

test("v2 issuance snapshots action pins before inspecting a hostile draft", async () => {
  const record = await issueV2();
  const { signature_profile, contract_digest, admission_domain_digest, ...draft } = record.body;
  const context = { action: { ...ACTION }, admission_domain: { ...BOUNDARY } };
  draft.action = { ...ACTION, action_digest: `sha256:${"01".repeat(32)}` };
  const hostile = new Proxy(draft, {
    ownKeys(target) { Object.assign(context.action, target.action); return Reflect.ownKeys(target); },
  });
  await assert.rejects(() => issueAebCrossingRecordV2(hostile, context, {
    signing_keys: [...SIGNERS], mldsaBackend,
  }));
});

test("v2 issuance snapshots signing keys before asynchronous signing yields", async () => {
  const record = await issueV2();
  const { signature_profile, contract_digest, admission_domain_digest, ...draft } = record.body;
  const options = {
    signing_keys: SIGNERS.map((key) => ({ ...key })),
    mldsaBackend,
  };
  const pending = issueAebCrossingRecordV2(draft, {
    action: ACTION, admission_domain: BOUNDARY,
  }, options);
  options.signing_keys.length = 0;
  const result = await pending;
  assert.equal(result.signatures.length, 2);
  assert.equal((await verifyAebCrossingRecordV2(result, {
    verification_keys: [...VERIFICATION_KEYS], mldsaBackend,
  })).verified, true);
});

test("v1 and v2 reject downgrade, relabeling, and cross-version verification", async () => {
  const v1 = await issue();
  const v2 = await issueV2();
  assert.equal((await verify(v2)).verified, false);
  assert.equal((await verifyAebCrossingRecordV2(v1, {
    verification_keys: [...VERIFICATION_KEYS], mldsaBackend,
  })).verified, false);

  const relabeledV1 = structuredClone(v1) as any;
  relabeledV1["@version"] = AEB_CROSSING_RECORD_V2_VERSION;
  assert.equal((await verifyAebCrossingRecordV2(relabeledV1, {
    verification_keys: [...VERIFICATION_KEYS], mldsaBackend,
  })).verified, false);

  const relabeledV2 = structuredClone(v2) as any;
  relabeledV2["@version"] = AEB_CROSSING_RECORD_VERSION;
  assert.equal((await verify(relabeledV2)).verified, false);
});

test("the lifecycle index references separate records without flattening native authority or policy", async () => {
  const index = await issueLifecycleIndex();
  assert.equal(
    index["@version"],
    AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION,
  );
  assert.equal(index.body.execution_authorizing, false);
  assert.equal("native_authority" in index.body, false);
  assert.equal("referee" in index.body, false);
  assert.equal("boundary" in index.body, false);
  assert.equal(
    index.body.admission_domain_digest,
    crossingLifecycleIndexV2AdmissionDomainDigest(BOUNDARY),
  );
  assert.equal(
    index.body.contract_digest,
    crossingLifecycleIndexV2ContractDigest(index.body),
  );
  const result = await verifyAebCrossingLifecycleIndexV2(index, {
    verification_keys: [...VERIFICATION_KEYS],
    expected_action: ACTION,
    admission_domain: BOUNDARY,
    expected_evaluation: index.body.lifecycle.evaluation,
    mldsaBackend,
  });
  assert.equal(result.verified, true, JSON.stringify(result));
  assert.equal(result.execution_authorizing, false);
  assert.equal(result.conversion_status, "NATIVE");
});

test("the lifecycle index refuses action, admission-domain, evaluation, and digest substitution", async () => {
  const index = await issueLifecycleIndex();
  const baseOptions = {
    verification_keys: [...VERIFICATION_KEYS],
    expected_action: ACTION,
    admission_domain: BOUNDARY,
    expected_evaluation: index.body.lifecycle.evaluation,
    mldsaBackend,
  };
  assert.equal((await verifyAebCrossingLifecycleIndexV2(index, {
    ...baseOptions,
    expected_action: {
      ...ACTION,
      action_digest: `sha256:${"01".repeat(32)}`,
    },
  })).reason, "action_mismatch");
  assert.equal((await verifyAebCrossingLifecycleIndexV2(index, {
    ...baseOptions,
    admission_domain: { ...BOUNDARY, audience: "erp:other" },
  })).reason, "admission_domain_mismatch");
  assert.equal((await verifyAebCrossingLifecycleIndexV2(index, {
    ...baseOptions,
    expected_evaluation: {
      ...index.body.lifecycle.evaluation,
      digest: `sha256:${"02".repeat(32)}`,
    },
  })).reason, "evaluation_reference_mismatch");

  for (const mutate of [
    (value: typeof index) => {
      value.body.lifecycle.local_admission_digest = `sha256:${"03".repeat(32)}`;
    },
    (value: typeof index) => {
      value.body.lifecycle.authority_custody.digest = `sha256:${"04".repeat(32)}`;
    },
    (value: typeof index) => {
      value.body.lifecycle.provider_entry_digest = `sha256:${"05".repeat(32)}`;
    },
  ]) {
    const changed = structuredClone(index);
    mutate(changed);
    const result = await verifyAebCrossingLifecycleIndexV2(changed, baseOptions);
    assert.equal(result.verified, false);
  }
});

test("the lifecycle index refuses impossible ordering before signing", async () => {
  const evaluation = {
    profile: AEB_EVALUATION_V2_VERSION,
    digest: EVALUATION_V2_DIGEST,
  } as const;
  await assert.rejects(
    () => issueLifecycleIndex({
      lifecycle: {
        evaluation,
        local_admission_digest: ADMISSION_DIGEST,
        authority_custody: {
          phase: "RESERVATION",
          digest: CONSUMPTION_DIGEST,
        },
        provider_entry_digest: null,
        effect_observation_digest: null,
        provider_outcome_digest: `sha256:${"06".repeat(32)}`,
        reconciliation_digest: null,
      },
    }),
    /lifecycle_order_invalid/,
  );
});

test("v1 upgrade preserves resolvable lifecycle references and reports unrecoverable state", async () => {
  const source = await issue();
  const converted = await upgradeAebCrossingRecordV1ToLifecycleIndexV2(
    source,
    {
      signing_keys: [...SIGNERS],
      source_verification_keys: [...VERIFICATION_KEYS],
      deterministic: true,
      mldsaBackend,
    },
  );
  // Without the source evaluation, v1's unlabeled evaluation digest is
  // carried as an unverified reference: no profile label is invented and the
  // conversion is not COMPLETE.
  assert.equal(converted.body.conversion.status, "INDETERMINATE");
  assert.deepEqual(converted.body.conversion.reason_codes, [
    "evaluation_reference_unverified",
  ]);
  assert.equal(
    converted.body.source_crossing_record.version,
    AEB_CROSSING_RECORD_VERSION,
  );
  assert.equal(converted.body.lifecycle.evaluation.profile, null);
  assert.equal(
    converted.body.lifecycle.evaluation.digest,
    source.body.lifecycle_records.evaluation_digest,
  );
  assert.equal(
    converted.body.lifecycle.authority_custody.phase,
    "RESERVATION",
  );
  assert.equal((await verify(source)).verified, true, "v1 remains valid");
  const convertedResult = await verifyAebCrossingLifecycleIndexV2(converted, {
    verification_keys: [...VERIFICATION_KEYS],
    expected_action: ACTION,
    admission_domain: BOUNDARY,
    expected_evaluation: converted.body.lifecycle.evaluation,
    mldsaBackend,
  });
  assert.equal(convertedResult.verified, true, JSON.stringify(convertedResult));
  assert.equal(convertedResult.conversion_status, "INDETERMINATE");
  assert.equal(convertedResult.evaluation_binding, "INDETERMINATE");

  const terminal = await issue(wimseAuthority(), {
    lifecycle_records: {
      evaluation_digest: `sha256:${"ee".repeat(32)}`,
      consumption_digest: CONSUMPTION_DIGEST,
      provider_entry_digest: `sha256:${"07".repeat(32)}`,
    },
    referee: {
      ...ADMIT_AXES,
      custody: "TERMINAL",
      provider_commitment: "COMMITTED",
      retry: "REFUSE",
    },
  });
  const terminalConverted =
    await upgradeAebCrossingRecordV1ToLifecycleIndexV2(terminal, {
      signing_keys: [...SIGNERS],
      source_verification_keys: [...VERIFICATION_KEYS],
      deterministic: true,
      mldsaBackend,
    });
  assert.equal(terminalConverted.body.conversion.status, "INDETERMINATE");
  assert.ok(
    terminalConverted.body.conversion.reason_codes.includes(
      "provider_outcome_reference_unavailable",
    ),
  );
  assert.equal(
    terminalConverted.body.lifecycle.authority_custody.phase,
    "CONSUMPTION",
  );
});

test("v1 lifecycle upgrade refuses an unverified source", async () => {
  const source = await issue();
  const tampered = structuredClone(source);
  tampered.signatures[0].sig = tampered.signatures[0].sig.replace(/.$/, "A");
  await assert.rejects(
    () => upgradeAebCrossingRecordV1ToLifecycleIndexV2(tampered, {
      signing_keys: [...SIGNERS],
      source_verification_keys: [...VERIFICATION_KEYS],
      deterministic: true,
      mldsaBackend,
    }),
    /source_crossing_record_unverified/,
  );
});

test("crossing records and lifecycle indexes cannot be relabeled across profiles", async () => {
  const v1 = await issue();
  const v2 = await issueV2();
  const index = await issueLifecycleIndex();
  const indexOptions = {
    verification_keys: [...VERIFICATION_KEYS],
    expected_action: ACTION,
    admission_domain: BOUNDARY,
    expected_evaluation: index.body.lifecycle.evaluation,
    mldsaBackend,
  };
  assert.equal((await verify(index)).verified, false);
  assert.equal((await verifyAebCrossingRecordV2(index, {
    verification_keys: [...VERIFICATION_KEYS],
    mldsaBackend,
  })).verified, false);
  for (const crossing of [v1, v2]) {
    const relabeled = structuredClone(crossing) as any;
    relabeled["@version"] = AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION;
    assert.equal(
      (await verifyAebCrossingLifecycleIndexV2(relabeled, indexOptions)).verified,
      false,
    );
  }
  const stripped = structuredClone(index);
  stripped.signatures = stripped.signatures.filter(
    (signature) => signature.alg === "Ed25519",
  );
  assert.equal(
    (await verifyAebCrossingLifecycleIndexV2(stripped, indexOptions)).reason,
    "hybrid_leg_missing",
  );
});

test("the committed v2 vector catalog covers the direct hostile cases", () => {
  const vectors = JSON.parse(
    readFileSync(
      new URL(
        "../../conformance/composition/aeb-crossing-record-v2/cases.catalog.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(vectors.record_version, AEB_CROSSING_RECORD_V2_VERSION);
  assert.deepEqual(
    new Set(vectors.cases.map((entry: { id: string }) => entry.id)),
    new Set([
      "V2-VALID",
      "V2-RELYING-PARTY-SUBSTITUTION",
      "V2-AUDIENCE-SUBSTITUTION",
      "V2-EXECUTOR-SUBSTITUTION",
      "V2-STATE-DOMAIN-SUBSTITUTION",
      "V2-ACTION-SUBSTITUTION",
      "V2-AUTHORITY-CONTEXT-SUBSTITUTION",
      "V2-STALE-ADMISSION",
      "V2-AS-V1",
      "V1-AS-V2",
      "V1-RELABEL-V2",
      "V2-RELABEL-V1",
      "V2-EVALUATION-UNCHECKED-INDETERMINATE",
      "V2-EVALUATION-BOUND",
      "V2-UNRELATED-EVALUATION",
      "V2-EVALUATION-DIGEST-MISMATCH",
      "V2-AUTHORITY-NOT-IN-EVALUATION",
      "V2-ADMIT-UNSATISFIED-EVALUATION",
    ]),
  );
});

test("signature stripping and algorithm-set narrowing both refuse", async () => {
  const record = await issue();
  const stripped = structuredClone(record);
  stripped.signatures = stripped.signatures.filter(
    (signature) => signature.alg === "Ed25519",
  );
  assert.equal((await verify(stripped)).reason, "hybrid_leg_missing");

  const narrowed = structuredClone(record);
  narrowed.body.signature_profile.required_algorithms = ["Ed25519"];
  narrowed.signatures = narrowed.signatures.filter(
    (signature) => signature.alg === "Ed25519",
  );
  assert.equal((await verify(narrowed)).reason, "algorithm_set_mismatch");
});

test("action, replay-unit, and mapping-profile substitution refuse", async () => {
  const record = await issue();
  for (const mutate of [
    (value: typeof record) => {
      value.body.action.action_digest = `sha256:${"01".repeat(32)}`;
    },
    (value: typeof record) => {
      value.body.native_authority.replay_unit = `sha256:${"02".repeat(32)}`;
    },
    (value: typeof record) => {
      value.body.native_authority.mapping_profile_digest = `sha256:${"03".repeat(32)}`;
    },
  ]) {
    const changed = structuredClone(record);
    mutate(changed);
    const result = await verify(changed);
    assert.equal(result.verified, false);
    assert.ok(
      ["contract_digest_mismatch", "signature_invalid"].includes(
        result.reason ?? "",
      ),
      result.reason ?? "",
    );
  }
});

test("stale native status remains STALE and cannot be flattened into an admitted result", async () => {
  const authority = wimseAuthority();
  authority.status = { ...authority.status, value: "STALE" };
  const staleRefusal = await issue(authority, {
    admission_reference: { state: "NOT_APPLICABLE", digest: null },
    lifecycle_records: {
      evaluation_digest: `sha256:${"ee".repeat(32)}`,
      consumption_digest: null,
      provider_entry_digest: null,
    },
    referee: {
      ...ADMIT_AXES,
      status: "STALE",
      admission: "REFUSE",
      custody: "UNRESERVED",
      reason_codes: ["status_stale"],
    },
  });
  assert.equal((await verify(staleRefusal)).verified, true);
  assert.equal(staleRefusal.body.referee.status, "STALE");

  await assert.rejects(() => issue(authority), /status_inconsistent/);
});

test("an admitted crossing requires a PRESENT admission reference and consumption record", async () => {
  await assert.rejects(
    () =>
      issue(wimseAuthority(), {
        admission_reference: { state: "MISSING", digest: null },
      }),
    /admission_reference_invalid/,
  );
  await assert.rejects(
    () =>
      issue(wimseAuthority(), {
        lifecycle_records: {
          evaluation_digest: `sha256:${"ee".repeat(32)}`,
          consumption_digest: null,
          provider_entry_digest: null,
        },
      }),
    /consumption_record_required/,
  );
});

test("a review can report MISSING admission evidence only as non-authorizing uncertainty", async () => {
  const review = await issue(wimseAuthority(), {
    admission_reference: { state: "MISSING", digest: null },
    lifecycle_records: {
      evaluation_digest: `sha256:${"ee".repeat(32)}`,
      consumption_digest: null,
      provider_entry_digest: null,
    },
    referee: {
      ...ADMIT_AXES,
      admission: "INDETERMINATE",
      custody: "INDETERMINATE",
      retry: "REFUSE",
      reconciliation: "REQUIRED",
      reason_codes: [],
    },
  });
  const result = await verify(review);
  assert.equal(result.verified, true, JSON.stringify(result));
  assert.equal(review.body.admission_reference.state, "MISSING");
  assert.equal(review.body.referee.admission, "INDETERMINATE");
});

test("local refusal may narrow accepted native authority", async () => {
  const refused = await issue(wimseAuthority(), {
    admission_reference: { state: "NOT_APPLICABLE", digest: null },
    lifecycle_records: {
      evaluation_digest: `sha256:${"ee".repeat(32)}`,
      consumption_digest: null,
      provider_entry_digest: null,
    },
    referee: {
      ...ADMIT_AXES,
      admission: "REFUSE",
      custody: "UNRESERVED",
      retry: "REQUIRES_NEW_ADMISSION",
    },
  });
  assert.equal((await verify(refused)).verified, true);
});

test("the boundary cannot broaden rejected native authority into ADMIT", async () => {
  const authority = wimseAuthority();
  authority.rp_acceptance = "REJECTED";
  await assert.rejects(() => issue(authority), /authority_broadened/);
});

test("wrong relying-party key and malformed input refuse without throwing", async () => {
  const record = await issue();
  const other = crypto.generateKeyPairSync("ed25519");
  const wrongSpki = other.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64url");
  const result = await verifyAebCrossingRecord(record, {
    verification_keys: [
      { alg: "Ed25519", key_id: "crossing-ed", public_key: wrongSpki },
      VERIFICATION_KEYS[1],
    ],
    mldsaBackend,
  });
  assert.equal(result.verified, false);
  assert.equal(result.reason, "signature_invalid");

  const malformed = await verify({ nope: true });
  assert.equal(malformed.verified, false);
  assert.equal(malformed.reason, "malformed_record");
});

test("carrier fields are outside the closed signed record contract", async () => {
  const record = await issue();
  const withCarrier = { ...record, carrier: { type: "AAC" } };
  const result = await verify(withCarrier);
  assert.equal(result.verified, false);
  assert.equal(result.reason, "malformed_record");
});

// Evaluation binding (amendment 26 in docs/protocol/crossing-record-decisions.md).

async function verifyV2(record: unknown, evaluation?: unknown) {
  return verifyAebCrossingRecordV2(record, {
    verification_keys: [...VERIFICATION_KEYS],
    mldsaBackend,
    ...(evaluation === undefined ? {} : { evaluation }),
  });
}

async function verifyV1(record: unknown, evaluation?: unknown) {
  return verifyAebCrossingRecord(record, {
    verification_keys: [...VERIFICATION_KEYS],
    mldsaBackend,
    ...(evaluation === undefined ? {} : { evaluation }),
  });
}

const V1_OPERATION = "operation:vendor-master:0001";
const V2_OPERATION = "operation:vendor-master:v2:0001";

test("without a supplied evaluation, v1 and v2 report the evaluation binding as INDETERMINATE", async () => {
  const v1 = await verifyV1(await issue());
  assert.equal(v1.verified, true, JSON.stringify(v1));
  assert.equal(v1.evaluation_binding, "INDETERMINATE");
  assert.equal(v1.checks.evaluation_binding, null);
  const v2 = await verifyV2(await issueV2());
  assert.equal(v2.verified, true, JSON.stringify(v2));
  assert.equal(v2.evaluation_binding, "INDETERMINATE");
  assert.equal(v2.checks.evaluation_binding, null);
});

test("a supplied evaluation binds by record digest, operation, CAID, action, and authority leg", async () => {
  const { config, record: evaluationV1 } = evaluationFor(V1_OPERATION);
  assert.equal(evaluationV1.verdict, "SATISFIED", JSON.stringify(evaluationV1.reasons));
  // The committed digest is the evaluation verifier's own record_digest.
  const evaluationCheck = verifyAebEvaluation(evaluationV1, {
    config,
    adapters: { [EVALUATION_ADAPTER_ID]: evaluationAdapter() } as any,
    artifacts: { [EVALUATION_ARTIFACT_REF]: EVALUATION_ARTIFACT },
  });
  assert.equal(evaluationCheck.valid, true, JSON.stringify(evaluationCheck));
  assert.equal(evaluationCheck.record_digest, digestAeb(evaluationV1));

  const record = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: boundLifecycleRecords(evaluationV1),
  });
  const bound = await verifyV1(record, evaluationV1);
  assert.equal(bound.verified, true, JSON.stringify(bound));
  assert.equal(bound.evaluation_binding, "BOUND");
  assert.equal(bound.checks.evaluation_binding, true);
  assert.equal(bound.execution_authorizing, false);

  const { record: evaluationForV2 } = evaluationFor(V2_OPERATION);
  const recordV2 = await issueV2({
    native_authority: wimseAuthority(EVALUATION_TOKEN_DIGEST),
    lifecycle_records: boundLifecycleRecords(evaluationForV2),
  });
  const boundV2 = await verifyV2(recordV2, evaluationForV2);
  assert.equal(boundV2.verified, true, JSON.stringify(boundV2));
  assert.equal(boundV2.evaluation_binding, "BOUND");
});

test("v1 and v2 refuse an unrelated evaluation even when the record commits to its digest", async () => {
  const { record: unrelated } = evaluationFor("op-UNRELATED", {
    caid: UNRELATED_CAID,
  });
  assert.equal(unrelated.verdict, "UNSATISFIED");
  const v1 = await issue(bcrAuthority(), {
    lifecycle_records: boundLifecycleRecords(unrelated),
  });
  // Pre-fix behaviour: the record verified and the binding was never checked.
  assert.equal((await verifyV1(v1)).verified, true);
  const refused = await verifyV1(v1, unrelated);
  assert.equal(refused.verified, false);
  assert.equal(refused.reason, "evaluation_operation_mismatch");
  assert.equal(refused.evaluation_binding, "MISMATCH");
  assert.equal(refused.checks.evaluation_binding, false);

  const v2 = await issueV2({
    native_authority: bcrAuthority(),
    lifecycle_records: boundLifecycleRecords(unrelated),
  });
  const refusedV2 = await verifyV2(v2, unrelated);
  assert.equal(refusedV2.verified, false);
  assert.equal(refusedV2.reason, "evaluation_operation_mismatch");
  assert.equal(refusedV2.evaluation_binding, "MISMATCH");

  // Same operation identifier, different CAID: still not this action.
  const { record: otherAction } = evaluationFor(V1_OPERATION, {
    caid: UNRELATED_CAID,
  });
  const otherActionRecord = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: boundLifecycleRecords(otherAction),
    admission_reference: { state: "NOT_APPLICABLE", digest: null },
    referee: {
      ...ADMIT_AXES,
      admission: "REFUSE",
      custody: "UNRESERVED",
      retry: "REQUIRES_NEW_ADMISSION",
    },
  });
  assert.equal(
    (await verifyV1(otherActionRecord, otherAction)).reason,
    "evaluation_action_mismatch",
  );
});

test("v1 and v2 refuse an evaluation whose digest the record does not commit to", async () => {
  const { record: evaluationV1 } = evaluationFor(V1_OPERATION);
  const record = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST));
  const refused = await verifyV1(record, evaluationV1);
  assert.equal(refused.verified, false);
  assert.equal(refused.reason, "evaluation_digest_mismatch");
  assert.equal(refused.evaluation_binding, "MISMATCH");

  const { record: evaluationForV2 } = evaluationFor(V2_OPERATION);
  const recordV2 = await issueV2({
    native_authority: wimseAuthority(EVALUATION_TOKEN_DIGEST),
  });
  assert.equal(
    (await verifyV2(recordV2, evaluationForV2)).reason,
    "evaluation_digest_mismatch",
  );
});

test("v1 and v2 refuse a native authority that matches no evaluated leg", async () => {
  const { record: evaluationV1 } = evaluationFor(V1_OPERATION);
  const record = await issue(wimseAuthority(), {
    lifecycle_records: boundLifecycleRecords(evaluationV1),
  });
  const refused = await verifyV1(record, evaluationV1);
  assert.equal(refused.verified, false);
  assert.equal(refused.reason, "evaluation_authority_unmatched");

  const bcrRecord = await issue(bcrAuthority(), {
    lifecycle_records: boundLifecycleRecords(evaluationV1),
  });
  assert.equal(
    (await verifyV1(bcrRecord, evaluationV1)).reason,
    "evaluation_authority_unmatched",
  );

  const { record: evaluationForV2 } = evaluationFor(V2_OPERATION);
  const recordV2 = await issueV2({
    lifecycle_records: boundLifecycleRecords(evaluationForV2),
  });
  assert.equal(
    (await verifyV2(recordV2, evaluationForV2)).reason,
    "evaluation_authority_unmatched",
  );
});

test("an admitted crossing cannot cite an evaluation that was not SATISFIED", async () => {
  const { record: revoked } = evaluationFor(V1_OPERATION, {
    status: { revoked: true },
  });
  assert.equal(revoked.verdict, "UNSATISFIED");
  const admitted = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: boundLifecycleRecords(revoked),
  });
  const refused = await verifyV1(admitted, revoked);
  assert.equal(refused.verified, false);
  assert.equal(refused.reason, "evaluation_verdict_inconsistent");

  const { record: revokedV2 } = evaluationFor(V2_OPERATION, {
    status: { revoked: true },
  });
  const admittedV2 = await issueV2({
    native_authority: wimseAuthority(EVALUATION_TOKEN_DIGEST),
    lifecycle_records: boundLifecycleRecords(revokedV2),
  });
  assert.equal(
    (await verifyV2(admittedV2, revokedV2)).reason,
    "evaluation_verdict_inconsistent",
  );

  // A refusal may cite the unsatisfied evaluation that caused it.
  const refusal = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: {
      ...boundLifecycleRecords(revoked),
      consumption_digest: null,
    },
    admission_reference: { state: "NOT_APPLICABLE", digest: null },
    referee: {
      ...ADMIT_AXES,
      admission: "REFUSE",
      custody: "UNRESERVED",
      retry: "REQUIRES_NEW_ADMISSION",
    },
  });
  const refusalCheck = await verifyV1(refusal, revoked);
  assert.equal(refusalCheck.verified, true, JSON.stringify(refusalCheck));
  assert.equal(refusalCheck.evaluation_binding, "BOUND");
});

test("an evaluation that verified authority less strongly than the record claims refuses", async () => {
  const { record: evaluationV1 } = evaluationFor(V1_OPERATION);
  const weakened = structuredClone(evaluationV1);
  weakened.legs[0].acceptance = "INDETERMINATE";
  const record = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: boundLifecycleRecords(weakened),
  });
  assert.equal(
    (await verifyV1(record, weakened)).reason,
    "evaluation_authority_inconsistent",
  );

  // An admission cannot rest on an authority leg the evaluation did not
  // satisfy, even when the evaluation as a whole reports SATISFIED.
  const unsatisfiedLeg = structuredClone(evaluationV1);
  unsatisfiedLeg.legs[0].verdict = "UNSATISFIED";
  assert.equal(unsatisfiedLeg.verdict, "SATISFIED");
  const admitted = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: boundLifecycleRecords(unsatisfiedLeg),
  });
  assert.equal(
    (await verifyV1(admitted, unsatisfiedLeg)).reason,
    "evaluation_authority_inconsistent",
  );
});

test("hostile evaluation inputs refuse with a reason and never throw", async () => {
  const { record: evaluationV1 } = evaluationFor(V1_OPERATION);
  const record = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: boundLifecycleRecords(evaluationV1),
  });
  let getterCalls = 0;
  const accessor = structuredClone(evaluationV1) as any;
  Object.defineProperty(accessor, "operation_id", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return V1_OPERATION;
    },
  });
  const proxy = new Proxy(structuredClone(evaluationV1), {
    ownKeys() {
      throw new Error("hostile ownKeys");
    },
  });
  const missingLegs = structuredClone(evaluationV1) as any;
  delete missingLegs.legs;
  for (const hostile of [
    null,
    "evaluation",
    [],
    { "@type": AEB_EVALUATION_VERSION },
    missingLegs,
    accessor,
    proxy,
  ]) {
    const result = await verifyV1(record, hostile);
    assert.equal(result.verified, false);
    assert.equal(result.evaluation_binding, "MISMATCH");
    assert.match(result.reason ?? "", /^evaluation_/);
  }
  assert.equal(getterCalls, 0);
});

async function issueBoundIndex(
  evaluation: { profile: string | null; digest: string },
  lifecycleOverrides: Record<string, unknown> = {},
  overrides: Record<string, unknown> = {},
) {
  return issueAebCrossingLifecycleIndexV2(
    {
      record_id: "crossing-lifecycle:finance:bound",
      operation_id: V2_OPERATION,
      issued_at: NOW,
      action: ACTION,
      lifecycle: {
        evaluation,
        local_admission_digest: ADMISSION_DIGEST,
        authority_custody: { phase: "RESERVATION", digest: CONSUMPTION_DIGEST },
        provider_entry_digest: null,
        effect_observation_digest: null,
        provider_outcome_digest: null,
        reconciliation_digest: null,
        ...lifecycleOverrides,
      },
      source_crossing_record: { version: null, digest: null },
      conversion: { status: "NATIVE", reason_codes: [] },
      execution_authorizing: false,
      ...overrides,
    } as any,
    { action: ACTION, admission_domain: BOUNDARY, evaluation } as any,
    { signing_keys: [...SIGNERS], deterministic: true, mldsaBackend },
  );
}

function indexOptions(extra: Record<string, unknown> = {}) {
  return {
    verification_keys: [...VERIFICATION_KEYS],
    expected_action: ACTION,
    admission_domain: BOUNDARY,
    mldsaBackend,
    ...extra,
  } as any;
}

test("the lifecycle index reports the evaluation binding as INDETERMINATE without the evaluation", async () => {
  const index = await issueLifecycleIndex();
  const result = await verifyAebCrossingLifecycleIndexV2(
    index,
    indexOptions({ expected_evaluation: index.body.lifecycle.evaluation }),
  );
  assert.equal(result.verified, true, JSON.stringify(result));
  assert.equal(result.evaluation_binding, "INDETERMINATE");
  assert.equal(result.checks.evaluation_binding, null);

  const noReference = await verifyAebCrossingLifecycleIndexV2(index, indexOptions());
  assert.equal(noReference.verified, false);
  assert.equal(noReference.reason, "evaluation_reference_required");
});

test("the lifecycle index binds AEB-EVALUATION-v1 and -v2 records by the verifier record digest", async () => {
  const { config, record: evaluationV1 } = evaluationFor(V2_OPERATION);
  const v1Reference = aebCrossingEvaluationReference(evaluationV1);
  assert.deepEqual(v1Reference, {
    profile: AEB_EVALUATION_VERSION,
    digest: digestAeb(evaluationV1),
  });
  const v1Index = await issueBoundIndex(v1Reference);
  const v1Bound = await verifyAebCrossingLifecycleIndexV2(
    v1Index,
    indexOptions({ evaluation: evaluationV1 }),
  );
  assert.equal(v1Bound.verified, true, JSON.stringify(v1Bound));
  assert.equal(v1Bound.evaluation_binding, "BOUND");
  assert.equal(v1Bound.checks.evaluation, true);

  const evaluationV2 = issueAebEvaluationV2FromV1(evaluationV1, {
    signer: { key_id: "eval:crossing", private_key: edPrivate },
    profiles: config.profiles,
  });
  const v2Check = verifyAebEvaluationV2(evaluationV2, {
    source_evaluation: evaluationV1,
    evaluator_keys: config.evaluator_keys,
    profiles: config.profiles,
  });
  assert.equal(v2Check.valid, true, JSON.stringify(v2Check));
  const v2Reference = aebCrossingEvaluationReference(evaluationV2);
  assert.equal(v2Reference.profile, AEB_EVALUATION_V2_VERSION);
  // The index digest is the v2 verifier's record_digest over the complete
  // signed record, not the typed digest of the unsigned body.
  assert.equal(v2Reference.digest, v2Check.record_digest);
  const { signature: _signature, ...v2Body } = evaluationV2;
  assert.notEqual(v2Reference.digest, aebEvaluationV2Digest(v2Body as any));

  const v2Index = await issueBoundIndex(v2Reference);
  const v2Bound = await verifyAebCrossingLifecycleIndexV2(
    v2Index,
    indexOptions({
      expected_evaluation: v2Reference,
      evaluation: evaluationV2,
    }),
  );
  assert.equal(v2Bound.verified, true, JSON.stringify(v2Bound));
  assert.equal(v2Bound.evaluation_binding, "BOUND");

  const bodyDigestIndex = await issueBoundIndex({
    profile: AEB_EVALUATION_V2_VERSION,
    digest: aebEvaluationV2Digest(v2Body as any),
  });
  assert.equal(
    (await verifyAebCrossingLifecycleIndexV2(
      bodyDigestIndex,
      indexOptions({ evaluation: evaluationV2 }),
    )).reason,
    "evaluation_digest_mismatch",
  );
});

test("the lifecycle index refuses an unrelated or relabeled evaluation", async () => {
  const { record: unrelated } = evaluationFor("op-UNRELATED", {
    caid: UNRELATED_CAID,
  });
  // The reviewer's case: a v1 digest under the v2 label, pinned by a
  // self-referential expected pointer.
  const relabeledReference = {
    profile: AEB_EVALUATION_V2_VERSION,
    digest: digestAeb(unrelated),
  };
  const relabeled = await issueBoundIndex(relabeledReference);
  assert.equal((await verifyAebCrossingLifecycleIndexV2(
    relabeled,
    indexOptions({ expected_evaluation: relabeledReference }),
  )).verified, true, "the pointer-only check still cannot see the join");
  const relabeledResult = await verifyAebCrossingLifecycleIndexV2(
    relabeled,
    indexOptions({
      expected_evaluation: relabeledReference,
      evaluation: unrelated,
    }),
  );
  assert.equal(relabeledResult.verified, false);
  assert.equal(relabeledResult.reason, "evaluation_profile_mismatch");
  assert.equal(relabeledResult.evaluation_binding, "MISMATCH");

  const unrelatedIndex = await issueBoundIndex(
    aebCrossingEvaluationReference(unrelated),
  );
  assert.equal((await verifyAebCrossingLifecycleIndexV2(
    unrelatedIndex,
    indexOptions({ evaluation: unrelated }),
  )).reason, "evaluation_operation_mismatch");

  // Same operation and CAID, but the SATISFIED evaluation committed to a
  // different normalized action than the one the index names.
  const { record: evaluationV1 } = evaluationFor(V2_OPERATION);
  const otherActionIndex = await issueAebCrossingLifecycleIndexV2(
    {
      record_id: "crossing-lifecycle:finance:other-action",
      operation_id: V2_OPERATION,
      issued_at: NOW,
      action: { ...ACTION, action_digest: `sha256:${"01".repeat(32)}` },
      lifecycle: {
        evaluation: aebCrossingEvaluationReference(evaluationV1),
        local_admission_digest: ADMISSION_DIGEST,
        authority_custody: { phase: "RESERVATION", digest: CONSUMPTION_DIGEST },
        provider_entry_digest: null,
        effect_observation_digest: null,
        provider_outcome_digest: null,
        reconciliation_digest: null,
      },
      source_crossing_record: { version: null, digest: null },
      conversion: { status: "NATIVE", reason_codes: [] },
      execution_authorizing: false,
    } as any,
    {
      action: { ...ACTION, action_digest: `sha256:${"01".repeat(32)}` },
      admission_domain: BOUNDARY,
      evaluation: aebCrossingEvaluationReference(evaluationV1),
    } as any,
    { signing_keys: [...SIGNERS], deterministic: true, mldsaBackend },
  );
  assert.equal((await verifyAebCrossingLifecycleIndexV2(
    otherActionIndex,
    indexOptions({
      expected_action: otherActionIndex.body.action,
      evaluation: evaluationV1,
    }),
  )).reason, "evaluation_action_mismatch");
});

test("the lifecycle index refuses provider entry without an authority reservation", async () => {
  const evaluation = { profile: AEB_EVALUATION_V2_VERSION, digest: EVALUATION_V2_DIGEST };
  const entry = `sha256:${"07".repeat(32)}`;
  for (const custody of [
    { phase: "NOT_APPLICABLE", digest: null },
    { phase: "INDETERMINATE", digest: null },
    { phase: "INDETERMINATE", digest: CONSUMPTION_DIGEST },
  ]) {
    await assert.rejects(
      () => issueBoundIndex(evaluation, {
        authority_custody: custody,
        provider_entry_digest: entry,
        provider_outcome_digest: `sha256:${"08".repeat(32)}`,
      }),
      /lifecycle_order_invalid/,
      JSON.stringify(custody),
    );
  }

  // A hostile issuer that signs the impossible ordering directly.
  const valid = await issueBoundIndex(evaluation);
  const body = structuredClone(valid.body) as any;
  body.lifecycle.authority_custody = { phase: "NOT_APPLICABLE", digest: null };
  body.lifecycle.provider_entry_digest = entry;
  body.lifecycle.reconciliation_digest = `sha256:${"09".repeat(32)}`;
  body.contract_digest = crossingLifecycleIndexV2ContractDigest(body);
  const signed = await signIndexBody(body);
  const result = await verifyAebCrossingLifecycleIndexV2(
    signed,
    indexOptions({ expected_evaluation: evaluation }),
  );
  assert.equal(result.verified, false);
  assert.equal(result.reason, "lifecycle_order_invalid");
  assert.equal(result.checks.lifecycle_order, false);
});

test("a lifecycle index cannot claim COMPLETE with an unlabeled evaluation or unknown custody", async () => {
  const source = await issue();
  const converted = await upgradeAebCrossingRecordV1ToLifecycleIndexV2(source, {
    signing_keys: [...SIGNERS],
    source_verification_keys: [...VERIFICATION_KEYS],
    deterministic: true,
    mldsaBackend,
  });
  const complete = structuredClone(converted.body) as any;
  complete.conversion = { status: "COMPLETE", reason_codes: [] };
  complete.contract_digest = crossingLifecycleIndexV2ContractDigest(complete);
  const result = await verifyAebCrossingLifecycleIndexV2(
    await signIndexBody(complete),
    indexOptions({ expected_evaluation: complete.lifecycle.evaluation }),
  );
  assert.equal(result.verified, false);
  assert.equal(result.reason, "conversion_report_invalid");

  const unknownCustody = structuredClone(converted.body) as any;
  unknownCustody.lifecycle.evaluation = {
    profile: AEB_EVALUATION_VERSION,
    digest: converted.body.lifecycle.evaluation.digest,
  };
  unknownCustody.lifecycle.authority_custody = {
    phase: "INDETERMINATE",
    digest: CONSUMPTION_DIGEST,
  };
  unknownCustody.conversion = { status: "COMPLETE", reason_codes: [] };
  unknownCustody.contract_digest =
    crossingLifecycleIndexV2ContractDigest(unknownCustody);
  assert.equal((await verifyAebCrossingLifecycleIndexV2(
    await signIndexBody(unknownCustody),
    indexOptions({ expected_evaluation: unknownCustody.lifecycle.evaluation }),
  )).reason, "conversion_report_invalid");

  const nativeUnlabeled = structuredClone(converted.body) as any;
  nativeUnlabeled.conversion = { status: "NATIVE", reason_codes: [] };
  nativeUnlabeled.source_crossing_record = { version: null, digest: null };
  nativeUnlabeled.contract_digest =
    crossingLifecycleIndexV2ContractDigest(nativeUnlabeled);
  assert.equal((await verifyAebCrossingLifecycleIndexV2(
    await signIndexBody(nativeUnlabeled),
    indexOptions({ expected_evaluation: nativeUnlabeled.lifecycle.evaluation }),
  )).reason, "conversion_report_invalid");
});

test("v1 upgrade with the bound source evaluation is COMPLETE and carries its profile", async () => {
  const { record: evaluationV1 } = evaluationFor(V1_OPERATION);
  const source = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: boundLifecycleRecords(evaluationV1),
  });
  const converted = await upgradeAebCrossingRecordV1ToLifecycleIndexV2(source, {
    signing_keys: [...SIGNERS],
    source_verification_keys: [...VERIFICATION_KEYS],
    source_evaluation: evaluationV1,
    deterministic: true,
    mldsaBackend,
  });
  assert.equal(converted.body.conversion.status, "COMPLETE");
  assert.deepEqual(
    converted.body.lifecycle.evaluation,
    aebCrossingEvaluationReference(evaluationV1),
  );
  const result = await verifyAebCrossingLifecycleIndexV2(
    converted,
    indexOptions({
      expected_action: ACTION,
      evaluation: evaluationV1,
    }),
  );
  assert.equal(result.verified, true, JSON.stringify(result));
  assert.equal(result.evaluation_binding, "BOUND");
  assert.equal(result.conversion_status, "COMPLETE");

  const { record: unrelated } = evaluationFor("op-UNRELATED", {
    caid: UNRELATED_CAID,
  });
  await assert.rejects(
    () => upgradeAebCrossingRecordV1ToLifecycleIndexV2(source, {
      signing_keys: [...SIGNERS],
      source_verification_keys: [...VERIFICATION_KEYS],
      source_evaluation: unrelated,
      deterministic: true,
      mldsaBackend,
    }),
    /source_evaluation_mismatch/,
  );
});

test("v1 upgrade converts MISSING admission with later references to INDETERMINATE instead of throwing", async () => {
  const source = await issue(wimseAuthority(), {
    admission_reference: { state: "MISSING", digest: null },
    lifecycle_records: {
      evaluation_digest: `sha256:${"ee".repeat(32)}`,
      consumption_digest: CONSUMPTION_DIGEST,
      provider_entry_digest: `sha256:${"07".repeat(32)}`,
    },
    referee: {
      ...ADMIT_AXES,
      admission: "INDETERMINATE",
      custody: "TERMINAL",
      provider_commitment: "INDETERMINATE",
      retry: "REFUSE",
      reconciliation: "REQUIRED",
    },
  });
  assert.equal((await verify(source)).verified, true);
  const converted = await upgradeAebCrossingRecordV1ToLifecycleIndexV2(source, {
    signing_keys: [...SIGNERS],
    source_verification_keys: [...VERIFICATION_KEYS],
    deterministic: true,
    mldsaBackend,
  });
  assert.equal(converted.body.conversion.status, "INDETERMINATE");
  for (const reason of [
    "custody_reference_without_admission",
    "local_admission_reference_indeterminate",
    "provider_entry_reference_without_admission",
    "evaluation_reference_unverified",
  ])
    assert.ok(converted.body.conversion.reason_codes.includes(reason), reason);
  assert.deepEqual(converted.body.lifecycle.authority_custody, {
    phase: "INDETERMINATE",
    digest: null,
  });
  assert.equal(converted.body.lifecycle.provider_entry_digest, null);
  const result = await verifyAebCrossingLifecycleIndexV2(
    converted,
    indexOptions({ expected_evaluation: converted.body.lifecycle.evaluation }),
  );
  assert.equal(result.verified, true, JSON.stringify(result));
});

test("v1 upgrade never reports provider entry without custody or admission as COMPLETE", async () => {
  const { record: evaluationV1 } = evaluationFor(V1_OPERATION);
  const source = await issue(wimseAuthority(EVALUATION_TOKEN_DIGEST), {
    lifecycle_records: {
      evaluation_digest: digestAeb(evaluationV1),
      consumption_digest: null,
      provider_entry_digest: `sha256:${"07".repeat(32)}`,
    },
    referee: {
      ...ADMIT_AXES,
      admission: "REFUSE",
      custody: "UNRESERVED",
      retry: "REQUIRES_NEW_ADMISSION",
    },
  });
  assert.equal((await verify(source)).verified, true);
  const converted = await upgradeAebCrossingRecordV1ToLifecycleIndexV2(source, {
    signing_keys: [...SIGNERS],
    source_verification_keys: [...VERIFICATION_KEYS],
    source_evaluation: evaluationV1,
    deterministic: true,
    mldsaBackend,
  });
  assert.equal(converted.body.conversion.status, "INDETERMINATE");
  assert.deepEqual(converted.body.conversion.reason_codes, [
    "provider_entry_without_admit",
    "provider_entry_without_custody_reference",
  ]);
  assert.equal(converted.body.lifecycle.authority_custody.phase, "INDETERMINATE");
  const result = await verifyAebCrossingLifecycleIndexV2(
    converted,
    indexOptions({ evaluation: evaluationV1 }),
  );
  assert.equal(result.verified, true, JSON.stringify(result));
  assert.equal(result.evaluation_binding, "BOUND");
});
