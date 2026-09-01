// SPDX-License-Identifier: Apache-2.0
/**
 * AIC x EP-AEB-CROSSING-RECORD-v1 deterministic composition runner.
 *
 * The native AIC verifier remains authoritative for AIC-JWT or AIC-X509
 * validation. This runner starts from that verifier's result, checks the
 * relying party's pinned issuer and principal binding, and records the local
 * boundary decision. It does not turn an AIC credential or a crossing record
 * into reusable execution authority.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import {
  AIC_ADMISSION_DOMAIN_VERSION,
  AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
  AIC_JWT_JKT_CROSSING_MAPPING_PROFILE,
  AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE,
  AIC_X509_CREDENTIAL_BUNDLE_DIGEST_VERSION,
  AIC_X509_SPKI_CROSSING_MAPPING_PROFILE,
  AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE,
  mapAicJwtJktCrossingAuthority,
  mapAicJwtJktBoundCrossingAuthority,
  mapAicX509SpkiCrossingAuthority,
  mapAicX509SpkiBoundCrossingAuthority,
  projectAicJwtToStrictJwtSvid,
  type AicCrossingRelyingPartyContext,
  type AicCrossingRelyingPartyPolicy,
  type AicJwtJktCrossingInput,
  type AicJwtJktBoundCrossingInput,
  type AicX509SpkiCrossingInput,
  type AicX509SpkiBoundCrossingInput,
} from "../../../packages/verify/aeb-aic-crossing-adapter.js";
import {
  AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS,
  AEB_CROSSING_RECORD_VERSION,
  issueAebCrossingRecord,
  verifyAebCrossingRecord,
  type CrossingNativeAuthority,
  type CrossingRefereeAxes,
} from "../../../packages/verify/aeb-crossing-record.js";
import {
  canonicalizeAeb,
  digestAebTyped,
} from "../../../packages/verify/aeb-adapter-contract.js";
import { loadDefaultAgilityMldsaBackend } from "../../../packages/verify/pq-signature-agility.js";

export const PROFILE = "EP-AIC-AEB-CROSSING-COMPOSITION-v0.2";
const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PATH = resolve(HERE, "report.reference.json");
const SOURCE_LOCK = JSON.parse(
  readFileSync(resolve(HERE, "source-lock.json"), "utf8"),
);
const SOURCE_LOCK_DIGEST = `sha256:${crypto.hash(
  "sha256",
  canonicalizeAeb(SOURCE_LOCK),
  "hex",
)}` as const;
const MAPPING_PROFILE = JSON.parse(
  readFileSync(resolve(HERE, "mapping-profile.json"), "utf8"),
);
const MAPPING_PROFILE_DIGEST = `sha256:${crypto.hash(
  "sha256",
  canonicalizeAeb(MAPPING_PROFILE),
  "hex",
)}` as const;
const NOW = "2026-09-01T07:00:00Z";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type CaseResult = {
  id: string;
  category: "mapping" | "positive" | "hostile" | "boundary";
  passed: boolean;
  expected: string;
  observed: Json;
};

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
const edPrivate = crypto.createPrivateKey({ key: ED_PRIVATE_JWK, format: "jwk" });
const edPublic = crypto.createPublicKey({ key: ED_PUBLIC_JWK, format: "jwk" });
const edPublicSpki = edPublic
  .export({ type: "spki", format: "der" })
  .toString("base64url");
const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x41));
const pqPublic = Buffer.from(pqPair.publicKey).toString("base64url");
const mldsaBackend = await loadDefaultAgilityMldsaBackend();
assert.ok(mldsaBackend, "real ML-DSA-65 backend must be available");

const SIGNERS = [
  { alg: "Ed25519", key_id: "aic-crossing-ed", private_key: edPrivate },
  { alg: "ML-DSA-65", key_id: "aic-crossing-pq", private_key: pqPair.secretKey },
] as const;
const VERIFICATION_KEYS = [
  { alg: "Ed25519", key_id: "aic-crossing-ed", public_key: edPublicSpki },
  { alg: "ML-DSA-65", key_id: "aic-crossing-pq", public_key: pqPublic },
] as const;

const ISSUER_PIN = `sha256:${"a1".repeat(32)}` as const;
const PRINCIPAL_JWK = Object.freeze({
  kty: "OKP" as const,
  crv: "Ed25519",
  x: "c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI",
});
const JKT = crypto.createHash("sha256")
  .update(JSON.stringify({
    crv: PRINCIPAL_JWK.crv,
    kty: PRINCIPAL_JWK.kty,
    x: PRINCIPAL_JWK.x,
  }))
  .digest("base64url");
const SPKI = "HHZknPZ96UejPrdBkR8uVScD38l0C-CydQ-8aWJ1iFo";
const AGENT_CERTIFICATE_DER = "MIIBczCCASWgAwIBAgICEIcwBQYDK2VwMDgxGTAXBgNVBAMMEGFnZW50LWFjY291bnRpbmcxGzAZBgNVBAoMEkVNSUxJQSBBSUMgRml4dHVyZTAeFw0yNjA5MDEwNjM1MTRaFw0zNjA4MjkwNjM1MTRaMDgxGTAXBgNVBAMMEGFnZW50LWFjY291bnRpbmcxGzAZBgNVBAoMEkVNSUxJQSBBSUMgRml4dHVyZTAqMAUGAytlcAMhABlRhmmMT_c3eHf39WJ53gjQ-XsXrkk2JjbOst7y2iG6o1MwUTAdBgNVHQ4EFgQUYRN3QUuM-4WfrO9gw0jrbCge6WkwHwYDVR0jBBgwFoAUYRN3QUuM-4WfrO9gw0jrbCge6WkwDwYDVR0TAQH_BAUwAwEB_zAFBgMrZXADQQAMwAAYlEzDMMFWXJomesb1_O7QypjsRF3DGHQLhuoBh2op5s9xTo7aiF1BAfW2O82QCy9LOCZsX1ymKcLUEJYL";
const PRINCIPAL_CERTIFICATE_DER = "MIIBezCCAS2gAwIBAgICEIgwBQYDK2VwMDwxHTAbBgNVBAMMFHByaW5jaXBhbC1hY2NvdW50aW5nMRswGQYDVQQKDBJFTUlMSUEgQUlDIEZpeHR1cmUwHhcNMjYwOTAxMDYzNTE0WhcNMzYwODI5MDYzNTE0WjA8MR0wGwYDVQQDDBRwcmluY2lwYWwtYWNjb3VudGluZzEbMBkGA1UECgwSRU1JTElBIEFJQyBGaXh0dXJlMCowBQYDK2VwAyEAWP6IT_BCkU9xUCVQR2MePkJ_zYdkFYqAFp0jSzW6Re6jUzBRMB0GA1UdDgQWBBRZkhmqaCLhEEtolUAUZLVa7eBfejAfBgNVHSMEGDAWgBRZkhmqaCLhEEtolUAUZLVa7eBfejAPBgNVHRMBAf8EBTADAQH_MAUGAytlcANBAL-e_CxbdYdZRTB86m3ldvMg_dCpJHAtMl26I-T40QR2JFbG3xWhJTKfEMuZooI2jjHbjLsE1qHQ6s5v3EtphQ0";
function pinnedSourceDigest(
  repository: string,
  path: string,
  revision?: string,
): string {
  const repositories = SOURCE_LOCK.varwof.repositories.filter(
    (entry: any) => entry.repository === repository
      && (revision === undefined || entry.revision === revision),
  );
  assert.equal(
    repositories.length,
    1,
    `ambiguous pinned repository ${repository}${revision ? `@${revision}` : ""}`,
  );
  const file = repositories[0].inspected_files.find((entry: any) => entry.path === path);
  assert.equal(typeof file?.sha256, "string", `missing pinned source ${repository}:${path}`);
  return file.sha256;
}
const JWT_VERIFIER = Object.freeze({
  id: "varwof:aic-jwt-validate.gateway-verify-bearer",
  version: "source-lock-v0.2",
  implementation_digest: digestAebTyped({
    validate_go_sha256: pinnedSourceDigest(
      "https://github.com/varwof/types",
      "aicjwt/validate.go",
      "76f725ffc375ae7fda1f0255ea3e12a0074f6c4c",
    ),
    keyhash_go_sha256: pinnedSourceDigest(
      "https://github.com/varwof/types",
      "aicjwt/keyhash.go",
      "76f725ffc375ae7fda1f0255ea3e12a0074f6c4c",
    ),
    gateway_bearer_sha256: pinnedSourceDigest(
      "https://github.com/varwof/gateway-core",
      "jwt.go",
    ),
    gateway_go_mod_sha256: pinnedSourceDigest(
      "https://github.com/varwof/gateway-core",
      "go.mod",
    ),
    complete_inspection_set_digest: SOURCE_LOCK_DIGEST,
  }, "AIC-JWT-NATIVE-VERIFIER-SOURCE-LOCK-v1"),
});
const X509_VERIFIER = Object.freeze({
  id: "varwof:gateway-verify-credential-bundle",
  version: "source-lock-v0.2",
  implementation_digest: digestAebTyped({
    credential_bundle_sha256: pinnedSourceDigest(
      "https://github.com/varwof/gateway-core",
      "credential_bundle.go",
    ),
    gateway_go_mod_sha256: pinnedSourceDigest(
      "https://github.com/varwof/gateway-core",
      "go.mod",
    ),
    complete_inspection_set_digest: SOURCE_LOCK_DIGEST,
  }, "AIC-X509-NATIVE-VERIFIER-SOURCE-LOCK-v1"),
});

function jwtCompactToken(
  typ = "aic+jwt",
  audience: string | string[] = "erp:vendor-master",
): string {
  const segment = (value: unknown) => Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64url");
  return [
    segment({ alg: "EdDSA", typ, kid: "issuer-key-1" }),
    segment({
      iss: "https://issuer.example",
      sub: "spiffe://example.org/agent/accounting",
      aud: audience,
      iat: 1788245700,
      exp: 1788246300,
      jti: "aic-jwt:agent-accounting:17",
      cnf: { jkt: JKT },
      aic: {
        ver: 1,
        principal: {
          realm: "example.org",
          id: "principal:accounting-owner",
          key_hash: JKT,
          hash_alg: "jkt",
        },
        delegation_mode: "authorized",
        capabilities: [{
          scheme: "varwof/core",
          id: "finance.vendor-account-change",
          params: {
            vendor_id: "vendor-0042",
            account_fingerprint: "acct:7e8c",
          },
        }],
      },
    }),
    Buffer.from("fixture-signature", "utf8").toString("base64url"),
  ].join(".");
}

const JWT_COMPACT_TOKEN = jwtCompactToken();
const JWT_ARTIFACT_DIGEST = `sha256:${crypto.createHash("sha256")
  .update(JWT_COMPACT_TOKEN, "utf8")
  .digest("hex")}` as const;
const X509_ARTIFACT_DIGEST = digestAebTyped(
  {
    agent_certificate_der: AGENT_CERTIFICATE_DER,
    principal_certificate_der: PRINCIPAL_CERTIFICATE_DER,
  },
  AIC_X509_CREDENTIAL_BUNDLE_DIGEST_VERSION,
);
const ACTION = Object.freeze({
  caid: "caid:1:finance.vendor-account-change.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  action_digest: `sha256:${"11".repeat(32)}` as const,
});
const BOUNDARY = Object.freeze({
  relying_party_id: "rp:example-finance",
  audience: "erp:vendor-master",
  executor_id: "executor:erp-production",
  state_domain_id: "state-domain:finance-primary",
});
const REQUEST_BINDING = Object.freeze({
  action_projection_profile_id: "AIC-EXACT-ACTION-PROJECTION-v1",
  action_projection_profile_digest: MAPPING_PROFILE_DIGEST,
  requested_capability_digest: sha256(canonicalizeAeb({
    scheme: "varwof/core",
    id: "finance.vendor-account-change",
    params: {
      vendor_id: "vendor-0042",
      account_fingerprint: "acct:7e8c",
    },
  })) as `sha256:${string}`,
  projected_action: ACTION,
  projected_admission_domain_digest: digestAebTyped(
    BOUNDARY,
    AIC_ADMISSION_DOMAIN_VERSION,
  ),
});
const JWT_POLICY = Object.freeze({
  mapping_profile_id: AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE,
  mapping_profile_digest: MAPPING_PROFILE_DIGEST,
  action_projection_profile_id: REQUEST_BINDING.action_projection_profile_id,
  action_projection_profile_digest:
    REQUEST_BINDING.action_projection_profile_digest,
  trusted_issuer_trust_anchor_digests: [ISSUER_PIN],
  native_verifier: JWT_VERIFIER,
}) satisfies AicCrossingRelyingPartyPolicy;
const X509_POLICY = Object.freeze({
  mapping_profile_id: AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE,
  mapping_profile_digest: MAPPING_PROFILE_DIGEST,
  action_projection_profile_id: REQUEST_BINDING.action_projection_profile_id,
  action_projection_profile_digest:
    REQUEST_BINDING.action_projection_profile_digest,
  trusted_issuer_trust_anchor_digests: [ISSUER_PIN],
  native_verifier: X509_VERIFIER,
}) satisfies AicCrossingRelyingPartyPolicy;
const JWT_UNBOUND_POLICY = Object.freeze({
  ...JWT_POLICY,
  mapping_profile_id: AIC_JWT_JKT_CROSSING_MAPPING_PROFILE,
}) satisfies AicCrossingRelyingPartyPolicy;
const X509_UNBOUND_POLICY = Object.freeze({
  ...X509_POLICY,
  mapping_profile_id: AIC_X509_SPKI_CROSSING_MAPPING_PROFILE,
}) satisfies AicCrossingRelyingPartyPolicy;
function relyingPartyContext(
  policy: AicCrossingRelyingPartyPolicy = JWT_POLICY,
): AicCrossingRelyingPartyContext {
  return {
    action: ACTION,
    admission_domain: BOUNDARY,
    requested_capability_digest: REQUEST_BINDING.requested_capability_digest,
    evaluated_at: NOW,
    max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
    policy,
  };
}
const RP_CONTEXT = Object.freeze(relyingPartyContext());
const X509_RP_CONTEXT = Object.freeze(relyingPartyContext(X509_POLICY));
const REQUIREMENTS = Object.freeze({
  admission_digest: `sha256:${"22".repeat(32)}` as const,
  review_digest: `sha256:${"33".repeat(32)}` as const,
});
const ADMIT_AXES = {
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
  reason_codes: [] as string[],
} satisfies CrossingRefereeAxes;

function sorted(value: any): Json {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
    ) as Json;
  }
  return value as Json;
}

function sha256(value: string): string {
  return `sha256:${crypto.hash("sha256", value, "hex")}`;
}

function result(
  id: string,
  category: CaseResult["category"],
  passed: boolean,
  expected: string,
  observed: Json,
): CaseResult {
  return { id, category, passed, expected, observed };
}

function jktInput(
  overrides: Partial<AicJwtJktBoundCrossingInput> = {},
): AicJwtJktBoundCrossingInput {
  return {
    native_verification: "VERIFIED",
    native_verifier: JWT_VERIFIER,
    native_verification_evidence_digest: `sha256:${"b0".repeat(32)}`,
    carrier_provenance: {
      source_carrier: "AIC-JWT-COMPACT",
      compact_token: JWT_COMPACT_TOKEN,
      presented_principal_jwk: PRINCIPAL_JWK,
      downstream_representation: "DIRECT",
    },
    issuer: "https://issuer.example",
    subject: "spiffe://example.org/agent/accounting",
    artifact_id: "aic-jwt:agent-accounting:17",
    artifact_digest: JWT_ARTIFACT_DIGEST,
    issuer_trust_anchor_digest: ISSUER_PIN,
    constraints_digest: `sha256:${"b3".repeat(32)}`,
    principal_binding: {
      kind: "RFC7638_JKT",
      hash_alg: "jkt",
      claimed_key_hash: JKT,
      presented_key_hash: JKT,
    },
    status: {
      value: "CURRENT",
      checked_at: NOW,
      source_head_digest: `sha256:${"b4".repeat(32)}`,
    },
    validity: {
      not_before: "2026-09-01T06:55:00Z",
      not_after: "2026-09-01T07:05:00Z",
    },
    request_binding: REQUEST_BINDING,
    ...overrides,
  };
}

function x509Input(
  overrides: Partial<AicX509SpkiBoundCrossingInput> = {},
): AicX509SpkiBoundCrossingInput {
  return {
    native_verification: "VERIFIED",
    native_verifier: X509_VERIFIER,
    native_verification_evidence_digest: `sha256:${"c0".repeat(32)}`,
    carrier_provenance: {
      source_carrier: "AIC-X509-CREDENTIAL-BUNDLE",
      agent_certificate_der: AGENT_CERTIFICATE_DER,
      principal_certificate_der: PRINCIPAL_CERTIFICATE_DER,
    },
    issuer: "https://ca.example",
    subject: "spiffe://example.org/agent/accounting",
    artifact_id: "aic-x509:agent-accounting:17",
    artifact_digest: X509_ARTIFACT_DIGEST,
    issuer_trust_anchor_digest: ISSUER_PIN,
    constraints_digest: `sha256:${"c3".repeat(32)}`,
    principal_binding: {
      kind: "X509_SPKI",
      hash_alg: "sha-256",
      claimed_key_hash: SPKI,
      presented_key_hash: SPKI,
    },
    status: {
      value: "CURRENT",
      checked_at: NOW,
      source_head_digest: `sha256:${"c4".repeat(32)}`,
    },
    validity: {
      not_before: "2026-09-01T06:55:00Z",
      not_after: "2026-09-01T07:05:00Z",
    },
    request_binding: REQUEST_BINDING,
    ...overrides,
  };
}

function unboundJktInput(): AicJwtJktCrossingInput {
  const { request_binding: omitted, ...input } = jktInput();
  assert.ok(omitted);
  return input;
}

function unboundX509Input(): AicX509SpkiCrossingInput {
  const { request_binding: omitted, ...input } = x509Input();
  assert.ok(omitted);
  return input;
}

function mapJkt(input = jktInput()): CrossingNativeAuthority {
  const mapped = mapAicJwtJktBoundCrossingAuthority(input, RP_CONTEXT);
  assert.equal(mapped.ok, true, JSON.stringify(mapped));
  return mapped.authority;
}

function mapX509(input = x509Input()): CrossingNativeAuthority {
  const mapped = mapAicX509SpkiBoundCrossingAuthority(input, X509_RP_CONTEXT);
  assert.equal(mapped.ok, true, JSON.stringify(mapped));
  return mapped.authority;
}

async function issue(authority: CrossingNativeAuthority, recordId: string) {
  return issueAebCrossingRecord(
    {
      record_id: recordId,
      operation_id: `operation:${recordId}`,
      issued_at: NOW,
      native_authority: authority,
      action: ACTION,
      boundary: BOUNDARY,
      requirements: REQUIREMENTS,
      admission_reference: {
        state: "PRESENT",
        digest: `sha256:${"88".repeat(32)}`,
      },
      lifecycle_records: {
        evaluation_digest: `sha256:${"ee".repeat(32)}`,
        consumption_digest: `sha256:${"99".repeat(32)}`,
        provider_entry_digest: null,
      },
      evaluated_evidence_digests: [
        `sha256:${"66".repeat(32)}`,
        `sha256:${"77".repeat(32)}`,
      ],
      configuration_digests: [
        `sha256:${"44".repeat(32)}`,
        `sha256:${"55".repeat(32)}`,
      ],
      referee: ADMIT_AXES,
    },
    { signing_keys: [...SIGNERS], deterministic: true, mldsaBackend },
  );
}

async function verify(value: unknown) {
  return verifyAebCrossingRecord(value, {
    verification_keys: [...VERIFICATION_KEYS],
    mldsaBackend,
  });
}

export async function buildReferenceReport() {
  const cases: CaseResult[] = [];
  const jkt = mapJkt();
  const x509 = mapX509();

  const jktRecord = await issue(jkt, "crossing:aic:jkt:0001");
  const jktCheck = await verify(jktRecord);
  cases.push(result(
    "AIC-JWT-JKT-CROSSING",
    "positive",
    jkt.mapping_profile_id === AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE
      && jktCheck.verified
      && jktCheck.execution_authorizing === false,
    "RFC7638 jkt maps, receipt verifies, and remains non-authorizing",
    {
      mapping_profile: jkt.mapping_profile_id,
      verified: jktCheck.verified,
      execution_authorizing: jktCheck.execution_authorizing,
      algorithms: jktRecord.signatures.map((entry) => entry.alg),
    },
  ));

  const x509Record = await issue(x509, "crossing:aic:x509:0001");
  const x509Check = await verify(x509Record);
  cases.push(result(
    "AIC-X509-SPKI-CROSSING",
    "positive",
    x509.mapping_profile_id === AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE
      && x509Check.verified
      && x509Check.execution_authorizing === false,
    "X.509 SPKI maps, receipt verifies, and remains non-authorizing",
    {
      mapping_profile: x509.mapping_profile_id,
      verified: x509Check.verified,
      execution_authorizing: x509Check.execution_authorizing,
      algorithms: x509Record.signatures.map((entry) => entry.alg),
    },
  ));

  cases.push(result(
    "NATIVE-BINDINGS-REMAIN-DISTINCT",
    "mapping",
    jkt.mapping_profile_id !== x509.mapping_profile_id
      && jkt.native_profile !== x509.native_profile
      && jkt.authority_instance_digest !== x509.authority_instance_digest,
    "RFC7638 jkt and X.509 SPKI are separate native profiles and instances",
    {
      jkt_profile: jkt.mapping_profile_id,
      x509_profile: x509.mapping_profile_id,
      profiles_differ: jkt.mapping_profile_id !== x509.mapping_profile_id,
      instances_differ: jkt.authority_instance_digest !== x509.authority_instance_digest,
    },
  ));

  const relabeledArtifact = mapX509(x509Input({
    artifact_id: "wrapper-label:changed",
  }));
  const relabeledIssuer = mapX509(x509Input({
    issuer: "https://other-wrapper-label.example",
  }));
  cases.push(result(
    "X509-DER-REPLAY-IDENTITY-STABLE",
    "mapping",
    x509.replay_unit === relabeledArtifact.replay_unit
      && x509.replay_unit === relabeledIssuer.replay_unit
      && x509.authority_instance_digest !== relabeledArtifact.authority_instance_digest
      && x509.authority_instance_digest !== relabeledIssuer.authority_instance_digest,
    "exact DER fixes replay identity while authenticated wrapper metadata remains instance-bound",
    {
      artifact_replay_stable: x509.replay_unit === relabeledArtifact.replay_unit,
      issuer_replay_stable: x509.replay_unit === relabeledIssuer.replay_unit,
      artifact_instance_changed:
        x509.authority_instance_digest !== relabeledArtifact.authority_instance_digest,
      issuer_instance_changed:
        x509.authority_instance_digest !== relabeledIssuer.authority_instance_digest,
    },
  ));

  const synthesizedJwtAsX509 = mapAicX509SpkiBoundCrossingAuthority({
    ...x509Input(),
    artifact_digest: JWT_ARTIFACT_DIGEST,
    carrier_provenance: {
      ...jktInput().carrier_provenance,
      downstream_representation: "SYNTHESIZED-X509",
    },
  } as unknown as AicX509SpkiBoundCrossingInput, X509_RP_CONTEXT);
  const synthesizedJwtAsJwt = mapAicJwtJktBoundCrossingAuthority(jktInput({
    carrier_provenance: {
      ...jktInput().carrier_provenance,
      downstream_representation: "SYNTHESIZED-X509",
    },
  }), RP_CONTEXT);
  cases.push(result(
    "SYNTHESIZED-X509-CARRIER-CONFUSION-REFUSED",
    "hostile",
    !synthesizedJwtAsX509.ok
      && synthesizedJwtAsX509.reason === "aic_carrier_provenance_unverifiable"
      && synthesizedJwtAsJwt.ok,
    "JWT-origin synthesized X.509 refuses the native X.509 path and remains JWT/JKT",
    {
      x509_path_ok: synthesizedJwtAsX509.ok,
      x509_path_reason:
        synthesizedJwtAsX509.ok ? null : synthesizedJwtAsX509.reason,
      jwt_path_ok: synthesizedJwtAsJwt.ok,
    },
  ));

  const mismatch = mapAicJwtJktBoundCrossingAuthority(jktInput({
    principal_binding: {
      kind: "RFC7638_JKT",
      hash_alg: "jkt",
      claimed_key_hash: JKT,
      presented_key_hash: "K".repeat(43),
    },
  }), RP_CONTEXT);
  cases.push(result(
    "PRINCIPAL-BINDING-MISMATCH",
    "hostile",
    !mismatch.ok && mismatch.reason === "aic_principal_binding_mismatch",
    "aic_principal_binding_mismatch",
    { ok: mismatch.ok, reason: mismatch.ok ? null : mismatch.reason },
  ));

  const attackerAnchor = `sha256:${"a2".repeat(32)}` as const;
  const untrusted = mapAicX509SpkiBoundCrossingAuthority(x509Input({
    issuer_trust_anchor_digest: attackerAnchor,
  }), X509_RP_CONTEXT);
  const selfPinned = mapAicX509SpkiBoundCrossingAuthority({
    ...x509Input(),
    issuer_trust_anchor_digest: attackerAnchor,
    trusted_issuer_trust_anchor_digests: [attackerAnchor],
  } as unknown as AicX509SpkiBoundCrossingInput, X509_RP_CONTEXT);
  cases.push(result(
    "RP-POLICY-SELF-PIN-REFUSED",
    "hostile",
    !untrusted.ok && untrusted.reason === "aic_issuer_untrusted"
      && !selfPinned.ok && selfPinned.reason === "mapping_input_invalid",
    "native result cannot carry or replace relying-party trust pins",
    {
      untrusted: untrusted.ok ? null : untrusted.reason,
      self_pin: selfPinned.ok ? null : selfPinned.reason,
    },
  ));

  const wrongTypToken = jwtCompactToken("JWT");
  const confused = mapAicJwtJktBoundCrossingAuthority({
    ...jktInput(),
    artifact_digest: `sha256:${crypto.createHash("sha256")
      .update(wrongTypToken, "utf8")
      .digest("hex")}`,
    carrier_provenance: {
      ...jktInput().carrier_provenance,
      compact_token: wrongTypToken,
    },
  }, RP_CONTEXT);
  cases.push(result(
    "NATIVE-TYPE-CONFUSION",
    "hostile",
    !confused.ok && confused.reason === "aic_carrier_provenance_unverifiable",
    "aic_carrier_provenance_unverifiable",
    { ok: confused.ok, reason: confused.ok ? null : confused.reason },
  ));

  const failed = mapAicJwtJktBoundCrossingAuthority(jktInput({
    native_verification: "FAILED",
  }), RP_CONTEXT);
  const indeterminate = mapAicX509SpkiBoundCrossingAuthority(x509Input({
    native_verification: "INDETERMINATE",
  }), X509_RP_CONTEXT);
  cases.push(result(
    "NATIVE-VERIFICATION-REFUSAL",
    "hostile",
    !failed.ok && failed.reason === "aic_native_verification_failed"
      && !indeterminate.ok
      && indeterminate.reason === "aic_native_verification_indeterminate",
    "FAILED and INDETERMINATE both refuse",
    {
      failed: failed.ok ? null : failed.reason,
      indeterminate: indeterminate.ok ? null : indeterminate.reason,
    },
  ));

  const actionMismatch = mapAicJwtJktBoundCrossingAuthority(
    jktInput(),
    {
      ...RP_CONTEXT,
      action: {
        ...ACTION,
        action_digest: `sha256:${"01".repeat(32)}`,
      },
    },
  );
  cases.push(result(
    "EXACT-ACTION-SUBSTITUTION-REFUSED",
    "hostile",
    !actionMismatch.ok
      && actionMismatch.reason === "aic_action_projection_mismatch",
    "aic_action_projection_mismatch",
    {
      ok: actionMismatch.ok,
      reason: actionMismatch.ok ? null : actionMismatch.reason,
    },
  ));

  const changedCapability = mapAicJwtJktBoundCrossingAuthority(jktInput({
    request_binding: {
      ...REQUEST_BINDING,
      requested_capability_digest: `sha256:${"02".repeat(32)}`,
    },
  }), RP_CONTEXT);
  cases.push(result(
    "REQUEST-CAPABILITY-SUBSTITUTION-REFUSED",
    "hostile",
    !changedCapability.ok
      && changedCapability.reason === "aic_requested_capability_mismatch",
    "aic_requested_capability_mismatch",
    {
      ok: changedCapability.ok,
      reason: changedCapability.ok ? null : changedCapability.reason,
    },
  ));

  const wrongDomain = mapAicJwtJktBoundCrossingAuthority(
    jktInput(),
    {
      ...RP_CONTEXT,
      admission_domain: {
        ...BOUNDARY,
        relying_party_id: "rp:other-company",
      },
    },
  );
  cases.push(result(
    "RELYING-PARTY-DOMAIN-SUBSTITUTION-REFUSED",
    "hostile",
    !wrongDomain.ok
      && wrongDomain.reason === "aic_admission_domain_mismatch",
    "aic_admission_domain_mismatch",
    {
      ok: wrongDomain.ok,
      reason: wrongDomain.ok ? null : wrongDomain.reason,
    },
  ));

  const wrongAudienceToken = jwtCompactToken("aic+jwt", "erp:other-system");
  const wrongAudience = mapAicJwtJktBoundCrossingAuthority(jktInput({
    artifact_digest: `sha256:${crypto.createHash("sha256")
      .update(wrongAudienceToken, "utf8")
      .digest("hex")}`,
    carrier_provenance: {
      ...jktInput().carrier_provenance,
      compact_token: wrongAudienceToken,
    },
  }), RP_CONTEXT);
  cases.push(result(
    "JWT-AUDIENCE-SUBSTITUTION-REFUSED",
    "hostile",
    !wrongAudience.ok && wrongAudience.reason === "aic_audience_mismatch",
    "aic_audience_mismatch",
    {
      ok: wrongAudience.ok,
      reason: wrongAudience.ok ? null : wrongAudience.reason,
    },
  ));

  const relabeledJwtValidity = mapAicJwtJktBoundCrossingAuthority(jktInput({
    validity: {
      not_before: "2026-09-01T06:54:00Z",
      not_after: "2026-09-01T07:06:00Z",
    },
  }), RP_CONTEXT);
  cases.push(result(
    "JWT-TEMPORAL-RELABELING-REFUSED",
    "hostile",
    !relabeledJwtValidity.ok
      && relabeledJwtValidity.reason === "aic_jwt_validity_mismatch",
    "signed compact-token iat/nbf/exp must exactly bind wrapper validity",
    {
      ok: relabeledJwtValidity.ok,
      reason: relabeledJwtValidity.ok ? null : relabeledJwtValidity.reason,
    },
  ));

  const stale = mapAicJwtJktBoundCrossingAuthority(jktInput({
    status: {
      value: "CURRENT",
      checked_at: "2026-09-01T06:58:00Z",
      source_head_digest: `sha256:${"b4".repeat(32)}`,
    },
  }), RP_CONTEXT);
  const future = mapAicJwtJktBoundCrossingAuthority(jktInput({
    status: {
      value: "CURRENT",
      checked_at: "2026-09-01T07:00:01Z",
      source_head_digest: `sha256:${"b4".repeat(32)}`,
    },
  }), RP_CONTEXT);
  cases.push(result(
    "STATUS-OBSERVATION-TIME-REFUSALS",
    "hostile",
    !stale.ok && stale.reason === "aic_status_observation_stale"
      && !future.ok && future.reason === "aic_status_observation_future",
    "stale and future observations both refuse",
    {
      stale: stale.ok ? null : stale.reason,
      future: future.ok ? null : future.reason,
    },
  ));

  const widenedFreshness = {
    evaluated_at: NOW,
    max_status_age_seconds: 86_400,
  };
  const widenedBoundJwt = mapAicJwtJktBoundCrossingAuthority(jktInput(), {
    ...RP_CONTEXT,
    ...widenedFreshness,
  });
  const widenedBoundX509 = mapAicX509SpkiBoundCrossingAuthority(x509Input(), {
    ...X509_RP_CONTEXT,
    ...widenedFreshness,
  });
  const widenedUnboundJwt = mapAicJwtJktCrossingAuthority(
    unboundJktInput(),
    JWT_UNBOUND_POLICY,
    widenedFreshness,
  );
  const widenedUnboundX509 = mapAicX509SpkiCrossingAuthority(
    unboundX509Input(),
    X509_UNBOUND_POLICY,
    widenedFreshness,
  );
  const widenedProjection = projectAicJwtToStrictJwtSvid({
    source: unboundJktInput(),
    purpose: "WORKLOAD_IDENTITY_ONLY",
    audience: ["spiffe://services.example/payment-gate"],
    issued_at: 1788246000,
    not_before: 1788245940,
    expires_at: 1788246240,
    token_id: "jwt-svid-projection-freshness-widening",
    projected_algorithm: "ES256",
    projected_key_id: "jwt-svid-key-2026-08",
  }, {
    relying_party_policy: JWT_UNBOUND_POLICY,
    ...widenedFreshness,
  });
  const freshnessMismatch = (value: { ok: boolean; reason?: string }) =>
    !value.ok && value.reason === "aic_status_freshness_profile_mismatch";
  cases.push(result(
    "STATUS-FRESHNESS-PROFILE-WIDENING-REFUSED",
    "hostile",
    freshnessMismatch(widenedBoundJwt)
      && freshnessMismatch(widenedBoundX509)
      && freshnessMismatch(widenedUnboundJwt)
      && freshnessMismatch(widenedUnboundX509)
      && freshnessMismatch(widenedProjection),
    "the fixed 60-second v0.2 freshness profile cannot be widened by a caller",
    {
      bound_jwt: widenedBoundJwt.ok ? null : widenedBoundJwt.reason,
      bound_x509: widenedBoundX509.ok ? null : widenedBoundX509.reason,
      unbound_jwt: widenedUnboundJwt.ok ? null : widenedUnboundJwt.reason,
      unbound_x509: widenedUnboundX509.ok ? null : widenedUnboundX509.reason,
      jwt_svid_projection: widenedProjection.ok ? null : widenedProjection.reason,
    },
  ));

  const revoked = mapAicX509SpkiBoundCrossingAuthority(x509Input({
    status: {
      value: "REVOKED",
      checked_at: NOW,
      source_head_digest: `sha256:${"c4".repeat(32)}`,
    },
  }), X509_RP_CONTEXT);
  const unavailable = mapAicX509SpkiBoundCrossingAuthority(x509Input({
    status: {
      value: "UNAVAILABLE",
      checked_at: NOW,
      source_head_digest: `sha256:${"c4".repeat(32)}`,
    },
  }), X509_RP_CONTEXT);
  cases.push(result(
    "NON-CURRENT-SOURCE-STATUS-REFUSED",
    "hostile",
    !revoked.ok && revoked.reason === "aic_status_not_current"
      && !unavailable.ok && unavailable.reason === "aic_status_not_current",
    "revoked and unavailable source status both refuse",
    {
      revoked: revoked.ok ? null : revoked.reason,
      unavailable: unavailable.ok ? null : unavailable.reason,
    },
  ));

  const outOfWindow = mapAicJwtJktBoundCrossingAuthority(
    jktInput({
      status: {
        ...jktInput().status,
        checked_at: "2026-09-01T07:06:00Z",
      },
    }),
    {
      ...RP_CONTEXT,
      evaluated_at: "2026-09-01T07:06:00Z",
      max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
    },
  );
  cases.push(result(
    "NATIVE-VALIDITY-WINDOW-REFUSED",
    "hostile",
    !outOfWindow.ok
      && outOfWindow.reason === "aic_validity_window_mismatch",
    "aic_validity_window_mismatch",
    {
      ok: outOfWindow.ok,
      reason: outOfWindow.ok ? null : outOfWindow.reason,
    },
  ));

  const rpSubstitutedRecord = structuredClone(jktRecord);
  rpSubstitutedRecord.body.boundary.relying_party_id = "rp:other-company";
  const rpSubstitutedCheck = await verify(rpSubstitutedRecord);
  cases.push(result(
    "SIGNED-CROSSING-RP-SUBSTITUTION-REFUSED",
    "boundary",
    !rpSubstitutedCheck.verified
      && ["contract_digest_mismatch", "signature_invalid"].includes(
        rpSubstitutedCheck.reason ?? "",
      ),
    "signed record substitution refuses",
    {
      verified: rpSubstitutedCheck.verified,
      reason: rpSubstitutedCheck.reason,
    },
  ));

  const base = {
    "@version": "AIC-AEB-CROSSING-REFERENCE-REPORT-v0.2",
    profile: PROFILE,
    crossing_record_version: AEB_CROSSING_RECORD_VERSION,
    required_algorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
    mappings: [
      AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE,
      AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE,
    ],
    action_projection: MAPPING_PROFILE.action_projection,
    admission_domain: MAPPING_PROFILE.admission_domain,
    source_status: MAPPING_PROFILE.source_status,
    source_lock: SOURCE_LOCK,
    source_lock_digest: SOURCE_LOCK_DIGEST,
    mapping_profile_digest: sha256(canonicalizeAeb(MAPPING_PROFILE)),
    native_verification_fixture: {
      execution: "STIPULATED_NOT_EXECUTED",
      jwt_signature: "PLACEHOLDER",
      x509_aic_and_principal_authorization_extensions: "ABSENT",
      upstream_native_acceptance_claimed: false,
    },
    cases,
    passed: cases.every((entry) => entry.passed),
    known_limits: [
      "This run exercises the EMILIA reference adapter and crossing-record implementation; it is not an independent implementation of AIC-JWT or AIC-X509.",
      "The adapter consumes a native verifier result; it does not reimplement AIC signature, certificate-path, delegation, capability, constraint, status, or proof-of-possession validation.",
      "This deterministic suite stipulates native VERIFIED results to test the adapter boundary. Its JWT signature is a placeholder and its parseable X.509 certificates are not AIC credential-bundle fixtures, so it does not claim the pinned upstream verifiers accepted them.",
      "The relying party pins the exact requested-capability digest and action-projection profile. Production integration must also provide an authenticated native result proving that the same capability request was evaluated; the pinned gateway bearer helper does not set RequestCapability.",
      "The adapter checks a supplied capability-to-action projection for exact equality; it does not produce that projection. Unknown schemes, ambiguous mappings, and unmapped material parameters must refuse upstream.",
      "The profile binds one exact action and one relying-party admission domain; changing the action, relying party, audience, executor, or state domain requires a new evaluation.",
      "status.checked_at is the explicit source-status observation time. The v0.2 runtime accepts exactly a 60-second maximum age; a caller cannot widen it. CURRENT status is accepted only within that fixed freshness limit and native validity window; revoked, unavailable, stale, future, or otherwise non-current observations refuse.",
      "The native verifier result and relying-party policy are structurally separate. Trusted anchors and expected verifier, mapping-profile, and action-projection pins come only from relying-party policy, never from the presented native result.",
      "The relying party supplies and authenticates mapping-profile provenance and its digest. This reusable adapter enforces the profile identifier and fixed freshness rule but does not load or recompute the checked-in mapping-profile JSON.",
      "RFC 7638 JWK thumbprints and X.509 SHA-256 SPKI hashes remain separate native mappings and are never treated as interchangeable proof. The JWT path derives the presented JWK thumbprint but does not prove possession of that key.",
      "The JWT/JKT mapping requires the original compact token, derives its audience, issuer/JTI replay identity, and signed iat/nbf/exp envelope, requires exact agreement with wrapper validity, and requires explicit public JWK material. A bare X.509 object synthesized from a verified AIC-JWT has no native bundle DER and cannot enter the native X.509/SPKI mapping.",
      "The X.509 path derives replay identity, bundle digest, serial, and principal SHA-256 SPKI from DER. Issuer, subject, status, validity, constraints, trust-anchor selection, and verification evidence remain authenticated native-wrapper outputs, not facts derived by this adapter from the leaf DER.",
      "Raw-carrier fingerprints are derived from the bytes supplied to this adapter. They do not prove that the native verifier saw those same bytes unless an authenticated wrapper binds the verifier result to them.",
      "The local raw-source boundary does not authenticate a verifier result crossing an untrusted Go or JSON boundary. Integration still requires a tagged or authenticated verifier-result wrapper; the pinned gateway bearer helper sets neither ExpectedAudience, RequestCapability, PrincipalMaterial, nor PresenterKey, and no non-test VerifyBearer wiring was observed.",
      "A verified crossing record is evidence of one past relying-party boundary decision and never authorizes another action.",
      "Passing these checks does not establish IETF adoption, certification, production deployment, independent interoperability, or employer endorsement.",
    ],
  };
  return { ...base, results_digest: sha256(canonicalizeAeb(base)) };
}

export async function runProfile(
  runner = {
    name: "EMILIA reference runner",
    affiliation: "EMILIA Protocol",
    revision: "aic-aeb-crossing-v0.2",
    executed_at: NOW,
  },
) {
  const reference = await buildReferenceReport();
  const passed = reference.cases.filter((entry) => entry.passed).length;
  return {
    ...reference,
    runner,
    reproduction_statement: `${runner.name} (${runner.affiliation}) reproduced ${passed}/${reference.cases.length} AIC crossing checks at ${runner.revision}. This is a reproduction of the EMILIA reference composition, not independent AIC interoperability, IETF adoption, certification, or employer endorsement.`,
  };
}

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const deterministicReference = sorted(await buildReferenceReport());
  if (process.argv.includes("--check")) {
    assert.deepEqual(
      deterministicReference,
      JSON.parse(readFileSync(REFERENCE_PATH, "utf8")),
      "AIC crossing output changed; inspect the semantic delta before deliberately re-pinning report.reference.json",
    );
  }
  const report = await runProfile({
    name: argument("--runner-name") ?? "EMILIA reference runner",
    affiliation: argument("--runner-affiliation") ?? "EMILIA Protocol",
    revision: argument("--runner-revision") ?? "aic-aeb-crossing-v0.2",
    executed_at: argument("--executed-at") ?? NOW,
  });
  const output = argument("--output");
  if (process.argv.includes("--write-reference")) {
    writeFileSync(
      REFERENCE_PATH,
      `${JSON.stringify(deterministicReference, null, 2)}\n`,
      "utf8",
    );
  }
  if (output) {
    writeFileSync(resolve(output), `${JSON.stringify(sorted(report), null, 2)}\n`, "utf8");
  } else {
    process.stdout.write(`${JSON.stringify(sorted(report), null, 2)}\n`);
  }
  if (!report.passed) process.exitCode = 1;
}
