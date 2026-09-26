#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { computeCaid } from "../../../caid/impl/js/caid.mjs";
import { loadRegistryEnumSnapshots } from "../../../caid/registry/enum-snapshots.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "../../..");
const profilePath = join(here, "profile.json");
const vectorsPath = join(here, "vectors.json");

const profile = JSON.parse(readFileSync(profilePath, "utf8"));
const vectorSuite = JSON.parse(readFileSync(vectorsPath, "utf8"));
const registryPath = join(
  repositoryRoot,
  profile.registry.path_from_repository_root,
);
const registryBytes = readFileSync(registryPath);
const registry = JSON.parse(registryBytes.toString("utf8"));
// The value-set snapshots the pinned registry bytes list, each checked
// against the registry's labels, values digest, and whole-file digest.
const enumSnapshots = loadRegistryEnumSnapshots(registry);

const SEGMENT = "[a-z][a-z0-9_-]*";
const LITERAL_SCOPE_RE = new RegExp(`^${SEGMENT}\\.${SEGMENT}(?:\\.${SEGMENT})*$`);
const WILDCARD_SCOPE_RE = new RegExp(`^${SEGMENT}(?:\\.${SEGMENT})*\\.\\*$`);
const DETAIL_KEYS = new Set(["type", "scopes", "constraints"]);
const EXPECTED_DETAIL_TYPE = "agent_delegation";
const EXPECTED_MAPPINGS = new Map([
  ["payment.release", "payment.release.1"],
  ["tool.call", "tool.call.1"],
]);
const EXPECTED_PAYMENT_CURRENCIES = ["EUR", "USD"];
const EXPECTED_TOOL_REQUIRED_FIELDS = ["occurrence_id"];
const EXPECTED_TOOL_RETRY_SEMANTICS = {
  same_logical_invocation: "reuse_identical_occurrence_id_and_caid",
  new_logical_invocation: "new_occurrence_id_and_caid",
};

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function refusal(reason, extra = {}) {
  return { decision: "REFUSED", reason, ...extra };
}

function isScope(value) {
  return typeof value === "string" &&
    (LITERAL_SCOPE_RE.test(value) || WILDCARD_SCOPE_RE.test(value));
}

function covers(grant, requested) {
  if (!isScope(grant) || !LITERAL_SCOPE_RE.test(requested)) return false;
  if (LITERAL_SCOPE_RE.test(grant)) return grant === requested;
  const prefixWithDot = grant.slice(0, -1);
  return requested.startsWith(prefixWithDot);
}

function validateProfilePins() {
  const problems = [];
  const actualRegistryDigest = sha256(registryBytes);

  if (profile.profile_id !== "WIMSE-CAID-SCOPE-01") {
    problems.push("unexpected profile_id");
  }
  if (profile.authorization_details_type !== EXPECTED_DETAIL_TYPE) {
    problems.push("unexpected authorization_details_type");
  }
  if (profile.authorization_details_cardinality?.min !== 1 ||
      profile.authorization_details_cardinality?.max !== 1) {
    problems.push("profile must pin exactly one authorization detail");
  }
  if (profile.caid_suite !== "jcs-sha256") {
    problems.push("profile must pin jcs-sha256");
  }
  if (actualRegistryDigest !== profile.registry.sha256) {
    problems.push(
      `registry digest mismatch: expected ${profile.registry.sha256}, got ${actualRegistryDigest}`,
    );
  }
  if (registry.meta?.registry !== profile.registry.name) {
    problems.push("registry name mismatch");
  }
  if (registry.meta?.registry_version !== profile.registry.version) {
    problems.push("registry version mismatch");
  }
  if (!Array.isArray(profile.mappings) || profile.mappings.length !== 2) {
    problems.push("profile must contain exactly two mappings");
  }

  const definitions = Array.isArray(registry.types) ? registry.types : [];
  const seenScopes = new Set();
  for (const mapping of profile.mappings ?? []) {
    if (!isPlainObject(mapping) || !LITERAL_SCOPE_RE.test(mapping.scope_family)) {
      problems.push("mapping has invalid literal scope_family");
      continue;
    }
    if (seenScopes.has(mapping.scope_family)) {
      problems.push(`duplicate mapping for ${mapping.scope_family}`);
    }
    seenScopes.add(mapping.scope_family);
    if (EXPECTED_MAPPINGS.get(mapping.scope_family) !== mapping.caid_action_type) {
      problems.push(
        `unexpected mapping ${mapping.scope_family} -> ${mapping.caid_action_type}`,
      );
    }
    const definition = definitions.find(
      (entry) => entry.action_type === mapping.caid_action_type,
    );
    if (!definition) {
      problems.push(`missing CAID type ${mapping.caid_action_type}`);
    } else if (definition.status !== "active") {
      problems.push(`CAID type is not active: ${mapping.caid_action_type}`);
    }
  }
  for (const [scopeFamily, actionType] of EXPECTED_MAPPINGS) {
    if (!profile.mappings?.some(
      (mapping) => mapping.scope_family === scopeFamily &&
        mapping.caid_action_type === actionType,
    )) {
      problems.push(`missing expected mapping ${scopeFamily} -> ${actionType}`);
    }
  }

  const currencyPin =
    profile.external_value_pins?.["payment.release.1"]?.currency;
  if (currencyPin?.values_ref !== "ISO 4217 alpha-3" ||
      !Array.isArray(currencyPin.allowed_values) ||
      JSON.stringify(currencyPin.allowed_values) !==
        JSON.stringify(EXPECTED_PAYMENT_CURRENCIES)) {
    problems.push("unexpected payment.release.1 currency pin");
  }
  // The profile subset narrows the registry's pinned snapshot; it must name
  // that exact snapshot and list only codes inside it.
  const registryCurrency = definitions
    .find((entry) => entry.action_type === "payment.release.1")
    ?.required_fields?.find((field) => field.name === "currency");
  const pinnedSnapshot = enumSnapshots.find((snapshot) =>
    snapshot.values_ref === registryCurrency?.values_ref &&
    snapshot.values_snapshot === registryCurrency?.values_snapshot &&
    snapshot.values_sha256 === registryCurrency?.values_sha256);
  if (!pinnedSnapshot ||
      currencyPin?.values_snapshot !== registryCurrency.values_snapshot ||
      currencyPin?.values_sha256 !== registryCurrency.values_sha256 ||
      !currencyPin.allowed_values.every((code) => pinnedSnapshot.values.includes(code))) {
    problems.push("payment.release.1 currency subset does not narrow the registry's pinned snapshot");
  }

  const toolRules = profile.action_type_rules?.["tool.call.1"];
  if (!isPlainObject(toolRules) ||
      JSON.stringify(toolRules.required_profile_fields) !==
        JSON.stringify(EXPECTED_TOOL_REQUIRED_FIELDS) ||
      JSON.stringify(toolRules.retry_semantics) !==
        JSON.stringify(EXPECTED_TOOL_RETRY_SEMANTICS)) {
    problems.push("unexpected tool.call.1 occurrence or retry rules");
  }

  return problems;
}

export function evaluate(input) {
  if (!isPlainObject(input) || input.native_chain_verified !== true) {
    return refusal("native_chain_unverified");
  }
  if (input.constraints_satisfied !== true) {
    return refusal("constraints_not_satisfied");
  }
  if (!Array.isArray(input.authorization_details) ||
      input.authorization_details.length !== 1) {
    return refusal("unsupported_authorization_details_cardinality");
  }

  const detail = input.authorization_details[0];
  if (!isPlainObject(detail)) {
    return refusal("malformed_authorization_detail");
  }
  if (detail.type !== profile.authorization_details_type) {
    return refusal("unknown_authorization_details_type");
  }
  if (Object.keys(detail).some((key) => !DETAIL_KEYS.has(key)) ||
      !Array.isArray(detail.scopes) ||
      ("constraints" in detail && !Array.isArray(detail.constraints))) {
    return refusal("malformed_authorization_detail");
  }
  if (detail.scopes.some((scope) => !isScope(scope))) {
    return refusal("malformed_scope");
  }

  const mapping = profile.mappings.find(
    (candidate) => candidate.scope_family === input.requested_scope,
  );
  if (!mapping || !LITERAL_SCOPE_RE.test(input.requested_scope)) {
    return refusal("unknown_scope_family");
  }
  if (!detail.scopes.some((grant) => covers(grant, input.requested_scope))) {
    return refusal("scope_not_covered");
  }
  if (!isPlainObject(input.action_object) ||
      input.action_object.action_type !== mapping.caid_action_type) {
    return refusal("action_type_mismatch");
  }

  const requiredProfileFields =
    profile.action_type_rules?.[mapping.caid_action_type]
      ?.required_profile_fields ?? [];
  for (const field of requiredProfileFields) {
    if (typeof input.action_object[field] !== "string" ||
        input.action_object[field].length === 0) {
      return refusal("invalid_action_object", {
        caid_reasons: [`missing_or_empty_profile_field:${field}`],
      });
    }
  }

  const computed = computeCaid(input.action_object, {
    suite: profile.caid_suite,
    definitions: registry.types,
    enumSnapshots,
  });
  if (Array.isArray(computed.refusals)) {
    return refusal("invalid_action_object", { caid_reasons: computed.refusals });
  }

  const valuePins = profile.external_value_pins?.[mapping.caid_action_type];
  if (isPlainObject(valuePins)) {
    for (const [field, pin] of Object.entries(valuePins)) {
      if (!isPlainObject(pin) ||
          !Array.isArray(pin.allowed_values) ||
          !pin.allowed_values.includes(input.action_object[field])) {
        return refusal("invalid_action_object", {
          caid_reasons: [`external_enum_not_allowed:${field}`],
        });
      }
    }
  }

  if (computed.caid !== input.presented_caid) {
    return refusal("caid_mismatch");
  }

  return {
    decision: "COVERED",
    reason: "covered",
    scope_family: mapping.scope_family,
    caid_action_type: mapping.caid_action_type,
    caid: computed.caid,
  };
}

function equal(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

const pinProblems = validateProfilePins();
if (pinProblems.length > 0) {
  for (const problem of pinProblems) console.error(`FAIL profile: ${problem}`);
  process.exit(1);
}
console.log(
  `PASS profile pins (${profile.registry.name} v${profile.registry.version}, sha256:${profile.registry.sha256})`,
);

let passed = 0;
let failed = 0;
for (const vector of vectorSuite.vectors ?? []) {
  const actual = evaluate(vector.input);
  if (equal(actual, vector.expect)) {
    passed += 1;
    console.log(`PASS ${vector.id}`);
  } else {
    failed += 1;
    console.error(`FAIL ${vector.id}`);
    console.error(`  expected ${JSON.stringify(vector.expect)}`);
    console.error(`  actual   ${JSON.stringify(actual)}`);
  }
}

console.log(`${passed} vectors passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
