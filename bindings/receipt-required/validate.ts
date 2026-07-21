// SPDX-License-Identifier: Apache-2.0
/**
 * Pure conformance helpers for the data-only Receipt Required binding registry.
 * This module does not verify any foreign protocol artifact or grant authority.
 */

import { computeCaid } from "../../caid/impl/js/caid.mjs";

type JsonRecord = Record<string, any>;

export type BindingValidation = {
  valid: boolean;
  errors: string[];
};

const TOP_KEYS = new Set([
  "@version",
  "registry_id",
  "description",
  "artifact_boundary",
  "profiles",
]);
const PROFILE_KEYS = new Set([
  "profile_id",
  "protocol_id",
  "protocol_version",
  "implementation_status",
  "match_selector",
  "challenge_carrier",
  "proof_carrier",
  "caid_extraction",
  "required_field_mapping",
  "conformance_vector_refs",
  "claim_boundary",
]);
const SELECTOR_KEYS = new Set([
  "carrier",
  "discriminator_path",
  "discriminator_value",
]);
const CHALLENGE_KEYS = new Set([
  "kind",
  "location",
  "content_type",
  "refusal_code",
]);
const PROOF_KEYS = new Set(["kind", "location", "content_type"]);
const CAID_KEYS = new Set(["caid_path", "action_hash_path"]);
const MAPPING_KEYS = new Set(["action_field", "source_path"]);
const STATUSES = new Set([
  "reference_implemented",
  "experimental_reference",
  "documented_profile",
  "synthetic_binding_profile",
  "verification_context_only",
]);
const PROFILE_ID = /^ep:receipt-required:binding:[a-z0-9-]+:v1$/;
const PROTOCOL_ID = /^[a-z0-9-]+$/;
const ACTION_FIELD = /^[a-z][a-z0-9_]*$/;
const CAID = /^caid:1:[a-z][a-z0-9._-]{0,126}:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ACTION_HASH = /^sha256:[0-9a-f]{64}$/;
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function closed(
  path: string,
  value: unknown,
  allowed: Set<string>,
  errors: string[],
): value is JsonRecord {
  if (!isRecord(value)) {
    errors.push(`${path} must be an object`);
    return false;
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) errors.push(`${path}.${key} is not allowed`);
  }
  return true;
}

function requiredString(
  path: string,
  value: unknown,
  errors: string[],
  pattern?: RegExp,
): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    (pattern && !pattern.test(value))
  ) {
    errors.push(`${path} must be a valid non-empty string`);
  }
}

function validPointer(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith("/")) return false;
  try {
    return pointerSegments(value).every(
      (segment) => !FORBIDDEN_SEGMENTS.has(segment),
    );
  } catch {
    return false;
  }
}

function pointerSegments(pointer: string): string[] {
  if (pointer === "") return [];
  if (!pointer.startsWith("/"))
    throw new Error("JSON pointer must start with /");
  return pointer
    .slice(1)
    .split("/")
    .map((segment) => {
      if (/~(?:[^01]|$)/.test(segment))
        throw new Error("invalid JSON pointer escape");
      return segment.replace(/~1/g, "/").replace(/~0/g, "~");
    });
}

function getPointer(value: unknown, pointer: string): unknown {
  let current: any = value;
  for (const segment of pointerSegments(pointer)) {
    if (
      FORBIDDEN_SEGMENTS.has(segment) ||
      !isRecord(current) ||
      !Object.prototype.hasOwnProperty.call(current, segment)
    )
      return undefined;
    current = current[segment];
  }
  return current;
}

function setPointer(
  value: unknown,
  pointer: string,
  replacement: unknown,
): void {
  const segments = pointerSegments(pointer);
  if (segments.length === 0)
    throw new Error("mutation path cannot target the document root");
  let current: any = value;
  for (const segment of segments.slice(0, -1)) {
    if (
      FORBIDDEN_SEGMENTS.has(segment) ||
      !isRecord(current) ||
      !Object.prototype.hasOwnProperty.call(current, segment)
    ) {
      throw new Error(`mutation path ${pointer} does not exist`);
    }
    current = current[segment];
  }
  const leaf = segments.at(-1)!;
  if (
    FORBIDDEN_SEGMENTS.has(leaf) ||
    !isRecord(current) ||
    !Object.prototype.hasOwnProperty.call(current, leaf)
  ) {
    throw new Error(`mutation path ${pointer} does not exist`);
  }
  current[leaf] = replacement;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value as JsonRecord)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${canonical((value as JsonRecord)[key])}`,
    )
    .join(",")}}`;
}

export function validateBindingRegistry(registry: unknown): BindingValidation {
  const errors: string[] = [];
  if (!closed("registry", registry, TOP_KEYS, errors))
    return { valid: false, errors };

  if (registry["@version"] !== "EP-RECEIPT-REQUIRED-BINDINGS-v1") {
    errors.push("registry.@version must be EP-RECEIPT-REQUIRED-BINDINGS-v1");
  }
  if (registry.registry_id !== "ep:receipt-required:bindings:v1") {
    errors.push("registry.registry_id must be ep:receipt-required:bindings:v1");
  }
  requiredString("registry.description", registry.description, errors);
  requiredString(
    "registry.artifact_boundary",
    registry.artifact_boundary,
    errors,
  );
  if (!Array.isArray(registry.profiles) || registry.profiles.length === 0) {
    errors.push("registry.profiles must be a non-empty array");
    return { valid: false, errors };
  }

  const profileIds = new Set<string>();
  const protocolIds = new Set<string>();
  const selectors = new Map<string, string>();

  registry.profiles.forEach((profile: unknown, index: number) => {
    const path = `profiles[${index}]`;
    if (!closed(path, profile, PROFILE_KEYS, errors)) return;

    requiredString(
      `${path}.profile_id`,
      profile.profile_id,
      errors,
      PROFILE_ID,
    );
    requiredString(
      `${path}.protocol_id`,
      profile.protocol_id,
      errors,
      PROTOCOL_ID,
    );
    requiredString(
      `${path}.protocol_version`,
      profile.protocol_version,
      errors,
    );
    requiredString(`${path}.claim_boundary`, profile.claim_boundary, errors);
    if (!STATUSES.has(profile.implementation_status)) {
      errors.push(`${path}.implementation_status is unsupported`);
    }
    if (typeof profile.profile_id === "string") {
      if (profileIds.has(profile.profile_id))
        errors.push(`${path}.profile_id is duplicated`);
      profileIds.add(profile.profile_id);
    }
    if (typeof profile.protocol_id === "string") {
      if (protocolIds.has(profile.protocol_id))
        errors.push(`${path}.protocol_id is duplicated`);
      protocolIds.add(profile.protocol_id);
    }

    if (
      closed(
        `${path}.match_selector`,
        profile.match_selector,
        SELECTOR_KEYS,
        errors,
      )
    ) {
      requiredString(
        `${path}.match_selector.carrier`,
        profile.match_selector.carrier,
        errors,
      );
      if (!validPointer(profile.match_selector.discriminator_path)) {
        errors.push(
          `${path}.match_selector.discriminator_path must be a safe JSON pointer`,
        );
      }
      if (
        typeof profile.match_selector.discriminator_value !== "string" &&
        !Number.isInteger(profile.match_selector.discriminator_value)
      ) {
        errors.push(
          `${path}.match_selector.discriminator_value must be a string or integer`,
        );
      }
      const signature = canonical(profile.match_selector);
      const prior = selectors.get(signature);
      if (prior)
        errors.push(
          `${path}.match_selector is an ambiguous match selector with ${prior}`,
        );
      else selectors.set(signature, path);
    }

    if (
      closed(
        `${path}.challenge_carrier`,
        profile.challenge_carrier,
        CHALLENGE_KEYS,
        errors,
      )
    ) {
      requiredString(
        `${path}.challenge_carrier.kind`,
        profile.challenge_carrier.kind,
        errors,
      );
      requiredString(
        `${path}.challenge_carrier.location`,
        profile.challenge_carrier.location,
        errors,
      );
      requiredString(
        `${path}.challenge_carrier.content_type`,
        profile.challenge_carrier.content_type,
        errors,
      );
      if (
        typeof profile.challenge_carrier.refusal_code !== "string" &&
        !Number.isInteger(profile.challenge_carrier.refusal_code)
      ) {
        errors.push(
          `${path}.challenge_carrier.refusal_code must be a string or integer`,
        );
      }
    }
    if (
      closed(`${path}.proof_carrier`, profile.proof_carrier, PROOF_KEYS, errors)
    ) {
      requiredString(
        `${path}.proof_carrier.kind`,
        profile.proof_carrier.kind,
        errors,
      );
      requiredString(
        `${path}.proof_carrier.location`,
        profile.proof_carrier.location,
        errors,
      );
      requiredString(
        `${path}.proof_carrier.content_type`,
        profile.proof_carrier.content_type,
        errors,
      );
    }
    if (
      closed(
        `${path}.caid_extraction`,
        profile.caid_extraction,
        CAID_KEYS,
        errors,
      )
    ) {
      for (const key of CAID_KEYS) {
        if (!validPointer(profile.caid_extraction[key])) {
          errors.push(
            `${path}.caid_extraction.${key} must be a safe JSON pointer`,
          );
        }
      }
    }

    if (
      !Array.isArray(profile.required_field_mapping) ||
      profile.required_field_mapping.length === 0
    ) {
      errors.push(`${path}.required_field_mapping must be a non-empty array`);
    } else {
      const actionFields = new Set<string>();
      profile.required_field_mapping.forEach(
        (mapping: unknown, mappingIndex: number) => {
          const mappingPath = `${path}.required_field_mapping[${mappingIndex}]`;
          if (!closed(mappingPath, mapping, MAPPING_KEYS, errors)) return;
          requiredString(
            `${mappingPath}.action_field`,
            mapping.action_field,
            errors,
            ACTION_FIELD,
          );
          if (!validPointer(mapping.source_path)) {
            errors.push(
              `${mappingPath}.source_path must be a safe JSON pointer`,
            );
          }
          if (typeof mapping.action_field === "string") {
            if (actionFields.has(mapping.action_field))
              errors.push(`${mappingPath}.action_field is duplicated`);
            actionFields.add(mapping.action_field);
          }
        },
      );
    }

    if (
      !Array.isArray(profile.conformance_vector_refs) ||
      profile.conformance_vector_refs.length === 0 ||
      profile.conformance_vector_refs.some(
        (ref: unknown) => typeof ref !== "string" || ref.length === 0,
      ) ||
      new Set(profile.conformance_vector_refs).size !==
        profile.conformance_vector_refs.length
    ) {
      errors.push(
        `${path}.conformance_vector_refs must contain unique non-empty strings`,
      );
    }
  });

  return { valid: errors.length === 0, errors };
}

export function projectBoundAction(
  profile: JsonRecord,
  artifact: unknown,
): {
  action: JsonRecord;
  caid: string;
  actionHash: string;
} {
  const action: JsonRecord = {};
  for (const mapping of profile.required_field_mapping ?? []) {
    const value = getPointer(artifact, mapping.source_path);
    if (value === undefined || value === null || value === "") {
      throw new Error(`missing required binding for ${mapping.action_field}`);
    }
    action[mapping.action_field] = structuredClone(value);
  }
  const caid = getPointer(artifact, profile.caid_extraction?.caid_path);
  const actionHash = getPointer(
    artifact,
    profile.caid_extraction?.action_hash_path,
  );
  if (typeof caid !== "string" || !CAID.test(caid))
    throw new Error("missing or malformed CAID binding");
  if (typeof actionHash !== "string" || !ACTION_HASH.test(actionHash)) {
    throw new Error("missing or malformed action-hash binding");
  }
  return { action, caid, actionHash };
}

export function evaluateBindingVectors(
  registry: JsonRecord,
  suite: JsonRecord,
): Array<{
  id: string;
  valid: boolean;
  reason: string | null;
}> {
  const registryCheck = validateBindingRegistry(registry);
  if (!registryCheck.valid)
    throw new Error(
      `invalid binding registry: ${registryCheck.errors.join("; ")}`,
    );
  if (
    suite?.["@version"] !== "EP-RECEIPT-REQUIRED-BINDING-VECTORS-v1" ||
    !isRecord(suite.fixtures) ||
    !Array.isArray(suite.vectors)
  ) {
    throw new Error("invalid binding vector suite");
  }

  const computed = computeCaid(suite.canonical_action, {
    suite: "jcs-sha256",
    definitions: suite.definitions,
  });
  if (
    computed.caid !== suite.expected_caid ||
    computed.digest !== suite.expected_action_hash
  ) {
    throw new Error(
      "vector suite CAID does not recompute from canonical_action",
    );
  }

  return suite.vectors.map((vector: JsonRecord) => {
    let reason: string | null = null;
    for (const profile of registry.profiles) {
      const fixtureRef = vector.fixture_refs?.[profile.protocol_id];
      const sourceFixture =
        typeof fixtureRef === "string" ? suite.fixtures[fixtureRef] : null;
      if (!isRecord(sourceFixture) || !isRecord(sourceFixture.artifact)) {
        reason = "missing_binding";
        break;
      }
      const fixture = structuredClone(sourceFixture);
      for (const mutation of vector.mutations ?? []) {
        if (mutation.protocol_id === profile.protocol_id) {
          setPointer(fixture.artifact, mutation.path, mutation.value);
        }
      }
      let projection;
      try {
        projection = projectBoundAction(profile, fixture.artifact);
      } catch {
        reason = "missing_binding";
        break;
      }
      if (canonical(projection.action) !== canonical(suite.canonical_action)) {
        reason = "action_binding_mismatch";
        break;
      }
      if (projection.caid !== suite.expected_caid) {
        reason = "caid_mismatch";
        break;
      }
      if (projection.actionHash !== suite.expected_action_hash) {
        reason = "action_hash_mismatch";
        break;
      }
    }
    return { id: vector.id, valid: reason === null, reason };
  });
}
