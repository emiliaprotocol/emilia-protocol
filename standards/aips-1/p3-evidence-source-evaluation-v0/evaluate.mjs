#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Local, experimental evaluator for AIPS-1 P3 public-comment analysis.
// AIPS-1 v0.1 publishes neither a normative predicate grammar nor a reference
// verifier. This file therefore implements a closed, repository-local dialect
// and never reports AIPS conformance, authorization, coverage, liability,
// claim acceptance, payout, or a certificate state transition.

import { createHash } from "node:crypto";
import { closeSync, openSync, readSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { types as utilTypes } from "node:util";

export const PROFILE_VERSION = "aips1-p3-evidence-source-evaluation-v0.1";
export const EVIDENCE_SET_VERSION = "aips1-p3-evidence-set-v0.1";
export const REPORT_VERSION = "aips1-p3-evidence-source-report-v0.1";
export const VERDICTS = ["SATISFIED", "NOT_SATISFIED", "INDETERMINATE"];
export const SUPPORTED_OPERATORS = ["EQUALS", "NOT_EQUALS", "NUMBER_GTE", "NUMBER_LTE"];
export const SUPPORTED_SOURCE_FORMATS = ["application/json"];

export const LIMITS = Object.freeze({
  max_input_bytes: 1_048_576,
  max_depth: 32,
  max_total_nodes: 10_000,
  max_collection_items: 256,
  max_string_length: 8_192,
  max_total_string_length: 1_048_576,
  max_identifier_length: 256,
  max_locator_length: 2_048,
  max_sources: 32,
  max_predicates: 64,
  max_observations: 128,
  max_age_seconds: 31_536_000,
  max_validation_errors: 64,
  max_validation_error_length: 512,
});

export const LOCAL_DIALECT = Object.freeze({
  dialect_id: "emilia-aips1-p3-local-json-pointer-v0.1",
  authority: "repository_local_proposal_not_aips1_v0.1",
  appendix_a_example_mapping: {
    type: "sources[].source_type",
    sourceRef: "predicates[].source_ids resolved through sources[].locator",
    field: "predicates[].path as an RFC 6901 JSON Pointer",
    operator_eq: "EQUALS",
    value: "predicates[].expected",
  },
  local_extensions: [
    "ALL composition",
    "multiple declared sources per predicate",
    "NOT_EQUALS",
    "NUMBER_GTE",
    "NUMBER_LTE",
    "three-state runtime verdict",
    "safe-integer-only JSON numbers",
  ],
});

export const SCOPE = Object.freeze({
  evaluates: "local_trigger_predicate_satisfaction",
  evaluation_mode: "offline_fixture_evaluation",
  does_not_evaluate: ["AIPS certificate evidenceRequired", "AIPS certificate state transitions"],
  assumptions: [
    "the evaluation profile is trusted out of band",
    "fixture locator, revision, observed_at, and availability metadata are supplied inputs",
    "data_sha256 pins canonical parsed JSON, not source raw bytes",
    "JSON numbers are restricted to signed IEEE-754 safe integers; decimals use fixed-point integers or strings",
  ],
  does_not_determine: [
    "authorization",
    "coverage",
    "liability",
    "claim_acceptance",
    "payout",
  ],
});

const PROFILE_FIELDS = [
  "profile_version",
  "profile_id",
  "evaluation_time",
  "combiner",
  "sources",
  "predicates",
];
const SOURCE_FIELDS = [
  "source_id",
  "source_type",
  "locator",
  "revision",
  "format",
  "basis",
  "data_sha256",
  "max_age_seconds",
];
const PREDICATE_FIELDS = [
  "predicate_id",
  "source_ids",
  "path",
  "operator",
  "expected",
];
const EVIDENCE_SET_FIELDS = ["evidence_set_version", "observations"];
const OBSERVATION_FIELDS = [
  "source_id",
  "locator",
  "revision",
  "observed_at",
  "availability",
  "format",
  "basis",
  "data",
];

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isBoundedString(value, maximum) {
  return isNonEmptyString(value) && value.length <= maximum;
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function unknownFields(object, allowed, prefix) {
  if (!isRecord(object)) return [];
  return Object.keys(object)
    .filter((key) => !allowed.includes(key))
    .sort()
    .map((key) => `${prefix}unknown-field:${key}`);
}

const STRICT_TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/;

function strictTimestampMs(value) {
  if (typeof value !== "string") return null;
  const match = STRICT_TIMESTAMP_PATTERN.exec(value);
  if (!match || match[1] === "0000") return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return null;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > days[month - 1]) return null;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? milliseconds : null;
}

function isRfc3339(value) {
  return strictTimestampMs(value) !== null;
}

function inspectJson(value) {
  const errors = [];
  let nodes = 0;
  let totalStringLength = 0;
  const ancestors = new Set();

  function countString(valueToCount) {
    totalStringLength += valueToCount.length;
    if (valueToCount.length > LIMITS.max_string_length) {
      errors.push("input:max-string-length-exceeded");
    }
    if (totalStringLength > LIMITS.max_total_string_length) {
      errors.push("input:max-total-string-length-exceeded");
    }
  }

  function visit(current, depth) {
    nodes += 1;
    if (nodes > LIMITS.max_total_nodes) {
      errors.push("input:max-total-nodes-exceeded");
      return;
    }
    if (depth > LIMITS.max_depth) {
      errors.push("input:max-depth-exceeded");
      return;
    }
    if (current === null || typeof current === "boolean") return;
    if (typeof current === "string") {
      countString(current);
      return;
    }
    if (typeof current === "number") {
      if (!Number.isSafeInteger(current) || Object.is(current, -0)) {
        errors.push("input:unsafe-number");
      }
      return;
    }
    if (typeof current !== "object") {
      errors.push("input:non-json-value");
      return;
    }
    if (utilTypes.isProxy(current)) {
      errors.push("input:proxy-object");
      return;
    }
    if (ancestors.has(current)) {
      errors.push("input:cyclic-value");
      return;
    }
    ancestors.add(current);
    if (Array.isArray(current)) {
      if (Object.getPrototypeOf(current) !== Array.prototype) {
        errors.push("input:non-plain-object");
        ancestors.delete(current);
        return;
      }
      const descriptors = Object.getOwnPropertyDescriptors(current);
      const length = descriptors.length?.value;
      if (!Number.isSafeInteger(length) || length < 0) {
        errors.push("input:invalid-array-length");
        ancestors.delete(current);
        return;
      }
      if (length > LIMITS.max_collection_items) {
        errors.push("input:max-collection-items-exceeded");
      }
      for (const key of Reflect.ownKeys(descriptors)) {
        if (typeof key !== "string") {
          errors.push("input:symbol-property");
          continue;
        }
        if (key !== "length" && !/^(?:0|[1-9]\d*)$/.test(key)) {
          errors.push("input:array-extra-property");
        }
      }
      const maximum = Math.min(length, LIMITS.max_collection_items + 1);
      for (let index = 0; index < maximum; index += 1) {
        const descriptor = descriptors[index];
        if (!descriptor) {
          errors.push("input:sparse-array");
          continue;
        }
        if (!("value" in descriptor)) {
          errors.push("input:accessor-property");
          continue;
        }
        if (!descriptor.enumerable) {
          errors.push("input:non-enumerable-property");
          continue;
        }
        visit(descriptor.value, depth + 1);
      }
    } else {
      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        errors.push("input:non-plain-object");
        ancestors.delete(current);
        return;
      }
      const descriptors = Object.getOwnPropertyDescriptors(current);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.length > LIMITS.max_collection_items) {
        errors.push("input:max-collection-items-exceeded");
      }
      for (const key of keys.slice(0, LIMITS.max_collection_items + 1)) {
        if (typeof key !== "string") {
          errors.push("input:symbol-property");
          continue;
        }
        countString(key);
        const descriptor = descriptors[key];
        if (!("value" in descriptor)) {
          errors.push("input:accessor-property");
          continue;
        }
        if (!descriptor.enumerable) {
          errors.push("input:non-enumerable-property");
          continue;
        }
        visit(descriptor.value, depth + 1);
      }
    }
    ancestors.delete(current);
  }

  visit(value, 0);
  return [...new Set(errors)].sort();
}

function isJsonValue(value) {
  return inspectJson(value).length === 0;
}

function snapshotJson(value, snapshots = new Map()) {
  if (value === null || typeof value !== "object") return value;
  if (snapshots.has(value)) return snapshots.get(value);
  if (Array.isArray(value)) {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const snapshot = [];
    snapshots.set(value, snapshot);
    for (let index = 0; index < descriptors.length.value; index += 1) {
      snapshot.push(snapshotJson(descriptors[index].value, snapshots));
    }
    return snapshot;
  }
  const snapshot = Object.create(null);
  snapshots.set(value, snapshot);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Object.keys(descriptors)) {
    Object.defineProperty(snapshot, key, {
      value: snapshotJson(descriptors[key].value, snapshots),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return snapshot;
}

function canonicalJsonUnchecked(value, seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new TypeError("number is outside the safe-integer JSON subset");
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object" || seen.has(value)) {
    throw new TypeError("value is not acyclic JSON");
  }
  seen.add(value);
  let encoded;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!hasOwn(value, index)) throw new TypeError("sparse arrays are not JSON values");
    }
    encoded = `[${value.map((item) => canonicalJsonUnchecked(item, seen)).join(",")}]`;
  } else {
    const members = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJsonUnchecked(value[key], seen)}`);
    encoded = `{${members.join(",")}}`;
  }
  seen.delete(value);
  return encoded;
}

export function canonicalJson(value) {
  const errors = inspectJson(value);
  if (errors.length > 0) throw new TypeError(errors[0]);
  return canonicalJsonUnchecked(value);
}

export function digestJson(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

class StrictJsonError extends SyntaxError {
  constructor(code) {
    super(code);
    this.name = "StrictJsonError";
    this.code = code;
  }
}

function strictJsonError(code) {
  throw new StrictJsonError(code);
}

export function parseJsonStrict(source) {
  if (typeof source !== "string") strictJsonError("MALFORMED_JSON");
  if (Buffer.byteLength(source, "utf8") > LIMITS.max_input_bytes) {
    strictJsonError("INPUT_LIMIT_EXCEEDED");
  }
  let index = 0;
  let nodes = 0;

  function whitespace() {
    while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1;
  }

  function countNode(depth) {
    nodes += 1;
    if (nodes > LIMITS.max_total_nodes || depth > LIMITS.max_depth) {
      strictJsonError("INPUT_LIMIT_EXCEEDED");
    }
  }

  function stringValue() {
    if (source[index] !== '"') strictJsonError("MALFORMED_JSON");
    const start = index;
    index += 1;
    let escaped = false;
    while (index < source.length) {
      const code = source.charCodeAt(index);
      if (escaped) {
        if (source[index] === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(index + 1, index + 5))) {
            strictJsonError("MALFORMED_JSON");
          }
          index += 5;
        } else {
          if (!['"', "\\", "/", "b", "f", "n", "r", "t"].includes(source[index])) {
            strictJsonError("MALFORMED_JSON");
          }
          index += 1;
        }
        escaped = false;
        continue;
      }
      if (source[index] === "\\") {
        escaped = true;
        index += 1;
        continue;
      }
      if (source[index] === '"') {
        index += 1;
        let decoded;
        try {
          decoded = JSON.parse(source.slice(start, index));
        } catch {
          strictJsonError("MALFORMED_JSON");
        }
        if (decoded.length > LIMITS.max_string_length) strictJsonError("INPUT_LIMIT_EXCEEDED");
        return decoded;
      }
      if (code < 0x20) strictJsonError("MALFORMED_JSON");
      index += 1;
    }
    strictJsonError("MALFORMED_JSON");
  }

  function arrayValue(depth) {
    index += 1;
    const result = [];
    whitespace();
    if (source[index] === "]") {
      index += 1;
      return result;
    }
    while (index < source.length) {
      if (result.length >= LIMITS.max_collection_items) strictJsonError("INPUT_LIMIT_EXCEEDED");
      result.push(value(depth + 1));
      whitespace();
      if (source[index] === "]") {
        index += 1;
        return result;
      }
      if (source[index] !== ",") strictJsonError("MALFORMED_JSON");
      index += 1;
      whitespace();
    }
    strictJsonError("MALFORMED_JSON");
  }

  function objectValue(depth) {
    index += 1;
    const result = Object.create(null);
    const members = new Set();
    whitespace();
    if (source[index] === "}") {
      index += 1;
      return result;
    }
    while (index < source.length) {
      if (members.size >= LIMITS.max_collection_items) strictJsonError("INPUT_LIMIT_EXCEEDED");
      const key = stringValue();
      if (members.has(key)) strictJsonError("DUPLICATE_MEMBER");
      members.add(key);
      whitespace();
      if (source[index] !== ":") strictJsonError("MALFORMED_JSON");
      index += 1;
      whitespace();
      Object.defineProperty(result, key, {
        value: value(depth + 1),
        enumerable: true,
        configurable: true,
        writable: true,
      });
      whitespace();
      if (source[index] === "}") {
        index += 1;
        return result;
      }
      if (source[index] !== ",") strictJsonError("MALFORMED_JSON");
      index += 1;
      whitespace();
    }
    strictJsonError("MALFORMED_JSON");
  }

  function value(depth) {
    whitespace();
    countNode(depth);
    const character = source[index];
    if (character === '"') return stringValue();
    if (character === "[") return arrayValue(depth);
    if (character === "{") return objectValue(depth);
    for (const [literal, decoded] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) {
        index += literal.length;
        return decoded;
      }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(index));
    if (!number) strictJsonError("MALFORMED_JSON");
    index += number[0].length;
    const token = number[0];
    const decoded = Number(token);
    if (!Number.isSafeInteger(decoded) || Object.is(decoded, -0) || token !== String(decoded)) {
      strictJsonError("UNSAFE_NUMBER");
    }
    return decoded;
  }

  const result = value(0);
  whitespace();
  if (index !== source.length) strictJsonError("MALFORMED_JSON");
  return result;
}

function readTextBounded(filePath) {
  const descriptor = openSync(filePath, "r");
  try {
    const buffer = Buffer.allocUnsafe(LIMITS.max_input_bytes + 1);
    let total = 0;
    while (total < buffer.length) {
      const count = readSync(descriptor, buffer, total, buffer.length - total, null);
      if (count === 0) break;
      total += count;
    }
    if (total > LIMITS.max_input_bytes) strictJsonError("INPUT_LIMIT_EXCEEDED");
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, total));
    } catch {
      strictJsonError("MALFORMED_JSON");
    }
  } finally {
    closeSync(descriptor);
  }
}

export function loadJsonFileStrict(filePath) {
  return parseJsonStrict(readTextBounded(filePath));
}

export const LOCAL_DIALECT_SHA256 = digestJson(LOCAL_DIALECT);

function validPointer(pointer) {
  if (pointer === "") return true;
  if (typeof pointer !== "string" || !pointer.startsWith("/")) return false;
  return !/(?:~(?![01]))/.test(pointer);
}

function pointerValue(document, pointer) {
  if (pointer === "") return { found: true, value: document };
  if (!validPointer(pointer)) return { found: false };
  let current = document;
  for (const token of pointer.slice(1).split("/")) {
    const key = token.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9]\d*)$/.test(key)) return { found: false };
      const arrayIndex = Number(key);
      if (!Number.isSafeInteger(arrayIndex) || arrayIndex >= current.length || !hasOwn(current, arrayIndex)) {
        return { found: false };
      }
      current = current[arrayIndex];
      continue;
    }
    if (current === null || typeof current !== "object" || !hasOwn(current, key)) {
      return { found: false };
    }
    current = current[key];
  }
  return { found: true, value: current };
}

function validateProfile(profile) {
  const errors = [];
  if (!isRecord(profile)) return ["profile:not-an-object"];
  errors.push(...unknownFields(profile, PROFILE_FIELDS, "profile:"));
  if (profile.profile_version !== PROFILE_VERSION) errors.push("profile:wrong-version");
  if (!isBoundedString(profile.profile_id, LIMITS.max_identifier_length)) {
    errors.push("profile:invalid-profile-id");
  }
  if (!isRfc3339(profile.evaluation_time)) errors.push("profile:invalid-evaluation-time");
  if (profile.combiner !== "ALL") errors.push("profile:unsupported-combiner");
  if (!Array.isArray(profile.sources) || profile.sources.length === 0) {
    errors.push("profile:sources-must-be-non-empty-array");
  } else if (profile.sources.length > LIMITS.max_sources) {
    errors.push("profile:too-many-sources");
  }
  if (!Array.isArray(profile.predicates) || profile.predicates.length === 0) {
    errors.push("profile:predicates-must-be-non-empty-array");
  } else if (profile.predicates.length > LIMITS.max_predicates) {
    errors.push("profile:too-many-predicates");
  }

  if (Array.isArray(profile.sources)) {
    profile.sources.forEach((source, index) => {
      const prefix = `profile:sources[${index}]:`;
      if (!isRecord(source)) {
        errors.push(`${prefix}not-an-object`);
        return;
      }
      errors.push(...unknownFields(source, SOURCE_FIELDS, prefix));
      for (const field of SOURCE_FIELDS) {
        if (!hasOwn(source, field)) errors.push(`${prefix}missing:${field}`);
      }
      for (const field of ["source_id", "source_type", "revision", "format"]) {
        if (!isBoundedString(source[field], LIMITS.max_identifier_length)) {
          errors.push(`${prefix}invalid:${field}`);
        }
      }
      if (!isBoundedString(source.locator, LIMITS.max_locator_length)) {
        errors.push(`${prefix}invalid:locator`);
      }
      if (!["OBSERVED_FACT", "ISSUER_OPINION"].includes(source.basis)) {
        errors.push(`${prefix}invalid:basis`);
      }
      if (!/^sha256:[0-9a-f]{64}$/.test(source.data_sha256 ?? "")) {
        errors.push(`${prefix}invalid:data_sha256`);
      }
      if (
        !Number.isInteger(source.max_age_seconds) ||
        source.max_age_seconds < 0 ||
        source.max_age_seconds > LIMITS.max_age_seconds
      ) {
        errors.push(`${prefix}invalid:max_age_seconds`);
      }
    });
  }

  if (Array.isArray(profile.predicates)) {
    profile.predicates.forEach((predicate, index) => {
      const prefix = `profile:predicates[${index}]:`;
      if (!isRecord(predicate)) {
        errors.push(`${prefix}not-an-object`);
        return;
      }
      errors.push(...unknownFields(predicate, PREDICATE_FIELDS, prefix));
      for (const field of PREDICATE_FIELDS) {
        if (!hasOwn(predicate, field)) errors.push(`${prefix}missing:${field}`);
      }
      if (!isBoundedString(predicate.predicate_id, LIMITS.max_identifier_length)) {
        errors.push(`${prefix}invalid:predicate_id`);
      }
      if (!validPointer(predicate.path)) errors.push(`${prefix}invalid:path`);
      if (!isBoundedString(predicate.path, LIMITS.max_locator_length)) errors.push(`${prefix}invalid:path`);
      if (!isBoundedString(predicate.operator, LIMITS.max_identifier_length)) {
        errors.push(`${prefix}invalid:operator`);
      }
      if (!hasOwn(predicate, "expected") || !isJsonValue(predicate.expected)) {
        errors.push(`${prefix}invalid:expected`);
      }
      if (!Array.isArray(predicate.source_ids) || predicate.source_ids.length === 0) {
        errors.push(`${prefix}invalid:source_ids`);
      } else {
        if (predicate.source_ids.length > LIMITS.max_sources) {
          errors.push(`${prefix}too-many:source_ids`);
        }
        const localIds = new Set();
        predicate.source_ids.forEach((sourceId) => {
          if (!isBoundedString(sourceId, LIMITS.max_identifier_length)) {
            errors.push(`${prefix}invalid:source_id`);
          }
          if (localIds.has(sourceId)) errors.push(`${prefix}duplicate-source-ref`);
          localIds.add(sourceId);
        });
      }
    });
  }
  return [...new Set(errors)].sort();
}

function validateEvidenceSet(evidenceSet) {
  const errors = [];
  if (!isRecord(evidenceSet)) return ["evidence-set:not-an-object"];
  errors.push(...unknownFields(evidenceSet, EVIDENCE_SET_FIELDS, "evidence-set:"));
  if (evidenceSet.evidence_set_version !== EVIDENCE_SET_VERSION) {
    errors.push("evidence-set:wrong-version");
  }
  if (!Array.isArray(evidenceSet.observations)) {
    errors.push("evidence-set:observations-must-be-array");
    return [...new Set(errors)].sort();
  }
  if (evidenceSet.observations.length > LIMITS.max_observations) {
    errors.push("evidence-set:too-many-observations");
  }
  evidenceSet.observations.forEach((observation, index) => {
    const prefix = `evidence-set:observations[${index}]:`;
    if (!isRecord(observation)) {
      errors.push(`${prefix}not-an-object`);
      return;
    }
    errors.push(...unknownFields(observation, OBSERVATION_FIELDS, prefix));
    for (const field of ["source_id", "locator", "revision", "availability"]) {
      if (!hasOwn(observation, field)) errors.push(`${prefix}missing:${field}`);
    }
    for (const field of ["source_id", "revision"]) {
      if (!isBoundedString(observation[field], LIMITS.max_identifier_length)) {
        errors.push(`${prefix}invalid:${field}`);
      }
    }
    if (!isBoundedString(observation.locator, LIMITS.max_locator_length)) {
      errors.push(`${prefix}invalid:locator`);
    }
    if (!["AVAILABLE", "UNAVAILABLE"].includes(observation.availability)) {
      errors.push(`${prefix}invalid:availability`);
    }
    if (observation.availability === "AVAILABLE") {
      for (const field of ["observed_at", "format", "basis", "data"]) {
        if (!hasOwn(observation, field)) errors.push(`${prefix}missing:${field}`);
      }
    }
    if (hasOwn(observation, "observed_at") && !isRfc3339(observation.observed_at)) {
      errors.push(`${prefix}invalid:observed_at`);
    }
    if (
      hasOwn(observation, "format") &&
      !isBoundedString(observation.format, LIMITS.max_identifier_length)
    ) {
      errors.push(`${prefix}invalid:format`);
    }
    if (hasOwn(observation, "basis") && !["OBSERVED_FACT", "ISSUER_OPINION"].includes(observation.basis)) {
      errors.push(`${prefix}invalid:basis`);
    }
    if (hasOwn(observation, "data") && !isJsonValue(observation.data)) {
      errors.push(`${prefix}invalid:data`);
    }
  });
  return [...new Set(errors)].sort();
}

function deepEqualJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function indexBy(items, key) {
  const index = new Map();
  for (const item of items) {
    const value = item[key];
    const group = index.get(value) ?? [];
    group.push(item);
    index.set(value, group);
  }
  return index;
}

function staticPredicateIssue(predicate, indexes) {
  if (!SUPPORTED_OPERATORS.includes(predicate.operator)) return "PREDICATE_UNSUPPORTED";
  if ((indexes.predicates.get(predicate.predicate_id) ?? []).length > 1) {
    return "PREDICATE_ID_AMBIGUOUS";
  }
  for (const sourceId of predicate.source_ids) {
    const pins = indexes.sources.get(sourceId) ?? [];
    if (pins.length === 0) return "SOURCE_UNPINNED";
    if (pins.length > 1) return "SOURCE_AMBIGUOUS";
    const [pin] = pins;
    if (!SUPPORTED_SOURCE_FORMATS.includes(pin.format)) return "SOURCE_UNSUPPORTED";
  }
  return null;
}

function compare(operator, actual, expected) {
  if (operator === "EQUALS" || operator === "NOT_EQUALS") {
    const equal = deepEqualJson(actual, expected);
    return { determinate: true, satisfied: operator === "EQUALS" ? equal : !equal };
  }
  if (["NUMBER_GTE", "NUMBER_LTE"].includes(operator)) {
    if (
      typeof actual !== "number" ||
      !Number.isFinite(actual) ||
      typeof expected !== "number" ||
      !Number.isFinite(expected)
    ) {
      return { determinate: false, reason: "VALUE_TYPE_UNSUPPORTED" };
    }
    return {
      determinate: true,
      satisfied: operator === "NUMBER_GTE" ? actual >= expected : actual <= expected,
    };
  }
  return { determinate: false, reason: "PREDICATE_UNSUPPORTED" };
}

function observationConflict(observations) {
  if (observations.length < 2) return false;
  const first = canonicalJson(observations[0]);
  return observations.slice(1).some((observation) => canonicalJson(observation) !== first);
}

function predicateResult(predicate, profile, indexes) {
  const staticIssue = staticPredicateIssue(predicate, indexes);
  if (staticIssue) {
    return {
      predicate_id: predicate.predicate_id,
      source_ids: [...predicate.source_ids],
      static_evaluable: false,
      runtime_evaluable: false,
      verdict: "INDETERMINATE",
      reason_codes: [staticIssue],
    };
  }

  const reasons = [];
  const values = [];
  const bases = [];
  for (const sourceId of predicate.source_ids) {
    const [pin] = indexes.sources.get(sourceId);
    const observations = indexes.observations.get(sourceId) ?? [];
    if (observations.length === 0) {
      reasons.push("SOURCE_MISSING");
      continue;
    }
    if (observationConflict(observations)) {
      reasons.push("SOURCE_CONFLICT");
      continue;
    }
    const observation = observations[0];
    if (observation.locator !== pin.locator || observation.revision !== pin.revision) {
      reasons.push("SOURCE_UNPINNED");
      continue;
    }
    if (observation.availability !== "AVAILABLE") {
      reasons.push("SOURCE_UNAVAILABLE");
      continue;
    }
    if (observation.format !== pin.format || !SUPPORTED_SOURCE_FORMATS.includes(observation.format)) {
      reasons.push("SOURCE_UNSUPPORTED");
      continue;
    }
    if (observation.basis !== pin.basis) {
      reasons.push("SOURCE_UNPINNED");
      continue;
    }
    const observedAt = strictTimestampMs(observation.observed_at);
    const evaluatedAt = strictTimestampMs(profile.evaluation_time);
    if (observedAt > evaluatedAt || evaluatedAt - observedAt > pin.max_age_seconds * 1000) {
      reasons.push("SOURCE_STALE");
      continue;
    }
    if (digestJson(observation.data) !== pin.data_sha256) {
      reasons.push("SOURCE_UNPINNED");
      continue;
    }
    const selected = pointerValue(observation.data, predicate.path);
    if (!selected.found) {
      reasons.push("VALUE_MISSING");
      continue;
    }
    values.push(selected.value);
    bases.push(observation.basis);
  }

  if (reasons.length > 0 || values.length !== predicate.source_ids.length) {
    return {
      predicate_id: predicate.predicate_id,
      source_ids: [...predicate.source_ids],
      static_evaluable: true,
      runtime_evaluable: false,
      verdict: "INDETERMINATE",
      reason_codes: [...new Set(reasons)].sort(),
    };
  }
  if (values.slice(1).some((value) => !deepEqualJson(value, values[0]))) {
    return {
      predicate_id: predicate.predicate_id,
      source_ids: [...predicate.source_ids],
      static_evaluable: true,
      runtime_evaluable: false,
      verdict: "INDETERMINATE",
      reason_codes: ["SOURCE_CONFLICT"],
    };
  }
  if (bases.every((basis) => basis === "ISSUER_OPINION")) {
    return {
      predicate_id: predicate.predicate_id,
      source_ids: [...predicate.source_ids],
      static_evaluable: true,
      runtime_evaluable: false,
      verdict: "INDETERMINATE",
      reason_codes: ["SOURCE_ISSUER_OPINION_ONLY"],
    };
  }

  const comparison = compare(predicate.operator, values[0], predicate.expected);
  if (!comparison.determinate) {
    return {
      predicate_id: predicate.predicate_id,
      source_ids: [...predicate.source_ids],
      static_evaluable: comparison.reason !== "PREDICATE_UNSUPPORTED",
      runtime_evaluable: false,
      verdict: "INDETERMINATE",
      reason_codes: [comparison.reason],
    };
  }
  return {
    predicate_id: predicate.predicate_id,
    source_ids: [...predicate.source_ids],
    static_evaluable: true,
    runtime_evaluable: true,
    verdict: comparison.satisfied ? "SATISFIED" : "NOT_SATISFIED",
    reason_codes: [comparison.satisfied ? "PREDICATE_SATISFIED" : "PREDICATE_NOT_SATISFIED"],
  };
}

function safeDigest(value) {
  try {
    return value === undefined ? null : digestJson(value);
  } catch {
    return null;
  }
}

function safeRead(object, key) {
  try {
    return object?.[key];
  } catch {
    return undefined;
  }
}

function sourceSnapshots(profile, evidenceSet) {
  const observations = indexBy(evidenceSet.observations, "source_id");
  const pins = indexBy(profile.sources, "source_id");
  const visited = new Set();
  return profile.sources.flatMap((source) => {
    if (visited.has(source.source_id)) return [];
    visited.add(source.source_id);
    return [{
      source_id: source.source_id,
      pin_count: pins.get(source.source_id).length,
      locator: source.locator,
      revision: source.revision,
      format: source.format,
      basis: source.basis,
      data_sha256: source.data_sha256,
      max_age_seconds: source.max_age_seconds,
      observations: (observations.get(source.source_id) ?? []).map((observation) => ({
        availability: observation.availability,
        locator: observation.locator,
        revision: observation.revision,
        observed_at: hasOwn(observation, "observed_at") ? observation.observed_at : null,
        format: hasOwn(observation, "format") ? observation.format : null,
        basis: hasOwn(observation, "basis") ? observation.basis : null,
        data_sha256: hasOwn(observation, "data") ? safeDigest(observation.data) : null,
      })),
    }];
  });
}

function digestStringList(values) {
  const hash = createHash("sha256");
  for (const value of values) {
    hash.update(String(Buffer.byteLength(value, "utf8")));
    hash.update(":");
    hash.update(value);
  }
  return hash.digest("hex");
}

function normalizeValidationErrors(validationErrors) {
  const unique = [...new Set(validationErrors)].sort();
  const normalized = unique.map((error) => {
    if (error.length <= LIMITS.max_validation_error_length) return error;
    return `validation-error-hashed:sha256:${digestStringList([error])}`;
  });
  if (normalized.length <= LIMITS.max_validation_errors) return normalized;
  const retained = normalized.slice(0, LIMITS.max_validation_errors - 1);
  retained.push(
    `validation-errors-truncated:count=${unique.length}:sha256:${digestStringList(unique)}`,
  );
  return retained;
}

function invalidReport(input, reasonCodes, validationErrors, options = {}) {
  const candidateCaseId = safeRead(input, "case_id");
  const profile = safeRead(input, "profile");
  const evidenceSet = safeRead(input, "evidence_set");
  const profileId = safeRead(profile, "profile_id");
  const evaluationTime = safeRead(profile, "evaluation_time");
  return {
    report_version: REPORT_VERSION,
    lab_profile: PROFILE_VERSION,
    predicate_dialect: {
      dialect_id: LOCAL_DIALECT.dialect_id,
      digest: LOCAL_DIALECT_SHA256,
      authority: LOCAL_DIALECT.authority,
    },
    case_id: isBoundedString(candidateCaseId, LIMITS.max_identifier_length)
      ? candidateCaseId
      : "invalid-input",
    profile_id: isBoundedString(profileId, LIMITS.max_identifier_length) ? profileId : null,
    evaluation_time: isRfc3339(evaluationTime) ? evaluationTime : null,
    input_digest: hasOwn(options, "input_digest") ? options.input_digest : safeDigest(input),
    profile_digest: safeDigest(profile),
    evidence_set_digest: safeDigest(evidenceSet),
    source_snapshots: [],
    static_evaluable: false,
    runtime_evaluable: false,
    verdict: "INDETERMINATE",
    reason_codes: [...new Set(reasonCodes)].sort(),
    validation_errors: normalizeValidationErrors(validationErrors),
    predicate_results: [],
    scope: SCOPE,
  };
}

function evaluateCaseInternal(input) {
  if (!isRecord(input)) return invalidReport(input, ["CASE_INVALID"], ["case:not-an-object"]);
  const profileErrors = validateProfile(input.profile);
  const evidenceErrors = validateEvidenceSet(input.evidence_set);
  const reasons = [];
  if (profileErrors.length > 0) reasons.push("PROFILE_INVALID");
  if (evidenceErrors.length > 0) reasons.push("EVIDENCE_SET_INVALID");
  if (reasons.length > 0) {
    return invalidReport(input, reasons, [...profileErrors, ...evidenceErrors]);
  }

  const indexes = {
    sources: indexBy(input.profile.sources, "source_id"),
    predicates: indexBy(input.profile.predicates, "predicate_id"),
    observations: indexBy(input.evidence_set.observations, "source_id"),
  };
  const predicateResults = input.profile.predicates.map((predicate) =>
    predicateResult(predicate, input.profile, indexes),
  );
  const staticEvaluable = predicateResults.every((result) => result.static_evaluable);
  const runtimeEvaluable = predicateResults.every((result) => result.runtime_evaluable);
  const verdict = !runtimeEvaluable
    ? "INDETERMINATE"
    : predicateResults.some((result) => result.verdict === "NOT_SATISFIED")
      ? "NOT_SATISFIED"
      : "SATISFIED";
  const reasonCodes = [...new Set(predicateResults.flatMap((result) => result.reason_codes))]
    .filter((reason) => !["PREDICATE_SATISFIED", "PREDICATE_NOT_SATISFIED"].includes(reason))
    .sort();

  return {
    report_version: REPORT_VERSION,
    lab_profile: PROFILE_VERSION,
    predicate_dialect: {
      dialect_id: LOCAL_DIALECT.dialect_id,
      digest: LOCAL_DIALECT_SHA256,
      authority: LOCAL_DIALECT.authority,
    },
    case_id: isBoundedString(input.case_id, LIMITS.max_identifier_length)
      ? input.case_id
      : "unnamed-case",
    profile_id: input.profile.profile_id,
    evaluation_time: input.profile.evaluation_time,
    input_digest: digestJson(input),
    profile_digest: digestJson(input.profile),
    evidence_set_digest: digestJson(input.evidence_set),
    source_snapshots: sourceSnapshots(input.profile, input.evidence_set),
    static_evaluable: staticEvaluable,
    runtime_evaluable: runtimeEvaluable,
    verdict,
    reason_codes: reasonCodes,
    validation_errors: [],
    predicate_results: predicateResults,
    scope: SCOPE,
  };
}

export function evaluateCase(input) {
  try {
    const inspectionErrors = inspectJson(input);
    const bounds = inspectionErrors.filter((error) => error.startsWith("input:max-"));
    if (bounds.length > 0) {
      return invalidReport({}, ["INPUT_LIMIT_EXCEEDED"], bounds, { input_digest: null });
    }
    if (inspectionErrors.includes("input:unsafe-number")) {
      return invalidReport({}, ["INPUT_NUMBER_UNSAFE"], ["input:unsafe-number"], {
        input_digest: null,
      });
    }
    const nonInert = inspectionErrors;
    if (nonInert.length > 0) {
      return invalidReport({}, ["CASE_INVALID"], nonInert, { input_digest: null });
    }
    return evaluateCaseInternal(snapshotJson(input));
  } catch {
    return invalidReport({}, ["EVALUATION_FAILURE"], ["evaluation:internal-failure"], {
      input_digest: null,
    });
  }
}

export function stableReportJson(report) {
  return `${canonicalJson(report)}\n`;
}

export function evaluateFile(filePath) {
  let source;
  try {
    source = readTextBounded(filePath);
  } catch (error) {
    if (error?.code === "INPUT_LIMIT_EXCEEDED") {
      return invalidReport({}, ["INPUT_LIMIT_EXCEEDED"], ["input:max-bytes-exceeded"], {
        input_digest: null,
      });
    }
    if (error?.code === "MALFORMED_JSON") {
      return invalidReport({}, ["INPUT_MALFORMED"], ["input:malformed-json"], {
        input_digest: null,
      });
    }
    return invalidReport({}, ["INPUT_UNREADABLE"], ["input:unreadable"], {
      input_digest: null,
    });
  }
  let input;
  try {
    input = parseJsonStrict(source);
  } catch (error) {
    const inputDigest = digestBytes(Buffer.from(source, "utf8"));
    if (error?.code === "DUPLICATE_MEMBER") {
      return invalidReport({}, ["INPUT_DUPLICATE_MEMBER"], ["input:duplicate-member"], {
        input_digest: inputDigest,
      });
    }
    if (error?.code === "UNSAFE_NUMBER") {
      return invalidReport({}, ["INPUT_NUMBER_UNSAFE"], ["input:unsafe-number"], {
        input_digest: inputDigest,
      });
    }
    if (error?.code === "INPUT_LIMIT_EXCEEDED") {
      return invalidReport({}, ["INPUT_LIMIT_EXCEEDED"], ["input:resource-limit-exceeded"], {
        input_digest: inputDigest,
      });
    }
    return invalidReport({}, ["INPUT_MALFORMED"], ["input:malformed-json"], {
      input_digest: inputDigest,
    });
  }
  return evaluateCase(input);
}

function main(argv) {
  const args = argv.slice(2);
  const files = args.filter((arg) => arg !== "--json");
  const unknownFlags = files.filter((arg) => arg.startsWith("--"));
  if (unknownFlags.length > 0 || files.length !== 1) {
    process.stderr.write("usage: node evaluate.mjs <evaluation-case.json> [--json]\n");
    return 2;
  }
  let report = evaluateFile(files[0]);
  try {
    process.stdout.write(stableReportJson(report));
  } catch {
    report = invalidReport({}, ["EVALUATION_FAILURE"], ["evaluation:report-serialization-failed"], {
      input_digest: null,
    });
    process.stdout.write(stableReportJson(report));
  }
  return report.reason_codes.some(
    (reason) => reason.startsWith("INPUT_") || reason === "EVALUATION_FAILURE",
  )
    ? 1
    : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv));
}
