// caid.mjs - CAID v1 reference implementation (JavaScript, ESM).
//
// Implements draft-schrock-canonical-action-identifier-04. The draft is the
// normative text. Every grammar, limit, reason code, reason rank, field type
// and definition rule this file applies comes from the generated region
// below, which caid/spec/gen.mjs compiles from the draft's Appendix A
// (caid/spec/caid.abnf), caid/spec/core.json and caid/registry/suites.json.
// Nothing in the region may be restated by hand elsewhere in this file.
//
// Suite support: jcs-sha256 only. cbor-sha256 is registered, so its CAIDs
// parse, but this implementation does not implement it: compute and verify
// refuse it as unknown_suite.
//
// Scope: CAID carries no trust semantics. It commits an identifier to
// canonical typed content. It does not prove the action was authorized,
// executed, safe, or wise. Nothing in this module verifies signatures,
// identity, or authorization.
//
// Entry points:
//   decodeCaidJson(bytes)             strict JSON text decoder (-04 2.4)
//   decodeCaidDocument(bytes)         the same rules without the size cap,
//                                     for definitions, registries, enum
//                                     snapshots and mapping profiles
//   computeCaidJson(bytes, options)   compute over received JSON text
//   verifyCaidJson(bytes, caid, opts) verify over received JSON text
//   computeCaid(value, options)       compute over a host value the
//                                     application constructed (-04 2.5)
//   verifyCaid(value, caid, options)  verify over such a host value
//   parseCaid(string)                 strict identifier parser
//   definitionSha256(definition)      the definition digest
//   canonicalize(value)               RFC 8785 over the data model
//
// Never throws: every entry point returns a refusal with reasons for junk
// input. A host value is read exactly once, iteratively and without invoking
// getters, into a copy of the data model; a value outside the model is
// refused, never serialized as something else.
//
// Dependencies: node:crypto only.

import { createHash } from "node:crypto";

// BEGIN GENERATED CAID SPEC: node caid/spec/gen.mjs --write. Do not edit by hand.
// Derived from caid/spec/caid.abnf, caid/spec/core.json, caid/registry/suites.json.
// The draft is the normative text; these constants are generated from it.

function caidSpecData(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(caidSpecData));
  if (value instanceof RegExp) return Object.freeze(value);
  if (value !== null && typeof value === "object") {
    const out = Object.create(null);
    for (const key of Object.keys(value)) out[key] = caidSpecData(value[key]);
    return Object.freeze(out);
  }
  return value;
}

// Rule data. Every object is frozen and has a null prototype.
export const CAID_SPEC = caidSpecData({
  draft: "draft-schrock-canonical-action-identifier-04",
  identifier: {
    scheme: "caid",
    version: "1",
    separator: ":",
    parts: 5,
  },
  patterns: {
    caid: "caid\\x3a1\\x3a(?:[a-z][\\x2d0-9a-z]*\\x2e)+[1-9][0-9]*\\x3a[a-z][\\x2d0-9a-z]*\\x3a[\\x2d0-9A-Z\\x5fa-z]+",
    action_type: "(?:[a-z][\\x2d0-9a-z]*\\x2e)+[1-9][0-9]*",
    suite: "[a-z][\\x2d0-9a-z]*",
    digest: "[\\x2d0-9A-Z\\x5fa-z]+",
    amount_string: "\\x2d?(?:0|[1-9][0-9]*)(?:\\x2e[0-9]+)?",
    digest_field: "sha256\\x3a[0-9a-f]{64}",
    timestamp: "[0-9]{4}\\x2d(?:0[1-9]|1[0-2])\\x2d(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3])\\x3a[0-5][0-9]\\x3a[0-5][0-9](?:\\x2e[0-9]+)?Z",
    format_name: "[a-z][\\x2d0-9a-z]*",
    code_system: "[A-Za-z][\\x2b\\x2d\\x2e0-9A-Za-z]*\\x3a(?:[\\x21\\x24\\x26-\\x3b\\x3d\\x3f-Z\\x5fa-z\\x7e]|\\x25[0-9A-Fa-f][0-9A-Fa-f])+",
    array_index: "(?:0|[1-9][0-9]*)",
    hex_sha256: "[0-9a-f]{64}",
  },
  code_formats: {
    "icd-10-cm": "[A-Z][0-9A-Z]{2}(?:\\x2e[0-9A-Z]{1,4})?",
    "ndc-11": "[0-9]{11}",
    "ndc-10-hyphenated": "(?:[0-9]{4}\\x2d[0-9]{4}\\x2d[0-9]{2}|[0-9]{5}\\x2d[0-9]{4}\\x2d[0-9]|[0-9]{5}\\x2d[0-9]{3}\\x2d[0-9]{2})",
    cpt: "[0-9]{4}[0-9A-Z]",
    "hcpcs-level-ii": "[A-Z][0-9]{4}",
    hcpcs: "(?:[0-9]{4}[0-9A-Z]|[A-Z][0-9]{4})",
    "iso-3166-1-alpha-2": "[A-Z]{2}",
    "iso-3166-2": "[A-Z]{2}\\x2d[0-9A-Z]{1,3}",
    "iso20022-external-code": "[0-9A-Z]{1,4}",
    "nacha-sec": "[0-9A-Z]{3}",
  },
  suites: [
    {
      suite: "jcs-sha256",
      digest_octets: 32,
      digest_length: 43,
      digest_pattern: "[\\x2d0-9A-Z\\x5fa-z]{42}[048AEIMQUYcgkosw]",
    },
    {
      suite: "cbor-sha256",
      digest_octets: 32,
      digest_length: 43,
      digest_pattern: "[\\x2d0-9A-Z\\x5fa-z]{42}[048AEIMQUYcgkosw]",
    },
  ],
  timestamp_date_offsets: {
    year: [0, 4],
    month: [5, 7],
    day: [8, 10],
  },
  limits: {
    json_text_octets: 33554432,
    nesting_depth: 64,
    canonical_octets: 16777216,
    max_safe_integer: 9007199254740991,
    mapping_rules_min: 1,
    mapping_rules_max: 128,
    mapping_pointer_octets_max: 2048,
    mapping_string_octets_min: 1,
    mapping_string_octets_max: 512,
    mapping_omission_reason_octets_min: 1,
    mapping_omission_reason_octets_max: 2048,
  },
  json_text: {
    byte_order_mark: [239, 187, 191],
    whitespace: [32, 9, 10, 13],
  },
  reasons: ["malformed_json", "malformed_caid", "unknown_suite", "invalid_action_type", "unknown_action_type", "invalid_definition", "definition_mismatch", "missing_material_field", "mistyped_field", "invalid_amount", "invalid_code", "unsupported_number", "unsupported_value", "action_type_mismatch", "digest_mismatch", "invalid_object"],
  reason_params: {
    malformed_json: "none",
    malformed_caid: "none",
    unknown_suite: "none",
    invalid_action_type: "none",
    unknown_action_type: "none",
    invalid_definition: "none",
    definition_mismatch: "none",
    missing_material_field: "field-name",
    mistyped_field: "field-name",
    invalid_amount: "field-name",
    invalid_code: "field-name",
    unsupported_number: "none",
    unsupported_value: "none",
    action_type_mismatch: "none",
    digest_mismatch: "none",
    invalid_object: "none",
  },
  operations: {
    decode: [
      {
        rank: 0,
        gate: true,
        reasons: ["malformed_json"],
      },
    ],
    parse: [
      {
        rank: 1,
        gate: true,
        reasons: ["malformed_caid", "unknown_suite"],
        steps: [
          {
            check: "caid-rule",
            reason: "malformed_caid",
          },
          {
            check: "suite-registered",
            reason: "unknown_suite",
          },
          {
            check: "suite-digest-syntax",
            reason: "malformed_caid",
          },
        ],
      },
    ],
    compute: [
      {
        rank: 0,
        gate: true,
        entry: "json_text",
        reasons: ["malformed_json"],
      },
      {
        rank: 1,
        gate: true,
        reasons: ["invalid_action_type"],
      },
      {
        rank: 2,
        gate: true,
        reasons: ["unknown_action_type", "invalid_definition"],
      },
      {
        rank: 3,
        gate: false,
        reasons: ["missing_material_field"],
        position: "required_fields",
      },
      {
        rank: 4,
        gate: false,
        reasons: ["mistyped_field", "invalid_amount", "invalid_code"],
        position: "required_then_optional_fields",
        per_position_max: 1,
      },
      {
        rank: 5,
        gate: false,
        reasons: ["unknown_suite"],
      },
      {
        rank: 6,
        gate: false,
        reasons: ["unsupported_number"],
      },
      {
        rank: 7,
        gate: false,
        reasons: ["unsupported_value"],
      },
    ],
    verify: [
      {
        rank: 1,
        gate: true,
        entry: "parse",
        reasons: ["malformed_caid", "unknown_suite"],
      },
      {
        rank: 2,
        gate: true,
        entry: "json_text",
        reasons: ["malformed_json"],
      },
      {
        rank: 3,
        gate: true,
        reasons: ["invalid_object"],
        when: "not_an_object",
      },
      {
        rank: 4,
        gate: false,
        reasons: ["action_type_mismatch"],
      },
      {
        rank: 5,
        gate: false,
        reasons: ["definition_mismatch"],
        when: "expected_definition_sha256",
      },
      {
        rank: 6,
        gate: false,
        reasons: ["unknown_suite", "digest_mismatch"],
        per_position_max: 1,
      },
      {
        rank: 7,
        gate: false,
        reasons: ["invalid_object"],
        when: "compute_refuses",
      },
    ],
  },
  gates: {
    decode: [
      ["malformed_json"],
    ],
    parse: [
      ["malformed_caid", "unknown_suite"],
    ],
    compute: [
      ["malformed_json"],
      ["invalid_action_type"],
      ["unknown_action_type", "invalid_definition"],
    ],
    verify: [
      ["malformed_caid", "unknown_suite"],
      ["malformed_json"],
      ["invalid_object"],
    ],
  },
  sort_rank: {
    decode: {},
    parse: {},
    compute: {
      missing_material_field: 3,
      mistyped_field: 4,
      invalid_amount: 4,
      invalid_code: 4,
      unknown_suite: 5,
      unsupported_number: 6,
      unsupported_value: 7,
    },
    verify: {
      action_type_mismatch: 4,
      definition_mismatch: 5,
      unknown_suite: 6,
      digest_mismatch: 6,
      invalid_object: 7,
    },
  },
  position: {
    decode: {},
    parse: {},
    compute: {
      missing_material_field: "required_fields",
      mistyped_field: "required_then_optional_fields",
      invalid_amount: "required_then_optional_fields",
      invalid_code: "required_then_optional_fields",
    },
    verify: {},
  },
  per_position_max: {
    decode: {},
    parse: {},
    compute: {
      mistyped_field: 1,
      invalid_amount: 1,
      invalid_code: 1,
    },
    verify: {
      unknown_suite: 1,
      digest_mismatch: 1,
    },
  },
  results: {
    decode: {
      accepted: ["ok", "value"],
      refused: ["ok", "refusals"],
    },
    parse: {
      accepted: ["ok", "caid"],
      refused: ["ok", "refusals"],
      caid_members: ["version", "action_type", "suite", "digest"],
    },
    compute: {
      accepted: ["caid", "digest", "definition_sha256"],
      refused: ["refusals"],
    },
    verify: {
      members: ["valid", "reasons", "details"],
      optional_members: ["definition_sha256"],
    },
    definition_sha256: {
      accepted: ["definition_sha256"],
      refused: ["refusals"],
      refusal: "invalid_definition",
    },
  },
  options: {
    compute: ["suite", "definitions", "enum_snapshots"],
    verify: ["definitions", "enum_snapshots", "expected_definition_sha256"],
  },
  verify_details: {
    members: ["reason", "field", "rule", "observed"],
    expand: {
      invalid_object: {
        operation: "compute",
        omit: ["unknown_suite"],
      },
    },
    field_sources: ["param", "action_type"],
    observed_sources: ["member", "argument"],
    observed_kinds: ["absent", "null", "boolean", "number", "string", "array", "object", "unsupported"],
    reasons: {
      malformed_caid: {
        rule: "caid",
        field: null,
        observed: "argument",
      },
      unknown_suite: {
        rule: "suite",
        field: null,
        observed: null,
      },
      malformed_json: {
        rule: "json-text",
        field: null,
        observed: null,
      },
      action_type_mismatch: {
        rule: "action-type-equal",
        field: "action_type",
        observed: "member",
      },
      definition_mismatch: {
        rule: "definition-sha256",
        field: null,
        observed: null,
      },
      digest_mismatch: {
        rule: "digest-equal",
        field: null,
        observed: null,
      },
      invalid_action_type: {
        rule: "action-type",
        field: "action_type",
        observed: "member",
      },
      unknown_action_type: {
        rule: "definition-resolution",
        field: null,
        observed: null,
      },
      invalid_definition: {
        rule: "definition-conformance",
        field: null,
        observed: null,
      },
      missing_material_field: {
        rule: "required-field",
        field: "param",
        observed: "member",
      },
      mistyped_field: {
        rule: "field-type",
        field: "param",
        observed: "member",
      },
      invalid_amount: {
        rule: "amount-string",
        field: "param",
        observed: "member",
      },
      invalid_code: {
        rule: "code-format",
        field: "param",
        observed: "member",
      },
      unsupported_number: {
        rule: "number",
        field: null,
        observed: null,
      },
      unsupported_value: {
        rule: "data-model",
        field: null,
        observed: null,
      },
    },
  },
  field_types: [
    {
      type: "string",
      json: "string",
      members: [],
      required_members: {},
    },
    {
      type: "amount-string",
      json: "string",
      members: [],
      required_members: {},
      pattern: "amount_string",
      pattern_refusal: "invalid_amount",
    },
    {
      type: "digest",
      json: "string",
      members: [],
      required_members: {},
      pattern: "digest_field",
      pattern_refusal: "mistyped_field",
    },
    {
      type: "enum",
      json: "string",
      members: ["values", "values_ref", "values_snapshot", "values_sha256"],
      required_members: {},
    },
    {
      type: "code",
      json: "string",
      members: ["code_system", "format"],
      required_members: {
        code_system: "code_system",
        format: "format_name",
      },
      format_refusal: "invalid_code",
      unregistered_format_refusal: "mistyped_field",
    },
    {
      type: "timestamp",
      json: "string",
      members: [],
      required_members: {},
      pattern: "timestamp",
      pattern_refusal: "mistyped_field",
      calendar_check: "day_within_month",
    },
    {
      type: "integer",
      json: "number",
      members: [],
      required_members: {},
    },
    {
      type: "boolean",
      json: "boolean",
      members: [],
      required_members: {},
    },
    {
      type: "object",
      json: "object",
      members: [],
      required_members: {},
    },
    {
      type: "array",
      json: "array",
      members: [],
      required_members: {},
    },
  ],
  unknown_field_type_refusal: "mistyped_field",
  definition: {
    field_lists: ["required_fields", "optional_fields"],
    required_fields_min: 1,
    field_common_members: ["name", "type", "notes"],
    field_name: {
      rule: "field-name",
      min_length: 1,
      forbidden_code_points: [58],
      reserved: ["action_type"],
      unique_across: ["required_fields", "optional_fields"],
    },
    resolution: {
      match_member: "action_type",
      none: "unknown_action_type",
      conflict: "invalid_definition",
      nonconforming: "invalid_definition",
      equal_when: "same_definition_sha256",
    },
    projection: {
      members: ["action_type", "required_fields", "optional_fields"],
      defaults: {
        optional_fields: [],
      },
      field_members_excluded: ["notes"],
      canonicalization: "RFC 8785",
      digest: "sha256",
      prefix: "sha256:",
    },
    status_values: ["active", "deprecated"],
    status_affects_computation: false,
    lifecycle_members: ["supersedes", "superseded_by"],
    registry_entry_members: ["action_type", "status", "risk_class", "summary", "required_fields", "optional_fields", "digest_notes", "references", "supersedes", "superseded_by"],
  },
  enum: {
    inline_prefix: "inline:",
    inline_separator: "|",
    inline_trim: [" "],
    values_sha256_input: "rfc8785-values-array",
  },
  mapping: {
    profile_version: "CAID-MAPPING-PROFILE-v1",
    members: {
      profile: ["@version", "profile_id", "source_format", "target_action_type", "loss_policy", "omitted_source_fields", "material_source_paths", "rules"],
      source_format: ["media_type", "schema", "version"],
      rule: ["source_path", "target_field", "transform"],
      omitted_source_field: ["source_path", "reason"],
    },
    optional_members: {
      profile: ["omitted_source_fields"],
    },
    null_member_refusal: "invalid_mapping_profile",
    member_rules: [
      {
        path: ["profile_id"],
        json: "string",
        min_octets: "mapping_string_octets_min",
        max_octets: "mapping_string_octets_max",
      },
      {
        path: ["source_format", "media_type"],
        json: "string",
        min_octets: "mapping_string_octets_min",
        max_octets: "mapping_string_octets_max",
      },
      {
        path: ["source_format", "schema"],
        json: "string",
        min_octets: "mapping_string_octets_min",
        max_octets: "mapping_string_octets_max",
      },
      {
        path: ["source_format", "version"],
        json: "string",
        min_octets: "mapping_string_octets_min",
        max_octets: "mapping_string_octets_max",
      },
      {
        path: ["target_action_type"],
        json: "string",
        min_octets: "mapping_string_octets_min",
        max_octets: "mapping_string_octets_max",
      },
      {
        path: ["loss_policy"],
        json: "string",
        closed: "loss_policies",
      },
      {
        path: ["rules"],
        json: "array",
        min_items: "mapping_rules_min",
        max_items: "mapping_rules_max",
      },
      {
        path: ["rules", "*", "source_path"],
        json: "string",
        rule: "source-path",
        max_octets: "mapping_pointer_octets_max",
      },
      {
        path: ["rules", "*", "target_field"],
        json: "string",
        rule: "field-name",
        reserved: ["action_type"],
      },
      {
        path: ["rules", "*", "transform"],
        json: "string",
        closed: "transforms",
      },
      {
        path: ["material_source_paths"],
        json: "array",
        min_items: "mapping_rules_min",
      },
      {
        path: ["material_source_paths", "*"],
        json: "string",
        rule: "source-path",
        max_octets: "mapping_pointer_octets_max",
      },
      {
        path: ["omitted_source_fields"],
        json: "array",
      },
      {
        path: ["omitted_source_fields", "*", "source_path"],
        json: "string",
        rule: "source-path",
        max_octets: "mapping_pointer_octets_max",
      },
      {
        path: ["omitted_source_fields", "*", "reason"],
        json: "string",
        min_octets: "mapping_omission_reason_octets_min",
        max_octets: "mapping_omission_reason_octets_max",
      },
    ],
    unique: [
      ["rules", "*", "source_path"],
      ["rules", "*", "target_field"],
      ["material_source_paths", "*"],
      ["omitted_source_fields", "*", "source_path"],
    ],
    equal_sets: [
      [
        ["rules", "*", "source_path"],
        ["material_source_paths", "*"],
      ],
    ],
    disjoint: [
      [
        ["omitted_source_fields", "*", "source_path"],
        ["rules", "*", "source_path"],
      ],
    ],
    string_comparison: "code_points",
    transforms: [
      {
        transform: "copy",
        input: "any",
      },
      {
        transform: "sha256-utf8",
        input: "string",
      },
      {
        transform: "sha256-jcs",
        input: "any",
      },
      {
        transform: "sha256-hex-to-digest",
        input: "string",
        pattern: "hex_sha256",
      },
    ],
    loss_policies: [
      {
        policy: "no-material-field-loss",
        omitted_source_fields: "absent_or_empty",
      },
      {
        policy: "declared-source-semantic-loss",
        omitted_source_fields: "non_empty",
        stage_reason: "declared_source_semantic_loss",
      },
    ],
    verdicts: ["EQUIVALENT_UNDER_PROFILE", "NOT_EQUIVALENT", "INDETERMINATE"],
    reasons: [
      {
        code: "invalid_mapping_profile",
        param: "none",
      },
      {
        code: "unknown_action_type",
        param: "none",
      },
      {
        code: "invalid_definition",
        param: "none",
      },
      {
        code: "unmapped_material_field",
        param: "field-name",
      },
      {
        code: "native_verification_required",
        param: "none",
      },
      {
        code: "mapping_profile_unpinned",
        param: "none",
      },
      {
        code: "source_format_mismatch",
        param: "none",
      },
      {
        code: "source_not_object",
        param: "none",
      },
      {
        code: "source_not_canonicalizable",
        param: "none",
      },
      {
        code: "declared_source_semantic_loss",
        param: "none",
      },
      {
        code: "invalid_source_path",
        param: "source-path",
      },
      {
        code: "missing_source_field",
        param: "source-path",
      },
      {
        code: "source_value_type_mismatch",
        param: "source-path",
      },
      {
        code: "source_value_not_canonicalizable",
        param: "source-path",
      },
      {
        code: "unknown_transform",
        param: "source-path",
      },
      {
        code: "mapped_action",
        param: "compute-reason",
      },
      {
        code: "target_action_type_mismatch",
        param: "none",
      },
      {
        code: "material_projection_mismatch",
        param: "none",
      },
    ],
    stages: [
      {
        stage: "A",
        reasons: ["invalid_mapping_profile", "unknown_action_type", "invalid_definition", "unmapped_material_field"],
        position: {
          unmapped_material_field: "required_fields",
        },
        shape_gate: "invalid_mapping_profile",
        shape_checks: ["object", "version", "closed_members", "member_rules"],
      },
      {
        stage: "B",
        reasons: ["native_verification_required", "mapping_profile_unpinned", "source_format_mismatch", "source_not_object", "source_not_canonicalizable", "declared_source_semantic_loss"],
        joins: "A",
        stop_if_any: true,
      },
      {
        stage: "C",
        reasons: ["invalid_source_path", "missing_source_field", "source_value_type_mismatch", "source_value_not_canonicalizable", "unknown_transform"],
        position: "rules",
        per_position_max: 1,
        stop_if_any: true,
      },
      {
        stage: "D",
        reasons: ["mapped_action"],
        order: "compute",
      },
    ],
    comparison: {
      prefixes: ["left", "right"],
      reasons: ["target_action_type_mismatch", "material_projection_mismatch"],
      prefixed_verdict: "INDETERMINATE",
      reason_verdicts: {
        target_action_type_mismatch: "INDETERMINATE",
        material_projection_mismatch: "NOT_EQUIVALENT",
      },
    },
    fault_reasons: ["unexpected_mapping_error", "invalid_mapped_action"],
    reason_params: {
      invalid_mapping_profile: "none",
      unknown_action_type: "none",
      invalid_definition: "none",
      unmapped_material_field: "field-name",
      native_verification_required: "none",
      mapping_profile_unpinned: "none",
      source_format_mismatch: "none",
      source_not_object: "none",
      source_not_canonicalizable: "none",
      declared_source_semantic_loss: "none",
      invalid_source_path: "source-path",
      missing_source_field: "source-path",
      source_value_type_mismatch: "source-path",
      source_value_not_canonicalizable: "source-path",
      unknown_transform: "source-path",
      mapped_action: "compute-reason",
      target_action_type_mismatch: "none",
      material_projection_mismatch: "none",
    },
    reason_rank: {
      invalid_mapping_profile: 0,
      unknown_action_type: 1,
      invalid_definition: 2,
      unmapped_material_field: 3,
      native_verification_required: 4,
      mapping_profile_unpinned: 5,
      source_format_mismatch: 6,
      source_not_object: 7,
      source_not_canonicalizable: 8,
      declared_source_semantic_loss: 9,
      invalid_source_path: 10,
      missing_source_field: 11,
      source_value_type_mismatch: 12,
      source_value_not_canonicalizable: 13,
      unknown_transform: 14,
      mapped_action: 15,
    },
    stage_of: {
      invalid_mapping_profile: "A",
      unknown_action_type: "A",
      invalid_definition: "A",
      unmapped_material_field: "A",
      native_verification_required: "B",
      mapping_profile_unpinned: "B",
      source_format_mismatch: "B",
      source_not_object: "B",
      source_not_canonicalizable: "B",
      declared_source_semantic_loss: "B",
      invalid_source_path: "C",
      missing_source_field: "C",
      source_value_type_mismatch: "C",
      source_value_not_canonicalizable: "C",
      unknown_transform: "C",
      mapped_action: "D",
    },
  },
});

// Whole-string matchers: each is ^(?:R)$ over the portable expression R
// in CAID_SPEC.patterns, so a value followed by any further character,
// including a final line feed, does not match. Test only strings: RegExp
// test() converts any other value to a string first.
export const CAID_PATTERNS = caidSpecData({
  caid: /^(?:caid\x3a1\x3a(?:[a-z][\x2d0-9a-z]*\x2e)+[1-9][0-9]*\x3a[a-z][\x2d0-9a-z]*\x3a[\x2d0-9A-Z\x5fa-z]+)$/,
  action_type: /^(?:(?:[a-z][\x2d0-9a-z]*\x2e)+[1-9][0-9]*)$/,
  suite: /^(?:[a-z][\x2d0-9a-z]*)$/,
  digest: /^(?:[\x2d0-9A-Z\x5fa-z]+)$/,
  amount_string: /^(?:\x2d?(?:0|[1-9][0-9]*)(?:\x2e[0-9]+)?)$/,
  digest_field: /^(?:sha256\x3a[0-9a-f]{64})$/,
  timestamp: /^(?:[0-9]{4}\x2d(?:0[1-9]|1[0-2])\x2d(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3])\x3a[0-5][0-9]\x3a[0-5][0-9](?:\x2e[0-9]+)?Z)$/,
  format_name: /^(?:[a-z][\x2d0-9a-z]*)$/,
  code_system: /^(?:[A-Za-z][\x2b\x2d\x2e0-9A-Za-z]*\x3a(?:[\x21\x24\x26-\x3b\x3d\x3f-Z\x5fa-z\x7e]|\x25[0-9A-Fa-f][0-9A-Fa-f])+)$/,
  array_index: /^(?:(?:0|[1-9][0-9]*))$/,
  hex_sha256: /^(?:[0-9a-f]{64})$/,
});

// Whole-string matcher of each registered code format, keyed by format name.
export const CAID_CODE_FORMATS = caidSpecData({
  "icd-10-cm": /^(?:[A-Z][0-9A-Z]{2}(?:\x2e[0-9A-Z]{1,4})?)$/,
  "ndc-11": /^(?:[0-9]{11})$/,
  "ndc-10-hyphenated": /^(?:(?:[0-9]{4}\x2d[0-9]{4}\x2d[0-9]{2}|[0-9]{5}\x2d[0-9]{4}\x2d[0-9]|[0-9]{5}\x2d[0-9]{3}\x2d[0-9]{2}))$/,
  "cpt": /^(?:[0-9]{4}[0-9A-Z])$/,
  "hcpcs-level-ii": /^(?:[A-Z][0-9]{4})$/,
  "hcpcs": /^(?:(?:[0-9]{4}[0-9A-Z]|[A-Z][0-9]{4}))$/,
  "iso-3166-1-alpha-2": /^(?:[A-Z]{2})$/,
  "iso-3166-2": /^(?:[A-Z]{2}\x2d[0-9A-Z]{1,3})$/,
  "iso20022-external-code": /^(?:[0-9A-Z]{1,4})$/,
  "nacha-sec": /^(?:[0-9A-Z]{3})$/,
});

// Digest syntax of each registered suite, keyed by suite name.
export const CAID_SUITE_DIGEST_PATTERNS = caidSpecData({
  "jcs-sha256": /^(?:[\x2d0-9A-Z\x5fa-z]{42}[048AEIMQUYcgkosw])$/,
  "cbor-sha256": /^(?:[\x2d0-9A-Z\x5fa-z]{42}[048AEIMQUYcgkosw])$/,
});
// END GENERATED CAID SPEC

/**
 * @typedef {{caid: string, digest: string, definition_sha256: string, refusals?: undefined}} CaidComputed
 * @typedef {{refusals: string[], caid?: undefined, digest?: undefined, definition_sha256?: undefined}} CaidRefused
 * @typedef {{reason: string, field: string | null, rule: string, observed: string | null}} CaidDetail
 * @typedef {{valid: boolean, reasons: string[], details: CaidDetail[], definition_sha256?: string}} CaidVerifyResult
 * @typedef {{ok: true, caid: {version: string, action_type: string, suite: string, digest: string}} | {ok: false, refusals: string[]}} CaidParseResult
 * @typedef {{ok: true, value: any} | {ok: false, refusals: string[]}} CaidDecodeResult
 */

// ---------------------------------------------------------------------------
// Constants derived from the generated region
// ---------------------------------------------------------------------------

const LIMITS = CAID_SPEC.limits;
const MAX_DEPTH = LIMITS.nesting_depth;
const MAX_SAFE = LIMITS.max_safe_integer;
const ID = CAID_SPEC.identifier;
const DEFINITION = CAID_SPEC.definition;
const PROJECTION = DEFINITION.projection;
const ENUM = CAID_SPEC.enum;
const COMPUTE_RANK = CAID_SPEC.sort_rank.compute;
const DETAIL_RULES = CAID_SPEC.verify_details.reasons;
const EXPAND_INVALID_OBJECT = CAID_SPEC.verify_details.expand.invalid_object;
const FIELD_TYPES = new Map(CAID_SPEC.field_types.map((t) => [t.type, t]));
const FIELD_COMMON_MEMBERS = new Set(DEFINITION.field_common_members);
// The members a field entry of each registered type may carry.
const FIELD_ALLOWED_MEMBERS = new Map(CAID_SPEC.field_types.map((t) => [t.type, new Set([...FIELD_COMMON_MEMBERS, ...t.members])]));
const FIELD_NAME_FORBIDDEN = new Set(DEFINITION.field_name.forbidden_code_points);
const FIELD_NAME_RESERVED = new Set(DEFINITION.field_name.reserved);
const PROJECTION_EXCLUDED = new Set(PROJECTION.field_members_excluded);
const INLINE_TRIM = new Set(ENUM.inline_trim);
const JSON_WHITESPACE = new Set(CAID_SPEC.json_text.whitespace);
const BOM = CAID_SPEC.json_text.byte_order_mark;

// The suites this implementation computes. The registry (CAID_SPEC.suites)
// is what parses; this set is an implementation choice, not spec data.
const IMPLEMENTED_SUITES = new Set(["jcs-sha256"]);

// A host value is refused once its copy passes this many units (one per
// value plus one per UTF-16 code unit of each string and member name). Every
// value the JSON text decoder can produce stays under it, because each unit
// needs at least one octet of text, so the bound refuses only host values
// that no conforming JSON text can express. It keeps a host value whose
// references fan out (one object reached through many paths) from expanding
// without limit.
const SNAPSHOT_UNIT_BUDGET = LIMITS.json_text_octets;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// Any value outside the data model, in a copy made from a host value: an
// accessor, a Map, a Date, a class instance, a function, a symbol, a bigint,
// undefined in an array, a cycle, or a container nested deeper than the
// limit. It is never serialized; its presence refuses as unsupported_value.
class OutsideDataModel {}
const UNSUPPORTED = Object.freeze(new OutsideDataModel());

/**
 * @param {any} v
 * @returns {v is Record<string, any>}
 */
function isDataObject(v) {
  return typeof v === "object" && v !== null && v !== UNSUPPORTED && !Array.isArray(v);
}

// The JSON kind of a data-model value, as verify details report it.
function dataKind(v) {
  if (v === undefined) return "absent";
  if (v === null) return "null";
  if (v === UNSUPPORTED) return "unsupported";
  const t = typeof v;
  if (t === "boolean" || t === "number" || t === "string") return t;
  return Array.isArray(v) ? "array" : "object";
}

// The kind of an arbitrary host argument (the CAID string argument of
// verify), without invoking any user code.
function hostKind(v) {
  if (v === undefined) return "absent";
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean" || t === "number" || t === "string") return t;
  if (t !== "object") return "unsupported";
  try {
    if (Array.isArray(v)) return "array";
    const proto = Object.getPrototypeOf(v);
    return proto === Object.prototype || proto === null ? "object" : "unsupported";
  } catch {
    return "unsupported";
  }
}

// True when s holds a UTF-16 surrogate code unit that is not half of a
// well-formed pair: s is then not a sequence of Unicode scalar values and has
// no UTF-8 encoding or RFC 8785 form.
function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function sha256(text) {
  // CAID content-addressing commitment, not password or credential storage.
  // codeql[js/insufficient-password-hash]
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest();
}

// An own member of a data-model object, or undefined. Never reads an
// inherited property, so a polluted Object.prototype cannot supply one.
function member(obj, key) {
  return hasOwn(obj, key) ? obj[key] : undefined;
}

// Adds an own data member to a fresh plain object. A name that also exists
// on Object.prototype (such as __proto__, or toString on a frozen prototype)
// is defined, never assigned, so no setter runs and nothing is rejected;
// any other name is assigned, which creates the same own member faster.
/**
 * @param {any} obj
 * @param {string} key
 * @param {any} value
 */
function defineMember(obj, key, value) {
  if (key in Object.prototype) {
    Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
  } else {
    obj[key] = value;
  }
}

// Reads one own data property of a host object without invoking a getter or
// throwing. Returns undefined when the property is absent or an accessor.
function readOwnData(obj, key) {
  if (typeof obj !== "object" || obj === null) return undefined;
  try {
    const d = Reflect.getOwnPropertyDescriptor(obj, key);
    return d && hasOwn(d, "value") ? d.value : undefined;
  } catch {
    return undefined;
  }
}

// Reads a host array's elements without invoking user code. Returns null
// when the value is not an array or cannot be read completely: an option of
// the wrong type counts as absent.
function readHostArray(value) {
  try {
    if (!Array.isArray(value)) return null;
    const length = readOwnData(value, "length");
    if (typeof length !== "number") return null;
    const items = [];
    for (let i = 0; i < length; i++) {
      const d = Reflect.getOwnPropertyDescriptor(value, String(i));
      if (!d || !hasOwn(d, "value")) return null;
      items.push(d.value);
    }
    return items;
  } catch {
    return null;
  }
}

function readOption(options, key, type) {
  const v = readOwnData(options, key);
  if (type === "array") return readHostArray(v) === null ? undefined : v;
  return typeof v === type ? v : undefined;
}

// ---------------------------------------------------------------------------
// Host values (-04 Section 2.5)
//
// snapshot(value) copies a host value into the data model. It is iterative,
// never throws and never invokes a getter: members are read through
// Object.getOwnPropertyDescriptors, and a Proxy trap that throws refuses the
// value. Accepted: null, booleans, numbers, strings, arrays whose prototype
// is Array.prototype that are dense with no extra own properties, and
// objects whose prototype is Object.prototype or null with only own,
// enumerable, string-keyed data properties. An own member whose value is
// undefined is absent for field presence and refuses the value as
// unsupported_value. Everything else becomes UNSUPPORTED: accessors,
// non-enumerable or symbol-keyed properties, Map, Set, Date, typed arrays,
// class instances, functions, symbols, bigints, undefined array elements,
// cycles, and containers nested deeper than the limit. Numbers and strings
// are copied as they are; canonicalization decides whether they are in the
// model (unsupported_number, lone surrogates).
//
// With proxyCheck, a copy that is otherwise clean is also passed through
// structuredClone, which refuses any Proxy before calling a single trap, so
// a Proxy anywhere in an action object refuses it (outside: true).
// ---------------------------------------------------------------------------

/**
 * @param {any} root
 * @param {boolean} [proxyCheck]
 * @returns {{value: any, outside: boolean, clean: boolean}}
 */
function snapshot(root, proxyCheck = false) {
  /** @type {SnapshotState} */
  const st = { units: 0, outside: false, unsupported: false };
  /** @type {Set<any>} */
  const path = new Set();
  const top = admit(root, 1, st, path);
  let value = top.value;
  if (top.pending) {
    /** @type {Array<{p: Pending, children: Pending[], next: number}>} */
    const stack = [];
    /** @param {Pending} p */
    const enter = (p) => {
      path.add(p.src);
      const children = expand(p, st, path);
      if (children === null) {
        path.delete(p.src);
        st.unsupported = true;
        if (p.parent === null) value = UNSUPPORTED;
        else if (Array.isArray(p.parent)) p.parent[/** @type {number} */ (p.key)] = UNSUPPORTED;
        else defineMember(p.parent, /** @type {string} */ (p.key), UNSUPPORTED);
        return;
      }
      stack.push({ p, children, next: 0 });
    };
    enter(top.pending);
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      if (frame.next >= frame.children.length) {
        path.delete(frame.p.src);
        stack.pop();
        continue;
      }
      const child = frame.children[frame.next++];
      if (st.units > SNAPSHOT_UNIT_BUDGET) {
        // Past the budget: the container keeps its kind but stays empty, and
        // the whole value refuses as unsupported_value.
        st.outside = true;
        continue;
      }
      enter(child);
    }
  }
  let outside = st.outside;
  if (proxyCheck && !outside && !st.unsupported && typeof root === "object" && root !== null
      && typeof structuredClone === "function") {
    try {
      structuredClone(root);
    } catch {
      outside = true;
    }
  }
  return { value, outside, clean: !outside && !st.unsupported };
}

/**
 * @typedef {{src: any, dst: any, isArray: boolean, depth: number, parent: any, key: string | number | null}} Pending
 * @typedef {{units: number, outside: boolean, unsupported: boolean}} SnapshotState
 */

// Classifies one host value: a scalar copy, UNSUPPORTED, or an empty
// container plus the work item that fills it.
/**
 * @param {any} v
 * @param {number} depth
 * @param {SnapshotState} st
 * @param {Set<any>} path
 * @param {any} [parent]
 * @param {string | number | null} [key]
 * @returns {{value: any, pending: Pending | null}}
 */
function admit(v, depth, st, path, parent = null, key = null) {
  switch (typeof v) {
    case "string":
      st.units += 1 + v.length;
      return { value: v, pending: null };
    case "number":
    case "boolean":
      st.units += 1;
      return { value: v, pending: null };
    case "object":
      if (v === null) {
        st.units += 1;
        return { value: null, pending: null };
      }
      break;
    default:
      st.unsupported = true;
      return { value: UNSUPPORTED, pending: null };
  }
  let isArray;
  let proto;
  try {
    isArray = Array.isArray(v);
    proto = Object.getPrototypeOf(v);
  } catch {
    st.unsupported = true;
    return { value: UNSUPPORTED, pending: null };
  }
  const plain = isArray ? proto === Array.prototype : proto === Object.prototype || proto === null;
  if (!plain || depth > MAX_DEPTH || path.has(v)) {
    st.unsupported = true;
    return { value: UNSUPPORTED, pending: null };
  }
  st.units += 1;
  const dst = isArray ? [] : {};
  return { value: dst, pending: { src: v, dst, isArray, depth, parent, key } };
}

// Reads the members of one container. A member or element that is an
// accessor, non-enumerable, or (in an array) a hole becomes UNSUPPORTED in
// place, so a declared field that holds one refuses as mistyped_field.
// Returns the pending child containers, or null when the container itself
// is outside the data model: it cannot be read, has a symbol-keyed
// property, or is an array with properties other than its elements.
/**
 * @param {Pending} p
 * @param {SnapshotState} st
 * @param {Set<any>} path
 * @returns {Pending[] | null}
 */
function expand(p, st, path) {
  /** @type {Pending[]} */
  const pending = [];
  /**
   * @param {string | number} key
   * @param {PropertyDescriptor} d
   */
  const place = (key, d) => {
    if (!hasOwn(d, "value") || d.enumerable !== true) {
      st.unsupported = true;
      return UNSUPPORTED;
    }
    const r = admit(d.value, p.depth + 1, st, path, p.dst, key);
    if (r.pending) pending.push(r.pending);
    return r.value;
  };
  try {
    if (p.isArray) {
      const length = readOwnData(p.src, "length");
      if (typeof length !== "number") return null;
      let present = 0;
      for (let i = 0; i < length; i++) {
        const d = Reflect.getOwnPropertyDescriptor(p.src, String(i));
        if (!d) {
          st.unsupported = true;
          p.dst.push(UNSUPPORTED);
          continue;
        }
        present++;
        p.dst.push(place(i, d));
      }
      return Reflect.ownKeys(p.src).length === present + 1 ? pending : null;
    }
    const descriptors = /** @type {Record<string, PropertyDescriptor>} */ (Object.getOwnPropertyDescriptors(p.src));
    const allKeys = Reflect.ownKeys(descriptors);
    for (const key of allKeys) if (typeof key !== "string") return null;
    for (const key of /** @type {string[]} */ (allKeys)) {
      const d = descriptors[key];
      if (hasOwn(d, "value") && d.enumerable === true && d.value === undefined) {
        // undefined is not a JSON value: the member is absent for field
        // presence, and the value refuses as unsupported_value.
        st.outside = true;
        continue;
      }
      st.units += key.length;
      defineMember(p.dst, key, place(key, d));
    }
    return pending;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Canonicalization: RFC 8785 over the data model, iteratively.
//
// Numbers: a finite integer of magnitude at most 2^53-1, else
// unsupported_number. For such integers JSON.stringify is the ECMAScript
// Number-to-String form RFC 8785 requires, and -0 prints as 0. Strings and
// member names must be scalar-value sequences, else unsupported_value; for
// those, JSON.stringify's escaping is the RFC 8785 form. Member names sort by
// UTF-16 code units, the default string order. A container nested deeper
// than the limit, or any UNSUPPORTED value, is unsupported_value and nothing
// below it is visited. When capOctets is a number and nothing else refused,
// an encoding longer than capOctets octets is unsupported_value.
// ---------------------------------------------------------------------------

/**
 * @param {any} root
 * @param {number | null} capOctets
 * @param {boolean} outside
 * @returns {{ok: true, canonical: string} | {ok: false, refusals: string[]}}
 */
function serialize(root, capOctets, outside) {
  let number = false;
  let other = outside === true;
  let oversize = false;
  let units = 0;
  /** @type {string[]} */
  const parts = [];
  /** @param {string} text */
  const emit = (text) => {
    if (number || other || oversize) return;
    units += text.length;
    if (capOctets !== null && units > capOctets) {
      // Each UTF-16 code unit encodes to at least one octet.
      oversize = true;
      parts.length = 0;
      return;
    }
    parts.push(text);
  };
  // Work items: [value, level] where level counts the enclosing containers
  // plus one, or [null, -1, text] for literal text.
  /** @type {Array<[any, number, string?]>} */
  const work = [[root, 1]];
  while (work.length > 0 && !(number && other)) {
    const item = /** @type {[any, number, string?]} */ (work.pop());
    if (item[1] === -1) {
      emit(/** @type {string} */ (item[2]));
      continue;
    }
    const v = item[0];
    const level = item[1];
    if (v === null) {
      emit("null");
      continue;
    }
    const t = typeof v;
    if (t === "boolean") {
      emit(v ? "true" : "false");
      continue;
    }
    if (t === "number") {
      if (!Number.isFinite(v) || !Number.isInteger(v) || Math.abs(v) > MAX_SAFE) number = true;
      else emit(JSON.stringify(v));
      continue;
    }
    if (t === "string") {
      if (hasLoneSurrogate(v)) other = true;
      else emit(JSON.stringify(v));
      continue;
    }
    if (v === UNSUPPORTED || t !== "object" || level > MAX_DEPTH) {
      other = true;
      continue;
    }
    if (Array.isArray(v)) {
      work.push([null, -1, "]"]);
      for (let i = v.length - 1; i >= 0; i--) {
        work.push([v[i], level + 1]);
        if (i > 0) work.push([null, -1, ","]);
      }
      work.push([null, -1, "["]);
      continue;
    }
    const keys = Object.keys(v).sort();
    work.push([null, -1, "}"]);
    for (let i = keys.length - 1; i >= 0; i--) {
      const key = keys[i];
      work.push([v[key], level + 1]);
      if (hasLoneSurrogate(key)) {
        other = true;
        work.push([null, -1, ":"]);
      } else {
        work.push([null, -1, JSON.stringify(key) + ":"]);
      }
      if (i > 0) work.push([null, -1, ","]);
    }
    work.push([null, -1, "{"]);
  }
  if (!number && !other && oversize) other = true;
  const canonical = number || other ? "" : parts.join("");
  if (!number && !other && capOctets !== null && Buffer.byteLength(canonical, "utf8") > capOctets) other = true;
  if (number || other) {
    const refusals = [];
    if (number) refusals.push("unsupported_number");
    if (other) refusals.push("unsupported_value");
    return { ok: false, refusals };
  }
  return { ok: true, canonical };
}

/**
 * canonicalize(value) -> {ok: true, canonical: string}
 *                      | {ok: false, refusals: string[]}
 *
 * RFC 8785 over the data model, for any document (action objects,
 * definitions, value sets, mapping profiles). Refusals, in this order:
 * unsupported_number (a number that is not a finite integer of magnitude at
 * most 2^53-1) and unsupported_value (a lone surrogate, nesting deeper than
 * 64, or a host value outside the data model). The canonical-size limit
 * applies to action objects only and is enforced by compute and verify.
 *
 * @param {*} value
 * @returns {{ok: true, canonical: string} | {ok: false, refusals: string[]}}
 */
export function canonicalize(value) {
  const snap = snapshot(value, true);
  return serialize(snap.value, null, snap.outside);
}

/**
 * toCaidData(value) -> {ok: true, value} | {ok: false, refusals: ["unsupported_value"]}
 *
 * Reads a host value once into a copy in the data model, or refuses it when
 * any part is outside the model (Section 2.5). The copy is plain objects and
 * arrays whose members are own data properties, so `__proto__` is an
 * ordinary member. Numbers and strings are copied unchanged:
 * canonicalization still decides whether they are in the model.
 *
 * @param {*} value
 * @returns {{ok: true, value: any} | {ok: false, refusals: string[]}}
 */
export function toCaidData(value) {
  const snap = snapshot(value, true);
  if (!snap.clean) return { ok: false, refusals: ["unsupported_value"] };
  return { ok: true, value: snap.value };
}

// ---------------------------------------------------------------------------
// Strict JSON text (-04 Section 2.4)
//
// The input is octets (a Uint8Array, which includes a Node Buffer); any
// other type is refused, including a string, whose re-encoding would
// silently replace lone surrogates. The text must be an I-JSON message
// [RFC 7493]: valid UTF-8 [RFC 3629] with no byte order mark, exactly one
// JSON text [RFC 8259] followed only by JSON whitespace, no duplicate member
// names after unescaping, no string or member name containing a surrogate
// or noncharacter code point (escaped or not), and nesting of at most 64.
// A number token is never refused here: its value is Number(token), the
// correctly rounded binary64 value (overflow is Infinity, underflow is 0),
// and the data model decides whether it is accepted. Every refusal is the
// single reason malformed_json. An action object or mapping source may be
// at most 33554432 octets; definitions, registries, enum snapshots and
// mapping profiles take the same rules without that cap.
// ---------------------------------------------------------------------------

const MALFORMED_JSON = Object.freeze(["malformed_json"]);
/** @returns {{ok: false, refusals: string[]}} */
const refusedJson = () => ({ ok: false, refusals: [...MALFORMED_JSON] });

const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG = /** @type {(this: unknown) => unknown} */ (
  /** @type {PropertyDescriptor} */ (Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, Symbol.toStringTag)).get);
const TYPED_ARRAY_BYTE_LENGTH = /** @type {(this: unknown) => number} */ (
  /** @type {PropertyDescriptor} */ (Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, "byteLength")).get);
const UTF8_DECODER = new TextDecoder("utf-8", { ignoreBOM: true });

// A private copy of the octets, or null when the input is not a Uint8Array.
// The brand check and the copy read internal slots only.
/**
 * @param {unknown} input
 * @param {number | null} capOctets
 * @returns {Uint8Array | null}
 */
function copyOctets(input, capOctets) {
  try {
    if (TYPED_ARRAY_TAG.call(input) !== "Uint8Array") return null;
    const length = TYPED_ARRAY_BYTE_LENGTH.call(input);
    if (capOctets !== null && length > capOctets) return null;
    return new Uint8Array(/** @type {Uint8Array} */ (input));
  } catch {
    return null;
  }
}

// Well-formed UTF-8 per Unicode Table 3-7: no overlong forms, no surrogates,
// nothing above U+10FFFF.
function isWellFormedUtf8(b) {
  const n = b.length;
  let i = 0;
  while (i < n) {
    const c = b[i];
    if (c < 0x80) {
      i += 1;
      continue;
    }
    let need;
    let lo = 0x80;
    let hi = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) need = 1;
    else if (c === 0xe0) { need = 2; lo = 0xa0; }
    else if ((c >= 0xe1 && c <= 0xec) || c === 0xee || c === 0xef) need = 2;
    else if (c === 0xed) { need = 2; hi = 0x9f; }
    else if (c === 0xf0) { need = 3; lo = 0x90; }
    else if (c >= 0xf1 && c <= 0xf3) need = 3;
    else if (c === 0xf4) { need = 3; hi = 0x8f; }
    else return false;
    if (i + need >= n) return false;
    const second = b[i + 1];
    if (second < lo || second > hi) return false;
    for (let k = 2; k <= need; k++) {
      const next = b[i + k];
      if (next < 0x80 || next > 0xbf) return false;
    }
    i += need + 1;
  }
  return true;
}

// The deepest nesting in a text, counting brackets outside strings. It runs
// before any value is built, so an input nested beyond the limit costs one
// linear scan and no allocation.
function maxNesting(s) {
  let depth = 0;
  let max = 0;
  let inString = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x7b || c === 0x5b) {
      depth++;
      if (depth > max) max = depth;
    } else if (c === 0x7d || c === 0x5d) {
      depth--;
    }
  }
  return max;
}

function isNoncharacter(cp) {
  return (cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe;
}

const HEX = (c) => (c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 0x37 : c >= 0x61 && c <= 0x66 ? c - 0x57 : -1);
const SHORT_ESCAPES = new Map([
  [0x22, "\""], [0x5c, "\\"], [0x2f, "/"], [0x62, "\b"],
  [0x66, "\f"], [0x6e, "\n"], [0x72, "\r"], [0x74, "\t"],
]);

class JsonTextError {}
const JSON_TEXT_ERROR = new JsonTextError();

// One JSON text, iteratively. Throws JSON_TEXT_ERROR (caught by the caller)
// on any departure from the profile.
function parseJsonText(s) {
  const n = s.length;
  let i = 0;
  const fail = () => {
    throw JSON_TEXT_ERROR;
  };
  const skipWs = () => {
    while (i < n && JSON_WHITESPACE.has(s.charCodeAt(i))) i++;
  };
  const hex4 = () => {
    if (i + 4 > n) fail();
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const h = HEX(s.charCodeAt(i + k));
      if (h < 0) fail();
      v = v * 16 + h;
    }
    i += 4;
    return v;
  };
  const parseString = () => {
    i++; // opening quote
    let out = "";
    let start = i;
    while (true) {
      if (i >= n) fail();
      const c = s.charCodeAt(i);
      if (c === 0x22) {
        out += s.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) fail();
      if (c === 0x5c) {
        out += s.slice(start, i);
        i++;
        if (i >= n) fail();
        const e = s.charCodeAt(i);
        const short = SHORT_ESCAPES.get(e);
        if (short !== undefined) {
          out += short;
          i++;
        } else if (e === 0x75) {
          i++;
          const u = hex4();
          if (u >= 0xdc00 && u <= 0xdfff) fail();
          if (u >= 0xd800 && u <= 0xdbff) {
            if (s.charCodeAt(i) !== 0x5c || s.charCodeAt(i + 1) !== 0x75) fail();
            i += 2;
            const low = hex4();
            if (low < 0xdc00 || low > 0xdfff) fail();
            if (isNoncharacter(0x10000 + ((u - 0xd800) << 10) + (low - 0xdc00))) fail();
            out += String.fromCharCode(u, low);
          } else {
            if (isNoncharacter(u)) fail();
            out += String.fromCharCode(u);
          }
        } else {
          fail();
        }
        start = i;
        continue;
      }
      if (c >= 0xd800 && c <= 0xdbff) {
        // The text came from well-formed UTF-8, so a high surrogate here is
        // always followed by its low half.
        const low = s.charCodeAt(i + 1);
        if (isNoncharacter(0x10000 + ((c - 0xd800) << 10) + (low - 0xdc00))) fail();
        i += 2;
        continue;
      }
      if (isNoncharacter(c)) fail();
      i++;
    }
  };
  const parseNumber = () => {
    const begin = i;
    if (s.charCodeAt(i) === 0x2d) i++;
    const digit = (k) => {
      const c = s.charCodeAt(k);
      return c >= 0x30 && c <= 0x39;
    };
    if (s.charCodeAt(i) === 0x30) i++;
    else if (digit(i)) while (digit(i)) i++;
    else fail();
    if (s.charCodeAt(i) === 0x2e) {
      i++;
      if (!digit(i)) fail();
      while (digit(i)) i++;
    }
    const e = s.charCodeAt(i);
    if (e === 0x65 || e === 0x45) {
      i++;
      const sign = s.charCodeAt(i);
      if (sign === 0x2b || sign === 0x2d) i++;
      if (!digit(i)) fail();
      while (digit(i)) i++;
    }
    return Number(s.slice(begin, i));
  };
  const literal = (word, value) => {
    if (s.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return fail();
  };
  const parseKey = () => {
    if (s.charCodeAt(i) !== 0x22) fail();
    const key = parseString();
    skipWs();
    if (s.charCodeAt(i) !== 0x3a) fail();
    i++;
    skipWs();
    return key;
  };

  /** @type {Array<{container: any, isArray: boolean, key: string | null}>} */
  const stack = [];
  skipWs();
  for (;;) {
    let value;
    let complete = true;
    const c = s.charCodeAt(i);
    if (c === 0x7b) {
      i++;
      skipWs();
      const obj = {};
      if (s.charCodeAt(i) === 0x7d) {
        i++;
        value = obj;
      } else {
        stack.push({ container: obj, isArray: false, key: parseKey() });
        complete = false;
      }
    } else if (c === 0x5b) {
      i++;
      skipWs();
      const arr = [];
      if (s.charCodeAt(i) === 0x5d) {
        i++;
        value = arr;
      } else {
        stack.push({ container: arr, isArray: true, key: null });
        complete = false;
      }
    } else if (c === 0x22) {
      value = parseString();
    } else if (c === 0x74) {
      value = literal("true", true);
    } else if (c === 0x66) {
      value = literal("false", false);
    } else if (c === 0x6e) {
      value = literal("null", null);
    } else if (c === 0x2d || (c >= 0x30 && c <= 0x39)) {
      value = parseNumber();
    } else {
      fail();
    }
    if (!complete) continue;
    // Place the finished value into its container, closing containers as
    // their final value arrives.
    for (;;) {
      if (stack.length === 0) {
        skipWs();
        if (i !== n) fail();
        return value;
      }
      const frame = stack[stack.length - 1];
      if (frame.isArray) {
        frame.container.push(value);
      } else {
        const key = /** @type {string} */ (frame.key);
        if (hasOwn(frame.container, key)) fail();
        defineMember(frame.container, key, value);
      }
      skipWs();
      const d = s.charCodeAt(i);
      if (d === 0x2c) {
        i++;
        skipWs();
        if (!frame.isArray) frame.key = parseKey();
        break;
      }
      if (d !== (frame.isArray ? 0x5d : 0x7d)) fail();
      i++;
      stack.pop();
      value = frame.container;
    }
  }
}

/**
 * @param {unknown} bytes
 * @param {number | null} capOctets
 * @returns {CaidDecodeResult}
 */
function decodeWith(bytes, capOctets) {
  const octets = copyOctets(bytes, capOctets);
  if (octets === null) return refusedJson();
  if (octets.length >= BOM.length && BOM.every((b, k) => octets[k] === b)) return refusedJson();
  if (!isWellFormedUtf8(octets)) return refusedJson();
  let text;
  try {
    text = UTF8_DECODER.decode(octets);
  } catch {
    return refusedJson();
  }
  if (maxNesting(text) > MAX_DEPTH) return refusedJson();
  try {
    return { ok: true, value: parseJsonText(text) };
  } catch {
    return refusedJson();
  }
}

/**
 * decodeCaidJson(bytes) -> {ok: true, value} | {ok: false, refusals: ["malformed_json"]}
 *
 * The strict decoder for an action object or mapping source received as
 * JSON text (-04 Section 2.4), including the 33554432-octet cap. Objects in
 * the result are plain, with every member an own data property.
 *
 * @param {unknown} bytes
 * @returns {CaidDecodeResult}
 */
export function decodeCaidJson(bytes) {
  return decodeWith(bytes, LIMITS.json_text_octets);
}

/**
 * decodeCaidDocument(bytes): decodeCaidJson's rules without the size cap,
 * for type definitions, registries, enum snapshots and mapping profiles.
 *
 * @param {unknown} bytes
 * @returns {CaidDecodeResult}
 */
export function decodeCaidDocument(bytes) {
  return decodeWith(bytes, null);
}

// ---------------------------------------------------------------------------
// Definitions (-04 Section 4.2): conformance, digest, resolution
// ---------------------------------------------------------------------------

function validFieldName(name) {
  if (typeof name !== "string" || name.length < DEFINITION.field_name.min_length) return false;
  if (hasLoneSurrogate(name) || FIELD_NAME_RESERVED.has(name)) return false;
  for (const ch of name) if (FIELD_NAME_FORBIDDEN.has(ch.codePointAt(0))) return false;
  return true;
}

// The validation projection of a data-model definition (-04 4.2.2), or null
// when a field list is not an array.
function projectionOf(d) {
  const out = {};
  defineMember(out, "action_type", member(d, "action_type"));
  for (const list of DEFINITION.field_lists) {
    const raw = hasOwn(d, list) ? d[list] : PROJECTION.defaults[list];
    if (!Array.isArray(raw)) return null;
    defineMember(out, list, raw.map((entry) => {
      if (!isDataObject(entry)) return entry;
      const kept = {};
      for (const key of Object.keys(entry)) if (!PROJECTION_EXCLUDED.has(key)) defineMember(kept, key, entry[key]);
      return kept;
    }));
  }
  return out;
}

function digestOfDefinition(d) {
  const p = projectionOf(d);
  if (p === null) return null;
  const c = serialize(p, null, false);
  return c.ok ? PROJECTION.prefix + sha256(c.canonical).toString("hex") : null;
}

// Definition conformance over a data-model value: the definition_sha256
// when it conforms, else null.
/**
 * @param {any} d
 * @returns {string | null}
 */
function conformingDigest(d) {
  if (!isDataObject(d)) return null;
  const actionType = member(d, "action_type");
  if (typeof actionType !== "string" || !CAID_PATTERNS.action_type.test(actionType)) return null;
  const required = member(d, "required_fields");
  if (!Array.isArray(required) || required.length < DEFINITION.required_fields_min) return null;
  if (hasOwn(d, "optional_fields") && !Array.isArray(d.optional_fields)) return null;
  const names = new Set();
  for (const list of DEFINITION.field_lists) {
    for (const entry of member(d, list) ?? []) {
      if (!isDataObject(entry)) return null;
      const name = member(entry, "name");
      if (!validFieldName(name) || names.has(name)) return null;
      names.add(name);
      const type = member(entry, "type");
      if (typeof type !== "string") return null;
      const t = FIELD_TYPES.get(type);
      if (t === undefined) continue; // unregistered: mistyped_field when present
      const allowed = /** @type {Set<string>} */ (FIELD_ALLOWED_MEMBERS.get(type));
      for (const key of Object.keys(entry)) if (!allowed.has(key)) return null;
      for (const key of Object.keys(t.required_members)) {
        const value = member(entry, key);
        if (typeof value !== "string" || !CAID_PATTERNS[t.required_members[key]].test(value)) return null;
      }
    }
  }
  return digestOfDefinition(d);
}

// A host definition copied into the data model, or UNSUPPORTED when any
// part of it is outside the model.
/**
 * @param {unknown} entry
 * @returns {any}
 */
function definitionData(entry) {
  const snap = snapshot(entry, false);
  return snap.clean ? snap.value : UNSUPPORTED;
}

// Resolution (-04 4.2.3): collect the definitions whose action_type equals
// the object's; none is unknown_action_type; any nonconforming candidate, or
// two whose definition_sha256 differ, is invalid_definition; candidates
// with equal projections count once.
/**
 * @param {string} actionType
 * @param {unknown} definitions
 * @returns {{reason: string, definition?: undefined, definition_sha256?: undefined} | {reason?: undefined, definition: any, definition_sha256: string}}
 */
function resolve(actionType, definitions) {
  const items = readHostArray(definitions) ?? [];
  const candidates = [];
  for (const entry of items) {
    if (readOwnData(entry, DEFINITION.resolution.match_member) !== actionType) continue;
    candidates.push(definitionData(entry));
  }
  if (candidates.length === 0) return { reason: DEFINITION.resolution.none };
  const digests = new Set();
  for (const d of candidates) {
    const digest = conformingDigest(d);
    if (digest === null) return { reason: DEFINITION.resolution.nonconforming };
    digests.add(digest);
  }
  if (digests.size !== 1) return { reason: DEFINITION.resolution.conflict };
  return { definition: candidates[0], definition_sha256: /** @type {string} */ ([...digests][0]) };
}

/**
 * definitionSha256(definition) -> {definition_sha256: "sha256:<hex>"}
 *                              | {refusals: ["invalid_definition"]}
 *
 * SHA-256 over the RFC 8785 encoding of the definition's validation
 * projection: action_type, required_fields and optional_fields (an absent
 * optional_fields is []), with each field entry's notes member removed.
 * Refuses a definition that does not conform.
 *
 * @param {*} definition
 * @returns {{definition_sha256: string, refusals?: undefined} | {refusals: string[], definition_sha256?: undefined}}
 */
export function definitionSha256(definition) {
  const d = definitionData(definition);
  const digest = conformingDigest(d);
  if (digest === null) return { refusals: [CAID_SPEC.results.definition_sha256.refusal] };
  return { definition_sha256: digest };
}

/**
 * resolveCaidDefinition(actionType, definitions)
 *   -> {ok: true, definition, definition_sha256}
 *   -> {ok: false, refusals: ["unknown_action_type" | "invalid_definition"]}
 *
 * The resolution step compute, verify and the mapping profile share. The
 * returned definition is a data-model copy. Status never gates resolution.
 *
 * @param {string} actionType
 * @param {any[]} definitions
 * @returns {{ok: true, definition: any, definition_sha256: string} | {ok: false, refusals: string[]}}
 */
export function resolveCaidDefinition(actionType, definitions) {
  if (typeof actionType !== "string") return { ok: false, refusals: [DEFINITION.resolution.none] };
  const r = resolve(actionType, definitions);
  if (r.reason !== undefined) return { ok: false, refusals: [r.reason] };
  return { ok: true, definition: r.definition, definition_sha256: /** @type {string} */ (r.definition_sha256) };
}

// ---------------------------------------------------------------------------
// Field validation (-04 Section 4.3, 4.4)
// ---------------------------------------------------------------------------

function validEnumValues(values) {
  return Array.isArray(values) && values.length > 0
    && values.every((v) => typeof v === "string" && v.length > 0)
    && new Set(values).size === values.length;
}

// Trims only the registered inline trim set (U+0020 SPACE) from both ends.
function trimInline(m) {
  let a = 0;
  let b = m.length;
  while (a < b && INLINE_TRIM.has(m[a])) a++;
  while (b > a && INLINE_TRIM.has(m[b - 1])) b--;
  return m.slice(a, b);
}

// The closed value set of an enum field, or null when it does not resolve.
// Presence is key presence: a member written as null is present and
// malformed. An external values_ref resolves only with a values_snapshot
// label and the SHA-256 digest of the RFC 8785 values array, from an
// embedded values array or an exactly matching supplied snapshot.
function resolveEnum(field, enumSnapshots) {
  const hasRef = hasOwn(field, "values_ref");
  const hasValues = hasOwn(field, "values");
  const ref = hasRef ? field.values_ref : undefined;
  let declared = hasValues ? field.values : undefined;
  if (typeof ref === "string" && ref.startsWith(ENUM.inline_prefix)) {
    const values = ref.slice(ENUM.inline_prefix.length).split(ENUM.inline_separator).map(trimInline);
    if (!validEnumValues(values)) return null;
    if (hasValues && !(Array.isArray(declared) && declared.length === values.length
        && declared.every((v, i) => v === values[i]))) return null;
    return values;
  }
  if (!hasRef) return validEnumValues(declared) ? declared : null;
  const snapshotLabel = hasOwn(field, "values_snapshot") ? field.values_snapshot : undefined;
  const digest = hasOwn(field, "values_sha256") ? field.values_sha256 : undefined;
  if (typeof ref !== "string" || ref.length === 0 || typeof snapshotLabel !== "string"
      || snapshotLabel.length === 0 || typeof digest !== "string"
      || !CAID_PATTERNS.digest_field.test(digest)) return null;
  if (!hasValues) {
    declared = undefined;
    for (const s of readHostArray(enumSnapshots) ?? []) {
      if (readOwnData(s, "values_ref") === ref && readOwnData(s, "values_snapshot") === snapshotLabel
          && readOwnData(s, "values_sha256") === digest) {
        const data = definitionData(s);
        declared = isDataObject(data) && hasOwn(data, "values") ? data.values : undefined;
        break;
      }
    }
  }
  if (!validEnumValues(declared)) return null;
  const c = serialize(declared, null, false);
  return c.ok && "sha256:" + sha256(c.canonical).toString("hex") === digest ? declared : null;
}

function daysInMonth(year, month) {
  if (month === 2) return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28;
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

// Returns null when the present value is valid for the field, else the
// reason code (mistyped_field, invalid_amount or invalid_code).
function checkField(value, field, enumSnapshots) {
  const t = FIELD_TYPES.get(field.type);
  if (t === undefined) return CAID_SPEC.unknown_field_type_refusal;
  const kind = dataKind(value);
  if (t.json === "number") return kind === "number" && Number.isInteger(value) ? null : "mistyped_field";
  if (kind !== t.json) return "mistyped_field";
  if (t.type === "enum") return resolveEnum(field, enumSnapshots)?.includes(value) ? null : "mistyped_field";
  if (t.type === "code") {
    const matcher = CAID_CODE_FORMATS[field.format];
    if (matcher === undefined) return t.unregistered_format_refusal;
    return matcher.test(value) ? null : t.format_refusal;
  }
  if (t.pattern !== undefined) {
    if (!CAID_PATTERNS[t.pattern].test(value)) return t.pattern_refusal;
    if (t.calendar_check === "day_within_month") {
      const o = CAID_SPEC.timestamp_date_offsets;
      const n = (r) => Number(value.slice(r[0], r[1]));
      if (n(o.day) > daysInMonth(n(o.year), n(o.month))) return t.pattern_refusal;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Computation (-04 Section 5): gates, then every check, in rank order
// ---------------------------------------------------------------------------

// Runs compute after the entry gate over a data-model value. Returns the
// ordered, deduplicated reasons, the resolution and the canonical text.
// With checkSuite false the suite phase is skipped (verification checks the
// suite of the CAID it is given instead).
/**
 * @param {any} obj
 * @param {boolean} outside
 * @param {unknown} definitions
 * @param {unknown} enumSnapshots
 * @param {unknown} suite
 * @param {boolean} checkSuite
 * @returns {{refusals: string[], resolved: {definition: any, definition_sha256: string} | null, canonical: string | null}}
 */
function evaluate(obj, outside, definitions, enumSnapshots, suite, checkSuite) {
  if (!isDataObject(obj) || !hasOwn(obj, "action_type") || typeof obj.action_type !== "string"
      || !CAID_PATTERNS.action_type.test(obj.action_type)) {
    return { refusals: ["invalid_action_type"], resolved: null, canonical: null };
  }
  const resolution = resolve(obj.action_type, definitions);
  if (resolution.reason !== undefined) return { refusals: [resolution.reason], resolved: null, canonical: null };
  const resolved = { definition: resolution.definition, definition_sha256: /** @type {string} */ (resolution.definition_sha256) };
  const d = resolved.definition;
  const required = d.required_fields;
  const all = [...required, ...(hasOwn(d, "optional_fields") ? d.optional_fields : [])];
  /** @type {Array<[number, number, string]>} */
  const found = [];
  required.forEach((/** @type {any} */ f, /** @type {number} */ i) => {
    if (!hasOwn(obj, f.name)) found.push([COMPUTE_RANK.missing_material_field, i, "missing_material_field:" + f.name]);
  });
  all.forEach((/** @type {any} */ f, /** @type {number} */ i) => {
    if (!hasOwn(obj, f.name)) return;
    const r = checkField(obj[f.name], f, enumSnapshots);
    if (r !== null) found.push([COMPUTE_RANK[r], i, r + ":" + f.name]);
  });
  if (checkSuite && !(typeof suite === "string" && IMPLEMENTED_SUITES.has(suite))) {
    found.push([COMPUTE_RANK.unknown_suite, 0, "unknown_suite"]);
  }
  const c = serialize(obj, LIMITS.canonical_octets, outside);
  if (!c.ok) for (const r of c.refusals) found.push([COMPUTE_RANK[r], 0, r]);
  found.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  return { refusals: [...new Set(found.map((f) => f[2]))], resolved, canonical: c.ok ? c.canonical : null };
}

/**
 * @param {any} obj
 * @param {boolean} outside
 * @param {unknown} options
 * @returns {CaidComputed | CaidRefused}
 */
function computeData(obj, outside, options) {
  const suite = readOption(options, "suite", "string");
  const definitions = readOption(options, "definitions", "array");
  const enumSnapshots = readOption(options, "enumSnapshots", "array");
  const r = evaluate(obj, outside, definitions, enumSnapshots, suite, true);
  if (r.refusals.length > 0) return { refusals: r.refusals };
  const bytes = sha256(/** @type {string} */ (r.canonical));
  return {
    caid: `${ID.scheme}${ID.separator}${ID.version}${ID.separator}${obj.action_type}${ID.separator}${suite}${ID.separator}${bytes.toString("base64url")}`,
    digest: "sha256:" + bytes.toString("hex"),
    definition_sha256: /** @type {{definition_sha256: string}} */ (r.resolved).definition_sha256,
  };
}

/**
 * computeCaid(actionObject, {suite, definitions, enumSnapshots})
 *   -> {caid, digest, definition_sha256}   on success
 *   -> {refusals: [string]}                on any failure (never throws)
 *
 * For an action object the application constructed. Received JSON text
 * must go through computeCaidJson instead.
 *
 * @param {*} actionObject
 * @param {*} [options]
 * @returns {CaidComputed | CaidRefused}
 */
export function computeCaid(actionObject, options) {
  const snap = snapshot(actionObject, true);
  return computeData(snap.value, snap.outside, options);
}

/**
 * computeCaidJson(bytes, options): computeCaid over received JSON text. A
 * text the strict decoder refuses yields exactly {refusals: ["malformed_json"]}.
 *
 * @param {unknown} bytes
 * @param {*} [options]
 * @returns {CaidComputed | CaidRefused}
 */
export function computeCaidJson(bytes, options) {
  const decoded = decodeCaidJson(bytes);
  if (!decoded.ok) return { refusals: decoded.refusals };
  return computeData(decoded.value, false, options);
}

// ---------------------------------------------------------------------------
// parseCaid (-04 Section 3.4)
// ---------------------------------------------------------------------------

/**
 * parseCaid(input)
 *   -> {ok: true, caid: {version, action_type, suite, digest}}
 *   -> {ok: false, refusals: ["malformed_caid" | "unknown_suite"]}
 *
 * Checks, in order: the caid rule of Appendix A (malformed_caid); the suite
 * is registered (unknown_suite); the digest has the suite's digest syntax,
 * including zero unused bits in its final character (malformed_caid). No
 * trimming, case folding, normalization or percent-decoding.
 *
 * @param {*} input
 * @returns {CaidParseResult}
 */
export function parseCaid(input) {
  if (typeof input !== "string" || !CAID_PATTERNS.caid.test(input)) {
    return { ok: false, refusals: ["malformed_caid"] };
  }
  const [, version, actionType, suite, digest] = input.split(ID.separator);
  const digestPattern = CAID_SUITE_DIGEST_PATTERNS[suite];
  if (digestPattern === undefined) return { ok: false, refusals: ["unknown_suite"] };
  if (!digestPattern.test(digest)) return { ok: false, refusals: ["malformed_caid"] };
  return { ok: true, caid: { version, action_type: actionType, suite, digest } };
}

// ---------------------------------------------------------------------------
// Verification (-04 Section 6)
// ---------------------------------------------------------------------------

// The closed-shape detail of one reason: {reason, field, rule, observed}.
/**
 * @param {string} reason
 * @param {any} value
 * @param {unknown} caidArgument
 * @returns {CaidDetail}
 */
function detailOf(reason, value, caidArgument) {
  const colon = reason.indexOf(":");
  const code = colon < 0 ? reason : reason.slice(0, colon);
  const rule = DETAIL_RULES[code];
  const field = rule.field === "param" ? reason.slice(colon + 1) : rule.field;
  let observed = null;
  if (rule.observed === "argument") {
    observed = hostKind(caidArgument);
  } else if (rule.observed === "member") {
    observed = isDataObject(value) ? dataKind(hasOwn(value, field) ? value[field] : undefined) : dataKind(value);
  }
  return { reason, field, rule: rule.rule, observed };
}

/**
 * @param {string[]} reasons
 * @param {any} value
 * @param {unknown} caidArgument
 * @returns {CaidVerifyResult}
 */
function refusedVerify(reasons, value, caidArgument) {
  return { valid: false, reasons, details: reasons.map((r) => detailOf(r, value, caidArgument)) };
}

/**
 * @param {any} obj
 * @param {boolean} outside
 * @param {unknown} caidString
 * @param {{version: string, action_type: string, suite: string, digest: string}} parsed
 * @param {unknown} options
 * @returns {CaidVerifyResult}
 */
function verifyData(obj, outside, caidString, parsed, options) {
  const definitions = readOption(options, "definitions", "array");
  const enumSnapshots = readOption(options, "enumSnapshots", "array");
  const expected = readOption(options, "expectedDefinitionSha256", "string");
  const checkSuite = !EXPAND_INVALID_OBJECT.omit.includes("unknown_suite");
  if (!isDataObject(obj)) {
    const r = evaluate(obj, outside, definitions, enumSnapshots, undefined, checkSuite);
    return { valid: false, reasons: ["invalid_object"], details: r.refusals.map((x) => detailOf(x, obj, caidString)) };
  }
  /** @type {string[]} */
  const reasons = [];
  /** @type {CaidDetail[]} */
  const details = [];
  /** @param {string} r */
  const add = (r) => {
    reasons.push(r);
    details.push(detailOf(r, obj, caidString));
  };
  // The in-object action_type must equal the CAID's type: this is where
  // cross-context reinterpretation dies, since there is no domain prefix.
  if (!hasOwn(obj, "action_type") || obj.action_type !== parsed.action_type) add("action_type_mismatch");
  const r = evaluate(obj, outside, definitions, enumSnapshots, undefined, checkSuite);
  const definitionDigest = r.resolved ? r.resolved.definition_sha256 : undefined;
  if (expected !== undefined && definitionDigest !== undefined && expected !== definitionDigest) {
    add("definition_mismatch");
  }
  if (!IMPLEMENTED_SUITES.has(parsed.suite)) {
    add("unknown_suite");
  } else {
    const c = serialize(obj, LIMITS.canonical_octets, outside);
    if (c.ok && sha256(c.canonical).toString("base64url") !== parsed.digest) add("digest_mismatch");
  }
  if (r.refusals.length > 0) {
    reasons.push("invalid_object");
    for (const x of r.refusals) details.push(detailOf(x, obj, caidString));
  }
  /** @type {CaidVerifyResult} */
  const out = { valid: reasons.length === 0, reasons, details };
  if (definitionDigest !== undefined) out.definition_sha256 = definitionDigest;
  return out;
}

/**
 * verifyCaid(actionObject, caidString, {definitions, enumSnapshots,
 *            expectedDefinitionSha256})
 *   -> {valid, reasons, details[, definition_sha256]}
 *
 * Reasons in order: the parse gate (malformed_caid or unknown_suite, alone);
 * invalid_object alone when the value is not an object; else
 * action_type_mismatch, definition_mismatch, unknown_suite or
 * digest_mismatch, then invalid_object when computation refuses. details
 * has one {reason, field, rule, observed} per reason, except that
 * invalid_object is replaced by one detail per underlying compute reason.
 * definition_sha256 is present whenever a conforming definition resolved.
 *
 * A valid result establishes only that the object recomputes to the CAID
 * under its suite. It establishes nothing about authorization, execution,
 * or trust.
 *
 * @param {*} actionObject
 * @param {*} caidString
 * @param {*} [options]
 * @returns {CaidVerifyResult}
 */
export function verifyCaid(actionObject, caidString, options) {
  const parsed = parseCaid(caidString);
  if (!parsed.ok) return refusedVerify(parsed.refusals, undefined, caidString);
  const snap = snapshot(actionObject, true);
  return verifyData(snap.value, snap.outside, caidString, parsed.caid, options);
}

/**
 * verifyCaidJson(bytes, caidString, options): verifyCaid over received JSON
 * text. The parse gate comes first; a text the strict decoder refuses then
 * yields exactly the reason malformed_json.
 *
 * @param {unknown} bytes
 * @param {*} caidString
 * @param {*} [options]
 * @returns {CaidVerifyResult}
 */
export function verifyCaidJson(bytes, caidString, options) {
  const parsed = parseCaid(caidString);
  if (!parsed.ok) return refusedVerify(parsed.refusals, undefined, caidString);
  const decoded = decodeCaidJson(bytes);
  if (!decoded.ok) return refusedVerify(decoded.refusals, undefined, caidString);
  return verifyData(decoded.value, false, caidString, parsed.caid, options);
}
