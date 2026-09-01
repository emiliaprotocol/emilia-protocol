// SPDX-License-Identifier: Apache-2.0
// Behavioral and schema-parity tests for the local AIPS-1 P3 comment lab.
// Run after repository dependencies are installed: node --test evaluate.selftest.mjs

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import {
  LIMITS,
  VERDICTS,
  digestJson,
  evaluateCase,
  evaluateFile,
  parseJsonStrict,
} from "./evaluate.mjs";
import {
  buildArtifactBindings,
  buildCorpusReport,
  loadCorpus,
  materializeVector,
  stableCorpusReportJson,
} from "./generate-report.mjs";

const here = dirname(fileURLToPath(import.meta.url));

function fileSha256(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function withTempDirectory(run) {
  const directory = mkdtempSync(join(tmpdir(), "aips1-p3-selftest-"));
  try {
    return run(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

const baseProfile = {
  profile_version: "aips1-p3-evidence-source-evaluation-v0.1",
  profile_id: "example.trigger.v1",
  evaluation_time: "2026-09-01T12:00:00Z",
  combiner: "ALL",
  sources: [
    {
      source_id: "filing",
      source_type: "regulator_filing",
      locator: "https://example.test/filings/42",
      revision: "sha256:source-revision-42",
      format: "application/json",
      basis: "OBSERVED_FACT",
      data_sha256: digestJson({ status: "effective" }),
      max_age_seconds: 86400,
    },
  ],
  predicates: [
    {
      predicate_id: "filing-is-effective",
      source_ids: ["filing"],
      path: "/status",
      operator: "EQUALS",
      expected: "effective",
    },
  ],
};

function evidenceWith(status) {
  return {
    evidence_set_version: "aips1-p3-evidence-set-v0.1",
    observations: [
      {
        source_id: "filing",
        locator: "https://example.test/filings/42",
        revision: "sha256:source-revision-42",
        observed_at: "2026-09-01T11:00:00Z",
        availability: "AVAILABLE",
        format: "application/json",
        basis: "OBSERVED_FACT",
        data: { status },
      },
    ],
  };
}

function evaluateMutation(caseId, mutate, { repinData = true } = {}) {
  const profile = structuredClone(baseProfile);
  const evidenceSet = evidenceWith("effective");
  mutate({ profile, evidenceSet });
  if (repinData && evidenceSet.observations[0]?.data !== undefined) {
    profile.sources[0].data_sha256 = digestJson(evidenceSet.observations[0].data);
  }
  return evaluateCase({ case_id: caseId, profile, evidence_set: evidenceSet });
}

test("exports exactly the three closed lab trigger verdicts", () => {
  assert.deepEqual(VERDICTS, ["SATISFIED", "NOT_SATISFIED", "INDETERMINATE"]);
});

test("returns SATISFIED only when a declared, pinned, current source makes the predicate true", () => {
  const report = evaluateCase({ case_id: "control-satisfied", profile: baseProfile, evidence_set: evidenceWith("effective") });
  assert.equal(report.verdict, "SATISFIED");
  assert.equal(report.predicate_results[0].verdict, "SATISFIED");
});

test("every report binds the canonical profile, evidence set, input, and source snapshot", () => {
  const input = {
    case_id: "digest-binding-control",
    profile: baseProfile,
    evidence_set: evidenceWith("effective"),
  };
  const report = evaluateCase(input);
  assert.equal(report.profile_digest, digestJson(input.profile));
  assert.equal(report.evidence_set_digest, digestJson(input.evidence_set));
  assert.equal(report.input_digest, digestJson(input));
  assert.deepEqual(report.source_snapshots, [
    {
      source_id: "filing",
      pin_count: 1,
      locator: "https://example.test/filings/42",
      revision: "sha256:source-revision-42",
      format: "application/json",
      basis: "OBSERVED_FACT",
      data_sha256: digestJson({ status: "effective" }),
      max_age_seconds: 86400,
      observations: [
        {
          availability: "AVAILABLE",
          locator: "https://example.test/filings/42",
          revision: "sha256:source-revision-42",
          observed_at: "2026-09-01T11:00:00Z",
          format: "application/json",
          basis: "OBSERVED_FACT",
          data_sha256: digestJson({ status: "effective" }),
        },
      ],
    },
  ]);

  const changedEvidence = evidenceWith("effective");
  changedEvidence.observations[0].observed_at = "2026-09-01T11:00:01Z";
  const changed = evaluateCase({ ...input, evidence_set: changedEvidence });
  assert.equal(changed.verdict, report.verdict);
  assert.notEqual(changed.evidence_set_digest, report.evidence_set_digest);
  assert.notEqual(changed.input_digest, report.input_digest);
  assert.notEqual(JSON.stringify(changed), JSON.stringify(report));
});

test("returns NOT_SATISFIED for a determinate false predicate", () => {
  const profile = structuredClone(baseProfile);
  profile.sources[0].data_sha256 = digestJson({ status: "withdrawn" });
  const report = evaluateCase({ case_id: "control-not-satisfied", profile, evidence_set: evidenceWith("withdrawn") });
  assert.equal(report.verdict, "NOT_SATISFIED");
  assert.equal(report.predicate_results[0].verdict, "NOT_SATISFIED");
});

test("returns INDETERMINATE, never false, when required evidence is missing", () => {
  const report = evaluateCase({
    case_id: "hostile-missing-source",
    profile: baseProfile,
    evidence_set: { evidence_set_version: "aips1-p3-evidence-set-v0.1", observations: [] },
  });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["SOURCE_MISSING"]);
});

for (const hostile of [
  {
    name: "unavailable",
    reason: "SOURCE_UNAVAILABLE",
    mutate: ({ evidenceSet }) => { evidenceSet.observations[0].availability = "UNAVAILABLE"; },
  },
  {
    name: "stale",
    reason: "SOURCE_STALE",
    mutate: ({ evidenceSet }) => { evidenceSet.observations[0].observed_at = "2026-08-30T11:59:59Z"; },
  },
  {
    name: "unsupported",
    reason: "SOURCE_UNSUPPORTED",
    mutate: ({ profile, evidenceSet }) => {
      profile.sources[0].format = "application/cbor";
      evidenceSet.observations[0].format = "application/cbor";
    },
  },
  {
    name: "wrong locator pin",
    reason: "SOURCE_UNPINNED",
    mutate: ({ evidenceSet }) => { evidenceSet.observations[0].locator = "https://attacker.test/filing"; },
  },
  {
    name: "wrong revision pin",
    reason: "SOURCE_UNPINNED",
    mutate: ({ evidenceSet }) => { evidenceSet.observations[0].revision = "sha256:substituted"; },
  },
  {
    name: "value missing from an otherwise available source",
    reason: "VALUE_MISSING",
    mutate: ({ evidenceSet }) => { evidenceSet.observations[0].data = {}; },
  },
]) {
  test(`${hostile.name} evidence is INDETERMINATE, not NOT_SATISFIED`, () => {
    const report = evaluateMutation(`hostile-${hostile.name}`, hostile.mutate);
    assert.equal(report.verdict, "INDETERMINATE");
    assert.deepEqual(report.reason_codes, [hostile.reason]);
  });
}

test("a trigger depending solely on issuer opinion is INDETERMINATE", () => {
  const report = evaluateMutation("hostile-issuer-opinion", ({ profile, evidenceSet }) => {
    profile.sources[0].basis = "ISSUER_OPINION";
    evidenceSet.observations[0].basis = "ISSUER_OPINION";
  });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["SOURCE_ISSUER_OPINION_ONLY"]);
});

test("issuer opinion plus a declared observed-fact source is not sole-opinion support", () => {
  const report = evaluateMutation("control-opinion-plus-observed-fact", ({ profile, evidenceSet }) => {
    profile.sources.push({
      source_id: "court-order",
      source_type: "court_order",
      locator: "https://example.test/orders/7",
      revision: "sha256:order-7",
      format: "application/json",
      basis: "OBSERVED_FACT",
      data_sha256: digestJson({ status: "effective" }),
      max_age_seconds: 86400,
    });
    profile.predicates[0].source_ids.push("court-order");
    profile.sources[0].basis = "ISSUER_OPINION";
    evidenceSet.observations[0].basis = "ISSUER_OPINION";
    evidenceSet.observations.push({
      source_id: "court-order",
      locator: "https://example.test/orders/7",
      revision: "sha256:order-7",
      observed_at: "2026-09-01T11:30:00Z",
      availability: "AVAILABLE",
      format: "application/json",
      basis: "OBSERVED_FACT",
      data: { status: "effective" },
    });
  });
  assert.equal(report.verdict, "SATISFIED");
});

test("RFC 6901 array selection accepts canonical indexes and rejects array properties", () => {
  const control = evaluateMutation("control-array-index", ({ profile, evidenceSet }) => {
    profile.predicates[0].path = "/0";
    evidenceSet.observations[0].data = ["effective"];
  });
  assert.equal(control.verdict, "SATISFIED");

  for (const path of ["/length", "/01", "/-"]) {
    const hostile = evaluateMutation(`hostile-array-pointer-${path}`, ({ profile, evidenceSet }) => {
      profile.predicates[0].path = path;
      profile.predicates[0].expected = path === "/length" ? 1 : "effective";
      evidenceSet.observations[0].data = ["effective"];
    });
    assert.equal(hostile.verdict, "INDETERMINATE", path);
    assert.deepEqual(hostile.reason_codes, ["VALUE_MISSING"], path);
  }
});

test("the empty RFC 6901 pointer selects the complete source value", () => {
  const report = evaluateMutation("control-root-pointer", ({ profile, evidenceSet }) => {
    profile.predicates[0].path = "";
    profile.predicates[0].expected = { status: "effective" };
    evidenceSet.observations[0].data = { status: "effective" };
  });
  assert.equal(report.verdict, "SATISFIED");
  assert.equal(report.predicate_results[0].runtime_evaluable, true);
});

test("string bounds count Unicode code points exactly as the JSON Schemas do", () => {
  const emoji = "😀";
  const sourceId = emoji.repeat(LIMITS.max_identifier_length);
  const revision = emoji.repeat(LIMITS.max_identifier_length);
  const locator = emoji.repeat(LIMITS.max_locator_length);
  const propertyName = emoji.repeat(LIMITS.max_locator_length - 1);
  const payload = emoji.repeat(LIMITS.max_string_length);
  const profile = structuredClone(baseProfile);
  const evidenceSet = evidenceWith("effective");

  profile.profile_id = emoji.repeat(200);
  profile.sources[0].source_id = sourceId;
  profile.sources[0].source_type = emoji.repeat(LIMITS.max_identifier_length);
  profile.sources[0].locator = locator;
  profile.sources[0].revision = revision;
  profile.predicates[0].predicate_id = emoji.repeat(LIMITS.max_identifier_length);
  profile.predicates[0].source_ids = [sourceId];
  profile.predicates[0].path = `/${propertyName}`;
  profile.predicates[0].expected = payload;
  evidenceSet.observations[0].source_id = sourceId;
  evidenceSet.observations[0].locator = locator;
  evidenceSet.observations[0].revision = revision;
  evidenceSet.observations[0].data = { [propertyName]: payload };
  profile.sources[0].data_sha256 = digestJson(evidenceSet.observations[0].data);

  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validateProfile = ajv.compile(
    JSON.parse(readFileSync(join(here, "evaluation-profile.schema.json"), "utf8")),
  );
  const validateEvidence = ajv.compile(
    JSON.parse(readFileSync(join(here, "evidence-set.schema.json"), "utf8")),
  );
  const validateReport = ajv.compile(
    JSON.parse(readFileSync(join(here, "evaluation-report.schema.json"), "utf8")),
  );
  assert.equal(validateProfile(profile), true, JSON.stringify(validateProfile.errors));
  assert.equal(validateEvidence(evidenceSet), true, JSON.stringify(validateEvidence.errors));

  const input = { case_id: "unicode-code-point-control", profile, evidence_set: evidenceSet };
  const programmaticReport = evaluateCase(input);
  assert.equal(programmaticReport.verdict, "SATISFIED");
  assert.equal(validateReport(programmaticReport), true, JSON.stringify(validateReport.errors));

  const parsedReport = evaluateCase(parseJsonStrict(JSON.stringify(input)));
  assert.equal(parsedReport.verdict, "SATISFIED");
  assert.equal(validateReport(parsedReport), true, JSON.stringify(validateReport.errors));

  const overBoundProfile = structuredClone(baseProfile);
  overBoundProfile.profile_id = emoji.repeat(LIMITS.max_identifier_length + 1);
  assert.equal(validateProfile(overBoundProfile), false);
  const overBoundReport = evaluateCase({
    case_id: "unicode-code-point-over-bound",
    profile: overBoundProfile,
    evidence_set: evidenceWith("effective"),
  });
  assert.equal(overBoundReport.verdict, "INDETERMINATE");
  assert.deepEqual(overBoundReport.reason_codes, ["PROFILE_INVALID"]);
  assert.ok(overBoundReport.validation_errors.includes("profile:invalid-profile-id"));
});

test("timestamps reject impossible calendar dates and precision beyond milliseconds", () => {
  for (const timestamp of [
    "2026-02-30T12:00:00Z",
    "2026-09-01T12:00:00.0001Z",
    "2026-09-01T12:00:00+00:00",
  ]) {
    const report = evaluateMutation(`hostile-timestamp-${timestamp}`, ({ profile }) => {
      profile.evaluation_time = timestamp;
    });
    assert.equal(report.verdict, "INDETERMINATE", timestamp);
    assert.deepEqual(report.reason_codes, ["PROFILE_INVALID"], timestamp);
    assert.ok(report.validation_errors.includes("profile:invalid-evaluation-time"), timestamp);
  }

  const millisecondControl = evaluateMutation("control-millisecond-time", ({ profile, evidenceSet }) => {
    profile.evaluation_time = "2026-09-01T12:00:00.125Z";
    evidenceSet.observations[0].observed_at = "2026-09-01T12:00:00.124Z";
  });
  assert.equal(millisecondControl.verdict, "SATISFIED");
});

test("conflicting declared sources yield INDETERMINATE", () => {
  const report = evaluateMutation("hostile-conflict", ({ profile, evidenceSet }) => {
    profile.sources.push({
      source_id: "court-order",
      source_type: "court_order",
      locator: "https://example.test/orders/7",
      revision: "sha256:order-7",
      format: "application/json",
      basis: "OBSERVED_FACT",
      data_sha256: digestJson({ status: "stayed" }),
      max_age_seconds: 86400,
    });
    profile.predicates[0].source_ids.push("court-order");
    evidenceSet.observations.push({
      source_id: "court-order",
      locator: "https://example.test/orders/7",
      revision: "sha256:order-7",
      observed_at: "2026-09-01T11:30:00Z",
      availability: "AVAILABLE",
      format: "application/json",
      basis: "OBSERVED_FACT",
      data: { status: "stayed" },
    });
  });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["SOURCE_CONFLICT"]);
});

test("duplicate observations that disagree for one source yield INDETERMINATE", () => {
  const report = evaluateMutation("hostile-duplicate-conflict", ({ evidenceSet }) => {
    const conflict = structuredClone(evidenceSet.observations[0]);
    conflict.data.status = "withdrawn";
    evidenceSet.observations.push(conflict);
  });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["SOURCE_CONFLICT"]);
});

test("forged data that does not match the relying-party content pin is INDETERMINATE", () => {
  const report = evaluateMutation("hostile-forged-data", ({ evidenceSet }) => {
    evidenceSet.observations[0].data.status = "forged-effective";
  }, { repinData: false });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["SOURCE_UNPINNED"]);
});

test("a basis label that does not match the relying-party source pin is INDETERMINATE", () => {
  const report = evaluateMutation("hostile-forged-basis", ({ evidenceSet }) => {
    evidenceSet.observations[0].basis = "ISSUER_OPINION";
  });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["SOURCE_UNPINNED"]);
});

test("an undefined local predicate operator yields INDETERMINATE", () => {
  const report = evaluateMutation("hostile-undefined-operator", ({ profile }) => {
    profile.predicates[0].operator = "ISSUER_DECIDES";
  });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["PREDICATE_UNSUPPORTED"]);
});

test("duplicate semantic identifiers remain schema-valid but evaluate as ambiguous", () => {
  const duplicateSourceProfile = structuredClone(baseProfile);
  duplicateSourceProfile.sources.push(structuredClone(duplicateSourceProfile.sources[0]));
  const sourceReport = evaluateCase({
    case_id: "hostile-duplicate-source-id",
    profile: duplicateSourceProfile,
    evidence_set: evidenceWith("effective"),
  });
  assert.equal(sourceReport.verdict, "INDETERMINATE");
  assert.deepEqual(sourceReport.reason_codes, ["SOURCE_AMBIGUOUS"]);

  const duplicatePredicateProfile = structuredClone(baseProfile);
  duplicatePredicateProfile.predicates.push(structuredClone(duplicatePredicateProfile.predicates[0]));
  const predicateReport = evaluateCase({
    case_id: "hostile-duplicate-predicate-id",
    profile: duplicatePredicateProfile,
    evidence_set: evidenceWith("effective"),
  });
  assert.equal(predicateReport.verdict, "INDETERMINATE");
  assert.deepEqual(predicateReport.reason_codes, ["PREDICATE_ID_AMBIGUOUS"]);
});

test("supported numeric predicates are determinate and reject type ambiguity", () => {
  const satisfied = evaluateMutation("control-number-gte", ({ profile, evidenceSet }) => {
    profile.predicates[0].operator = "NUMBER_GTE";
    profile.predicates[0].expected = 10;
    evidenceSet.observations[0].data.status = 12;
  });
  assert.equal(satisfied.verdict, "SATISFIED");

  const notSatisfied = evaluateMutation("control-number-gte-false", ({ profile, evidenceSet }) => {
    profile.predicates[0].operator = "NUMBER_GTE";
    profile.predicates[0].expected = 10;
    evidenceSet.observations[0].data.status = 9;
  });
  assert.equal(notSatisfied.verdict, "NOT_SATISFIED");

  const ambiguous = evaluateMutation("hostile-number-type", ({ profile, evidenceSet }) => {
    profile.predicates[0].operator = "NUMBER_GTE";
    profile.predicates[0].expected = 10;
    evidenceSet.observations[0].data.status = "12";
  });
  assert.equal(ambiguous.verdict, "INDETERMINATE");
  assert.deepEqual(ambiguous.reason_codes, ["VALUE_TYPE_UNSUPPORTED"]);
});

test("unsafe or non-integer programmatic numbers are rejected before evaluation", () => {
  for (const value of [
    9_007_199_254_740_992,
    1.5,
    -0,
  ]) {
    const evidenceSet = evidenceWith("effective");
    evidenceSet.observations[0].data.status = value;
    const report = evaluateCase({
      case_id: "hostile-programmatic-number",
      profile: baseProfile,
      evidence_set: evidenceSet,
    });
    assert.equal(report.verdict, "INDETERMINATE");
    assert.deepEqual(report.reason_codes, ["INPUT_NUMBER_UNSAFE"]);
    assert.deepEqual(report.validation_errors, ["input:unsafe-number"]);
  }
});

test("numeric JSON tokens that alias after Number conversion are rejected", () => {
  for (const token of [
    "9007199254740992",
    "9007199254740993",
    "0.10000000000000001",
  ]) {
    assert.throws(
      () => parseJsonStrict(`{"value":${token}}`),
      (error) => error?.code === "UNSAFE_NUMBER",
      token,
    );
  }

  assert.equal(
    parseJsonStrict('{"value":9007199254740991}').value,
    9_007_199_254_740_991,
  );
});

test("programmatic objects with inherited properties are rejected as non-plain", () => {
  const data = Object.create({ status: "effective" });
  const evidenceSet = evidenceWith("effective");
  evidenceSet.observations[0].data = data;
  const report = evaluateCase({ case_id: "hostile-inherited-field", profile: baseProfile, evidence_set: evidenceSet });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["CASE_INVALID"]);
  assert.deepEqual(report.validation_errors, ["input:non-plain-object"]);
});

test("programmatic sparse arrays are rejected instead of canonicalized as non-JSON", () => {
  const profile = structuredClone(baseProfile);
  profile.predicates[0].expected = new Array(2);
  const report = evaluateCase({ case_id: "hostile-sparse-array", profile, evidence_set: evidenceWith("effective") });
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["CASE_INVALID"]);
  assert.deepEqual(report.validation_errors, ["input:sparse-array"]);
});

test("an indeterminate predicate dominates a determinate false in ALL composition", () => {
  const report = evaluateMutation("hostile-false-plus-missing", ({ profile }) => {
    profile.predicates[0].expected = "withdrawn";
    profile.predicates.push({
      predicate_id: "missing-source-predicate",
      source_ids: ["absent-source"],
      path: "/status",
      operator: "EQUALS",
      expected: "effective",
    });
  });
  assert.equal(report.predicate_results[0].verdict, "NOT_SATISFIED");
  assert.equal(report.predicate_results[1].verdict, "INDETERMINATE");
  assert.equal(report.verdict, "INDETERMINATE");
});

test("invalid profile and evidence-set structures abstain with named reasons", () => {
  const invalidProfile = evaluateCase({
    case_id: "hostile-invalid-profile",
    profile: { profile_version: "wrong" },
    evidence_set: evidenceWith("effective"),
  });
  assert.equal(invalidProfile.verdict, "INDETERMINATE");
  assert.deepEqual(invalidProfile.reason_codes, ["PROFILE_INVALID"]);

  const invalidEvidence = evaluateCase({
    case_id: "hostile-invalid-evidence",
    profile: baseProfile,
    evidence_set: { evidence_set_version: "wrong", observations: [] },
  });
  assert.equal(invalidEvidence.verdict, "INDETERMINATE");
  assert.deepEqual(invalidEvidence.reason_codes, ["EVIDENCE_SET_INVALID"]);
});

test("the report keeps trigger evaluation separate from legal and payment decisions", () => {
  const report = evaluateCase({ case_id: "scope-control", profile: baseProfile, evidence_set: evidenceWith("effective") });
  assert.equal(report.scope.evaluates, "local_trigger_predicate_satisfaction");
  assert.equal(report.scope.evaluation_mode, "offline_fixture_evaluation");
  assert.equal(report.static_evaluable, true);
  assert.equal(report.runtime_evaluable, true);
  assert.equal(report.profile_id, "example.trigger.v1");
  assert.equal(report.evaluation_time, "2026-09-01T12:00:00Z");
  assert.deepEqual(report.scope.does_not_determine, [
    "authorization",
    "coverage",
    "liability",
    "claim_acceptance",
    "payout",
  ]);
  assert.ok(!("authorized" in report));
  assert.ok(!("eligible" in report));
});

test("the static vector corpus has a control paired with every hostile case", () => {
  const corpus = loadCorpus(join(here, "vectors", "cases.json"));
  const pairs = new Map();
  for (const vector of corpus.vectors) {
    const members = pairs.get(vector.pair_id) ?? [];
    members.push(vector.kind);
    pairs.set(vector.pair_id, members);
  }
  assert.ok(pairs.size >= 10);
  for (const members of pairs.values()) {
    assert.deepEqual([...members].sort(), ["CONTROL", "HOSTILE"]);
  }
});

test("every static vector reproduces its expected verdict and reason codes", () => {
  const corpus = loadCorpus(join(here, "vectors", "cases.json"));
  const report = buildCorpusReport(corpus);
  assert.equal(report.all_expectations_met, true);
  assert.ok(report.summary.total >= 20);
  assert.equal(report.summary.mismatches, 0);
  assert.deepEqual(
    [...new Set(report.cases.map((entry) => entry.actual_verdict))].sort(),
    ["INDETERMINATE", "NOT_SATISFIED", "SATISFIED"],
  );
  const hostileReasons = new Set(
    report.cases.filter((entry) => entry.kind === "HOSTILE").flatMap((entry) => entry.actual_reason_codes),
  );
  for (const required of [
    "SOURCE_MISSING",
    "SOURCE_UNAVAILABLE",
    "SOURCE_STALE",
    "SOURCE_UNSUPPORTED",
    "SOURCE_CONFLICT",
    "SOURCE_UNPINNED",
  ]) {
    assert.ok(hostileReasons.has(required), `missing hostile reason ${required}`);
  }
});

test("corpus mutation paths cannot traverse or assign prototype-bearing segments", () => {
  const corpus = loadCorpus(join(here, "vectors", "cases.json"));
  const marker = "__aips1_p3_polluted__";
  const paths = [
    ["__proto__", marker],
    ["constructor", "prototype", marker],
    ["profile", "__proto__"],
    ["profile", "constructor"],
  ];
  try {
    for (const path of paths) {
      assert.throws(
        () => materializeVector(corpus, {
          case_id: "hostile-prototype-path",
          mutations: [{ op: "SET", path, value: true }],
        }),
        /mutation path rejected/,
        path.join("/"),
      );
      assert.equal(Object.prototype[marker], undefined);
    }
  } finally {
    delete Object.prototype[marker];
  }
});

test("the generated corpus report is byte-stable and matches report.json", () => {
  const corpus = loadCorpus(join(here, "vectors", "cases.json"));
  const first = stableCorpusReportJson(buildCorpusReport(corpus));
  const second = stableCorpusReportJson(buildCorpusReport(corpus));
  assert.equal(first, second);
  assert.equal(first, readFileSync(join(here, "report.json"), "utf8"));
});

test("the corpus report binds its source lock, schema, evaluator, and generator bytes", () => {
  const corpus = loadCorpus(join(here, "vectors", "cases.json"));
  const report = buildCorpusReport(corpus);
  assert.deepEqual(report.artifact_bindings, buildArtifactBindings());
  for (const binding of [
    report.artifact_bindings.source_lock,
    report.artifact_bindings.corpus_report_schema,
    report.artifact_bindings.evaluator,
    report.artifact_bindings.generator,
  ]) {
    assert.equal(binding.sha256, fileSha256(join(here, binding.path)), binding.path);
  }
  const { binding_digest: claimedDigest, ...bindingMaterial } = report.artifact_bindings;
  assert.equal(claimedDigest, digestJson(bindingMaterial));
  assert.equal(
    report.artifact_bindings.source_lock.resolved_commit,
    "280a8ba0e9c2658ee6af10778e0f6a2fb669661d",
  );
  assert.equal(
    report.artifact_bindings.source_lock.resolved_tree,
    "0131893fd6a7c0341521d73591d14976b1af43ca",
  );
});

test("JSON schemas validate the executable's accepted envelopes and emitted reports", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const schemas = {};
  for (const name of [
    "evaluation-profile.schema.json",
    "evidence-set.schema.json",
    "evaluation-report.schema.json",
    "corpus-report.schema.json",
    "vector-corpus.schema.json",
  ]) {
    const schema = JSON.parse(readFileSync(join(here, name), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    schemas[name] = schema;
  }
  const reportSchema = schemas["evaluation-report.schema.json"];
  assert.deepEqual(reportSchema.$defs.verdict.enum, VERDICTS);

  const validateProfile = ajv.compile(schemas["evaluation-profile.schema.json"]);
  const validateEvidence = ajv.compile(schemas["evidence-set.schema.json"]);
  const validateReport = ajv.compile(reportSchema);
  const validateCorpus = ajv.compile(schemas["vector-corpus.schema.json"]);
  const validateCorpusReport = ajv.compile(schemas["corpus-report.schema.json"]);
  assert.equal(validateProfile(baseProfile), true, JSON.stringify(validateProfile.errors));
  assert.equal(validateEvidence(evidenceWith("effective")), true, JSON.stringify(validateEvidence.errors));
  const report = evaluateCase({ case_id: "schema-report-control", profile: baseProfile, evidence_set: evidenceWith("effective") });
  assert.equal(validateReport(report), true, JSON.stringify(validateReport.errors));
  const invalidReport = evaluateCase({
    case_id: "schema-report-invalid-control",
    profile: { profile_version: "wrong" },
    evidence_set: evidenceWith("effective"),
  });
  assert.equal(validateReport(invalidReport), true, JSON.stringify(validateReport.errors));

  const noisyProfile = structuredClone(baseProfile);
  for (let index = 0; index < 248; index += 1) {
    noisyProfile.sources[0][`unknown-${index.toString().padStart(3, "0")}`] = true;
  }
  const boundedDiagnosticReport = evaluateCase({
    case_id: "schema-report-bounded-diagnostics",
    profile: noisyProfile,
    evidence_set: evidenceWith("effective"),
  });
  assert.equal(boundedDiagnosticReport.verdict, "INDETERMINATE");
  assert.deepEqual(boundedDiagnosticReport.reason_codes, ["PROFILE_INVALID"]);
  assert.ok(boundedDiagnosticReport.validation_errors.length <= LIMITS.max_validation_errors);
  assert.match(boundedDiagnosticReport.validation_errors.at(-1), /^validation-errors-truncated:count=\d+:sha256:[0-9a-f]{64}$/);
  assert.equal(
    validateReport(boundedDiagnosticReport),
    true,
    JSON.stringify(validateReport.errors),
  );
  const corpus = loadCorpus(join(here, "vectors", "cases.json"));
  assert.equal(validateCorpus(corpus), true, JSON.stringify(validateCorpus.errors));
  const corpusReport = buildCorpusReport(corpus);
  assert.equal(validateCorpusReport(corpusReport), true, JSON.stringify(validateCorpusReport.errors));

  const unsupported = structuredClone(baseProfile);
  unsupported.predicates[0].operator = "FUTURE_PROFILE_OPERATOR";
  assert.equal(validateProfile(unsupported), true, JSON.stringify(validateProfile.errors));
  const unsupportedReport = evaluateCase({ case_id: "schema-unsupported-operator", profile: unsupported, evidence_set: evidenceWith("effective") });
  assert.deepEqual(unsupportedReport.reason_codes, ["PREDICATE_UNSUPPORTED"]);

  const duplicateSourceProfile = structuredClone(baseProfile);
  duplicateSourceProfile.sources.push(structuredClone(duplicateSourceProfile.sources[0]));
  assert.equal(validateProfile(duplicateSourceProfile), true, JSON.stringify(validateProfile.errors));
  assert.deepEqual(
    evaluateCase({ case_id: "schema-duplicate-source-id", profile: duplicateSourceProfile, evidence_set: evidenceWith("effective") }).reason_codes,
    ["SOURCE_AMBIGUOUS"],
  );

  const impossibleDate = structuredClone(baseProfile);
  impossibleDate.evaluation_time = "2026-02-30T12:00:00Z";
  assert.equal(validateProfile(impossibleDate), false);
  assert.deepEqual(
    evaluateCase({ case_id: "schema-impossible-date", profile: impossibleDate, evidence_set: evidenceWith("effective") }).reason_codes,
    ["PROFILE_INVALID"],
  );

  for (const unsafeValue of [9_007_199_254_740_992, 0.1]) {
    const unsafeEvidence = evidenceWith("effective");
    unsafeEvidence.observations[0].data.status = unsafeValue;
    assert.equal(validateEvidence(unsafeEvidence), false, String(unsafeValue));
  }
});

test("strict JSON rejects duplicate members at every evaluator envelope level", () => {
  for (const [name, source] of [
    ["case", '{"case_id":"first","case_id":"second","profile":{},"evidence_set":{}}'],
    ["profile", '{"case_id":"x","profile":{"profile_version":"a","profile_version":"b"},"evidence_set":{}}'],
    ["source", '{"profile":{"sources":[{"source_id":"a","source_id":"b"}]}}'],
    ["predicate", '{"profile":{"predicates":[{"path":"/a","path":"/b"}]}}'],
    ["observation", '{"evidence_set":{"observations":[{"availability":"AVAILABLE","availability":"UNAVAILABLE"}]}}'],
  ]) {
    assert.throws(
      () => parseJsonStrict(source),
      (error) => error?.code === "DUPLICATE_MEMBER",
      name,
    );
  }

  withTempDirectory((directory) => {
    const path = join(directory, "duplicate.json");
    writeFileSync(path, '{"case_id":"first","case_id":"second","profile":{},"evidence_set":{}}');
    const report = evaluateFile(path);
    assert.equal(report.verdict, "INDETERMINATE");
    assert.deepEqual(report.reason_codes, ["INPUT_DUPLICATE_MEMBER"]);
    assert.equal(report.case_id, "invalid-input");
  });
});

test("strict corpus loading rejects duplicate JSON members", () => {
  withTempDirectory((directory) => {
    const path = join(directory, "duplicate-corpus.json");
    writeFileSync(path, '{"corpus_version":"first","corpus_version":"second","base_case":{},"vectors":[]}');
    assert.throws(
      () => loadCorpus(path),
      (error) => error?.code === "DUPLICATE_MEMBER",
    );
  });
});

test("bounded inputs abstain deterministically instead of exhausting the evaluator", () => {
  const oversized = structuredClone(baseProfile);
  oversized.profile_id = "x".repeat(LIMITS.max_string_length + 1);
  const oversizedReport = evaluateCase({ case_id: "oversized", profile: oversized, evidence_set: evidenceWith("effective") });
  assert.equal(oversizedReport.verdict, "INDETERMINATE");
  assert.deepEqual(oversizedReport.reason_codes, ["INPUT_LIMIT_EXCEEDED"]);

  let tooDeep = "leaf";
  for (let depth = 0; depth <= LIMITS.max_depth; depth += 1) tooDeep = { nested: tooDeep };
  const deepReport = evaluateCase(tooDeep);
  assert.equal(deepReport.verdict, "INDETERMINATE");
  assert.deepEqual(deepReport.reason_codes, ["INPUT_LIMIT_EXCEEDED"]);

  withTempDirectory((directory) => {
    const path = join(directory, "oversized.json");
    writeFileSync(path, `{"padding":"${"x".repeat(LIMITS.max_input_bytes)}"}`);
    const report = evaluateFile(path);
    assert.equal(report.verdict, "INDETERMINATE");
    assert.deepEqual(report.reason_codes, ["INPUT_LIMIT_EXCEEDED"]);
  });
});

test("accessor-backed inputs are rejected without invoking an accessor", () => {
  const hostile = {};
  let reads = 0;
  Object.defineProperty(hostile, "profile", {
    enumerable: true,
    get() {
      reads += 1;
      return reads % 2 === 0 ? structuredClone(baseProfile) : { profile_version: "substituted" };
    },
  });
  const first = evaluateCase(hostile);
  const second = evaluateCase(hostile);
  assert.deepEqual(first, second);
  assert.equal(reads, 0);
  assert.equal(first.verdict, "INDETERMINATE");
  assert.deepEqual(first.reason_codes, ["CASE_INVALID"]);
  assert.deepEqual(first.validation_errors, ["input:accessor-property"]);
});

test("proxy and non-plain programmatic inputs are rejected without reading values", () => {
  let reads = 0;
  const proxy = new Proxy({}, {
    get() {
      reads += 1;
      return structuredClone(baseProfile);
    },
  });
  const proxyReport = evaluateCase(proxy);
  assert.equal(reads, 0);
  assert.deepEqual(proxyReport.reason_codes, ["CASE_INVALID"]);
  assert.deepEqual(proxyReport.validation_errors, ["input:proxy-object"]);

  const classInstance = new (class CaseEnvelope {})();
  const classReport = evaluateCase(classInstance);
  assert.deepEqual(classReport.reason_codes, ["CASE_INVALID"]);
  assert.deepEqual(classReport.validation_errors, ["input:non-plain-object"]);
});

test("malformed JSON produces a deterministic INDETERMINATE report without a crash", () => {
  const command = [join(here, "evaluate.mjs"), join(here, "vectors", "malformed.json"), "--json"];
  const first = spawnSync(process.execPath, command, { encoding: "utf8" });
  const second = spawnSync(process.execPath, command, { encoding: "utf8" });
  assert.equal(first.status, 1);
  assert.equal(second.status, 1);
  assert.equal(first.stderr, "");
  assert.equal(first.stdout, second.stdout);
  const report = JSON.parse(first.stdout);
  assert.equal(report.verdict, "INDETERMINATE");
  assert.deepEqual(report.reason_codes, ["INPUT_MALFORMED"]);
});

test("malformed and unreadable reports are path-independent across working directories", () => {
  const script = join(here, "evaluate.mjs");
  const first = spawnSync(process.execPath, [script, "vectors/malformed.json", "--json"], {
    cwd: here,
    encoding: "utf8",
  });
  const second = spawnSync(process.execPath, [script, "malformed.json", "--json"], {
    cwd: join(here, "vectors"),
    encoding: "utf8",
  });
  assert.equal(first.status, 1);
  assert.equal(second.status, 1);
  assert.equal(first.stdout, second.stdout);
  assert.ok(!first.stdout.includes("malformed.json"));

  const unreadableFirst = spawnSync(process.execPath, [script, "missing-a.json", "--json"], {
    cwd: here,
    encoding: "utf8",
  });
  const unreadableSecond = spawnSync(process.execPath, [script, "missing-b.json", "--json"], {
    cwd: join(here, "vectors"),
    encoding: "utf8",
  });
  assert.equal(unreadableFirst.stdout, unreadableSecond.stdout);
  assert.ok(!unreadableFirst.stdout.includes("missing-"));
});
