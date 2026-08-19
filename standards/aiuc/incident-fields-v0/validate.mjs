#!/usr/bin/env node
// Zero-dependency validator for aiuc-incident-fields-v0.1 coded incidents.
//
// Validates one coded-incident JSON document against SPECIFICATION.md in this
// directory: closed code sets, required fields, no unknown fields, and the
// cross-rules stated in the specification prose (Section 7 and the evidence
// grade table). It validates coding conformance only; it does not verify the
// underlying incident facts, the truth of any cited source, or that any URL
// resolves over the network.
//
// Usage:
//   node validate.mjs <coded-incident.json> [--report]
//
// Output is a deterministic report (stable check order, sorted failure
// details, no timestamps). Exit code 0 only when every check passes.
// --report is accepted for explicitness; the report is always printed and is
// byte-stable for identical input.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const SPEC_VERSION = "aiuc-incident-fields-v0.1";

// Closed code sets, transcribed from SPECIFICATION.md Sections 3, 4, 5, 6.
export const AUTHORIZATION_STATUS = [
  "standing_authority",
  "specific_approval",
  "denied",
  "revoked",
  "outside_scope",
  "authority_absent",
  "indeterminate",
];

export const DECISION_TIMING = ["before_attempt", "after_attempt", "indeterminate"];

export const EVIDENCE_GRADE = [
  "E0_no_reviewable_evidence",
  "E1_party_attested",
  "E2_independently_correlated",
  "E3_artifact_verifiable",
];

export const EXECUTION_STATUS = [
  "proposed_only",
  "blocked",
  "effected",
  "effect_reversed",
  "indeterminate",
];

export const ACTION_CLASS = [
  "read_only",
  "additive_write",
  "modify_write",
  "destructive",
  "monetary_low",
  "monetary_high",
  "external_commit",
];

export const SOURCE_ROLE = [
  "incident_registry",
  "affected_party",
  "system_operator",
  "independent_reporting",
  "post_incident_operator_documentation",
  "other",
];

const TOP_FIELDS = [
  "spec_version",
  "incident_ref",
  "action_ref",
  "action_summary",
  "action_class",
  "authorization",
  "execution",
  "sources",
  "coding_limitations",
];
const INCIDENT_REF_FIELDS = ["scheme", "id", "url"];
const AUTH_FIELDS = ["status", "basis_summary", "decision_timing", "evidence_grade", "evidence_refs"];
const EXEC_FIELDS = ["status", "evidence_grade", "evidence_refs"];
const SOURCE_FIELDS = ["id", "url", "title", "source_role", "published_at", "accessed_at"];

export const CHECK_ORDER = [
  "json-well-formed",
  "spec-version",
  "required-fields",
  "unknown-fields",
  "field-types",
  "action-class-code",
  "authorization-status-code",
  "decision-timing-code",
  "evidence-grade-codes",
  "execution-status-code",
  "timing-cross-rule",
  "e0-requires-indeterminate",
  "basis-summary-required",
  "evidence-refs-resolve",
  "date-format",
  "url-format",
];

function newResults() {
  const m = new Map();
  for (const id of CHECK_ORDER) m.set(id, { status: "PASS", details: [] });
  return m;
}

function fail(results, id, detail) {
  const r = results.get(id);
  r.status = "FAIL";
  r.details.push(detail);
}

function skip(results, id, reason) {
  const r = results.get(id);
  if (r.status === "PASS") {
    r.status = "SKIP";
    r.details = [reason];
  }
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isCalendarDate(s) {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y, m, d] = s.split("-").map(Number);
  if (m < 1 || m > 12 || d < 1) return false;
  const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return d <= days[m - 1];
}

function isParsableUrl(s) {
  if (typeof s !== "string") return false;
  try {
    new URL(s);
    return true;
  } catch {
    return false;
  }
}

function checkUnknownKeys(results, obj, pathPrefix, allowed) {
  for (const key of Object.keys(obj).sort()) {
    if (!allowed.includes(key)) {
      fail(results, "unknown-fields", `unknown-field: ${pathPrefix}${key}`);
    }
  }
}

// parseResult: { doc } on success or { error: true } on malformed JSON.
export function parseDocument(text) {
  try {
    return { doc: JSON.parse(text) };
  } catch {
    return { error: true };
  }
}

export function validateDocument(parseResult) {
  const results = newResults();

  if (parseResult.error) {
    fail(results, "json-well-formed", "malformed-json");
    for (const id of CHECK_ORDER) {
      if (id !== "json-well-formed") skip(results, id, "input-not-parsed");
    }
    return results;
  }

  const doc = parseResult.doc;
  if (!isPlainObject(doc)) {
    fail(results, "field-types", "document-not-an-object");
    for (const id of CHECK_ORDER) {
      if (id !== "json-well-formed" && id !== "field-types") skip(results, id, "document-not-an-object");
    }
    return results;
  }

  // required-fields (SPECIFICATION.md Section 2; schema required lists)
  for (const f of TOP_FIELDS) {
    if (!(f in doc)) fail(results, "required-fields", `missing-required-field: ${f}`);
  }
  if (isPlainObject(doc.incident_ref)) {
    for (const f of INCIDENT_REF_FIELDS) {
      if (!(f in doc.incident_ref)) fail(results, "required-fields", `missing-required-field: incident_ref.${f}`);
    }
  }
  if (isPlainObject(doc.authorization)) {
    for (const f of AUTH_FIELDS) {
      if (!(f in doc.authorization)) fail(results, "required-fields", `missing-required-field: authorization.${f}`);
    }
  }
  if (isPlainObject(doc.execution)) {
    for (const f of EXEC_FIELDS) {
      if (!(f in doc.execution)) fail(results, "required-fields", `missing-required-field: execution.${f}`);
    }
  }
  if (Array.isArray(doc.sources)) {
    doc.sources.forEach((s, i) => {
      if (isPlainObject(s)) {
        for (const f of SOURCE_FIELDS) {
          if (!(f in s)) fail(results, "required-fields", `missing-required-field: sources[${i}].${f}`);
        }
      }
    });
  }

  // unknown-fields (schema: additionalProperties false at every level)
  checkUnknownKeys(results, doc, "", TOP_FIELDS);
  if (isPlainObject(doc.incident_ref)) checkUnknownKeys(results, doc.incident_ref, "incident_ref.", INCIDENT_REF_FIELDS);
  if (isPlainObject(doc.authorization)) checkUnknownKeys(results, doc.authorization, "authorization.", AUTH_FIELDS);
  if (isPlainObject(doc.execution)) checkUnknownKeys(results, doc.execution, "execution.", EXEC_FIELDS);
  if (Array.isArray(doc.sources)) {
    doc.sources.forEach((s, i) => {
      if (isPlainObject(s)) checkUnknownKeys(results, s, `sources[${i}].`, SOURCE_FIELDS);
    });
  }

  // spec-version (Section 2: fixed value for this draft)
  if ("spec_version" in doc) {
    if (doc.spec_version !== SPEC_VERSION) {
      fail(results, "spec-version", `wrong-spec-version: ${String(doc.spec_version)}`);
    }
  } else {
    skip(results, "spec-version", "field-missing");
  }

  // field-types (structural: types, non-empty strings, array cardinalities)
  const ft = (detail) => fail(results, "field-types", detail);
  if ("incident_ref" in doc && !isPlainObject(doc.incident_ref)) ft("not-an-object: incident_ref");
  if ("authorization" in doc && !isPlainObject(doc.authorization)) ft("not-an-object: authorization");
  if ("execution" in doc && !isPlainObject(doc.execution)) ft("not-an-object: execution");
  for (const f of ["action_ref", "action_summary"]) {
    if (f in doc && !isNonEmptyString(doc[f])) ft(`not-a-non-empty-string: ${f}`);
  }
  if (isPlainObject(doc.incident_ref)) {
    for (const f of INCIDENT_REF_FIELDS) {
      if (f in doc.incident_ref && !isNonEmptyString(doc.incident_ref[f])) {
        ft(`not-a-non-empty-string: incident_ref.${f}`);
      }
    }
  }
  const checkEvidenceRefs = (owner, label) => {
    if (!isPlainObject(owner) || !("evidence_refs" in owner)) return;
    const refs = owner.evidence_refs;
    if (!Array.isArray(refs)) {
      ft(`not-an-array: ${label}.evidence_refs`);
      return;
    }
    if (refs.length < 1) ft(`empty-array: ${label}.evidence_refs`);
    const seen = new Set();
    refs.forEach((v, i) => {
      if (!isNonEmptyString(v)) {
        ft(`not-a-non-empty-string: ${label}.evidence_refs[${i}]`);
        return;
      }
      if (seen.has(v)) ft(`duplicate-evidence-ref: ${label}.evidence_refs ${v}`);
      seen.add(v);
    });
  };
  checkEvidenceRefs(doc.authorization, "authorization");
  checkEvidenceRefs(doc.execution, "execution");
  if (isPlainObject(doc.authorization) && "basis_summary" in doc.authorization) {
    if (!isNonEmptyString(doc.authorization.basis_summary)) ft("not-a-non-empty-string: authorization.basis_summary");
  }
  if ("sources" in doc) {
    if (!Array.isArray(doc.sources)) {
      ft("not-an-array: sources");
    } else {
      if (doc.sources.length < 1) ft("empty-array: sources");
      doc.sources.forEach((s, i) => {
        if (!isPlainObject(s)) {
          ft(`not-an-object: sources[${i}]`);
          return;
        }
        for (const f of ["id", "url", "title", "accessed_at"]) {
          if (f in s && !isNonEmptyString(s[f])) ft(`not-a-non-empty-string: sources[${i}].${f}`);
        }
        if ("source_role" in s && !SOURCE_ROLE.includes(s.source_role)) {
          ft(`invalid-source-role: sources[${i}].source_role=${String(s.source_role)}`);
        }
        if ("published_at" in s && s.published_at !== null && typeof s.published_at !== "string") {
          ft(`not-a-string-or-null: sources[${i}].published_at`);
        }
      });
    }
  }
  if ("coding_limitations" in doc) {
    if (!Array.isArray(doc.coding_limitations)) {
      ft("not-an-array: coding_limitations");
    } else {
      if (doc.coding_limitations.length < 1) ft("empty-array: coding_limitations");
      doc.coding_limitations.forEach((v, i) => {
        if (!isNonEmptyString(v)) ft(`not-a-non-empty-string: coding_limitations[${i}]`);
      });
    }
  }

  // action-class-code (Section 4 closed set)
  if (isNonEmptyString(doc.action_class)) {
    if (!ACTION_CLASS.includes(doc.action_class)) {
      fail(results, "action-class-code", `unknown-action-class: ${doc.action_class}`);
    }
  } else if ("action_class" in doc && typeof doc.action_class === "string") {
    skip(results, "action-class-code", "field-empty");
  } else if (!("action_class" in doc) || typeof doc.action_class !== "string") {
    skip(results, "action-class-code", "field-missing-or-not-a-string");
  }

  const auth = isPlainObject(doc.authorization) ? doc.authorization : null;
  const exec = isPlainObject(doc.execution) ? doc.execution : null;

  // authorization-status-code (Section 3 closed set)
  if (auth && typeof auth.status === "string") {
    if (!AUTHORIZATION_STATUS.includes(auth.status)) {
      fail(results, "authorization-status-code", `unknown-authorization-status: ${auth.status}`);
    }
  } else {
    skip(results, "authorization-status-code", "field-missing-or-not-a-string");
  }

  // decision-timing-code (Section 3 closed set)
  if (auth && typeof auth.decision_timing === "string") {
    if (!DECISION_TIMING.includes(auth.decision_timing)) {
      fail(results, "decision-timing-code", `unknown-decision-timing: ${auth.decision_timing}`);
    }
  } else {
    skip(results, "decision-timing-code", "field-missing-or-not-a-string");
  }

  // evidence-grade-codes (Section 5 closed set, authorization and execution)
  {
    let sawAny = false;
    for (const [label, owner] of [["authorization", auth], ["execution", exec]]) {
      if (owner && typeof owner.evidence_grade === "string") {
        sawAny = true;
        if (!EVIDENCE_GRADE.includes(owner.evidence_grade)) {
          fail(results, "evidence-grade-codes", `unknown-evidence-grade: ${label}/${owner.evidence_grade}`);
        }
      }
    }
    if (!sawAny) skip(results, "evidence-grade-codes", "fields-missing-or-not-strings");
  }

  // execution-status-code (Section 6 closed set)
  if (exec && typeof exec.status === "string") {
    if (!EXECUTION_STATUS.includes(exec.status)) {
      fail(results, "execution-status-code", `unknown-execution-status: ${exec.status}`);
    }
  } else {
    skip(results, "execution-status-code", "field-missing-or-not-a-string");
  }

  const authStatusKnown = auth && AUTHORIZATION_STATUS.includes(auth.status);

  // timing-cross-rule (Section 7 rule 5: denied, revoked, specific_approval
  // require decision_timing=before_attempt)
  if (authStatusKnown && DECISION_TIMING.includes(auth.decision_timing)) {
    if (
      ["specific_approval", "denied", "revoked"].includes(auth.status) &&
      auth.decision_timing !== "before_attempt"
    ) {
      fail(
        results,
        "timing-cross-rule",
        `decision-timing-must-be-before-attempt: ${auth.status}/${auth.decision_timing}`
      );
    }
  } else {
    skip(results, "timing-cross-rule", "prerequisite-fields-invalid");
  }

  // e0-requires-indeterminate (Section 5 E0 row and Section 7 rule 4: a code
  // other than indeterminate requires at least E1_party_attested evidence)
  if (authStatusKnown && typeof auth.evidence_grade === "string" && EVIDENCE_GRADE.includes(auth.evidence_grade)) {
    if (auth.evidence_grade === "E0_no_reviewable_evidence" && auth.status !== "indeterminate") {
      fail(results, "e0-requires-indeterminate", `e0-grade-with-non-indeterminate-status: ${auth.status}`);
    }
  } else {
    skip(results, "e0-requires-indeterminate", "prerequisite-fields-invalid");
  }

  // basis-summary-required (Section 7 rule 4: a code other than indeterminate
  // must have a non-empty basis_summary; whitespace-only is treated as empty)
  if (authStatusKnown) {
    if (auth.status !== "indeterminate") {
      const basis = auth.basis_summary;
      if (typeof basis !== "string" || basis.trim().length === 0) {
        fail(results, "basis-summary-required", `missing-basis-summary-for-status: ${auth.status}`);
      }
    }
  } else {
    skip(results, "basis-summary-required", "prerequisite-fields-invalid");
  }

  // evidence-refs-resolve (Section 7 rule 3: evidence references must resolve
  // to entries in sources)
  if (Array.isArray(doc.sources)) {
    const sourceIds = new Set(
      doc.sources.filter((s) => isPlainObject(s) && isNonEmptyString(s.id)).map((s) => s.id)
    );
    for (const [label, owner] of [["authorization", auth], ["execution", exec]]) {
      if (!owner || !Array.isArray(owner.evidence_refs)) continue;
      for (const ref of owner.evidence_refs) {
        if (isNonEmptyString(ref) && !sourceIds.has(ref)) {
          fail(results, "evidence-refs-resolve", `unresolved-evidence-ref: ${label}/${ref}`);
        }
      }
    }
  } else {
    skip(results, "evidence-refs-resolve", "sources-missing-or-not-an-array");
  }

  // date-format (schema: published_at nullable date, accessed_at date)
  if (Array.isArray(doc.sources)) {
    doc.sources.forEach((s, i) => {
      if (!isPlainObject(s)) return;
      if (typeof s.published_at === "string" && !isCalendarDate(s.published_at)) {
        fail(results, "date-format", `invalid-date: sources[${i}].published_at=${s.published_at}`);
      }
      if (typeof s.accessed_at === "string" && !isCalendarDate(s.accessed_at)) {
        fail(results, "date-format", `invalid-date: sources[${i}].accessed_at=${s.accessed_at}`);
      }
    });
  } else {
    skip(results, "date-format", "sources-missing-or-not-an-array");
  }

  // url-format (syntax only; Section 7 rule 1 resolution needs a network read
  // and is out of scope for this offline validator)
  {
    let sawAny = false;
    if (isPlainObject(doc.incident_ref) && "url" in doc.incident_ref) {
      sawAny = true;
      if (!isParsableUrl(doc.incident_ref.url)) {
        fail(results, "url-format", `unparsable-url: incident_ref.url=${String(doc.incident_ref.url)}`);
      }
    }
    if (Array.isArray(doc.sources)) {
      doc.sources.forEach((s, i) => {
        if (isPlainObject(s) && "url" in s) {
          sawAny = true;
          if (!isParsableUrl(s.url)) {
            fail(results, "url-format", `unparsable-url: sources[${i}].url=${String(s.url)}`);
          }
        }
      });
    }
    if (!sawAny) skip(results, "url-format", "no-url-fields-present");
  }

  return results;
}

export function buildReport(inputLabel, results) {
  const lines = [];
  lines.push("aiuc-incident-fields-v0.1 conformance report");
  lines.push(`input: ${inputLabel}`);
  for (const id of CHECK_ORDER) {
    const r = results.get(id);
    if (r.status === "PASS") {
      lines.push(`CHECK ${id} PASS`);
    } else if (r.status === "SKIP") {
      lines.push(`CHECK ${id} SKIP ${r.details[0]}`);
    } else {
      for (const d of [...r.details].sort()) lines.push(`CHECK ${id} FAIL ${d}`);
    }
  }
  const failed = [...results.values()].filter((r) => r.status === "FAIL").length;
  const skipped = [...results.values()].filter((r) => r.status === "SKIP").length;
  lines.push(
    failed === 0 && skipped === 0
      ? "RESULT PASS"
      : `RESULT FAIL (failed-checks: ${failed}, skipped-checks: ${skipped})`
  );
  return lines.join("\n") + "\n";
}

export function validateFile(filePath) {
  let text;
  try {
    text = readFileSync(filePath, "utf8");
  } catch {
    return { report: `aiuc-incident-fields-v0.1 conformance report\ninput: ${filePath}\nCHECK file-readable FAIL unreadable-file\nRESULT FAIL (failed-checks: 1, skipped-checks: 0)\n`, ok: false };
  }
  const results = validateDocument(parseDocument(text));
  const failed = [...results.values()].some((r) => r.status !== "PASS");
  return { report: buildReport(filePath, results), ok: !failed };
}

function main(argv) {
  const args = argv.slice(2);
  const files = args.filter((a) => a !== "--report");
  const unknownFlags = files.filter((a) => a.startsWith("--"));
  if (unknownFlags.length > 0) {
    process.stderr.write(`unknown flag: ${unknownFlags.join(" ")}\n`);
    return 2;
  }
  if (files.length !== 1) {
    process.stderr.write("usage: node validate.mjs <coded-incident.json> [--report]\n");
    return 2;
  }
  const { report, ok } = validateFile(files[0]);
  process.stdout.write(report);
  return ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv));
}
