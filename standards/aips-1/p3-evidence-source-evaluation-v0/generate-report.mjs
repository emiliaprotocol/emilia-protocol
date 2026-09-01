#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Deterministic report generator for the paired local evaluation vectors.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  LOCAL_DIALECT,
  LOCAL_DIALECT_SHA256,
  PROFILE_VERSION,
  SCOPE,
  digestJson,
  evaluateCase,
  loadJsonFileStrict,
  stableReportJson,
} from "./evaluate.mjs";

const here = dirname(fileURLToPath(import.meta.url));

export function loadCorpus(filePath = join(here, "vectors", "cases.json")) {
  return loadJsonFileStrict(filePath);
}

function resolveParent(root, path) {
  if (!Array.isArray(path) || path.length === 0) throw new Error("mutation path must be non-empty");
  let parent = root;
  for (const segment of path.slice(0, -1)) {
    if (parent === null || typeof parent !== "object" || !(segment in parent)) {
      throw new Error(`mutation path does not resolve: ${path.join("/")}`);
    }
    parent = parent[segment];
  }
  return { parent, key: path.at(-1) };
}

export function materializeVector(corpus, vector) {
  const input = structuredClone(corpus.base_case);
  input.case_id = vector.case_id;
  for (const mutation of vector.mutations) {
    const { parent, key } = resolveParent(input, mutation.path);
    if (mutation.op === "SET") {
      parent[key] = structuredClone(mutation.value);
    } else if (mutation.op === "APPEND") {
      if (!Array.isArray(parent[key])) throw new Error("APPEND target must be an array");
      parent[key].push(structuredClone(mutation.value));
    } else {
      throw new Error(`unsupported mutation op: ${mutation.op}`);
    }
  }
  return input;
}

export function buildCorpusReport(corpus) {
  const cases = corpus.vectors.map((vector) => {
    const actual = evaluateCase(materializeVector(corpus, vector));
    const verdictMatches = actual.verdict === vector.expected_verdict;
    const reasonsMatch = JSON.stringify(actual.reason_codes) === JSON.stringify(vector.expected_reason_codes);
    return {
      case_id: vector.case_id,
      pair_id: vector.pair_id,
      kind: vector.kind,
      expected_verdict: vector.expected_verdict,
      actual_verdict: actual.verdict,
      expected_reason_codes: vector.expected_reason_codes,
      actual_reason_codes: actual.reason_codes,
      actual_input_digest: actual.input_digest,
      actual_profile_digest: actual.profile_digest,
      actual_evidence_set_digest: actual.evidence_set_digest,
      static_evaluable: actual.static_evaluable,
      runtime_evaluable: actual.runtime_evaluable,
      expectation_met: verdictMatches && reasonsMatch,
    };
  });
  const counts = Object.fromEntries(
    ["SATISFIED", "NOT_SATISFIED", "INDETERMINATE"].map((verdict) => [
      verdict,
      cases.filter((entry) => entry.actual_verdict === verdict).length,
    ]),
  );
  const mismatches = cases.filter((entry) => !entry.expectation_met).length;
  return {
    corpus_report_version: "aips1-p3-evidence-source-corpus-report-v0.1",
    corpus_version: corpus.corpus_version,
    corpus_digest: digestJson(corpus),
    lab_profile: PROFILE_VERSION,
    predicate_dialect: {
      dialect_id: LOCAL_DIALECT.dialect_id,
      digest: LOCAL_DIALECT_SHA256,
      authority: LOCAL_DIALECT.authority,
    },
    all_expectations_met: mismatches === 0,
    summary: {
      total: cases.length,
      controls: cases.filter((entry) => entry.kind === "CONTROL").length,
      hostile: cases.filter((entry) => entry.kind === "HOSTILE").length,
      mismatches,
      verdict_counts: counts,
    },
    cases,
    scope: SCOPE,
  };
}

export function stableCorpusReportJson(report) {
  return stableReportJson(report);
}

function main(argv) {
  const args = argv.slice(2);
  if (args.some((arg) => arg !== "--check")) {
    process.stderr.write("usage: node generate-report.mjs [--check]\n");
    return 2;
  }
  let output;
  try {
    output = stableCorpusReportJson(buildCorpusReport(loadCorpus()));
  } catch (error) {
    const classification = ["DUPLICATE_MEMBER", "INPUT_LIMIT_EXCEEDED", "MALFORMED_JSON"].includes(error?.code)
      ? error.code.toLowerCase().replaceAll("_", "-")
      : "invalid-corpus";
    process.stderr.write(`vector corpus rejected: ${classification}\n`);
    return 1;
  }
  if (args.includes("--check")) {
    let committed;
    try {
      committed = readFileSync(join(here, "report.json"), "utf8");
    } catch {
      process.stderr.write("report.json is missing\n");
      return 1;
    }
    if (output !== committed) {
      process.stderr.write("report.json is stale\n");
      return 1;
    }
  } else {
    process.stdout.write(output);
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv));
}
