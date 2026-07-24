#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  runFormalRuntimeRefinement,
  runRuntimeTraceConformance,
  type RefinementEvidence,
} from "../conformance/refinement/harness.mjs";

export { runRuntimeTraceConformance };

export async function runFormalRuntimeTraceGate(
  options: {
    tlcJar?: string | null;
    emit?: boolean;
    check?: boolean;
  } = {},
): Promise<RefinementEvidence> {
  return runFormalRuntimeRefinement(options);
}

function readArg(name: string): string | null {
  const index = process.argv.indexOf(name);
  return index >= 0 ? (process.argv[index + 1] ?? null) : null;
}

function print(evidence: RefinementEvidence): void {
  console.log(
    `FORMAL RUNTIME REFINEMENT: PASS — ${evidence.summary.traces} traces, ` +
      `${evidence.summary.unsafe_mutations_detected} unsafe mutations detected, ` +
      `${evidence.summary.claims.length} claims`,
  );
}

const invokedAsScript =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) {
  try {
    const evidence = await runFormalRuntimeTraceGate({
      tlcJar: readArg("--tlc-jar") ?? process.env.TLA2TOOLS_JAR ?? null,
      emit: process.argv.includes("--emit"),
      check:
        process.argv.includes("--check") || !process.argv.includes("--emit"),
    });
    if (process.argv.includes("--json")) {
      process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
    } else {
      print(evidence);
    }
  } catch (error) {
    console.error(
      `FORMAL RUNTIME REFINEMENT: FAIL\n${(error as Error).message}`,
    );
    process.exitCode = 1;
  }
}
