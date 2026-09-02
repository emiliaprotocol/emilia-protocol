// SPDX-License-Identifier: Apache-2.0
// The security case used to accept a named evidence test on title presence
// alone: emptying the body of a claim's named test left the file green and the
// gate reporting METADATA OK. These tests pin the static half of the fix. The
// execution half (the runner must report that exact title as executed and
// passing) lives in executePlannedTests and is exercised by --execute.
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "..");
const verifier = path.join(root, "scripts", "verify-security-case.mjs");
const loader = path.join(root, "scripts", "ts-loader", "register.mjs");
const CHILD_PROCESS_TEST_TIMEOUT_MS = 120_000;

const temporaryDirectory = fs.mkdtempSync(
  path.join(root, ".ep-security-evidence-binding-"),
);

afterAll(() => {
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

interface NamedTest {
  claimId: string;
  file: string;
  title: string;
}

const sourceCaseText = fs.readFileSync(
  path.join(root, "security", "claims.v1.json"),
  "utf8",
);

function firstNamedTest(): NamedTest {
  const sourceCase = JSON.parse(sourceCaseText);
  for (const claim of sourceCase.claims)
    for (const test of claim.tests ?? [])
      if (test?.file?.endsWith(".js") && typeof test.title === "string")
        return { claimId: claim.claim_id, file: test.file, title: test.title };
  throw new Error("no named evidence test found in security/claims.v1.json");
}

// Rewrite one claim's named test to point at a copy of the real test file so a
// mutation never touches the checked-in evidence.
function runWithRewrittenTestFile(
  named: NamedTest,
  mutate: (source: string) => string,
) {
  const copyPath = path.join(
    temporaryDirectory,
    `${crypto.randomUUID()}.test.js`,
  );
  fs.writeFileSync(
    copyPath,
    mutate(fs.readFileSync(path.join(root, named.file), "utf8")),
  );
  const sourceCase = JSON.parse(sourceCaseText);
  for (const claim of sourceCase.claims) {
    if (claim.claim_id !== named.claimId) continue;
    for (const test of claim.tests ?? [])
      if (test.file === named.file)
        test.file = path.relative(root, copyPath).split(path.sep).join("/");
  }
  const sourcePath = path.join(
    temporaryDirectory,
    `${crypto.randomUUID()}.claims.json`,
  );
  fs.writeFileSync(sourcePath, `${JSON.stringify(sourceCase, null, 2)}\n`);
  return spawnSync(
    process.execPath,
    ["--import", loader, verifier, "--source", sourcePath, "--validate-only"],
    {
      cwd: root,
      encoding: "utf8",
      timeout: CHILD_PROCESS_TEST_TIMEOUT_MS,
      killSignal: "SIGKILL",
      maxBuffer: 16 * 1024 * 1024,
    },
  );
}

function replaceBodyOf(
  source: string,
  title: string,
  replacement: string,
): string {
  const declaration = new RegExp(
    `(?:test|it)\\s*\\(\\s*(['"\`])${title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\1`,
  ).exec(source);
  if (!declaration) throw new Error(`fixture lost its title: ${title}`);
  const bodyStart = /=>\s*\{|function\b[^(){}]*\([^()]*\)\s*\{/g;
  bodyStart.lastIndex = declaration.index + declaration[0].length;
  if (!bodyStart.exec(source))
    throw new Error(`fixture has no callback body: ${title}`);
  const open = bodyStart.lastIndex - 1;
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0)
        return `${source.slice(0, open + 1)}${replacement}${source.slice(index)}`;
    }
  }
  throw new Error(`fixture body is unbalanced: ${title}`);
}

describe("security case named evidence binding", () => {
  const named = firstNamedTest();

  it(
    "accepts an unmodified named evidence test",
    () => {
      const run = runWithRewrittenTestFile(named, (source) => source);
      expect(`${run.stdout}${run.stderr}`).toMatch(/METADATA OK/);
      expect(run.status).toBe(0);
    },
    CHILD_PROCESS_TEST_TIMEOUT_MS,
  );

  it(
    "refuses a named evidence test whose body was emptied",
    () => {
      const run = runWithRewrittenTestFile(named, (source) =>
        replaceBodyOf(source, named.title, "\n"),
      );
      expect(`${run.stdout}${run.stderr}`).toMatch(/body executes nothing/);
      expect(run.status).toBe(1);
    },
    CHILD_PROCESS_TEST_TIMEOUT_MS,
  );

  it(
    "refuses a named evidence test reduced to a comment",
    () => {
      const run = runWithRewrittenTestFile(named, (source) =>
        replaceBodyOf(
          source,
          named.title,
          "\n  // proven somewhere else\n  /* nothing runs here */\n",
        ),
      );
      expect(`${run.stdout}${run.stderr}`).toMatch(/body executes nothing/);
      expect(run.status).toBe(1);
    },
    CHILD_PROCESS_TEST_TIMEOUT_MS,
  );
});
