import {spawnSync} from "node:child_process";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {expect, test} from "vitest";

const here = dirname(fileURLToPath(import.meta.url));

test("the zero-dependency AIUC field-package self-test passes in full", () => {
  const result = spawnSync(
    process.execPath,
    ["--test", "--test-reporter=tap", join(here, "validate.selftest.mjs")],
    {cwd: here, encoding: "utf8"},
  );

  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toContain("# tests 14");
  expect(result.stdout).toContain("# pass 14");
  expect(result.stdout).toContain("# fail 0");
});
