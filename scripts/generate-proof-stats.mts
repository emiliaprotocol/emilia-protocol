#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Regenerates lib/proof-stats.json from ground truth or checks it in CI.
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { constants, hostname, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const PROOF_STATS_LOCK_TIMEOUT_MS = 30 * 60 * 1000;
const PROOF_STATS_LOCK_POLL_MS = 250;
const PROOF_STATS_LOCK_VERSION = 1;
const sleepArray = new Int32Array(new SharedArrayBuffer(4));

interface ProofStatsLockOwner {
  version: number;
  token: string;
  pid: number;
  host: string;
  processIdentity: string | null;
  createdAt: string;
  choosing: boolean;
  ticket: number | null;
}

export interface ProofStatsRunLock {
  queuePath: string;
  release: () => boolean;
}

interface ProofStatsRunLockOptions {
  cwd?: string;
  timeoutMs?: number;
  pollMs?: number;
}

function processIdentity(pid: number): string | null {
  if (process.platform === "win32") return null;
  const result = spawnSync("ps", ["-o", "lstart=", "-p", String(pid)], {
    encoding: "utf8",
    maxBuffer: 64 * 1024,
    timeout: 2_000,
  });
  if (result.status !== 0 || result.error) return null;
  const started = result.stdout.trim().replace(/\s+/g, " ");
  return started || null;
}

function ownerIsLive(owner: ProofStatsLockOwner): boolean {
  if (owner.host !== hostname()) return true;
  try {
    process.kill(owner.pid, 0);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false;
    return true;
  }
  const observedIdentity = processIdentity(owner.pid);
  return !owner.processIdentity || !observedIdentity ||
    owner.processIdentity === observedIdentity;
}

function readLockOwner(participantPath: string): ProofStatsLockOwner | null {
  try {
    const parsed = JSON.parse(
      readFileSync(join(participantPath, "owner.json"), "utf8"),
    ) as Partial<ProofStatsLockOwner>;
    const token = participantPath.slice(participantPath.lastIndexOf("-") + 1);
    if (
      parsed.version !== PROOF_STATS_LOCK_VERSION ||
      parsed.token !== token ||
      !Number.isSafeInteger(parsed.pid) ||
      (parsed.pid as number) < 1 ||
      parsed.host !== hostname() ||
      (parsed.processIdentity !== null &&
        typeof parsed.processIdentity !== "string") ||
      typeof parsed.createdAt !== "string" ||
      typeof parsed.choosing !== "boolean" ||
      (parsed.ticket !== null &&
        (!Number.isSafeInteger(parsed.ticket) || (parsed.ticket as number) < 1))
    ) {
      return null;
    }
    return parsed as ProofStatsLockOwner;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    return null;
  }
}

function writeLockOwner(participantPath: string, owner: ProofStatsLockOwner): void {
  const ownerPath = join(participantPath, "owner.json");
  const temporaryPath = join(
    participantPath,
    `.owner-${randomBytes(8).toString("hex")}.tmp`,
  );
  writeFileSync(temporaryPath, `${JSON.stringify(owner)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  renameSync(temporaryPath, ownerPath);
}

function lockParticipants(queuePath: string): string[] {
  return readdirSync(queuePath)
    .filter((name) => /^participant-[a-f0-9]{32}$/.test(name))
    .sort()
    .map((name) => join(queuePath, name));
}

export function resolveProofStatsLockQueue(cwd: string = process.cwd()): string {
  const commonDirectory = spawnSync(
    "git",
    ["rev-parse", "--git-common-dir"],
    {
      cwd,
      encoding: "utf8",
      maxBuffer: 64 * 1024,
      timeout: 5_000,
    },
  );
  if (commonDirectory.error || commonDirectory.status !== 0) {
    throw new Error(
      `proof-stats run lock could not resolve the shared Git directory: ${
        commonDirectory.error?.message || commonDirectory.stderr || "unknown error"
      }`,
    );
  }
  const rawCommonDirectory = commonDirectory.stdout.trim();
  if (!rawCommonDirectory) {
    throw new Error("proof-stats run lock resolved an empty Git common directory");
  }
  const absoluteCommonDirectory = realpathSync(resolve(cwd, rawCommonDirectory));
  const hostScope = createHash("sha256")
    .update(hostname())
    .digest("hex")
    .slice(0, 16);
  return join(
    absoluteCommonDirectory,
    "emilia-run-locks",
    hostScope,
    "proof-stats-run-v1",
  );
}

export function acquireProofStatsRunLock({
  cwd = process.cwd(),
  timeoutMs = PROOF_STATS_LOCK_TIMEOUT_MS,
  pollMs,
}: ProofStatsRunLockOptions = {}): ProofStatsRunLock {
  const effectivePollMs = pollMs ?? Math.min(
    PROOF_STATS_LOCK_POLL_MS,
    timeoutMs,
  );
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("proof-stats run lock timeout must be a positive integer");
  }
  if (
    !Number.isSafeInteger(effectivePollMs) ||
    effectivePollMs < 1 ||
    effectivePollMs > timeoutMs
  ) {
    throw new Error(
      "proof-stats run lock poll interval must be a positive integer no greater than its timeout",
    );
  }

  const queuePath = resolveProofStatsLockQueue(cwd);
  mkdirSync(queuePath, { recursive: true, mode: 0o700 });
  if (!lstatSync(queuePath).isDirectory()) {
    throw new Error("proof-stats run lock queue is not a directory");
  }
  const versionPath = join(queuePath, ".version");
  const versionStagingPath = join(
    queuePath,
    `.version-${randomBytes(16).toString("hex")}.tmp`,
  );
  writeFileSync(versionStagingPath, `${PROOF_STATS_LOCK_VERSION}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  try {
    linkSync(versionStagingPath, versionPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  } finally {
    rmSync(versionStagingPath, { force: true });
  }
  try {
    if (readFileSync(versionPath, "utf8") !== `${PROOF_STATS_LOCK_VERSION}\n`) {
      throw new Error("proof-stats run lock queue has an unsupported version");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("proof-stats run lock queue lost its version marker");
    }
    throw error;
  }

  const token = randomBytes(16).toString("hex");
  const participantPath = join(queuePath, `participant-${token}`);
  const stagingPath = join(queuePath, `.staging-${token}`);
  const owner: ProofStatsLockOwner = {
    version: PROOF_STATS_LOCK_VERSION,
    token,
    pid: process.pid,
    host: hostname(),
    processIdentity: processIdentity(process.pid),
    createdAt: new Date().toISOString(),
    choosing: true,
    ticket: null,
  };
  mkdirSync(stagingPath, { mode: 0o700 });
  try {
    writeLockOwner(stagingPath, owner);
    renameSync(stagingPath, participantPath);
  } catch (error) {
    rmSync(stagingPath, { recursive: true, force: true });
    throw error;
  }

  let released = false;
  const releaseEntry = (): boolean => {
    if (released) return false;
    released = true;
    process.removeListener("exit", onExit);
    for (const [signal, listener] of signalListeners) {
      process.removeListener(signal, listener);
    }
    const recorded = readLockOwner(participantPath);
    if (recorded?.token === token) {
      rmSync(participantPath, { recursive: true, force: true });
    }
    return true;
  };
  const onExit = (): void => {
    const recorded = readLockOwner(participantPath);
    if (recorded?.token === token) {
      rmSync(participantPath, { recursive: true, force: true });
    }
  };
  const signalListeners = new Map<NodeJS.Signals, () => void>();
  for (const signal of ["SIGHUP", "SIGINT", "SIGTERM"] as NodeJS.Signals[]) {
    const listener = (): void => {
      releaseEntry();
      process.exit(128 + constants.signals[signal]);
    };
    signalListeners.set(signal, listener);
    process.once(signal, listener);
  }
  process.once("exit", onExit);

  const describeOwner = (
    contender: ProofStatsLockOwner | null,
    participant: string,
  ): string => contender
    ? `live owner pid=${contender.pid} ticket=${contender.ticket ?? "choosing"} created_at=${contender.createdAt}`
    : `unreadable owner entry ${participant.slice(participant.lastIndexOf("/") + 1)}`;

  try {
    let maxTicket = 0;
    for (const participant of lockParticipants(queuePath)) {
      if (participant === participantPath) continue;
      const contender = readLockOwner(participant);
      if (contender && !ownerIsLive(contender)) {
        rmSync(participant, { recursive: true, force: true });
        continue;
      }
      if (contender?.ticket) maxTicket = Math.max(maxTicket, contender.ticket);
    }
    if (!Number.isSafeInteger(maxTicket + 1)) {
      throw new Error("proof-stats run lock ticket space is exhausted");
    }
    owner.choosing = false;
    owner.ticket = maxTicket + 1;
    writeLockOwner(participantPath, owner);

    let blocker = "another owner";
    let blockedSince: bigint | null = null;
    while (true) {
      blocker = "another owner";
      let blocked = false;
      for (const participant of lockParticipants(queuePath)) {
        if (participant === participantPath) continue;
        const contender = readLockOwner(participant);
        if (contender && !ownerIsLive(contender)) {
          rmSync(participant, { recursive: true, force: true });
          continue;
        }
        if (!contender) {
          blocked = true;
          blocker = describeOwner(null, participant);
          break;
        }
        if (
          contender.choosing ||
          contender.ticket === null ||
          contender.ticket < owner.ticket ||
          (contender.ticket === owner.ticket && contender.token < owner.token)
        ) {
          blocked = true;
          blocker = describeOwner(contender, participant);
          break;
        }
      }
      if (!blocked) {
        return { queuePath, release: releaseEntry };
      }
      if (blockedSince === null) blockedSince = process.hrtime.bigint();
      const elapsedBlockedMs = Number(
        (process.hrtime.bigint() - blockedSince) / 1_000_000n,
      );
      const remaining = timeoutMs - elapsedBlockedMs;
      if (remaining <= 0) break;
      Atomics.wait(sleepArray, 0, 0, Math.min(effectivePollMs, remaining));
    }
    throw new Error(
      `proof-stats run lock timed out after ${timeoutMs}ms; ${blocker}`,
    );
  } catch (error) {
    releaseEntry();
    throw error;
  }
}

export function securityCaseExecutionArgs(check: boolean): string[] {
  return [
    "--import",
    "./scripts/ts-loader/register.mjs",
    "scripts/verify-security-case.mjs",
    "--execute",
    // The writer resolves the case from this same live execution before using
    // it for counts. Check mode never rewrites evidence to make a check pass.
    ...(!check ? ["--emit", "security/security-case.json"] : []),
  ];
}

export function proofStatsTestArgs(reportPath: string, coverage = false): string[] {
  return [
    'vitest', 'run', '--silent',
    // Keep the complete inventory and existing integration budgets in both modes.
    '--maxWorkers=4', '--testTimeout=60000', '--hookTimeout=60000',
    '--reporter=json', `--outputFile=${reportPath}`,
    ...(coverage ? ['--coverage'] : []),
  ];
}

export interface ProofStats {
  generatedAt: string;
  tests: Record<string, any>;
  tla: Record<string, any>;
  formalScenarioConformance: Record<string, any>;
  formalEvidenceCoverage: Record<string, any>;
  alloy: Record<string, any>;
  tamarin: Record<string, any>;
  securityCase: Record<string, any>;
  conformance: Record<string, any>;
  externalImplementation: Record<string, any>;
  redTeamCases: number;
}

export type SourceProofStats = Omit<ProofStats, 'generatedAt' | 'tests'>;

/**
 * Deny by default: the only lib/proof-stats.json fields whose drift the
 * volatile-evidence policy (scripts/ci/volatile-evidence.mjs) may treat as lag
 * instead of failure. They are the measured test counts, which change with
 * almost every merge and which main refreshes after merge
 * (.github/workflows/volatile-evidence-refresh.yml). Every other field is
 * derived from the security case and the formal, conformance, external and
 * red-team evidence, and drift in any of them fails in every mode.
 * volatile-evidence.mjs keeps the same list; a node test pins the two.
 */
export const ADVISORY_PROOF_STATS_FIELDS: readonly string[] = Object.freeze([
  "tests.files",
  "tests.total",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** True for a canonical ISO-8601 UTC instant, as Date#toISOString writes it. */
export function isCanonicalInstant(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

/**
 * The dotted paths of the leaves that differ between a measured and a
 * recorded proof-stats object, sorted. Objects are compared field by field,
 * arrays and scalars as a whole. The top-level `generatedAt` is never
 * compared: it records when the test counts were measured (see
 * stableGeneratedAt).
 */
export function proofStatsDriftFields(
  measured: unknown,
  recorded: unknown,
  prefix: string = "",
): string[] {
  if (!isPlainObject(measured) || !isPlainObject(recorded)) {
    return isDeepStrictEqual(measured, recorded) ? [] : [prefix || "(root)"];
  }
  const fields: string[] = [];
  for (const key of new Set([...Object.keys(measured), ...Object.keys(recorded)])) {
    if (!prefix && key === "generatedAt") continue;
    const path = prefix ? `${prefix}.${key}` : key;
    const left = measured[key];
    const right = recorded[key];
    if (isPlainObject(left) && isPlainObject(right)) {
      fields.push(...proofStatsDriftFields(left, right, path));
    } else if (!isDeepStrictEqual(left, right)) {
      fields.push(path);
    }
  }
  return fields.sort();
}

/**
 * `generatedAt` records when the recorded test counts were measured, not each
 * execution of the writer. A refresh commit itself triggers another main
 * refresh, and writing a new clock value for otherwise identical evidence
 * would create an endless series of refresh pull requests. So the previous
 * timestamp is kept whenever the measured `tests` block equals the recorded
 * one, which covers every regeneration that changes nothing (the byte-
 * identity case) and also a pull request that refreshes only derived fields
 * (`--bootstrap-derived-evidence`): the counts, and the time they were
 * measured, stay main's. Derived fields are never carried by this: check
 * mode compares every one of them with the sources.
 *
 * A previous timestamp that is not a canonical UTC ISO instant, or is later
 * than this run's, is not carried forward as provenance.
 */
export function stableGeneratedAt(
  measured: ProofStats,
  previous: unknown,
): string {
  if (!isPlainObject(previous)) return measured.generatedAt;
  const earlier = previous.generatedAt;
  if (!isCanonicalInstant(earlier) || Date.parse(earlier) > Date.parse(measured.generatedAt)) {
    return measured.generatedAt;
  }
  return isDeepStrictEqual(previous.tests, measured.tests) ? earlier : measured.generatedAt;
}

/**
 * The text the writer stores in lib/proof-stats.json, with `generatedAt`
 * from stableGeneratedAt. A regeneration that changes nothing therefore
 * writes the same bytes: main's volatile-evidence refresh then finds main
 * current (publish skipped) and records the observation its grace clock
 * starts from.
 */
export function proofStatsFileText(stats: ProofStats, previousText?: string): string {
  let previous: unknown = null;
  if (previousText !== undefined) {
    try {
      previous = JSON.parse(previousText);
    } catch {
      previous = null;
    }
  }
  const generatedAt: string = stableGeneratedAt(stats, previous);
  return `${JSON.stringify({ ...stats, generatedAt }, null, 2)}\n`;
}

function generateProofStats(): void {
const check: boolean = process.argv.includes("--check");
const coverage = process.argv.includes('--coverage');
const bootstrapDerivedEvidence: boolean = process.argv.includes(
  "--bootstrap-derived-evidence",
);
const securityCasePreverified: boolean = process.argv.includes(
  "--security-case-preverified",
);
const driftReportIndex: number = process.argv.indexOf("--drift-report");
const driftReport: string | undefined =
  driftReportIndex === -1 ? undefined : process.argv[driftReportIndex + 1];
if (driftReportIndex !== -1) {
  if (!check) throw new Error("drift-report is check-mode only");
  if (!driftReport || driftReport.startsWith("--")) {
    throw new Error("drift-report requires a file path");
  }
}
if (check && bootstrapDerivedEvidence) {
  throw new Error("bootstrap-derived-evidence cannot be used in check mode");
}
if (coverage && bootstrapDerivedEvidence) {
  throw new Error('coverage requires a complete measured test run, not bootstrap mode');
}
if (securityCasePreverified) {
  if (!check) {
    throw new Error("security-case-preverified is check-mode only");
  }
  if (process.env.GITHUB_ACTIONS !== "true") {
    throw new Error("security-case-preverified requires GitHub Actions");
  }
  const expectedSha: string = process.env.SECURITY_CASE_PREVERIFIED_SHA || "";
  const head = spawnSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" });
  if (head.error) throw head.error;
  if (head.status !== 0 || !/^[0-9a-f]{40}$/.test(expectedSha)
      || head.stdout.trim() !== expectedSha
      || process.env.GITHUB_SHA !== expectedSha) {
    throw new Error("security-case-preverified SHA does not match the checkout");
  }
}

let j: Record<string, any>;
if (bootstrapDerivedEvidence) {
  // Refreshes every derived field (it still re-executes and re-emits the
  // security case) while keeping the recorded test counts, and with them the
  // recorded generatedAt (stableGeneratedAt). Pull requests and the evidence
  // autopilot use it when a change alters a derived field: the derived fields
  // must be exact, and the test counts stay main's, which the volatile
  // evidence refresh measures after merge. It is also the bootstrap for a new
  // claim, whose tests stay red until a ground-truth-derived candidate
  // exists. Check mode never uses it.
  const recorded = JSON.parse(
    readFileSync("lib/proof-stats.json", "utf8"),
  ) as Record<string, any>;
  if (
    !Number.isSafeInteger(recorded.tests?.total) ||
    !Number.isSafeInteger(recorded.tests?.files) ||
    recorded.tests.total < 1 ||
    recorded.tests.files < 1
  ) {
    throw new Error("recorded proof stats do not contain a reusable test measurement");
  }
  j = {
    numTotalTests: recorded.tests.total,
    testResults: Array.from({ length: recorded.tests.files }, () => ({})),
  };
} else {
  const reportDir: string = mkdtempSync(join(tmpdir(), "ep-proof-stats-"));
  const reportPath: string = join(reportDir, "vitest.json");
  const execution = spawnSync(
    "npx",
    proofStatsTestArgs(reportPath, coverage),
    {
      encoding: "utf8",
      maxBuffer: 1e9,
    },
  );
  if (execution.error) throw execution.error;
  if (!existsSync(reportPath)) {
    throw new Error(
      `Vitest did not write its JSON report:\n${execution.stderr || execution.stdout}`,
    );
  }
  j = JSON.parse(readFileSync(reportPath, "utf8")) as Record<string, any>;
  rmSync(reportDir, { recursive: true, force: true });
  if (execution.status !== 0) {
    console.error("PROOF STATS: FAIL — the measured test run did not pass");
    for (const result of (j.testResults as any[])
      .filter((item: any) => item.status === "failed")
      .slice(0, 20)) {
      console.error(result.name);
      for (const assertion of (result.assertionResults as any[])
        .filter((item: any) => item.status === "failed")
        .slice(0, 10)) {
        console.error(`  ${assertion.fullName}`);
        for (const message of assertion.failureMessages.slice(0, 2))
          console.error(`  ${message.split("\n")[0]}`);
      }
    }
    process.exit(1);
  }
}
if (!securityCasePreverified) {
  const liveSecurityCase = spawnSync(
    process.execPath,
    securityCaseExecutionArgs(check),
    {
      encoding: "utf8",
      maxBuffer: 1e9,
    },
  );
  if (liveSecurityCase.error) throw liveSecurityCase.error;
  if (liveSecurityCase.status !== 0) {
    throw new Error(
      `The live machine-verifiable security case failed:\n${
        liveSecurityCase.stderr || liveSecurityCase.stdout
      }`,
    );
  }
}
const stats: ProofStats = {
  generatedAt: new Date().toISOString(),
  tests: {
    total: j.numTotalTests,
    files: j.testResults.length,
    policy:
      "all platform-applicable cases must pass; platform-specific cases may skip",
  },
  ...deriveSourceProofStats(),
};

if (check) {
  const current: unknown = JSON.parse(
    readFileSync("lib/proof-stats.json", "utf8"),
  );
  const measured: Record<string, unknown> = { ...stats };
  const recorded: Record<string, unknown> = isPlainObject(current) ? { ...current } : {};
  delete measured.generatedAt;
  delete recorded.generatedAt;
  const matches = isPlainObject(current) && isDeepStrictEqual(measured, recorded);
  const fields: string[] = isPlainObject(current)
    ? proofStatsDriftFields(measured, recorded)
    : ["(root)"];
  if (!matches && fields.length === 0) fields.push("(root)");
  // Deny by default: anything outside the measured test counts.
  const denied: string[] = fields.filter(
    (field) => !ADVISORY_PROOF_STATS_FIELDS.includes(field),
  );
  if (driftReport) {
    // Every check above this point (a passing measured suite, the security
    // case, Tamarin binding, scenario evidence, claim taxonomy) has already
    // thrown or exited on failure. Drift in the measured test counts is
    // recorded for the volatile-evidence policy (scripts/ci/volatile-evidence.mjs)
    // and not failed here; drift in any other field still fails below.
    writeFileSync(driftReport, `${JSON.stringify({
      "@version": "EP-VOLATILE-EVIDENCE-DRIFT-v1",
      writer: "sync:proof-stats",
      current: matches,
      stale: matches ? [] : ["lib/proof-stats.json"],
      fields,
    }, null, 2)}\n`);
  }
  if (!matches) {
    const lagOnly: boolean = Boolean(driftReport) && denied.length === 0;
    console.error(
      lagOnly
        ? `PROOF STATS: DRIFT — only the measured test counts differ (${fields.join(", ")}); reported, not failed, because main refreshes them after merge`
        : driftReport
          ? `PROOF STATS: FAIL — lib/proof-stats.json fields other than the measured test counts do not match the sources: ${denied.join(", ")}`
          : "PROOF STATS: FAIL — lib/proof-stats.json does not match the executed suite",
    );
    console.error(JSON.stringify({ recorded, measured }, null, 2));
    if (!lagOnly) {
      console.error(
        driftReport
          ? "\nFix: commit your change, run `npm run sync:proof-stats -- --bootstrap-derived-evidence` (refreshes every derived field and keeps main's test counts), then `npm run sync:llm-context`, and commit the results."
          : "\nFix: run `npm run sync:proof-stats` and commit lib/proof-stats.json.",
      );
      console.error(
        "(Docs state the count as a floor, so no doc edits are needed — only the generated files.)",
      );
      process.exitCode = 1;
    }
  } else {
    console.log(
      `PROOF STATS: PASS (${stats.tests.total} test cases, ${stats.tests.files} files; ${stats.tamarin.verifiedObligations} verified Tamarin lemmas; ${stats.securityCase.claims} executable security claims; ${stats.conformance.vectors} conformance vectors; ${stats.externalImplementation.hostilityCases} external hostility cases)`,
    );
  }
} else {
  const previousText: string | undefined = existsSync("lib/proof-stats.json")
    ? readFileSync("lib/proof-stats.json", "utf8")
    : undefined;
  const text: string = proofStatsFileText(stats, previousText);
  writeFileSync("lib/proof-stats.json", text);
  console.log(JSON.parse(text));
}
}

/**
 * Every lib/proof-stats.json field that is derived from checked-in sources:
 * everything except `generatedAt` and the measured `tests` block. It reads
 * files only (no test run, no security-case execution) and throws on the same
 * inconsistent-evidence conditions as the writer, so tests and other checks
 * can compare their claims with the sources instead of with a proof-stats file
 * that main's volatile-evidence refresh may not have caught up with yet.
 */
export function deriveSourceProofStats(root: string = process.cwd()): SourceProofStats {
const sourcePath = (relative: string): string => join(root, relative);
const cfg: string = readFileSync(sourcePath("formal/ep_handshake.cfg"), "utf8");
const composedLifecycleCfg: string = readFileSync(
  sourcePath("formal/ep_composed_trust_lifecycle.cfg"),
  "utf8",
);
const als: string = readFileSync(sourcePath("formal/ep_relations.als"), "utf8");
const fedAls: string = readFileSync(sourcePath("formal/ep_federation.als"), "utf8");
const quorumAls: string = readFileSync(sourcePath("formal/ep_quorum.als"), "utf8");
const delegationAls: string = readFileSync(sourcePath("formal/ep_delegation.als"), "utf8");
const redTeam: string = readFileSync(
  sourcePath("docs/conformance/RED_TEAM_CASES.md"),
  "utf8",
);
const tamarinSummary: string = readFileSync(
  sourcePath("formal/tamarin/results/ep_reliance_composed.summary.txt"),
  "utf8",
);
const conformance: Record<string, any> = JSON.parse(
  readFileSync(sourcePath("conformance/conformance-manifest.json"), "utf8"),
);
const external: Record<string, any> = JSON.parse(
  readFileSync(sourcePath("conformance/external/rust-cleanroom-jdieselny.v1.json"), "utf8"),
);
const securityCase: Record<string, any> = JSON.parse(
  readFileSync(sourcePath("security/security-case.json"), "utf8"),
);
const claimSource: Record<string, any> = JSON.parse(
  readFileSync(sourcePath("security/claims.v1.json"), "utf8"),
);
const scenarioConformanceBytes: Buffer = readFileSync(
  sourcePath("formal/results/formal-runtime-scenario-conformance.v2.json"),
);
const scenarioConformance: Record<string, any> = JSON.parse(
  scenarioConformanceBytes.toString("utf8"),
);

const tamarinVerifiedRows: RegExpMatchArray[] = [
  ...tamarinSummary.matchAll(
    /^\s{2}\S.*\((all-traces|exists-trace)\):\s+verified\b.*$/gm,
  ),
];
const tamarinVerified: number = tamarinVerifiedRows.length;
const tamarinAllTraceObligations: number = tamarinVerifiedRows.filter(
  (match) => match[1] === "all-traces",
).length;
const tamarinExistsTraceWitnesses: number = tamarinVerifiedRows.filter(
  (match) => match[1] === "exists-trace",
).length;
const tamarinCounterexamples: number = (
  tamarinSummary.match(
    /^\s{2}\S.*:\s+falsified\s+-\s+found trace\b.*$/gm,
  ) || []
).length;
const tamarinVersion: string | undefined =
  tamarinSummary.match(/^Tamarin:\s+(.+)$/m)?.[1];
const tamarinModelHashes: string[] = [
  ...tamarinSummary.matchAll(/^Model SHA-256:\s+([a-f0-9]{64})$/gm),
].map((match) => match[1]);
const tamarinRunnerHash: string | undefined =
  tamarinSummary.match(/^Runner SHA-256:\s+([a-f0-9]{64})$/m)?.[1];
const currentTamarinModelHashes = [
  "formal/tamarin/ep_reliance_composed.spthy",
  "formal/tamarin/ep_six_claim_composed.spthy",
].map((file) =>
  createHash("sha256").update(readFileSync(sourcePath(file))).digest("hex"),
);
const currentTamarinRunnerHash = createHash("sha256")
  .update(readFileSync(sourcePath("formal/tamarin/run-composed.sh")))
  .digest("hex");
if (
  !tamarinVersion ||
  tamarinModelHashes.length !== 2 ||
  !isDeepStrictEqual(tamarinModelHashes, currentTamarinModelHashes) ||
  tamarinRunnerHash !== currentTamarinRunnerHash ||
  tamarinVerified === 0 ||
  tamarinAllTraceObligations === 0 ||
  tamarinExistsTraceWitnesses === 0 ||
  tamarinCounterexamples === 0
) {
  throw new Error(
    "The composed Tamarin proof summary is incomplete or not bound to the current model and runner bytes",
  );
}
if (securityCase.execution?.status !== "passed") {
  throw new Error("The machine-verifiable security case is not passing");
}
if (
  scenarioConformance["@version"] !==
    "EP-SELECTED-SCENARIO-CONFORMANCE-EVIDENCE-v2" ||
  scenarioConformance.method !== "bounded_selected_scenario_conformance" ||
  !Array.isArray(scenarioConformance.scenarios) ||
  scenarioConformance.scenarios.length === 0 ||
  !scenarioConformance.scenarios.every(
    (scenario: any) => scenario.matched === true,
  ) ||
  scenarioConformance.summary?.paired_negative_controls < 1 ||
  !Number.isSafeInteger(
    scenarioConformance.summary?.required_model_actions,
  ) ||
  scenarioConformance.summary.required_model_actions < 1 ||
  scenarioConformance.summary.covered_model_actions !==
    scenarioConformance.summary.required_model_actions ||
  !Array.isArray(scenarioConformance.summary?.action_complete_models) ||
  scenarioConformance.summary.action_complete_models.length < 1
) {
  throw new Error(
    "The formal runtime selected-scenario conformance evidence is missing or incomplete",
  );
}
if (
  !conformance.implementations?.every(
    (item) => item.relationship === "one_team_port",
  )
) {
  throw new Error(
    "Reference verifier relationship is not uniformly one_team_port",
  );
}
if (external.conformance?.status !== "pass") {
  throw new Error(
    "The pinned external implementation does not report conformance pass",
  );
}

type FormalEvidenceCoverage =
  | "verifiedFormalObligations"
  | "boundedRuntimeTraced"
  | "boundedFormalEvidence"
  | "partialSymbolicCoverage"
  | "executableOperationalEvidence";

const FORMAL_EVIDENCE_CATEGORIES: readonly FormalEvidenceCoverage[] =
  Object.freeze([
    "verifiedFormalObligations",
    "boundedRuntimeTraced",
    "boundedFormalEvidence",
    "partialSymbolicCoverage",
    "executableOperationalEvidence",
  ]);

function classifyFormalEvidence(
  formal: Record<string, any>[],
): FormalEvidenceCoverage {
  if (
    formal.length > 0 &&
    formal.every((entry) => entry.status === "verified")
  ) {
    return "verifiedFormalObligations";
  }
  if (
    formal.some(
      (entry) =>
        entry.status === "partial" &&
        entry.method?.startsWith("bounded_") &&
        entry.scenario_coverage === "selected" &&
        Array.isArray(entry.covered_actions) &&
        entry.covered_actions.length > 0 &&
        Array.isArray(entry.covered_obligations) &&
        entry.covered_obligations.length > 0 &&
        typeof entry.scenario_evidence === "string" &&
        entry.scenario_evidence.length > 0 &&
        typeof entry.scenario_runner === "string" &&
        entry.scenario_runner.length > 0 &&
        typeof entry.conformance_evidence === "string" &&
        entry.conformance_evidence.length > 0,
    )
  ) {
    return "boundedRuntimeTraced";
  }
  if (
    formal.some(
      (entry) =>
        entry.status === "partial" &&
        [
          "bounded_tla_model_checking",
          "bounded_exhaustive_state_exploration",
        ].includes(entry.method),
    )
  ) {
    return "boundedFormalEvidence";
  }
  if (
    formal.some(
      (entry) => entry.status === "partial" || entry.status === "verified",
    )
  ) {
    return "partialSymbolicCoverage";
  }
  return "executableOperationalEvidence";
}

const formalEvidenceCoverage: Record<
  FormalEvidenceCoverage,
  { count: number; claimIds: string[] }
> = Object.fromEntries(
  FORMAL_EVIDENCE_CATEGORIES.map((category) => [
    category,
    { count: 0, claimIds: [] },
  ]),
) as unknown as Record<
  FormalEvidenceCoverage,
  { count: number; claimIds: string[] }
>;

for (const claim of claimSource.claims ?? []) {
  const category = classifyFormalEvidence(claim.formal ?? []);
  formalEvidenceCoverage[category].count += 1;
  formalEvidenceCoverage[category].claimIds.push(claim.claim_id);
}
for (const category of FORMAL_EVIDENCE_CATEGORIES) {
  formalEvidenceCoverage[category].claimIds.sort();
}
const classifiedClaimCount = FORMAL_EVIDENCE_CATEGORIES.reduce(
  (total, category) => total + formalEvidenceCoverage[category].count,
  0,
);
if (
  classifiedClaimCount !== claimSource.claims?.length ||
  classifiedClaimCount !== securityCase.claim_count
) {
  throw new Error(
    "The formal evidence taxonomy does not cover the complete security claim inventory",
  );
}
const recordedRuntimeTracedClaims =
  formalEvidenceCoverage.boundedRuntimeTraced.claimIds;
const executedRuntimeTracedClaims = [
  ...scenarioConformance.summary.claims,
].sort();
if (
  !isDeepStrictEqual(recordedRuntimeTracedClaims, executedRuntimeTracedClaims)
) {
  throw new Error(
    "Bounded runtime-traced claim metadata does not match the executed selected-scenario evidence",
  );
}

return {
  tla: {
    invariants: (cfg.match(/^INVARIANT/gm) || []).length,
    composedLifecycleInvariants: (
      composedLifecycleCfg.match(/^INVARIANT/gm) || []
    ).length,
    checker: "TLC 2.19",
  },
  formalScenarioConformance: {
    method: scenarioConformance.method,
    models: scenarioConformance.summary.models.length,
    claims: scenarioConformance.summary.claims.length,
    scenarios: scenarioConformance.summary.scenarios,
    soundScenarios: scenarioConformance.summary.sound_scenarios,
    pairedNegativeControls:
      scenarioConformance.summary.paired_negative_controls,
    requiredModelActions:
      scenarioConformance.summary.required_model_actions,
    coveredModelActions:
      scenarioConformance.summary.covered_model_actions,
    actionCompleteModels:
      scenarioConformance.summary.action_complete_models.length,
    formalMutationOperators:
      scenarioConformance.summary.formal_mutation_operators,
    evidenceSha256: createHash("sha256")
      .update(scenarioConformanceBytes)
      .digest("hex"),
    boundary:
      "selected model/runtime scenarios under explicit projection relations; not a mechanized implementation refinement proof",
  },
  formalEvidenceCoverage,
  alloy: {
    // facts: the core relational model (ep_relations). assertions: total across
    // ALL FOUR models that execute headless in CI (ep_relations + ep_federation
    // + ep_quorum + ep_delegation, via formal/AlloyCheck.java in alloy.yml). The
    // count was ep_relations+ep_federation only before ep_quorum/ep_delegation
    // were CI-gated; docs state it as a floor, so widening it needs no doc edit.
    facts: (als.match(/^fact/gm) || []).length,
    assertions:
      (als.match(/^assert/gm) || []).length +
      (fedAls.match(/^assert/gm) || []).length +
      (quorumAls.match(/^assert/gm) || []).length +
      (delegationAls.match(/^assert/gm) || []).length,
    version: "6.2.0 (CI)",
  },
  tamarin: {
    model:
      "EP-RELIANCE-COMPOSED-v2 + EP-SIX-CLAIM-COMPOSED-v1",
    models: 2,
    verifiedObligations: tamarinVerified,
    allTraceObligations: tamarinAllTraceObligations,
    existsTraceWitnesses: tamarinExistsTraceWitnesses,
    deliberatelyUnsafeCounterexamples: tamarinCounterexamples,
    version: tamarinVersion,
    modelSha256: tamarinModelHashes[0],
    focusedModelSha256: tamarinModelHashes[1],
  },
  securityCase: {
    status: securityCase.execution.status,
    claims: securityCase.claim_count,
    evidenceFiles: securityCase.evidence_file_count,
    evidenceBundleSha256: securityCase.evidence_bundle_sha256,
  },
  conformance: {
    suites: conformance.totals.suites,
    vectors: conformance.totals.vectors,
    referencePorts: conformance.totals.implementations,
    relationship: "same_team_ports",
  },
  externalImplementation: {
    language: external.implementation.language,
    vectors: external.conformance.vectors,
    hostilityCases:
      external.hostility.structured_cases + external.hostility.raw_parser_cases,
    strictCleanRoomAcceptance:
      external.construction_evidence.strict_clean_room_acceptance,
  },
  redTeamCases: (redTeam.match(/^### /gm) || []).length,
};
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const proofStatsRunLock = acquireProofStatsRunLock();
  try {
    generateProofStats();
  } finally {
    proofStatsRunLock.release();
  }
}
