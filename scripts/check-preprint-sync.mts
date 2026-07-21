// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const TRACKED_DRAFTS: readonly string[] = [
  'draft-schrock-ep-authorization-receipts',
  'draft-schrock-ep-quorum',
  'draft-schrock-ep-authorization-evidence-chain',
  'draft-schrock-ep-evidence-record',
];

const LIGATURES: Map<string, string> = new Map([
  ['\uFB00', 'ff'],
  ['\uFB01', 'fi'],
  ['\uFB02', 'fl'],
  ['\uFB03', 'ffi'],
  ['\uFB04', 'ffl'],
  ['\uFB05', 'st'],
  ['\uFB06', 'st'],
]);

const sha256 = (text: string): string => createHash('sha256').update(text).digest('hex');
const escapeRegex = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function normalizeExtractedText(text: string): string {
  return text
    .normalize('NFKC')
    .replace(/[\uFB00-\uFB06]/g, (value: string) => LIGATURES.get(value) ?? value)
    .replace(/\s+/g, ' ')
    .trim();
}

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function currentDraftRevision(standardsStatus: any, draft: string): string {
  const entry = standardsStatus.active_datatracker?.find((item: any) => item.draft === draft);
  if (!entry || !/^\d{2}$/.test(entry.revision)) {
    throw new Error(`standards/STATUS.json has no two-digit active revision for ${draft}`);
  }
  return entry.revision;
}

export function deriveEvidence({
  canonicalMarkdown,
  manifest,
  proofStats,
  proofStatus,
  standardsStatus,
  external,
}: {
  canonicalMarkdown: string;
  manifest: any;
  proofStats: any;
  proofStatus: string;
  standardsStatus: any;
  external: any;
}): any {
  const failures: string[] = [];
  const suiteCount = manifest.suites?.length;
  const vectorCount = manifest.suites?.reduce((total: number, suite: any) => total + suite.vectors, 0);

  if (suiteCount !== manifest.totals?.suites) {
    failures.push(
      `conformance manifest lists ${suiteCount} suites but totals.suites is ${manifest.totals?.suites}`,
    );
  }
  if (vectorCount !== manifest.totals?.vectors) {
    failures.push(
      `conformance manifest sums to ${vectorCount} vectors but totals.vectors is ${manifest.totals?.vectors}`,
    );
  }
  if (
    proofStats.conformance?.suites !== manifest.totals?.suites
    || proofStats.conformance?.vectors !== manifest.totals?.vectors
  ) {
    failures.push('lib/proof-stats.json conformance totals diverge from the manifest');
  }

  const tlaResult = proofStatus.match(
    /\*\*Result:\*\*\s+([\d,]+) states generated, ([\d,]+) distinct states[\s\S]*?all (\d+) invariants/,
  );
  if (!tlaResult) {
    failures.push('formal/PROOF_STATUS.md has no parseable TLA+ result');
  } else if (Number(tlaResult[3]) !== proofStats.tla?.invariants) {
    failures.push('formal/PROOF_STATUS.md TLA+ invariant count diverges from lib/proof-stats.json');
  }

  const alloyVersion = String(proofStats.alloy?.version ?? '').replace(/\s+\(.*$/, '');
  if (!alloyVersion || !proofStatus.includes(`Alloy ${alloyVersion}`)) {
    failures.push('formal/PROOF_STATUS.md does not confirm the proof-stats Alloy version');
  }
  if (!proofStatus.includes(`${proofStats.alloy?.assertions}/${proofStats.alloy?.assertions} checks held`)) {
    failures.push('formal/PROOF_STATUS.md does not confirm the proof-stats Alloy assertion count');
  }

  const externalHostilityCases = (
    external.hostility?.structured_cases + external.hostility?.raw_parser_cases
  );
  if (external.conformance?.vectors !== proofStats.externalImplementation?.vectors) {
    failures.push('external verifier vector count diverges from lib/proof-stats.json');
  }
  if (externalHostilityCases !== proofStats.externalImplementation?.hostilityCases) {
    failures.push('external hostility total diverges from lib/proof-stats.json');
  }

  const drafts = Object.fromEntries(
    TRACKED_DRAFTS.map((draft) => [draft, currentDraftRevision(standardsStatus, draft)]),
  );

  return {
    failures,
    canonicalMarkdownSha256: sha256(canonicalMarkdown),
    conformance: {
      suites: manifest.totals.suites,
      vectors: manifest.totals.vectors,
      manifestSha256: manifest.manifest_sha256,
    },
    tla: {
      states: tlaResult?.[1],
      distinctStates: tlaResult?.[2],
      invariants: proofStats.tla.invariants,
      checker: proofStats.tla.checker,
    },
    alloy: {
      assertions: proofStats.alloy.assertions,
      version: alloyVersion,
    },
    tamarin: {
      verified: proofStats.tamarin.verifiedObligations,
      falsified: proofStats.tamarin.deliberatelyUnsafeCounterexamples,
    },
    external: {
      commit: external.source.commit,
      suites: external.conformance.suites,
      vectors: external.conformance.vectors,
      structuredCases: external.hostility.structured_cases,
      rawParserCases: external.hostility.raw_parser_cases,
      hostilityCases: externalHostilityCases,
    },
    drafts,
  };
}

function requireMatch(failures: string[], text: string, regex: RegExp, message: string): void {
  if (!regex.test(text)) {
    failures.push(message);
  }
}

function auditConformanceClaims(failures: string[], text: string, label: string, evidence: any, includeHeaderClaim: boolean): void {
  const { suites, vectors } = evidence.conformance;
  const claimPatterns: RegExp[] = [
    /conformance battery \((\d+) suites, (\d+) vectors\)/g,
    /conformance battery of (\d+) suites comprising (\d+) vectors/g,
    /(\d+)-suite\s*\/\s*(\d+)-vector conformance battery/g,
  ];

  for (const pattern of claimPatterns) {
    const matches = [...text.matchAll(pattern)];
    if (matches.length === 0) {
      failures.push(`${label} is missing conformance claim pattern ${pattern.source}`);
      continue;
    }
    for (const match of matches) {
      if (Number(match[1]) !== suites || Number(match[2]) !== vectors) {
        failures.push(
          `${label} claims ${match[1]} suites / ${match[2]} vectors; evidence is ${suites} / ${vectors}`,
        );
      }
    }
  }

  const agreementClaims = [...text.matchAll(/agreement across all (\d+) current vectors/g)];
  if (agreementClaims.length === 0) {
    failures.push(`${label} is missing the same-team current-vector agreement claim`);
  }
  for (const match of agreementClaims) {
    if (Number(match[1]) !== vectors) {
      failures.push(
        `${label} claims agreement across ${match[1]} vectors; evidence is ${vectors}`,
      );
    }
  }

  if (includeHeaderClaim) {
    const headerClaims = [...text.matchAll(/conformance (\d+) suites\s*\/\s*(\d+) vectors/g)];
    if (headerClaims.length === 0) {
      failures.push(`${label} is missing the traceability-header conformance claim`);
    }
    for (const match of headerClaims) {
      if (Number(match[1]) !== suites || Number(match[2]) !== vectors) {
        failures.push(
          `${label} header claims ${match[1]} suites / ${match[2]} vectors; evidence is ${suites} / ${vectors}`,
        );
      }
    }
  }
}

function auditDraftClaims(failures: string[], text: string, label: string, drafts: Record<string, string>): void {
  for (const [draft, expectedRevision] of Object.entries(drafts)) {
    const matches = [
      ...text.matchAll(new RegExp(`${escapeRegex(draft)}-(\\d{2})`, 'g')),
    ].map((match: RegExpExecArray) => match[1]);

    if (matches.length === 0) {
      failures.push(`${label} does not cite current ${draft}-${expectedRevision}`);
      continue;
    }

    for (const revision of new Set(matches)) {
      if (revision !== expectedRevision) {
        failures.push(
          `${label} cites stale ${draft}-${revision}; evidence is ${draft}-${expectedRevision}`,
        );
      }
    }
  }
}

function auditComposedTamarinBlock(failures: string[], text: string, label: string, evidence: any): void {
  const start: number = text.indexOf('executable_composed_reliance');
  const endMarker: string = 'unchecked_registry_view_is_current';
  const end: number = text.indexOf(endMarker, start);

  if (start < 0 || end < 0) {
    failures.push(`${label} has no complete composed Tamarin result block`);
    return;
  }

  const block = text.slice(start, end + endMarker.length + 80);
  const verified = (block.match(/\): verified/g) ?? []).length;
  const falsified = (block.match(/\): falsified/g) ?? []).length;

  if (verified !== evidence.tamarin.verified || falsified !== evidence.tamarin.falsified) {
    failures.push(
      `${label} composed Tamarin block is ${verified} verified / ${falsified} falsified; evidence is ${evidence.tamarin.verified} / ${evidence.tamarin.falsified}`,
    );
  }
}

function auditFormalAndExternalClaims(failures: string[], text: string, label: string, evidence: any): void {
  const { tla, alloy, external } = evidence;

  requireMatch(
    failures,
    text,
    new RegExp(
      `${escapeRegex(tla.states)} states \\(${escapeRegex(tla.distinctStates)} distinct\\).*?${tla.invariants} invariants`,
    ),
    `${label} does not carry the current TLA+ state and invariant counts`,
  );
  requireMatch(
    failures,
    text,
    new RegExp(
      `four Alloy models \\(${escapeRegex(alloy.version)}, SAT4J\\), with ${alloy.assertions} assertions`,
    ),
    `${label} does not carry the current Alloy version and assertion count`,
  );
  requireMatch(
    failures,
    text,
    new RegExp(`pinned ${external.suites}-suite\\/${external.vectors}-vector clean-room bundle`),
    `${label} does not carry the pinned external verifier corpus`,
  );
  requireMatch(
    failures,
    text,
    new RegExp(
      `${external.structuredCases} structured attacks plus ${external.rawParserCases} raw-parser refusals`,
    ),
    `${label} does not carry the external hostility split`,
  );
  requireMatch(
    failures,
    text,
    new RegExp(`${external.hostilityCases}-case hostility campaign`),
    `${label} does not carry the aggregate external hostility count`,
  );
  if (!text.includes(external.commit)) {
    failures.push(`${label} does not carry the pinned external verifier commit`);
  }

  auditComposedTamarinBlock(failures, text, label, evidence);
}

export function auditPreprintClaims({ tex, pdfText, staging, evidence }: {
  tex: string;
  pdfText: string;
  staging: string;
  evidence: any;
}): string[] {
  const failures: string[] = [...evidence.failures];
  const source: string = normalizeExtractedText(tex);
  const pdf: string = normalizeExtractedText(pdfText);
  const stagingText: string = normalizeExtractedText(staging);

  if (!tex.includes(`% Canonical Markdown SHA-256: ${evidence.canonicalMarkdownSha256}`)) {
    failures.push('main.tex canonical Markdown SHA-256 marker is missing or stale');
  }
  if (!tex.includes(`manifest_sha256=${evidence.conformance.manifestSha256}`)) {
    failures.push('main.tex conformance manifest_sha256 marker is missing or stale');
  }

  auditConformanceClaims(failures, source, 'main.tex', evidence, true);
  auditConformanceClaims(failures, pdf, 'main.pdf', evidence, false);
  auditDraftClaims(failures, source, 'main.tex', evidence.drafts);
  auditDraftClaims(failures, pdf, 'main.pdf', evidence.drafts);
  auditFormalAndExternalClaims(failures, source, 'main.tex', evidence);
  auditFormalAndExternalClaims(failures, pdf, 'main.pdf', evidence);

  if (/\bStatus:\s*READY to post\b/i.test(stagingText)) {
    failures.push('STAGING.md still claims READY to post');
  }
  requireMatch(
    failures,
    stagingText,
    new RegExp(
      `Conformance ${evidence.conformance.suites} suites \\/ ${evidence.conformance.vectors} vectors`,
      'i',
    ),
    'STAGING.md does not carry the current conformance totals',
  );
  requireMatch(
    failures,
    stagingText,
    new RegExp(
      `${evidence.tamarin.verified} composed obligations \\+ ${evidence.tamarin.falsified} deliberate falsifications`,
    ),
    'STAGING.md does not carry the current composed Tamarin totals',
  );
  requireMatch(
    failures,
    stagingText,
    new RegExp(
      `${escapeRegex(evidence.tla.states)} states \\/ ${evidence.tla.invariants} invariants`,
    ),
    'STAGING.md does not carry the current TLA+ totals',
  );
  requireMatch(
    failures,
    stagingText,
    new RegExp(
      `${evidence.alloy.assertions} assertions across four CI-gated models.*?${escapeRegex(evidence.alloy.version)}`,
    ),
    'STAGING.md does not carry the current Alloy totals and version',
  );
  requireMatch(
    failures,
    stagingText,
    new RegExp(
      `Rust external verifier \\/ ${evidence.external.vectors} vectors \\/ ${evidence.external.hostilityCases} hostility cases`,
    ),
    'STAGING.md does not carry the current external verifier totals',
  );

  for (const command of [
    'npm run preprint:build',
    'npm run check:preprint',
    'npm run test:preprint',
  ]) {
    if (!staging.includes(command)) {
      failures.push(`STAGING.md reproducibility instructions omit "${command}"`);
    }
  }

  return failures;
}

export function extractPdfText(pdfPath: string): string {
  const result = spawnSync('pdftotext', ['-nopgbrk', pdfPath, '-'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });

  if (result.error) {
    throw new Error(`pdftotext failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`pdftotext failed (${result.status}): ${(result.stderr as string).trim()}`);
  }
  return result.stdout as string;
}

export function checkRepository(root: string): { evidence: any; failures: string[] } {
  const canonicalMarkdown = readFileSync(
    resolve(root, 'papers/authorization-receipts-preprint.md'),
    'utf8',
  );
  const evidence = deriveEvidence({
    canonicalMarkdown,
    manifest: readJson(resolve(root, 'conformance/conformance-manifest.json')),
    proofStats: readJson(resolve(root, 'lib/proof-stats.json')),
    proofStatus: readFileSync(resolve(root, 'formal/PROOF_STATUS.md'), 'utf8'),
    standardsStatus: readJson(resolve(root, 'standards/STATUS.json')),
    external: readJson(resolve(root, 'conformance/external/rust-cleanroom-jdieselny.v1.json')),
  });
  const pdfPath = resolve(root, 'papers/preprint/main.pdf');

  return {
    evidence,
    failures: auditPreprintClaims({
      tex: readFileSync(resolve(root, 'papers/preprint/main.tex'), 'utf8'),
      pdfText: extractPdfText(pdfPath),
      staging: readFileSync(resolve(root, 'papers/preprint/STAGING.md'), 'utf8'),
      evidence,
    }),
  };
}

const invokedPath: string = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  const root: string = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  try {
    const { evidence, failures } = checkRepository(root);
    if (failures.length > 0) {
      console.error('PREPRINT SYNC: FAIL');
      for (const failure of failures) console.error(`- ${failure}`);
      process.exitCode = 1;
    } else {
      console.log(
        `PREPRINT SYNC: OK (${evidence.conformance.suites} suites / ${evidence.conformance.vectors} vectors; source, PDF, staging, and evidence agree)`,
      );
    }
  } catch (error) {
    console.error(`PREPRINT SYNC: FAIL\n- ${(error as Error).message}`);
    process.exitCode = 1;
  }
}
