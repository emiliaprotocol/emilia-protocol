// SPDX-License-Identifier: Apache-2.0
//
// Authority-claim guard.
//
//   node scripts/check-authority-claims.mjs
//
// EMILIA's public surfaces must never claim it ENFORCES scoped human authority
// unless the machinery that makes the claim true is present AND intact:
//   1. the admissibility registry carries the scoped-authority claim, and
//   2. the authority conformance suite exists with real refusal cases, and
//   3. the authority tests exist.
//
// This is the authority-specific twin of scripts/check-admissibility-registry.mjs:
// it scans public documentation for authority-enforcement language and fails the
// build if any such claim is made while the backing is missing or broken. It is
// the mechanized form of "no public claim without code, negative test, and a
// pinned-acceptance rule behind it" — applied to the one claim most tempting to
// overstate: that authority is enforced.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY: string = path.join(ROOT, 'admissibility', 'registry.json');
const VECTOR: string = path.join(ROOT, 'conformance', 'vectors', 'authority.v1.json');
const TEST: string = path.join(ROOT, 'tests', 'authority-registry.test.ts');
const CLAIM_ID: string = 'scoped-human-authority-valid-at-authorization';

// Phrases that assert authority is actually ENFORCED / scoped. Matched
// case-insensitively as whole phrases. Deliberately narrow: these are the
// specific overclaims the registry entry backs, not any mention of "authority".
const CLAIM_PHRASES: string[] = [
  'authority enforced',
  'authority is enforced',
  'enforces authority',
  'enforces scoped authority',
  'scoped authority',
  'scoped human authority',
  'within limit',
  'within their limit',
  'within authority',
  'authorized approver',
  'had authority to approve',
  'authority to approve this exact action',
];

// Public surfaces to scan. Documentation and the repo-root README are the
// customer-facing claim surfaces; the spec files intentionally use the phrases
// and are backed, which is exactly what this guard confirms is allowed.
const SCAN_DIRS: string[] = ['docs', 'content'];
const SCAN_FILES: string[] = ['README.md'];
const SCAN_EXT: Set<string> = new Set(['.md', '.mdx', '.html', '.txt']);

// The authority spec/doc files legitimately define the claim; the guard's job is
// to confirm backing exists, and it does. We do NOT exempt them — a present,
// intact backing is what makes their language allowed.

function walk(dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p: string = path.join(dir, e.name);
    if (e.isDirectory()) {
      // Skip private/gitignored strategy trees — they are not public surfaces.
      if (e.name === 'strategy-private' || e.name === 'ip' || e.name === 'node_modules') continue;
      walk(p, out);
    } else if (SCAN_EXT.has(path.extname(e.name))) {
      out.push(p);
    }
  }
}

function backingStatus(): { ok: boolean; problems: string[]; refusals: number } {
  const problems: string[] = [];

  // 1. Registry claim present.
  let claimPresent: boolean = false;
  try {
    const reg: Record<string, any> = JSON.parse(fs.readFileSync(REGISTRY, 'utf8')) as Record<string, any>;
    claimPresent = Array.isArray(reg.claims) && reg.claims.some((c: any) => c.claim_id === CLAIM_ID);
  } catch (e) {
    problems.push(`admissibility registry unreadable: ${(e as any).message}`);
  }
  if (!claimPresent) problems.push(`admissibility registry is missing the '${CLAIM_ID}' claim`);

  // 2. Conformance suite exists with real refusal cases.
  let refusals: number = 0;
  try {
    const suite: Record<string, any> = JSON.parse(fs.readFileSync(VECTOR, 'utf8')) as Record<string, any>;
    refusals = (Array.isArray(suite.vectors) ? suite.vectors : []).filter((v: any) => v?.expect?.valid === false).length;
  } catch (e) {
    problems.push(`authority conformance suite unreadable: ${(e as any).message}`);
  }
  if (refusals === 0) problems.push('conformance/vectors/authority.v1.json has no refusal case (expect.valid === false)');

  // 3. Tests exist.
  if (!fs.existsSync(TEST)) problems.push('tests/authority-registry.test.ts is missing');

  return { ok: problems.length === 0, problems, refusals };
}

function scanClaims(): Array<{ file: string; phrase: string }> {
  const files: string[] = [...SCAN_FILES.map((f) => path.join(ROOT, f))];
  for (const d of SCAN_DIRS) walk(path.join(ROOT, d), files);
  const hits: Array<{ file: string; phrase: string }> = [];
  for (const f of files) {
    let text: string;
    try {
      text = fs.readFileSync(f, 'utf8');
    } catch {
      continue;
    }
    const lower: string = text.toLowerCase();
    for (const phrase of CLAIM_PHRASES) {
      if (lower.includes(phrase)) {
        hits.push({ file: path.relative(ROOT, f), phrase });
      }
    }
  }
  return hits;
}

const backing: { ok: boolean; problems: string[]; refusals: number } = backingStatus();
const hits: Array<{ file: string; phrase: string }> = scanClaims();

if (hits.length > 0 && !backing.ok) {
  console.error('AUTHORITY-CLAIM GUARD: FAIL');
  console.error('Public surfaces assert enforced/scoped authority, but the backing is missing or broken:');
  for (const p of backing.problems) console.error(`  - ${p}`);
  console.error('Offending claim occurrences:');
  for (const h of hits.slice(0, 25)) console.error(`  - ${h.file}: "${h.phrase}"`);
  process.exit(1);
}

if (!backing.ok) {
  // No public claim yet, but the backing is broken — still a defect to fix
  // before any such claim can be made. Fail so the machinery is never silently
  // removed.
  console.error('AUTHORITY-CLAIM GUARD: FAIL (backing broken)');
  for (const p of backing.problems) console.error(`  - ${p}`);
  process.exit(1);
}

console.log(`AUTHORITY-CLAIM GUARD: OK (backing intact: registry claim + ${backing.refusals} refusal vectors + tests; ${hits.length} backed claim occurrence(s) in public docs)`);
