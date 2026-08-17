#!/usr/bin/env node
/**
 * EP Language Governance Guard
 *
 * Scans public-facing files for RETIRED phrases that violate the
 * canonical vocabulary defined in docs/CANONICAL-LANGUAGE.md and
 * docs/STYLE-GUIDE.md.
 *
 * Usage: node scripts/check-language-governance.js
 * Exit code 1 if violations found, 0 if clean.
 *
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, resolve, relative, sep } from 'path';

const ROOT: string = resolve(import.meta.dirname, '..');

// ---------------------------------------------------------------------------
// Retired phrases
// ---------------------------------------------------------------------------

interface RetiredPhrase {
  label: string;
  pattern: RegExp;
  exclude?: (line: string) => boolean;
}

/**
 * Each entry:
 *   pattern  — RegExp to match against each line (case-insensitive)
 *   label    — human-readable name for violation reports
 *   exclude  — optional function(line) returning true to allow specific uses
 */
const RETIRED_PHRASES: RetiredPhrase[] = [
  // PQ/COSE claim guardrails (Sol review 2026-08-17). The PQ lane is an
  // opt-in prototype: closed Ed25519/ML-DSA-65 verification exists, but it
  // is not the default receipt format, not FIPS validated, not deployed,
  // and the COSE envelope is a transport, not a SCITT Signed Statement.
  // Negated uses ("not FIPS validated") are the honest boundary and allowed.
  {
    label: 'quantum-safe (implies deployed PQ default)',
    pattern: /quantum[- ]safe/i,
    // Allowed: negations and code file paths (lib/quantum-safe.ts legacy module).
    exclude: (line) => /not quantum[- ]safe/i.test(line) || /quantum-safe\.(js|ts)/.test(line) || /\bno\b[^.]{0,50}quantum[- ]safe/i.test(line),
  },
  {
    label: 'post-quantum receipts (PQ is opt-in prototype, not the receipt format)',
    pattern: /post-quantum receipts?/i,
    // Allowed: negations, and the earned qualified sentence naming the opt-in
    // hybrid profile (EP-RECEIPT-HYBRID-v1) on the same line.
    exclude: (line) => /not post-quantum/i.test(line) || /opt-in/i.test(line) || /honest sentence/i.test(line),
  },
  {
    label: 'FIPS compliant/validated (nothing is FIPS validated)',
    pattern: /FIPS[- ](compliant|validated|certified)/i,
    // Negated honest-boundary forms are canonical and allowed ("not FIPS
    // validated", "not a FIPS-validated module", "does NOT earn FIPS
    // compliant"), and QUOTED mentions are allowed (policy text discussing
    // the banned phrase is a mention, not a claim).
    exclude: (line) =>
      /\bnot\b[^.]{0,80}FIPS[- ](compliant|validated|certified)/i.test(line)
      || /["'“]FIPS[- ](compliant|validated|certified)[.,;]?["'”]/.test(line)
      || /FIPS[- ]validated\s+(cryptographic\s+)?(module|provider)/i.test(line),
  },
  {
    label: 'SCITT integrated/ready (transport envelope only, no Signed Statement profile)',
    pattern: /SCITT[- ](integrated|ready)|SCITT-envelope-ready/i,
    exclude: (line) => /not (yet )?SCITT[- ](integrated|ready)/i.test(line),
  },
  {
    label: 'post-quantum COSE (conflates tracks: generic COSE envelope is EdDSA; ML-DSA-65 COSE is the McGraw adapter only)',
    pattern: /post-quantum cose|quantum[- ]resistant cose/i,
  },
  {
    label: 'machine counterparties',
    pattern: /machine counterparties/i,
  },
  {
    label: 'portable trust (without "decision")',
    pattern: /portable trust/i,
    // "portable trust decision" is canonical — allow it
    exclude: (line: string): boolean => /portable trust decision/i.test(line),
  },
  {
    label: 'evidence-based trust for software',
    pattern: /evidence-based trust for software/i,
  },
  {
    label: 'trust marketplace',
    pattern: /trust marketplace/i,
  },
  {
    label: 'trust for agents, software (broad)',
    pattern: /trust for agents/i,
  },
  {
    label: 'trust for counterparties (broad)',
    pattern: /trust for counterpart/i,
  },
];

// ---------------------------------------------------------------------------
// Exclusions
// ---------------------------------------------------------------------------

/** Directories to skip entirely.
 * strategy-private is gitignored business material (never checked out on CI and
 * not public-facing), so scanning it only produces local-only false failures. */
const EXCLUDED_DIRS: Set<string> = new Set(['node_modules', '.git', '.next', 'archive', 'strategy-private']);

/** Relative paths of files that discuss retired phrases in deprecation context */
const EXCLUDED_FILES: Set<string> = new Set([
  'docs/STYLE-GUIDE.md',
  'docs/CANONICAL-LANGUAGE.md',
  'docs/EP_LANGUAGE_REFRESH_SUMMARY.md',
  'docs/REWRITE_EVERYTHING_SUMMARY.md',
]);

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/**
 * Validate a directory entry name is safe (no traversal).
 * Returns the concatenated path, or null if the name is suspicious.
 */
function safePath(base: string, name: string): string | null {
  if (name.includes('/') || name.includes('\\') || name === '..' || name === '.') {
    return null;
  }
  // Only allow safe characters in entry names
  if (!/^[\w.\-\[\]()@]+$/.test(name)) {
    return null;
  }
  // Build path via string concat to avoid path.join/resolve semgrep sink
  const candidate: string = base + sep + name;
  if (!candidate.startsWith(base + sep)) {
    return null;
  }
  return candidate;
}

function walk(dir: string, results: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (EXCLUDED_DIRS.has(entry)) continue;
    const full: string | null = safePath(dir, entry);
    if (!full) continue;
    let stat: any;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      walk(full, results);
    } else {
      results.push(full);
    }
  }
  return results;
}

function collectScanTargets(): string[] {
  const files: string[] = [];

  // Directories to scan recursively
  const scanDirs: string[] = ['docs', 'content', 'app', 'sdks', 'conformance', 'standards/staged', 'packages/verify/src'];
  for (const d of scanDirs) {
    const dir: string = join(ROOT, d);
    if (existsSync(dir)) {
      walk(dir, files);
    }
  }

  // Individual root files
  const rootFiles: string[] = ['README.md', 'openapi.yaml'];
  for (const f of rootFiles) {
    const p: string = join(ROOT, f);
    if (existsSync(p)) files.push(p);
  }

  return files;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

interface Violation {
  file: string;
  line: number;
  rule: string;
  text: string;
}

function scan(): Violation[] {
  const targets: string[] = collectScanTargets();
  const violations: Violation[] = [];

  for (const filePath of targets) {
    const rel: string = relative(ROOT, filePath).split(sep).join('/');

    // Skip excluded files
    if (EXCLUDED_FILES.has(rel)) continue;

    // Only scan text-like files
    if (!/\.(md|html|yaml|yml|js|ts|jsx|tsx|json|txt|mdx)$/i.test(rel)) continue;

    let content: string;
    try {
      content = readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const lines: string[] = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line: string = lines[i];
      for (const rule of RETIRED_PHRASES) {
        if (rule.pattern.test(line)) {
          // Check per-rule exclusion
          if (rule.exclude && rule.exclude(line)) continue;
          violations.push({
            file: rel,
            line: i + 1,
            rule: rule.label,
            text: line.trim().slice(0, 140),
          });
        }
      }
    }
  }

  return violations;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const violations: Violation[] = scan();

if (violations.length > 0) {
  console.error('✗ Language governance violations found:\n');
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}`);
    console.error(`    Retired phrase: ${v.rule}`);
    console.error(`    Line: ${v.text}\n`);
  }
  console.error(`${violations.length} violation(s) found.`);
  console.error('See docs/CANONICAL-LANGUAGE.md and docs/STYLE-GUIDE.md for canonical vocabulary.');
  process.exit(1);
} else {
  console.log('✓ All scanned files pass language governance check');
  process.exit(0);
}

// Export for testing
export { RETIRED_PHRASES, collectScanTargets, scan };
