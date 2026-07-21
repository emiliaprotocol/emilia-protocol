import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, resolve } from 'path';

// ============================================================================
// Language Guard — prevents forbidden decision vocabulary from drifting back
// into public-facing docs.
//
// Canonical decision vocabulary: allow / review / deny
// Forbidden:
//   - "pass/fail" in decision context (not test-suite context)
//   - "allow/block" anywhere
//   - Old acronym "Entity Measurement Infrastructure"
//   - "settlement" or "escrow" in EP Commit descriptions
// ============================================================================

const ROOT = resolve(import.meta.dirname, '..');

/**
 * Collect all public-facing doc files that must use canonical language.
 */
function collectPublicDocFiles() {
  const files = [];

  // Root-level docs
  const rootDocs = ['README.md', 'CONFORMANCE.md'];
  for (const f of rootDocs) {
    const p = join(ROOT, f);
    if (existsSync(p)) files.push(p);
  }

  // mcp-server docs
  const mcpDocs = ['README.md', 'SETUP.md'];
  for (const f of mcpDocs) {
    const p = join(ROOT, 'mcp-server', f);
    if (existsSync(p)) files.push(p);
  }

  // docs/*.md
  const docsDir = join(ROOT, 'docs');
  if (existsSync(docsDir)) {
    for (const f of readdirSync(docsDir)) {
      if (f.endsWith('.md')) {
        files.push(join(docsDir, f));
      }
    }
  }

  // sdks/**/README.md
  const sdksDir = join(ROOT, 'sdks');
  if (existsSync(sdksDir)) {
    for (const sdk of readdirSync(sdksDir)) {
      const readme = join(sdksDir, sdk, 'README.md');
      if (existsSync(readme)) files.push(readme);
    }
  }

  // content/*.html (public website)
  const contentDir = join(ROOT, 'content');
  if (existsSync(contentDir)) {
    for (const f of readdirSync(contentDir)) {
      if (f.endsWith('.html')) {
        files.push(join(contentDir, f));
      }
    }
  }

  return files;
}

/**
 * Scan files for a regex pattern and return all violations.
 */
function findViolations(files, pattern, label) {
  const violations = [];
  for (const filePath of files) {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        const rel = filePath.replace(ROOT + '/', '');
        violations.push(`  ${rel}:${i + 1}: ${lines[i].trim().slice(0, 120)}`);
      }
    }
  }
  return violations;
}

describe('Language Guard — canonical decision vocabulary', () => {
  const publicDocs = collectPublicDocFiles();

  it('should not use "pass/fail" as decision language in public docs', () => {
    // Match "pass/fail" but not in contexts like "test pass/fail" or conformance fixture references
    const pattern = /pass\/fail/i;
    const violations = findViolations(publicDocs, pattern, 'pass/fail');
    expect(violations, `Found forbidden "pass/fail" decision language:\n${violations.join('\n')}`).toHaveLength(0);
  });

  it('should not use "allow/block" anywhere in public docs', () => {
    const pattern = /allow\/block/i;
    const violations = findViolations(publicDocs, pattern, 'allow/block');
    expect(violations, `Found forbidden "allow/block" vocabulary:\n${violations.join('\n')}`).toHaveLength(0);
  });

  it('should not use old acronym "Entity Measurement Infrastructure" anywhere', () => {
    const pattern = /Entity Measurement Infrastructure/;
    const violations = findViolations(publicDocs, pattern, 'Entity Measurement Infrastructure');
    expect(violations, `Found deprecated acronym expansion:\n${violations.join('\n')}`).toHaveLength(0);
  });

  it('should not use "settlement" or "escrow" in EP Commit descriptions', () => {
    // Scan all public docs for "settlement" or "escrow" near commit language.
    // We allow these words ONLY when explicitly stating EP does NOT do them
    // (e.g. "EP does not settle" in PROTOCOL-STANDARD.md).
    const commitDocs = publicDocs.filter(f => {
      const content = readFileSync(f, 'utf-8');
      return /\bcommit\b/i.test(content);
    });
    const pattern = /\b(settlement|escrow)\b/i;
    const violations = [];
    for (const filePath of commitDocs) {
      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (pattern.test(line)) {
          // Allow lines that explicitly negate settlement/escrow
          // e.g. "does not hold, escrow, custody, or settle"
          const negated = /does not|do not|is not|never|not a/i.test(line);
          if (!negated) {
            const rel = filePath.replace(ROOT + '/', '');
            violations.push(`  ${rel}:${i + 1}: ${line.trim().slice(0, 120)}`);
          }
        }
      }
    }
    expect(violations, `Found "settlement/escrow" without negation in commit docs:\n${violations.join('\n')}`).toHaveLength(0);
  });
});
