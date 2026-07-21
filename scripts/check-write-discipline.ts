#!/usr/bin/env node
/**
 * EP Write Discipline Guard
 *
 * Fails CI if any route file under app/api/ imports forbidden
 * mutating functions directly instead of using protocolWrite().
 *
 * Usage: node scripts/check-write-discipline.js
 *
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { sep, relative, resolve } from 'path';

const FORBIDDEN_IMPORTS: readonly string[] = [
  'canonicalSubmitReceipt',
  'canonicalSubmitAutoReceipt',
  'canonicalBilateralConfirm',
  'canonicalFileDispute',
  'canonicalResolveDispute',
  'canonicalRespondDispute',
  'canonicalAppealDispute',
  'canonicalResolveAppeal',
  'canonicalWithdrawDispute',
  'canonicalFileReport',
  'issueCommit',
  'verifyCommit',
  'revokeCommit',
];

const ALLOWED_IMPORTS: readonly string[] = [
  '@/lib/protocol-write',
  // Read-only query services are OK
];

const projectRoot: string = process.cwd();
const apiDir: string = resolve(projectRoot, 'app', 'api');

interface Violation {
  file: string;
  line: number;
  function: string;
  text: string;
}

/**
 * Validate a directory entry name is safe (no traversal).
 * Returns the concatenated path using the platform separator,
 * or null if the name is suspicious.
 */
function safePath(base: string, name: string): string | null {
  // Reject traversal components and names containing separators
  if (name.includes('/') || name.includes('\\') || name === '..' || name === '.') {
    return null;
  }
  // Only allow alphanumeric, hyphens, underscores, dots, brackets
  if (!/^[\w.\-\[\]()]+$/.test(name)) {
    return null;
  }
  const candidate: string = base + sep + name;
  if (!candidate.startsWith(base + sep)) {
    return null;
  }
  return candidate;
}

function walkDir(dir: string, results: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const fullPath: string | null = safePath(dir, entry);
    if (!fullPath) continue;
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      walkDir(fullPath, results);
    } else if (entry === 'route.js' || entry === 'route.ts') {
      results.push(fullPath);
    }
  }
  return results;
}

let violations: Violation[] = [];

try {
  const routeFiles: string[] = walkDir(apiDir);

  for (const file of routeFiles) {
    const content: string = readFileSync(file, 'utf-8');
    const relPath: string = relative(projectRoot, file);

    // Check 1: Forbidden canonical function imports
    for (const forbidden of FORBIDDEN_IMPORTS) {
      // Check for direct imports of forbidden functions
      const importPattern: RegExp = new RegExp(`\\b${forbidden}\\b`);
      if (importPattern.test(content)) {
        // Make sure it's not just in a comment
        const lines: string[] = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line: string = lines[i].trim();
          if (line.startsWith('//') || line.startsWith('*')) continue;
          if (importPattern.test(line)) {
            violations.push({
              file: relPath,
              line: i + 1,
              function: forbidden,
              text: line.substring(0, 120),
            });
          }
        }
      }
    }

    // Check 2: Route files must use getGuardedClient, not getServiceClient.
    // getServiceClient bypasses runtime write-path enforcement on trust tables.
    const lines: string[] = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line: string = lines[i].trim();
      if (line.startsWith('//') || line.startsWith('*')) continue;
      if (/\bgetServiceClient\b/.test(line)) {
        violations.push({
          file: relPath,
          line: i + 1,
          function: 'getServiceClient',
          text: line.substring(0, 120),
        });
      }
    }

    // Check 3: route handlers must not forward or inspect the raw auth row.
    // The row can contain api_key_hash and other sensitive fields. Use the
    // narrow helpers from lib/supabase.js for identity, operator, and actor
    // projections so a future auth-shape change cannot reintroduce the leak.
    const withoutComments: string = content
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|\s)\/\/.*$/gm, '$1');
    const rawAuthEntity: RegExp = /\bauth\s*\.\s*entity\b/;
    if (rawAuthEntity.test(withoutComments)) {
      const lines: string[] = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const lineWithoutComment: string = lines[i].replace(/\/\/.*$/, '');
        if (rawAuthEntity.test(lineWithoutComment)) {
          violations.push({
            file: relPath,
            line: i + 1,
            function: 'auth.entity',
            text: lines[i].trim().substring(0, 120),
          });
        }
      }
    }
  }
} catch (e) {
  if ((e as any).code === 'ENOENT') {
    console.log('✓ No app/api directory found — nothing to check');
    process.exit(0);
  }
  throw e;
}

if (violations.length > 0) {
  console.error('✗ Write discipline violations found:\n');
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}`);
    console.error(`    Forbidden: ${v.function}`);
    console.error(`    Line: ${v.text}\n`);
  }
  console.error(`\n${violations.length} violation(s) found.`);
  console.error('Routes must use protocolWrite() for trust-bearing writes and getGuardedClient() for database access.');
  console.error('getServiceClient() is only permitted in the canonical write layer and non-route library code.');
  console.error('Routes must use authEntityId()/authEntityActor() projections instead of the raw auth.entity row.');
  process.exit(1);
} else {
  console.log(`✓ All route files pass write discipline check`);
  process.exit(0);
}
