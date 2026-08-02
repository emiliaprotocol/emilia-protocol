// SPDX-License-Identifier: Apache-2.0
//
// Continuous "projection referenced but not called" sweep (regression guard).
//
// The auth projections in lib/auth-projections.ts each take the auth object and
// return an identity string. Referencing one WITHOUT calling it yields the
// function, and a function is truthy — so it survives every `if (!value)` guard
// downstream and only reveals itself much later, in a database filter or a
// serialized insert body. Audit #12 found exactly that in the delegations
// create route: `principal_id || authEntityId` where `authEntityId(auth)` was
// meant. TypeScript did not catch it because the request body is `any`, and
// `any || Function` is `any`, which is assignable to `principalId: string`.
//
// One instance existed. This makes the class impossible to reintroduce quietly:
// any bare reference to a projection in app/ or lib/ that is not a call, an
// import, a re-export, a type position, or a comment fails CI.

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_DIRS = ['app', 'lib'];

const PROJECTIONS = [
  'authEntityId',
  'authEntityDbId',
  'authEntityActor',
];

// The projection module defines them; handshake-auth uses `authEntityId` as a
// plain string PARAMETER name, which is a different symbol entirely.
const EXEMPT_FILES = new Set([
  path.join('lib', 'auth-projections.ts'),
  path.join('lib', 'handshake-auth.ts'),
]);

function sourceFiles(dir: string, out: string[] = []): string[] {
  const full = path.join(ROOT, dir);
  if (!fs.existsSync(full)) return out;
  for (const entry of fs.readdirSync(full, { withFileTypes: true })) {
    const rel = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      sourceFiles(rel, out);
    } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
      out.push(rel);
    }
  }
  return out;
}

/** Strip comments and string/template literals so their text cannot match. */
function stripNonCode(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
}

describe('auth projections are called, never referenced bare', () => {
  it('finds no projection used as a value in app/ or lib/', () => {
    const offenders: string[] = [];

    for (const dir of SCAN_DIRS) {
      for (const rel of sourceFiles(dir)) {
        if (EXEMPT_FILES.has(rel)) continue;
        const code = stripNonCode(fs.readFileSync(path.join(ROOT, rel), 'utf8'));

        for (const name of PROJECTIONS) {
          // Every occurrence not immediately followed by '(' is suspect.
          const re = new RegExp(`\\b${name}\\b(?!\\s*\\()`, 'g');
          let match: RegExpExecArray | null;
          while ((match = re.exec(code)) !== null) {
            const before = code.slice(Math.max(0, match.index - 90), match.index);
            const after = code.slice(match.index + name.length, match.index + name.length + 30);

            // Legitimate non-call positions: the import/export that brings the
            // symbol in, and a type annotation referring to its signature.
            if (/\b(import|export)\b[^;]*$/.test(before)) continue;
            if (/^\s*:/.test(after)) continue;

            const line = code.slice(0, match.index).split('\n').length;
            offenders.push(`  ${rel}:${line} — \`${name}\` referenced but not called`);
          }
        }
      }
    }

    expect(
      offenders.sort(),
      'An auth projection is being used as a VALUE. A function is truthy, so it '
      + 'passes every falsy guard and only surfaces downstream as a database '
      + 'filter on the function source text or a dropped key in a JSON insert. '
      + `Call it with the auth object:\n${offenders.sort().join('\n')}\n`,
    ).toEqual([]);
  });
});
