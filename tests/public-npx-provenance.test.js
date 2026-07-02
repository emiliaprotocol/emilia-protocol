import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const SCAN_DIRS = ['README.md', 'docs', 'app', 'public', 'create-ep-app', 'infrastructure'];
const BANNED = [
  /\bnpx\s+create-ep-app\b/g,
  /\bnpx\s+ep-conformance-test\b/g,
  /\bnpm\s+create\s+ep-app\b/g,
];

function* walk(p) {
  const full = path.join(ROOT, p);
  if (!fs.existsSync(full)) return;
  const stat = fs.statSync(full);
  if (stat.isFile()) {
    if (/\.(md|mdx|js|jsx|ts|tsx|mjs|yaml|yml|txt|html)$/.test(full)) yield full;
    return;
  }
  for (const entry of fs.readdirSync(full)) {
    if (entry === 'node_modules' || entry === '.next' || entry === 'archive') continue;
    yield* walk(path.join(p, entry));
  }
}

describe('public command provenance', () => {
  it('does not tell users to run unowned bare npx packages', () => {
    const findings = [];
    for (const file of SCAN_DIRS.flatMap((p) => [...walk(p)])) {
      const text = fs.readFileSync(file, 'utf8');
      for (const re of BANNED) {
        for (const match of text.matchAll(re)) {
          findings.push(`${path.relative(ROOT, file)}: ${match[0]}`);
        }
      }
    }
    expect(findings).toEqual([]);
  });

  // The bare `create-ep-app` npm name is owned by an unrelated third party, so
  // we cannot register it. The one way the risk re-opens FROM OUR SIDE is
  // accidentally publishing our scaffolder unscoped. Lock the scoped name and
  // keep the README's warning, so a rename/typo can't ship an unscoped package.
  it('create-ep-app stays scoped and keeps its foreign-name warning', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'create-ep-app/package.json'), 'utf8'));
    expect(pkg.name).toBe('@emilia-protocol/create-ep-app');
    const readme = fs.readFileSync(path.join(ROOT, 'create-ep-app/README.md'), 'utf8');
    expect(readme).toMatch(/unrelated third party/i);
  });
});
