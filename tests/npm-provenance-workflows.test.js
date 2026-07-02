import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const WORKFLOW_DIR = path.join(ROOT, '.github', 'workflows');

describe('npm publish workflows', () => {
  it('publish npm packages with OIDC provenance enabled', () => {
    const findings = [];
    for (const name of fs.readdirSync(WORKFLOW_DIR)) {
      if (!/\.(yml|yaml)$/.test(name)) continue;
      const file = path.join(WORKFLOW_DIR, name);
      const text = fs.readFileSync(file, 'utf8');
      if (!text.includes('npm publish')) continue;
      for (const line of text.split('\n').filter((l) => l.includes('npm publish'))) {
        if (!line.includes('--provenance')) {
          findings.push(`${name}: ${line.trim()} missing --provenance`);
        }
      }
      if (!/id-token:\s*write/.test(text)) {
        findings.push(`${name}: missing permissions.id-token: write`);
      }
    }
    expect(findings).toEqual([]);
  });
});
