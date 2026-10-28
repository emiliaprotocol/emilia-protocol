// SPDX-License-Identifier: Apache-2.0
// Exact public-reference exceptions must preserve every other scanner rule.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function scan(relativePath: string, content: string) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'docs-secret-fixture-'));
  try {
    fs.mkdirSync(path.join(root, 'scripts'));
    fs.copyFileSync(path.join(process.cwd(), 'scripts/check-docs-secrets.js'), path.join(root, 'scripts/check-docs-secrets.js'));
    fs.writeFileSync(path.join(root, 'package.json'), '{"type":"module"}');
    const target = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
    return spawnSync(process.execPath, [path.join(root, 'scripts/check-docs-secrets.js')], {
      encoding: 'utf8', env: {}, timeout: 5_000,
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

describe('documentation public-reference scanner boundaries', () => {
  it('accepts only the two documented public origins in their integration guide', () => {
    const result = scan('docs/operations/ORCAROUTER.md',
      'https://www.orcarouter.ai/auth\nhttps://api.orcarouter.ai/v1/models\n');
    expect(result.status).toBe(0);
  });

  it.each([
    ['docs/other.md', 'https://api.orcarouter.ai/v1'],
    ['content/ORCAROUTER.md', 'https://www.orcarouter.ai'],
    ['docs/operations/ORCAROUTER.md', 'https://tenant.orcarouter.ai'],
    ['docs/operations/ORCAROUTER.md', 'https://www.orcarouter.ai.attacker.com'],
    ['docs/operations/ORCAROUTER.md', 'https://www.orcarouter.ai@attacker.com'],
    ['docs/operations/ORCAROUTER.md', 'https://www.orcarouter.ai:443@attacker.com'],
  ])('keeps unrelated reference %s %s blocked', (relativePath, url) => {
    const result = scan(relativePath, url);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('[Real-looking hostname]');
  });

  it('still scans credential patterns inside the allowed integration guide', () => {
    const result = scan('docs/operations/ORCAROUTER.md',
      `https://api.orcarouter.ai/v1 key=sk-${'A'.repeat(25)}`);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('[OpenAI API key]');
  });
});
