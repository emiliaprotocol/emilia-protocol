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
      for (const line of text.split('\n').filter((l) => l.includes('npm publish') && !l.trim().startsWith('#'))) {
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

  it('requires an owner-approved manual dispatch for every registry publisher', () => {
    const directPublishers = [
      'publish-gate.yml',
      'publish-issue.yml',
      'publish-langchain-python.yml',
      'publish-langchain.yml',
      'publish-mcp.yml',
      'publish-python-sdk.yml',
      'publish-python-verify.yml',
      'publish-require-receipt.yml',
      'publish-typescript-sdk.yml',
      'publish-verify-sdk.yml',
    ];
    const findings = [];
    const reusable = fs.readFileSync(path.join(WORKFLOW_DIR, '_publish-npm-package.yml'), 'utf8');
    for (const name of directPublishers) {
      const text = fs.readFileSync(path.join(WORKFLOW_DIR, name), 'utf8');
      const usesReusableNpmGate = text.includes('./.github/workflows/_publish-npm-package.yml');
      if (/^[ \t]{2}push:/m.test(text)) findings.push(`${name}: tag pushes must not publish`);
      if (!/^[ \t]{2}workflow_dispatch:/m.test(text)) findings.push(`${name}: missing manual dispatch`);
      if (!/^[ \t]{6}release_tag:/m.test(text)) findings.push(`${name}: missing release_tag input`);
      if (!/^[ \t]{6}confirmation:/m.test(text)) findings.push(`${name}: missing confirmation input`);
      if (!text.includes('registry-publishing-approval')) findings.push(`${name}: missing protected approval environment`);
      if (!text.includes('require-release-approval.mjs') && !(usesReusableNpmGate && reusable.includes('require-release-approval.mjs'))) {
        findings.push(`${name}: missing release approval gate`);
      }
      if (!text.includes('persist-credentials: false') && !(usesReusableNpmGate && reusable.includes('persist-credentials: false'))) {
        findings.push(`${name}: checkout credential persists into release build`);
      }
    }
    expect(findings).toEqual([]);
  });

  it('ships no direct local registry publication path', () => {
    expect(fs.existsSync(path.join(ROOT, 'scripts', 'publish-verify.sh'))).toBe(false);
    expect(fs.readFileSync(path.join(ROOT, 'packages', 'python-verify', 'README.md'), 'utf8')).not.toMatch(/\btwine\s+upload\b/);
  });
});
