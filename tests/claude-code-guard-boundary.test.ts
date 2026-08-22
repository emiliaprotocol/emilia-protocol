// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const root = process.cwd();
const sourcePath = path.join(root, 'integrations/claude-code-plugin/hooks/guard.mts');
const runtimePath = path.join(root, 'integrations/claude-code-plugin/hooks/guard.mjs');
const readmePath = path.join(root, 'integrations/claude-code-plugin/README.md');

function runHook(event: object): string {
  const result = spawnSync(process.execPath, [runtimePath], {
    cwd: root,
    input: JSON.stringify(event),
    encoding: 'utf8',
    env: {
      ...process.env,
      EP_API_KEY: '',
      EP_ORG_ID: '',
      EP_GUARD_PATTERNS: '',
    },
  });
  expect(result.status).toBe(0);
  return result.stdout;
}

describe('Claude Code heuristic guard boundary', () => {
  it('never emits allow and caps the blocking window', () => {
    const source = fs.readFileSync(sourcePath, 'utf8');
    expect(source).not.toMatch(/emit\(\s*['"]allow['"]/u);
    expect(source).toMatch(/requestedTimeout\s*:\s*30/u);
    expect(source).toMatch(/,\s*60,\s*\)/u);
  });

  it('holds an obvious destructive command but does not pretend to catch an encoded equivalent', () => {
    const direct = runHook({ tool_name: 'Bash', tool_input: { command: 'rm -rf ./build-output' } });
    expect(JSON.parse(direct).hookSpecificOutput.permissionDecision).toBe('ask');

    const encoded = runHook({
      tool_name: 'Bash',
      tool_input: { command: "printf 'cm0gLXJmIC4vYnVpbGQtb3V0cHV0' | base64 -d | sh" },
    });
    expect(encoded).toBe('');
  });

  it('documents exact enforcement at the credential-owning boundary', () => {
    const readme = fs.readFileSync(readmePath, 'utf8');
    expect(readme).toContain('The hook therefore never emits `allow`');
    expect(readme).toContain('credential-owning execution boundary');
    expect(readme).toContain('Unmatched calls pass back to');
  });
});
