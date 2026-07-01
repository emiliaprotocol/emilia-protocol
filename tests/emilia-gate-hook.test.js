import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const script = join(root, 'scripts', 'emilia-gate.mjs');

function hook(input, env = {}) {
  return spawnSync(process.execPath, [script, '--hook'], {
    cwd: root,
    input,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

describe('scripts/emilia-gate.mjs hook fail-closed behavior', () => {
  it('holds on malformed hook JSON', () => {
    const r = hook('{not-json');
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Could not parse');
  });

  it('holds when EMILIA_GATE=off is attempted', () => {
    const r = hook(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } }), { EMILIA_GATE: 'off' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('fail-closed');
  });

  it('allows explicitly read-only shell commands', () => {
    const r = hook(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'git status --short' } }));
    expect(r.status).toBe(0);
  });

  it('holds unclassified shell commands by default', () => {
    const r = hook(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'node deploy.js' } }));
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('unclassified shell command');
  });
});
