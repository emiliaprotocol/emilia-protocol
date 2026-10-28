// SPDX-License-Identifier: Apache-2.0
// Verify actual Playwright collection without browsers or provider requests.
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const cli = path.join(root, 'node_modules/@playwright/test/cli.js');
const cleanEnvironment = { NODE_ENV: 'test' };

function list(config: string): string {
  return execFileSync(process.execPath, [cli, 'test', '--list', '--config', config], {
    cwd: root, encoding: 'utf8', env: cleanEnvironment, timeout: 15_000,
  });
}

describe('OrcaRouter Playwright suite wiring', () => {
  it('keeps ordinary smoke coverage while collecting live evidence only in its dedicated config', () => {
    const smoke = list('playwright.config.js');
    for (const file of [
      'agent-adoption-recovery.spec.ts', 'explorer.spec.ts', 'homepage.spec.ts',
      'multi-party-quorum.spec.ts', 'protocol.spec.ts', 'release-lock.spec.ts',
      'webauthn-signoff.spec.ts',
    ]) expect(smoke).toContain(file);
    expect(smoke).not.toContain('orca-evidence.spec.ts');
    const dedicated = list('playwright.orca.config.mjs');
    expect(dedicated).toContain('orca-evidence.spec.ts');
    expect(dedicated).toContain('OrcaRouter Cyber Inference provider shows both auth methods and a catalog dropdown');
    expect(dedicated).not.toContain('homepage.spec.ts');
  });

  it('supplies dedicated fixture authentication without silently supplying a provider key', () => {
    const probe = `const { default: config } = await import('./playwright.orca.config.mjs');
      process.stdout.write(JSON.stringify({
        secret: Boolean(process.env.TRUST_DESK_SESSION_SECRET),
        reviewer: Boolean(process.env.TRUST_DESK_REVIEWER_ID),
        enabled: config.webServer.env.ORCAROUTER_PROVIDER_ADMIN,
        key: Boolean(process.env.ORCAROUTER_API_KEY),
      }));`;
    const result = execFileSync(process.execPath, ['--input-type=module', '-e', probe], {
      cwd: root, encoding: 'utf8', env: cleanEnvironment, timeout: 5_000,
    });
    expect(JSON.parse(result)).toEqual({ secret: true, reviewer: true, enabled: '1', key: false });
  });
});
