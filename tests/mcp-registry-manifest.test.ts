// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const readJson = (path: string): Record<string, any> =>
  JSON.parse(readFileSync(resolve(ROOT, path), 'utf8'));

const manifest = readJson('server.json');
const packageManifest = readJson('mcp-server/package.json');

describe('official MCP Registry manifest', () => {
  it('stays aligned with the published npm package identity and version', () => {
    expect(manifest.name).toBe(packageManifest.mcpName);
    expect(manifest.version).toBe(packageManifest.version);
    expect(manifest.packages).toHaveLength(1);
    expect(manifest.packages[0]).toMatchObject({
      registryType: 'npm',
      identifier: packageManifest.name,
      version: packageManifest.version,
    });
  });

  it('keeps the server description inside the Registry schema limit', () => {
    expect(manifest.description.length).toBeLessThanOrEqual(100);
  });
});
