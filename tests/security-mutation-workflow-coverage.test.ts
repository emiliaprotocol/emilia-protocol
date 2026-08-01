// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

function mutationSources(configPath: string): string[] {
  const source = readFileSync(configPath, 'utf8');
  const mutateBlock = source.slice(
    source.indexOf('mutate: ['),
    source.indexOf('  testFiles: ['),
  );
  return [...mutateBlock.matchAll(/['"]((?:packages|lib)\/[^'":]+\.(?:ts|js))(?:[^'"]*)['"]/gu)]
    .map((match) => match[1]);
}

describe('security mutation workflow coverage', () => {
  it('runs when any configured mutation source changes', () => {
    const workflow = YAML.parse(readFileSync(
      '.github/workflows/security-mutation.yml',
      'utf8',
    ));
    const required = [...new Set([
      ...mutationSources('stryker.security.config.js'),
      ...mutationSources('stryker.aec.config.js'),
      ...mutationSources('stryker.model-to-matter.config.js'),
    ])].sort();
    expect(required.length).toBeGreaterThan(0);
    for (const event of ['pull_request', 'push']) {
      const watched = new Set(workflow.on[event].paths);
      expect(
        required.filter((source) => !watched.has(source)),
        `${event} must watch every configured mutation source`,
      ).toEqual([]);
    }
  });
});
