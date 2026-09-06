// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const workflow = YAML.parse(readFileSync('.github/workflows/publish-crewai.yml', 'utf8'));
const steps = workflow.jobs.publish.steps;
const wheelTest = steps.find((step: { name?: string }) => step.name === 'Test the exact wheel in an isolated environment').run;

describe('CrewAI fixed-verifier release contract', () => {
  it('requires the repaired verifier and excludes an unreviewed major version', () => {
    const metadata = readFileSync('packages/crewai/pyproject.toml', 'utf8');
    const dependencies = metadata.match(/^dependencies = \[([\s\S]*?)\]/m)?.[1];
    expect(dependencies).toContain('"emilia-verify>=2.8.5,<3"');
    // Hatch's default can advance beyond the pinned Twine metadata parser.
    // Keep both artifact formats compatible across this dependency chain.
    for (const packageName of ['python-verify', 'crewai', 'smolagents']) {
      const pyproject = readFileSync(`packages/${packageName}/pyproject.toml`, 'utf8');
      for (const target of ['wheel', 'sdist']) {
        const section = pyproject.split(`[tool.hatch.build.targets.${target}]`)[1]?.split('\n[')[0];
        expect(section, `${packageName} ${target} metadata`).toMatch(/^core-metadata-version = "2\.4"$/m);
      }
    }
  });

  it('replaces the tooling-lock verifier with the same-source wheel before installed tests', () => {
    const build = wheelTest.indexOf('python -m build --no-isolation --wheel packages/python-verify');
    const install = wheelTest.indexOf('"$TEST_ROOT"/dependencies/*.whl "${{ steps.build.outputs.wheel }}"');
    const check = wheelTest.indexOf('"$TEST_ROOT/venv/bin/python" -m pip check');
    expect(build).toBeGreaterThan(-1);
    expect(install).toBeGreaterThan(build);
    expect(wheelTest.slice(build, install)).toContain('--no-deps --force-reinstall');
    expect(check).toBeGreaterThan(install);
    expect(wheelTest.indexOf('python -m pytest')).toBeGreaterThan(check);
  });

  it('requires a clean public dependency resolution before the publishing action', () => {
    const resolverIndex = steps.findIndex((step: { name?: string }) => step.name === 'Require published runtime dependencies');
    const publishIndex = steps.findIndex((step: { uses?: string }) => step.uses?.startsWith('pypa/gh-action-pypi-publish@'));
    expect(resolverIndex).toBeGreaterThan(-1);
    expect(resolverIndex).toBeLessThan(publishIndex);
    const resolver = steps[resolverIndex].run;
    expect(resolver).toContain('python -m venv "$RUNNER_TEMP/crewai-registry-install"');
    expect(resolver).toContain('--index-url https://pypi.org/simple "${{ steps.build.outputs.wheel }}"');
    expect(resolver).toContain('-m pip check');
    expect(resolver).not.toMatch(/--no-deps|--find-links|dependencies\/|release\.txt/);
  });

  it.each([
    ['installed wheels', 'purelib', 'purelib', 0],
    ['source CrewAI', 'workspace', 'purelib', 1],
    ['source verifier', 'purelib', 'workspace', 1],
    ['arbitrary external CrewAI', 'external', 'purelib', 1],
    ['arbitrary external verifier', 'purelib', 'external', 1],
  ])('checks both wheel import origins: %s', (_label, crewaiOrigin, verifierOrigin, expectedStatus) => {
    const guard = wheelTest.match(/- <<'PY'\n([\s\S]*?)\nPY/)?.[1];
    expect(guard).toBeDefined();
    const fixture = `
import os, sys, sysconfig, types
from pathlib import Path
origins = {
    "purelib": Path(sysconfig.get_paths()["purelib"]),
    "workspace": Path(os.environ["GITHUB_WORKSPACE"]),
    "external": Path("/outside-the-virtual-environment"),
}
for name, origin in [("emilia_crewai", ${JSON.stringify(crewaiOrigin)}), ("emilia_verify", ${JSON.stringify(verifierOrigin)})]:
    module = types.ModuleType(name)
    module.__file__ = str(origins[origin] / name / "__init__.py")
    sys.modules[name] = module
`;
    const result = spawnSync('python3', ['-c', fixture + guard], {
      encoding: 'utf8',
      env: { ...process.env, GITHUB_WORKSPACE: '/synthetic-release-source' },
    });
    expect(result.status, result.stderr).toBe(expectedStatus);
  });
});
