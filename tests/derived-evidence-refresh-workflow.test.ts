// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';

const workflowPath = '.github/workflows/refresh-derived-evidence.yml';
const artifactPaths = [
  'security/security-case.json',
  'lib/proof-stats.json',
  'AI_CONTEXT.md',
  'public/llms.txt',
  'public/llms-full.txt',
  'public/.well-known/emilia-context.json',
  'test-results/derived-evidence-provenance.json',
];

function loadWorkflow() {
  const source = readFileSync(workflowPath, 'utf8');
  return { source, workflow: YAML.parse(source) };
}

describe('derived-evidence refresh workflow', () => {
  it('runs only by manual dispatch or an exact same-repository PR label', () => {
    const { source, workflow } = loadWorkflow();
    expect(Object.keys(workflow.on).sort()).toEqual(['pull_request', 'workflow_dispatch']);
    expect(workflow.on.pull_request).toEqual({ types: ['labeled'] });
    expect(source).not.toMatch(/pull_request_target|\bpush:|\bschedule:/u);

    const job = workflow.jobs.refresh;
    expect(job.if).toContain("github.event_name == 'workflow_dispatch'");
    expect(job.if).toContain("github.event.label.name == 'refresh-evidence'");
    expect(job.if).toContain('github.event.pull_request.head.repo.full_name == github.repository');
    expect(job['timeout-minutes']).toBe(45);
  });

  it('checks out the exact source SHA without persisting credentials', () => {
    const { workflow } = loadWorkflow();
    expect(workflow.permissions).toEqual({ contents: 'read' });
    const checkout = workflow.jobs.refresh.steps.find((step: { uses?: string }) =>
      step.uses?.startsWith('actions/checkout@'));
    expect(checkout.uses).toBe('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1');
    expect(checkout.with.ref).toBe("${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}");
    expect(checkout.with['persist-credentials']).toBe(false);
  });

  it('uses the pinned governed toolchain and unchanged official writer', () => {
    const { source, workflow } = loadWorkflow();
    const steps = workflow.jobs.refresh.steps;
    const uses = steps.map((step: { uses?: string }) => step.uses).filter(Boolean);
    expect(uses).toEqual(expect.arrayContaining([
      'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',
      'actions/setup-java@dd06d9cba3e5552c54d9f8ea23572deb30010f7c',
      'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97',
      'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e',
    ]));
    expect(source).toContain("node-version: '24'");
    expect(source).toContain("java-version: '17'");
    expect(source).toContain("python-version: '3.12'");
    expect(source).toContain("go-version: '1.27.0'");
    expect(source).toContain('python -m pip install --require-hashes -r .github/workflow-requirements/cryptography.txt');
    expect(source).toContain('npm ci --ignore-scripts');
    expect(source).toContain('scripts/download-tla2tools.sh "$TLA2TOOLS_JAR"');
    expect(source).toContain('TLA_VERSION: v1.7.4');
    expect(source).toContain("TLA_ASSET_ID: '184694200'");
    expect(source).toContain('TLA_SHA256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88');

    const writer = steps.find((step: { run?: string }) => step.run === 'npm run sync:proof-stats');
    expect(writer.env.NODE_OPTIONS).toBe('--import ${{ github.workspace }}/scripts/ts-loader/register.mjs');
    expect(workflow.jobs.refresh.env.TLA2TOOLS_JAR).toBe('${{ github.workspace }}/tla2tools.jar');
    expect(source).toContain('npm run sync:llm-context');
    expect(source).toContain('npm run check:llm-context');
    expect(source).toContain('npm run check:public-conformance-claims');
    expect(source).not.toMatch(/security-case-preverified|bootstrap-derived-evidence/u);
  });

  it('uploads only the reviewed derived files and source-SHA provenance on success', () => {
    const { source, workflow } = loadWorkflow();
    const upload = workflow.jobs.refresh.steps.find((step: { uses?: string }) =>
      step.uses?.startsWith('actions/upload-artifact@'));
    expect(upload.uses).toBe('actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a');
    expect(upload.if).toBe('${{ success() }}');
    expect(upload.with['if-no-files-found']).toBe('error');
    expect(upload.with['include-hidden-files']).toBe(true);
    expect(upload.with.path.trim().split(/\s*\n\s*/u)).toEqual(artifactPaths);
    expect(source).toContain('test "$SOURCE_SHA" = "$(git rev-parse \'HEAD^{commit}\')"');
    expect(source).toContain('source_sha: process.env.SOURCE_SHA');
    for (const artifactPath of artifactPaths.slice(0, -1)) {
      expect(source).toContain(`"${artifactPath}"`);
    }
    expect(source).not.toMatch(/\b(?:git push|gh pr merge|npm publish|deploy|attest)\b|secrets\./u);
  });
});
