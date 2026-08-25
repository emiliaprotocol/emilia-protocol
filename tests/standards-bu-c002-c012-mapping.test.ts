// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const mapping = readFileSync(
  resolve(ROOT, 'docs/standards-engagement/BU-C002-C012-MAPPING.md'),
  'utf8',
);
const status = JSON.parse(readFileSync(resolve(ROOT, 'standards/STATUS.json'), 'utf8')) as {
  active_datatracker: Array<{ draft: string; revision: string }>;
};

function currentRevision(draft: string): string {
  const row = status.active_datatracker.find((candidate) => candidate.draft === draft);
  if (!row) throw new Error(`missing STATUS.json row for ${draft}`);
  return row.revision;
}

describe('Bu C-002/C-012 mapping source locks', () => {
  it('pins the reviewed Bu source and current EMILIA specification revisions', () => {
    expect(mapping).toContain('draft-bu-agentproto-security-principal-binding-06');
    expect(mapping).toContain('sha256:4d08f60b22149f4590433a7f37d081700df27b37a457d09ca49cf018da9f5f37');
    expect(mapping).not.toContain('draft-bu-agentproto-security-principal-binding-05');
    expect(mapping).toContain(`draft-schrock-ep-authorization-receipts-${currentRevision('draft-schrock-ep-authorization-receipts')}`);
    expect(mapping).toContain(`draft-schrock-action-evidence-boundary-${currentRevision('draft-schrock-action-evidence-boundary')}`);
    expect(mapping).toContain(`draft-schrock-canonical-action-identifier-${currentRevision('draft-schrock-canonical-action-identifier')}`);
  });

  it('preserves the verifier-result and phase boundaries required by the review row', () => {
    for (const field of [
      'Claim grounding',
      'Digest or output representation',
      'Relying-party decision',
      'Implemented revision',
      'Dependency',
    ]) expect(mapping).toContain(field);
    expect(mapping).toContain('VERIFIED');
    expect(mapping).toContain('MATCH');
    expect(mapping).toContain('SATISFIED');
    expect(mapping).toContain('AUTHORIZED');
    expect(mapping).toContain('INDETERMINATE');
    expect(mapping).toContain('No independent implementation, external interoperability, deployment, or IETF adoption is claimed');
  });
});
