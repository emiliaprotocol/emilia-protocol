// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'vitest';

const HERE = new URL('./', import.meta.url);
const readJson = async (name) => JSON.parse(await readFile(new URL(name, HERE), 'utf8'));

test('the public pack contains exactly 25 version-pinned, reviewable mappings', async () => {
  const manifest = await readJson('manifest.json');

  assert.equal(manifest['@version'], 'CAID-CONSEQUENTIAL-ACTION-INTEROP-v1');
  assert.equal(manifest.mappings.length, 25);
  assert.equal(new Set(manifest.mappings.map(({ draft }) => draft)).size, 25);
  assert.equal(new Set(manifest.mappings.map(({ mapping_id }) => mapping_id)).size, 25);

  for (const mapping of manifest.mappings) {
    assert.match(mapping.draft, /^draft-[a-z0-9-]+$/);
    assert.match(mapping.revision, /^[0-9]{2}$/);
    assert.match(mapping.source_sha256, /^[a-f0-9]{64}$/);
    assert.equal(
      mapping.source_txt_url,
      `https://www.ietf.org/archive/id/${mapping.draft}-${mapping.revision}.txt`,
    );
    assert.equal(
      mapping.datatracker_url,
      `https://datatracker.ietf.org/doc/${mapping.draft}/`,
    );
    assert.ok(['COMPLETE', 'PARTIAL', 'ABSENT'].includes(mapping.native_binding));
    assert.ok(['EQUIVALENT_UNDER_PROFILE', 'INDETERMINATE'].includes(mapping.native_verdict));
    if (mapping.native_binding !== 'COMPLETE') {
      assert.equal(mapping.native_verdict, 'INDETERMINATE');
      assert.ok(mapping.missing_material_fields.length > 0);
    }
    assert.equal(mapping.author_review.status, 'PENDING_AUTHOR_REVIEW');
    assert.equal(mapping.author_review.endorsement_claimed, false);
    assert.ok(mapping.evidence.length > 0);
    assert.ok(mapping.evidence.every(({ locator, finding }) => locator && finding));
    assert.ok(mapping.native_profile.profile_id);
    assert.ok(mapping.carry_profile.profile_id);
  }
});

test('selection policy contains only the approved targets and requires Linda Dunbar DMSC', async () => {
  const manifest = await readJson('manifest.json');
  const approved = [
    'draft-araut-oauth-transaction-tokens-for-agents',
    'draft-baur-pap',
    'draft-bu-agentproto-security-principal-binding',
    'draft-coetzee-oauth-spt-txn-tokens',
    'draft-dunbar-dmsc-gw-scenarios-gap-analysis',
    'draft-emirdag-scitt-ai-agent-execution',
    'draft-hopley-x402-compliance-receipt',
    'draft-howe-vcon-agent-session',
    'draft-ietf-wimse-arch',
    'draft-ietf-wimse-http-signature',
    'draft-ietf-wimse-workload-creds',
    'draft-ietf-wimse-wpt',
    'draft-jiang-oauth-intent-admission',
    'draft-klrc-aiagent-auth',
    'draft-lee-orprg-permit-receipts',
    'draft-mcguinness-oauth-actor-profile',
    'draft-mcguinness-oauth-ai-agent-instance',
    'draft-mih-scitt-agent-action-capsule-sel-disc',
    'draft-nelson-agent-delegation-receipts',
    'draft-noa-scitt-ai-agent-receipt',
    'draft-pei-opsawg-agentops-observability',
    'draft-pidlisnyi-aps',
    'draft-rampalli-cross-org-delegation-mapping',
    'draft-rosomakho-oauth-txn-challenge',
    'draft-soden-wellknown-mcp-commerce',
  ].sort();
  assert.deepEqual(manifest.mappings.map(({ draft }) => draft).sort(), approved);
  const linda = manifest.mappings.find(
    ({ draft }) => draft === 'draft-dunbar-dmsc-gw-scenarios-gap-analysis',
  );
  assert.ok(linda, 'Linda Dunbar DMSC mapping must be present');
  assert.equal(linda.revision, '02');
  assert.match(linda.author_review.request, /Sections 6\.7 and 6\.9/);
});

test('every target has native and optional-carry executable vectors', async () => {
  const manifest = await readJson('manifest.json');
  const corpus = await readJson('mapping-vectors.json');

  assert.equal(corpus['@version'], 'CAID-CONSEQUENTIAL-ACTION-MAPPING-VECTORS-v1');
  assert.equal(corpus.definitions.length, 1);
  assert.equal(corpus.definitions[0].action_type, 'consequence.invoke.1');
  assert.equal(corpus.vectors.length, 100);
  assert.equal(new Set(corpus.vectors.map(({ id }) => id)).size, 100);

  for (const mapping of manifest.mappings) {
    const nativeVector = corpus.vectors.find(({ id }) => id === `${mapping.mapping_id}:native`);
    const carryVector = corpus.vectors.find(({ id }) => id === `${mapping.mapping_id}:carry`);
    const mutationVector = corpus.vectors.find(({ id }) => id === `${mapping.mapping_id}:mutation`);
    const missingVector = corpus.vectors.find(({ id }) => id === `${mapping.mapping_id}:missing`);
    assert.ok(nativeVector);
    assert.ok(carryVector);
    assert.ok(mutationVector);
    assert.ok(missingVector);
    assert.equal(nativeVector.expect.verdict, mapping.native_verdict);
    assert.equal(carryVector.expect.verdict, 'EQUIVALENT_UNDER_PROFILE');
    assert.equal(mutationVector.expect.verdict, 'NOT_EQUIVALENT');
    assert.equal(missingVector.expect.verdict, 'INDETERMINATE');
  }
});

test('generated artifacts are byte-for-byte current', async () => {
  const { spawnSync } = await import('node:child_process');
  const result = spawnSync(
    process.execPath,
    [new URL('generate.mjs', HERE).pathname, '--check'],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
