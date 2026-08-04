// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'vitest';

const HERE = new URL('./', import.meta.url);
const readJson = async (name) => JSON.parse(await readFile(new URL(name, HERE), 'utf8'));

test('the public pack contains exactly 25 version-pinned, reviewable mappings', async () => {
  const manifest = await readJson('manifest.json');

  assert.equal(manifest['@version'], 'CAID-CONSEQUENTIAL-ACTION-INTEROP-v2');
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
    assert.ok([
      'PENDING_AUTHOR_REVIEW',
      'AUTHOR_FEEDBACK_RECORDED',
    ].includes(mapping.author_review.status));
    assert.deepEqual(
      Object.keys(mapping.field_bindings).sort(),
      ['operation', 'parameters_digest', 'target_ref'],
    );
    assert.equal(
      mapping.native_binding,
      mapping.missing_material_fields.length === 0
        ? 'COMPLETE'
        : mapping.missing_material_fields.length === 3 ? 'ABSENT' : 'PARTIAL',
    );
    for (const [field, binding] of Object.entries(mapping.field_bindings)) {
      const unavailable = mapping.missing_material_fields.includes(field);
      assert.equal(binding.status, unavailable ? 'UNAVAILABLE' : 'MAPPED');
      if (unavailable) {
        assert.equal(binding.source_path, null);
        assert.equal(binding.path_kind, 'ABSENT_OR_NOT_PROFILE_INDEPENDENT');
        assert.equal(binding.transform, null);
        assert.ok(binding.reason);
      } else {
        assert.match(binding.source_path, /^\//);
        assert.doesNotMatch(binding.source_path, /^\/__caid_unavailable__\//);
        assert.ok(binding.path_kind);
        assert.ok(binding.transform);
      }
      const rule = mapping.native_profile.rules.find(({ target_field }) => target_field === field);
      assert.ok(rule);
      assert.equal(
        rule.source_path,
        unavailable ? `/__caid_unavailable__/${field}` : binding.source_path,
      );
    }
    assert.match(mapping.native_profile.profile_id, /:native:2$/);
    assert.ok(mapping.native_profile_role.includes('fail-closed probe'));
    assert.ok(mapping.excluded_native_candidates.every(
      ({ source_path, reason }) => source_path?.startsWith('/') && reason,
    ));
    assert.equal(mapping.author_review.endorsement_claimed, false);
    assert.ok(mapping.evidence.length > 0);
    assert.ok(mapping.evidence.every(({ locator, finding }) => locator && finding));
    assert.ok(mapping.native_profile.profile_id);
    assert.ok(mapping.carry_profile.profile_id);
  }
});

test('ORPRG records the author-confirmed narrow finding without claiming native fields or endorsement', async () => {
  const manifest = await readJson('manifest.json');
  const orprg = manifest.mappings.find(
    ({ draft }) => draft === 'draft-lee-orprg-permit-receipts',
  );

  assert.ok(orprg);
  assert.equal(orprg.native_binding, 'ABSENT');
  assert.equal(orprg.native_verdict, 'INDETERMINATE');
  assert.deepEqual(
    orprg.missing_material_fields,
    ['operation', 'target_ref', 'parameters_digest'],
  );
  assert.deepEqual(
    orprg.native_profile.material_source_paths,
    [
      '/__caid_unavailable__/operation',
      '/__caid_unavailable__/target_ref',
      '/__caid_unavailable__/parameters_digest',
    ],
  );
  assert.doesNotMatch(JSON.stringify(orprg), /\/effect_request\//);
  assert.match(orprg.native_profile_role, /not fields defined by ORPRG revision -00/);
  assert.equal(orprg.author_review.status, 'AUTHOR_FEEDBACK_RECORDED');
  assert.equal(orprg.author_review.confirmed_at, '2026-07-28');
  assert.match(orprg.author_review.scope, /not validation/);
  assert.match(orprg.author_review.scope, /not implementation, adoption, or endorsement/);
  assert.equal(orprg.author_review.endorsement_claimed, false);
});

test('APS records the author-confirmed composition boundary without inheriting native trust', async () => {
  const manifest = await readJson('manifest.json');
  const aps = manifest.mappings.find(
    ({ draft }) => draft === 'draft-pidlisnyi-aps',
  );

  assert.ok(aps);
  assert.equal(aps.native_binding, 'COMPLETE');
  assert.equal(aps.native_verdict, 'INDETERMINATE');
  assert.equal(aps.author_review.status, 'AUTHOR_FEEDBACK_RECORDED');
  assert.equal(aps.author_review.confirmed_at, '2026-08-03');
  assert.match(aps.author_review.finding, /APS defines what a native APS record establishes/);
  assert.match(aps.author_review.finding, /must verify the APS artifact under those native rules/);
  assert.match(aps.author_review.finding, /independently decide whether the verified artifact is accepted and sufficient/);
  assert.match(aps.author_review.finding, /Native APS verification is not inherited as trust/);
  assert.match(aps.author_review.scope, /not validation/);
  assert.match(aps.author_review.scope, /not implementation, adoption, or endorsement/);
  assert.equal(aps.author_review.endorsement_claimed, false);
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

test('the source audit locks each draft to only its defensible material fields', async () => {
  const manifest = await readJson('manifest.json');
  const expected = {
    'draft-klrc-aiagent-auth': ['ABSENT', []],
    'draft-mcguinness-oauth-ai-agent-instance': ['ABSENT', []],
    'draft-noa-scitt-ai-agent-receipt': ['PARTIAL', ['operation']],
    'draft-ietf-wimse-arch': ['ABSENT', []],
    'draft-ietf-wimse-http-signature': ['PARTIAL', ['operation', 'target_ref']],
    'draft-ietf-wimse-workload-creds': ['ABSENT', []],
    'draft-ietf-wimse-wpt': ['ABSENT', []],
    'draft-bu-agentproto-security-principal-binding': ['ABSENT', []],
    'draft-rosomakho-oauth-txn-challenge': ['ABSENT', []],
    'draft-nelson-agent-delegation-receipts': ['PARTIAL', ['operation']],
    'draft-jiang-oauth-intent-admission': ['PARTIAL', ['operation']],
    'draft-araut-oauth-transaction-tokens-for-agents': ['ABSENT', []],
    'draft-coetzee-oauth-spt-txn-tokens': ['COMPLETE', ['operation', 'parameters_digest', 'target_ref']],
    'draft-mcguinness-oauth-actor-profile': ['ABSENT', []],
    'draft-rampalli-cross-org-delegation-mapping': ['ABSENT', []],
    'draft-mih-scitt-agent-action-capsule-sel-disc': ['PARTIAL', ['operation']],
    'draft-emirdag-scitt-ai-agent-execution': ['PARTIAL', ['operation']],
    'draft-lee-orprg-permit-receipts': ['ABSENT', []],
    'draft-baur-pap': ['PARTIAL', ['operation']],
    'draft-pidlisnyi-aps': ['COMPLETE', ['operation', 'parameters_digest', 'target_ref']],
    'draft-howe-vcon-agent-session': ['ABSENT', []],
    'draft-pei-opsawg-agentops-observability': ['PARTIAL', ['operation']],
    'draft-dunbar-dmsc-gw-scenarios-gap-analysis': ['ABSENT', []],
    'draft-soden-wellknown-mcp-commerce': ['ABSENT', []],
    'draft-hopley-x402-compliance-receipt': ['ABSENT', []],
  };

  assert.equal(Object.keys(expected).length, 25);
  for (const mapping of manifest.mappings) {
    const [binding, mappedFields] = expected[mapping.draft];
    assert.equal(mapping.native_binding, binding, mapping.draft);
    assert.deepEqual(
      Object.entries(mapping.field_bindings)
        .filter(([, field]) => field.status === 'MAPPED')
        .map(([name]) => name)
        .sort(),
      mappedFields,
      mapping.draft,
    );
    const mappedPaths = new Set(Object.values(mapping.field_bindings)
      .filter((field) => field.status === 'MAPPED')
      .map((field) => field.source_path));
    assert.ok(mapping.excluded_native_candidates.every(
      ({ source_path }) => !mappedPaths.has(source_path),
    ), `${mapping.draft}: excluded candidate leaked into mapped paths`);
  }
});

test('source-side action-identity loss is explicit and can never produce equivalence', async () => {
  const manifest = await readJson('manifest.json');
  const corpus = await readJson('mapping-vectors.json');

  for (const mapping of manifest.mappings) {
    assert.ok(['NONE', 'DECLARED_SOURCE_SEMANTIC_LOSS'].includes(mapping.projection_loss.status));
    assert.ok(Array.isArray(mapping.projection_loss.omitted_source_fields));
    assert.ok(mapping.projection_loss.omitted_source_fields.every(
      ({ source_path, reason }) => source_path?.startsWith('/') && reason,
    ));
    if (mapping.projection_loss.status === 'DECLARED_SOURCE_SEMANTIC_LOSS') {
      assert.equal(mapping.native_verdict, 'INDETERMINATE', mapping.draft);
      assert.equal(mapping.native_profile.loss_policy, 'declared-source-semantic-loss');
      assert.deepEqual(
        mapping.native_profile.omitted_source_fields,
        mapping.projection_loss.omitted_source_fields,
      );
      const nativeVector = corpus.vectors.find(({ id }) => id === `${mapping.mapping_id}:native`);
      assert.equal(nativeVector.expect.verdict, 'INDETERMINATE');
      assert.equal(nativeVector.expect.reason_contains, 'right:declared_source_semantic_loss');
    } else {
      assert.equal(mapping.native_profile.loss_policy, 'no-material-field-loss');
      assert.deepEqual(mapping.native_profile.omitted_source_fields, []);
    }
  }

  const aps = manifest.mappings.find(({ draft }) => draft === 'draft-pidlisnyi-aps');
  assert.equal(aps.native_binding, 'COMPLETE');
  assert.equal(aps.native_verdict, 'INDETERMINATE');
  assert.deepEqual(
    aps.projection_loss.omitted_source_fields.map(({ source_path }) => source_path).sort(),
    [
      '/action_ref/agent_id',
      '/action_ref/issued_at',
      '/action_ref/nonce',
      '/action_ref/profile',
      '/action_ref/scope_required',
    ],
  );
  assert.equal(aps.field_bindings.parameters_digest.source_path, '/action_ref/payload_ref');
  assert.equal(aps.field_bindings.parameters_digest.transform, 'sha256-hex-to-digest');

  const equivalent = manifest.mappings.filter(
    ({ native_verdict }) => native_verdict === 'EQUIVALENT_UNDER_PROFILE',
  );
  assert.deepEqual(
    equivalent.map(({ draft }) => draft),
    ['draft-coetzee-oauth-spt-txn-tokens'],
    'all other 24 mappings must fail closed after the source audit',
  );
});

test('every target has native and optional-carry executable vectors', async () => {
  const manifest = await readJson('manifest.json');
  const corpus = await readJson('mapping-vectors.json');

  assert.equal(corpus['@version'], 'CAID-CONSEQUENTIAL-ACTION-MAPPING-VECTORS-v2');
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
