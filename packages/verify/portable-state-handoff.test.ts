// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  InMemoryRecipientStateBoundary,
  PORTABLE_STATE_ACTIONS,
  PORTABLE_STATE_AUTHORITY_PROFILE,
  PORTABLE_STATE_IMPORT_RECEIPT_VERSION,
  PORTABLE_STATE_LIMITS,
  PORTABLE_STATE_MANIFEST_VERSION,
  PORTABLE_STATE_SIGNATURE_PROFILE,
  STATE_HANDOFF_CAID_DEFINITIONS,
  buildSourceRetirementExpectation,
  importPortableState,
  reconcilePortableStateImport,
  signPortableStateManifest,
  stateActionExpectation,
  stateHandoffDigest,
  verifyPortableStateImportReceipt,
  verifyPortableStateImportReceiptForManifest,
  type ArtifactSigner,
  type ArtifactSignerPin,
  type ImportPortableStateOptions,
  type PortableStateBundle,
  type PortableStateImportReceipt,
  type PortableStateManifest,
  type RecipientStateBoundary,
  type StateDigest,
  type StateObjectDescriptor,
  type StatePayloadAdapter,
} from './src/portable-state-handoff.js';
import {
  SOMA_COGOBJ_PAYLOAD_PROFILE,
  SOMA_COGOBJ_VERSION,
  somaCogobjPayloadAdapter,
  type SomaCogobj,
} from './src/soma-cogobj-profile.js';

const SOURCE = 'urn:agent:continuum:smith';
const SOURCE_BOUNDARY = 'urn:ep:aeb:continuum:state-export';
const RECIPIENT = 'urn:agent:emilia:receiver';
const RECIPIENT_BOUNDARY = 'urn:ep:aeb:emilia:state-import';
const RELYING_PARTY = 'urn:org:example';
const NOW = '2026-08-21T18:00:00Z';

function ed25519(label: string): { privateKey: KeyObject; publicKey: KeyObject } {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      crypto.createHash('sha256').update(label).digest(),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

const sourceEd = ed25519('portable-state/source');
const importerEd = ed25519('portable-state/importer');
const sourcePq = ml_dsa65.keygen(new Uint8Array(32).fill(0x31));
const importerPq = ml_dsa65.keygen(new Uint8Array(32).fill(0x32));

const edPolicy = {
  profile: PORTABLE_STATE_SIGNATURE_PROFILE,
  required_algorithms: ['Ed25519'] as ['Ed25519'],
};
const hybridPolicy = {
  profile: PORTABLE_STATE_SIGNATURE_PROFILE,
  required_algorithms: ['Ed25519', 'ML-DSA-65'] as ['Ed25519', 'ML-DSA-65'],
};

const sourceSigner: ArtifactSigner = {
  principal_id: SOURCE,
  policy: edPolicy,
  keys: [{ alg: 'Ed25519', key_id: 'source-ed-1', private_key: sourceEd.privateKey }],
};
const importerSigner: ArtifactSigner = {
  principal_id: RECIPIENT_BOUNDARY,
  policy: edPolicy,
  keys: [{ alg: 'Ed25519', key_id: 'importer-ed-1', private_key: importerEd.privateKey }],
};
const sourcePins: ArtifactSignerPin[] = [{
  alg: 'Ed25519',
  key_id: 'source-ed-1',
  public_key: sourceEd.publicKey,
  status: 'active',
  principals: [SOURCE],
  valid_from: '2026-01-01T00:00:00Z',
  valid_until: '2027-01-01T00:00:00Z',
}];
const importerPins: ArtifactSignerPin[] = [{
  alg: 'Ed25519',
  key_id: 'importer-ed-1',
  public_key: importerEd.publicKey,
  status: 'active',
  principals: [RECIPIENT_BOUNDARY],
  valid_from: '2026-01-01T00:00:00Z',
  valid_until: '2027-01-01T00:00:00Z',
}];

function cogobj(overrides: Partial<SomaCogobj> = {}): SomaCogobj {
  return {
    '@version': SOMA_COGOBJ_VERSION,
    object_id: 'urn:cogobj:finance:payee-controls',
    domain: 'finance',
    schema_uri: 'urn:soma:schema:finance-control:v1',
    snapshot: {
      asserted_at: '2026-08-21T17:55:00Z',
      source_mutability: 'MUTABLE',
      observed_at: '2026-08-21T17:54:59Z',
      freshness_basis_digest: `sha256:${'4'.repeat(64)}`,
    },
    sensitivity: 'PROTECTED',
    protection: { mode: 'PLAINTEXT', profile: null, key_reference_digest: null },
    disposition: 'ACTIVE',
    origin: {
      assertion_class: 'operator-pinned',
      issuer: SOURCE,
      asserted_at: '2026-08-21T17:55:00Z',
      source_digest: null,
      transform_id: null,
    },
    lineage: { generation: 0, predecessor_digest: null },
    authority_semantics: 'NONE',
    content: {
      protected_fields: ['payee_account', 'routing_number'],
      authority: { fake_receipt: 'payload data is never authority evidence' },
    },
    ...overrides,
  };
}

function descriptors(objects: SomaCogobj[], optionalIds: string[] = []): StateObjectDescriptor[] {
  return objects.map((object, position) => ({
    position,
    object_id: object.object_id,
    object_digest: stateHandoffDigest(object),
    media_type: 'application/soma-cogobj+json',
    schema_uri: object.schema_uri,
    required: !optionalIds.includes(object.object_id),
    snapshot_at: object.snapshot.asserted_at,
    sensitivity: object.sensitivity,
    disposition: object.disposition,
    generation: object.lineage.generation,
    predecessor_digest: object.lineage.predecessor_digest,
  }));
}

async function manifestFor(
  objects: SomaCogobj[],
  options: { optionalIds?: string[]; signer?: ArtifactSigner; overrides?: Partial<PortableStateManifest> } = {},
): Promise<PortableStateManifest> {
  const listed = descriptors(objects, options.optionalIds);
  const indexDigest = stateHandoffDigest(listed);
  const sourceActions = [PORTABLE_STATE_ACTIONS.EXPORT];
  if (listed.some((entry) => entry.sensitivity === 'VAULT')) sourceActions.push(PORTABLE_STATE_ACTIONS.KEY_RELEASE);
  const base: Omit<PortableStateManifest, 'signatures'> = {
    '@version': PORTABLE_STATE_MANIFEST_VERSION,
    handoff_id: 'urn:ep:state-handoff:test:1',
    transfer_mode: 'COPY',
    payload_profile: SOMA_COGOBJ_PAYLOAD_PROFILE,
    source_agent: SOURCE,
    source_boundary_id: SOURCE_BOUNDARY,
    recipient_agent: RECIPIENT,
    recipient_boundary_id: RECIPIENT_BOUNDARY,
    relying_party_id: RELYING_PARTY,
    created_at: '2026-08-21T17:56:00Z',
    snapshot_at: '2026-08-21T17:55:00Z',
    expires_at: '2026-08-21T19:00:00Z',
    nonce: 'state-handoff-nonce-0001',
    index: {
      ordered_object_ids: listed.map((entry) => entry.object_id),
      index_digest: indexDigest,
    },
    objects: listed,
    scope_digest: stateHandoffDigest({
      transfer_mode: 'COPY',
      payload_profile: SOMA_COGOBJ_PAYLOAD_PROFILE,
      source_agent: SOURCE,
      source_boundary_id: SOURCE_BOUNDARY,
      recipient_agent: RECIPIENT,
      recipient_boundary_id: RECIPIENT_BOUNDARY,
      relying_party_id: RELYING_PARTY,
      index_digest: indexDigest,
    }),
    authority: {
      profile: PORTABLE_STATE_AUTHORITY_PROFILE,
      source_actions: sourceActions,
      recipient_action: PORTABLE_STATE_ACTIONS.IMPORT,
    },
    nonclaims: {
      source_truth: 'NOT_ESTABLISHED',
      authority_transfer: 'PROHIBITED',
      source_population_completeness: 'NOT_ESTABLISHED',
      physical_erasure: 'NOT_ESTABLISHED',
      trusted_time: 'NOT_ESTABLISHED',
    },
    signature_policy: options.signer?.policy ?? sourceSigner.policy,
  };
  const merged = { ...base, ...options.overrides } as Omit<PortableStateManifest, 'signatures'>;
  return signPortableStateManifest(merged, options.signer ?? sourceSigner);
}

async function bundleFor(
  objects: SomaCogobj[],
  manifestOptions: Parameters<typeof manifestFor>[1] = {},
): Promise<PortableStateBundle> {
  const manifest = await manifestFor(objects, manifestOptions);
  const evidence = Object.fromEntries(manifest.authority.source_actions.map((action) => {
    const expected = stateActionExpectation(manifest, action);
    return [action, { action, caid: expected.caid, consumed: true }];
  }));
  return { manifest, objects, source_authority_evidence: evidence };
}

function boundary(overrides: { allow?: boolean; loseAck?: boolean } = {}) {
  return new InMemoryRecipientStateBoundary({
    loseAcknowledgementAfterCommit: overrides.loseAck,
    authorizeImport(expected, evidence) {
      if (overrides.allow === false || !evidence || (evidence as { caid?: string }).caid !== expected.caid) {
        return { status: 'REFUSED', reasons: ['import_authority_invalid'] };
      }
      return {
        status: 'AUTHORIZED',
        receipt_digest: stateHandoffDigest({ stage: 'recipient', caid: expected.caid }),
      };
    },
  });
}

function importOptions(
  target: RecipientStateBoundary,
  overrides: Partial<ImportPortableStateOptions> = {},
): ImportPortableStateOptions {
  return {
    now: NOW,
    expected_recipient_agent: RECIPIENT,
    expected_recipient_boundary_id: RECIPIENT_BOUNDARY,
    expected_relying_party_id: RELYING_PARTY,
    source_signer_pins: sourcePins,
    payload_adapters: [somaCogobjPayloadAdapter],
    source_authority_verifier: {
      async verify(expected, evidence) {
        const value = evidence as { caid?: string; consumed?: boolean } | null;
        if (!value || value.caid !== expected.caid || value.consumed !== true) {
          return { status: 'REFUSED', reasons: ['source_release_invalid'] };
        }
        return {
          status: 'VERIFIED',
          consumption: 'CONSUMED',
          receipt_digest: stateHandoffDigest({ stage: 'source', caid: expected.caid }),
        };
      },
    },
    recipient_boundary: target,
    import_authority_evidence: { caid: 'filled-per-test' },
    importer_signer: importerSigner,
    ...overrides,
  };
}

function authorizeBundle(bundle: PortableStateBundle, options: ImportPortableStateOptions): void {
  const expected = stateActionExpectation(bundle.manifest, PORTABLE_STATE_ACTIONS.IMPORT);
  options.import_authority_evidence = { caid: expected.caid };
}

async function run(
  bundle: PortableStateBundle,
  target = boundary(),
  overrides: Partial<ImportPortableStateOptions> = {},
): Promise<{ receipt: PortableStateImportReceipt; target: InMemoryRecipientStateBoundary }> {
  const options = importOptions(target, overrides);
  authorizeBundle(bundle, options);
  return { receipt: await importPortableState(bundle, options), target };
}

test('accepts only after source release verification and atomic recipient admission', async () => {
  const bundle = await bundleFor([cogobj()]);
  const { receipt, target } = await run(bundle);
  assert.equal(receipt.result, 'ACCEPTED');
  assert.equal(receipt['@version'], PORTABLE_STATE_IMPORT_RECEIPT_VERSION);
  assert.equal(receipt.authority_evidence[0].action, PORTABLE_STATE_ACTIONS.EXPORT);
  assert.equal(receipt.authority_evidence[1].action, PORTABLE_STATE_ACTIONS.IMPORT);
  assert.equal(target.consumptionCount(), 1);
  assert.deepEqual(target.readObject(cogobj().object_id), cogobj());
  assert.deepEqual(await verifyPortableStateImportReceipt(receipt, importerPins), { valid: true, reasons: [] });
  assert.deepEqual(
    await verifyPortableStateImportReceiptForManifest(receipt, bundle.manifest, importerPins),
    { valid: true, reasons: [] },
  );
});

test('payload content that resembles authority never substitutes for source or import evidence', async () => {
  const object = cogobj({ content: { authorization_receipt: { status: 'AUTHORIZED' }, caid: 'fake' } });
  const bundle = await bundleFor([object]);
  bundle.source_authority_evidence = {};
  const target = boundary();
  const { receipt } = await run(bundle, target);
  assert.equal(receipt.result, 'REFUSED');
  assert.ok(receipt.reasons.includes('source_authority_evidence_set_mismatch'));
  assert.equal(target.consumptionCount(), 0);
});

test('tampering, required omission, and unlisted payloads refuse before authority consumption', async () => {
  for (const mutate of [
    (bundle: PortableStateBundle) => { (bundle.objects[0] as SomaCogobj).content = { changed: true }; },
    (bundle: PortableStateBundle) => { bundle.objects = []; },
    (bundle: PortableStateBundle) => { bundle.objects.push(cogobj({ object_id: 'urn:cogobj:extra' })); },
  ]) {
    const bundle = await bundleFor([cogobj()]);
    mutate(bundle);
    const target = boundary();
    const { receipt } = await run(bundle, target);
    assert.equal(receipt.result, 'REFUSED');
    assert.equal(target.consumptionCount(), 0);
  }
});

test('canonical state and receipt collections are bounded before admission', async () => {
  assert.throws(
    () => stateHandoffDigest(Array.from({ length: PORTABLE_STATE_LIMITS.max_nodes + 1 }, () => null)),
    /node count exceeds/,
  );

  const bundle = await bundleFor([cogobj()]);
  bundle.objects = Array.from({ length: PORTABLE_STATE_LIMITS.max_objects + 1 }, () => cogobj());
  const target = boundary();
  const { receipt } = await run(bundle, target);
  assert.equal(receipt.result, 'REFUSED');
  assert.ok(receipt.reasons.includes('bundle_schema_invalid'));
  assert.equal(target.consumptionCount(), 0);

  const valid = await run(await bundleFor([cogobj()]));
  const tooManyReasons = structuredClone(valid.receipt);
  tooManyReasons.reasons = Array.from(
    { length: PORTABLE_STATE_LIMITS.max_reasons + 1 },
    (_, index) => `reason-${index}`,
  );
  assert.deepEqual(await verifyPortableStateImportReceipt(tooManyReasons, importerPins), {
    valid: false,
    reasons: ['receipt_schema_invalid'],
  });
});

test('set and object time ordering is enforced rather than inferred from signatures', async () => {
  const future = await bundleFor([cogobj()]);
  const futureTarget = boundary();
  const futureRun = await run(future, futureTarget, { now: '2026-08-21T17:55:59Z' });
  assert.equal(futureRun.receipt.result, 'REFUSED');
  assert.ok(futureRun.receipt.reasons.includes('manifest_not_yet_valid'));
  assert.equal(futureTarget.consumptionCount(), 0);

  const lateObject = cogobj({
    snapshot: {
      asserted_at: '2026-08-21T17:55:01Z',
      source_mutability: 'MUTABLE',
      observed_at: '2026-08-21T17:55:00Z',
      freshness_basis_digest: `sha256:${'4'.repeat(64)}`,
    },
  });
  await assert.rejects(
    () => bundleFor([lateObject]),
    /object_snapshot_after_manifest_cut/,
  );

  await assert.rejects(
    () => bundleFor([cogobj()], { overrides: { created_at: '2026-02-30T17:56:00Z' } }),
    /manifest_schema_invalid/,
  );
});

test('SOMA profile refuses observations and origin assertions that postdate their snapshot', async () => {
  for (const object of [
    cogobj({ snapshot: {
      asserted_at: '2026-08-21T17:55:00Z',
      source_mutability: 'MUTABLE',
      observed_at: '2026-08-21T17:55:01Z',
      freshness_basis_digest: `sha256:${'4'.repeat(64)}`,
    } }),
    cogobj({ origin: {
      assertion_class: 'operator-pinned',
      issuer: SOURCE,
      asserted_at: '2026-08-21T17:55:01Z',
      source_digest: null,
      transform_id: null,
    } }),
  ]) {
    const target = boundary();
    const { receipt } = await run(await bundleFor([object]), target);
    assert.equal(receipt.result, 'REFUSED');
    assert.equal(target.consumptionCount(), 0);
  }
});

test('missing optional state is explicit PARTIAL, never silently dropped', async () => {
  const required = cogobj();
  const optional = cogobj({ object_id: 'urn:cogobj:finance:notes' });
  const bundle = await bundleFor([required, optional], { optionalIds: [optional.object_id] });
  bundle.objects = [required];
  const { receipt } = await run(bundle);
  assert.equal(receipt.result, 'PARTIAL');
  assert.deepEqual(receipt.accepted_object_ids, [required.object_id]);
  assert.deepEqual(receipt.unavailable_objects, [{ object_id: optional.object_id, reason: 'optional_object_missing' }]);
});

test('source release must already be consumed at the source boundary', async () => {
  const bundle = await bundleFor([cogobj()]);
  const target = boundary();
  const { receipt } = await run(bundle, target, {
    source_authority_verifier: {
      async verify() { return { status: 'REFUSED', reasons: ['source_receipt_not_consumed'] }; },
    },
  });
  assert.equal(receipt.result, 'REFUSED');
  assert.ok(receipt.reasons.includes('source_receipt_not_consumed'));
  assert.equal(target.consumptionCount(), 0);
});

test('recipient refusal does not consume import authority or commit state', async () => {
  const bundle = await bundleFor([cogobj()]);
  const target = boundary({ allow: false });
  const { receipt } = await run(bundle, target);
  assert.equal(receipt.result, 'REFUSED');
  assert.ok(receipt.reasons.includes('import_authority_invalid'));
  assert.equal(target.consumptionCount(), 0);
  assert.equal(target.readHead(cogobj().object_id), null);
});

test('a receipt key for another consequence boundary cannot admit state', async () => {
  const bundle = await bundleFor([cogobj()]);
  const target = boundary();
  const otherBoundarySigner: ArtifactSigner = {
    ...importerSigner,
    principal_id: 'urn:ep:aeb:emilia:other-import',
  };
  const { receipt } = await run(bundle, target, { importer_signer: otherBoundarySigner });
  assert.equal(receipt.result, 'REFUSED');
  assert.ok(receipt.reasons.includes('importer_signer_boundary_mismatch'));
  assert.equal(target.consumptionCount(), 0);
});

test('the atomic boundary rechecks the exact import action before consumption', async () => {
  const bundle = await bundleFor([cogobj()]);
  const inner = boundary();
  const substituting: RecipientStateBoundary = {
    readHead: (id) => inner.readHead(id),
    lookupAdmission: (id) => inner.lookupAdmission(id),
    commitImport: (request) => inner.commitImport({
      ...request,
      recipient_boundary_id: 'urn:ep:aeb:emilia:substituted-at-commit',
    }),
  };
  const options = importOptions(substituting);
  authorizeBundle(bundle, options);
  const receipt = await importPortableState(bundle, options);
  assert.equal(receipt.result, 'REFUSED');
  assert.ok(receipt.reasons.includes('recipient_commit_action_mismatch'));
  assert.equal(inner.consumptionCount(), 0);
});

test('a head change inside the commit window is indeterminate and burns no authority', async () => {
  const bundle = await bundleFor([cogobj()]);
  const inner = boundary();
  const racing: RecipientStateBoundary = {
    readHead: (id) => inner.readHead(id),
    lookupAdmission: (id) => inner.lookupAdmission(id),
    commitImport: async (request) => {
      inner.seedHead(request.writes[0].object_id, {
        generation: 0,
        object_digest: `sha256:${'7'.repeat(64)}`,
      });
      return inner.commitImport(request);
    },
  };
  const options = importOptions(racing);
  authorizeBundle(bundle, options);
  const receipt = await importPortableState(bundle, options);
  assert.equal(receipt.result, 'INDETERMINATE');
  assert.ok(receipt.reasons.includes('head_changed_during_commit'));
  assert.equal(inner.consumptionCount(), 0);
});

test('lost acknowledgement reconciles the committed record without a blind retry', async () => {
  const bundle = await bundleFor([cogobj()]);
  const target = boundary({ loseAck: true });
  const options = importOptions(target);
  authorizeBundle(bundle, options);
  const first = await importPortableState(bundle, options);
  assert.equal(first.result, 'INDETERMINATE');
  assert.ok(first.reasons.includes('commit_acknowledgement_lost'));
  assert.equal(target.consumptionCount(), 1);

  (bundle.objects[0] as SomaCogobj).content = { tampered_retransmission: true };
  const replay = await importPortableState(bundle, options);
  assert.equal(replay.result, 'INDETERMINATE');
  assert.ok(replay.reasons.includes('handoff_already_committed_use_reconciliation'));

  options.now = '2026-08-21T18:05:00Z';
  const reconciled = await reconcilePortableStateImport(
    bundle.manifest.handoff_id,
    stateHandoffDigest(bundle.manifest),
    options,
  );
  assert.equal(reconciled?.result, 'ACCEPTED');
  assert.equal(reconciled?.receipt_kind, 'RECONCILIATION');
  assert.equal(reconciled?.completed_at, NOW);
  assert.equal(reconciled?.issued_at, '2026-08-21T18:05:00Z');
  assert.deepEqual(
    await verifyPortableStateImportReceiptForManifest(reconciled, bundle.manifest, importerPins),
    { valid: true, reasons: [] },
  );
  assert.equal(target.consumptionCount(), 1);
});

test('rollback and fork refuse, while an unanchored gap is indeterminate', async () => {
  const current = `sha256:${'8'.repeat(64)}` as StateDigest;
  for (const [generation, predecessor, expected, marker] of [
    [1, current, 'REFUSED', 'lineage_rollback'],
    [2, `sha256:${'9'.repeat(64)}`, 'REFUSED', 'lineage_fork'],
    [3, current, 'INDETERMINATE', 'lineage_gap'],
  ] as const) {
    const next = cogobj({ lineage: { generation, predecessor_digest: predecessor } });
    const bundle = await bundleFor([next]);
    const target = boundary();
    target.seedHead(next.object_id, { generation: 1, object_digest: current });
    const { receipt } = await run(bundle, target);
    assert.equal(receipt.result, expected);
    assert.ok(receipt.reasons.includes(marker));
    assert.equal(target.consumptionCount(), 0);
  }
});

test('VAULT state must be opaque ciphertext and have source key-release evidence plus local availability', async () => {
  const plaintext = cogobj({ sensitivity: 'VAULT' });
  const refused = await run(await bundleFor([plaintext]));
  assert.equal(refused.receipt.result, 'REFUSED');
  assert.ok(refused.receipt.reasons.includes('vault_plaintext_prohibited'));

  const encrypted = cogobj({
    sensitivity: 'VAULT',
    protection: {
      mode: 'OPAQUE-CIPHERTEXT',
      profile: 'urn:example:hpke:v1',
      key_reference_digest: `sha256:${'a'.repeat(64)}`,
    },
    content: { ciphertext_b64u: Buffer.from('opaque').toString('base64url') },
  });
  const bundle = await bundleFor([encrypted]);
  assert.deepEqual(bundle.manifest.authority.source_actions, [
    PORTABLE_STATE_ACTIONS.EXPORT,
    PORTABLE_STATE_ACTIONS.KEY_RELEASE,
  ]);
  const accepted = await run(bundle, boundary(), {
    verify_vault_availability: async () => ({ status: 'AVAILABLE' }),
  });
  assert.equal(accepted.receipt.result, 'ACCEPTED', JSON.stringify(accepted.receipt.reasons));
});

test('unknown required payload profile stays INDETERMINATE', async () => {
  const object = cogobj();
  const original = await manifestFor([object]);
  const unsigned = { ...original, payload_profile: 'urn:unknown:profile', signatures: undefined } as unknown as Omit<PortableStateManifest, 'signatures'>;
  delete (unsigned as unknown as { signatures?: unknown }).signatures;
  unsigned.scope_digest = stateHandoffDigest({
    transfer_mode: 'COPY',
    payload_profile: unsigned.payload_profile,
    source_agent: SOURCE,
    source_boundary_id: SOURCE_BOUNDARY,
    recipient_agent: RECIPIENT,
    recipient_boundary_id: RECIPIENT_BOUNDARY,
    relying_party_id: RELYING_PARTY,
    index_digest: unsigned.index.index_digest,
  });
  const manifest = await signPortableStateManifest(unsigned, sourceSigner);
  const bundle: PortableStateBundle = { manifest, objects: [object], source_authority_evidence: {} };
  for (const action of manifest.authority.source_actions) {
    const expected = stateActionExpectation(manifest, action);
    bundle.source_authority_evidence[action] = { caid: expected.caid, consumed: true };
  }
  const { receipt } = await run(bundle);
  assert.equal(receipt.result, 'INDETERMINATE');
  assert.ok(receipt.reasons.includes('required_payload_profile_unsupported'));
});

test('hybrid manifest verification detects a stripped ML-DSA leg and narrowed algorithm set', async () => {
  const hybridSigner: ArtifactSigner = {
    principal_id: SOURCE,
    policy: hybridPolicy,
    keys: [
      { alg: 'Ed25519', key_id: 'source-ed-1', private_key: sourceEd.privateKey },
      { alg: 'ML-DSA-65', key_id: 'source-pq-1', private_key: sourcePq.secretKey },
    ],
    agility: { deterministic: true },
  };
  const bundle = await bundleFor([cogobj()], { signer: hybridSigner });
  const hybridPins: ArtifactSignerPin[] = [sourcePins[0], {
    alg: 'ML-DSA-65',
    key_id: 'source-pq-1',
    public_key: sourcePq.publicKey,
    status: 'active',
    principals: [SOURCE],
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: '2027-01-01T00:00:00Z',
  }];
  const target = boundary();
  const accepted = await run(bundle, target, { source_signer_pins: hybridPins });
  assert.equal(accepted.receipt.result, 'ACCEPTED', JSON.stringify(accepted.receipt.reasons));

  bundle.manifest.signatures = bundle.manifest.signatures.filter((entry) => entry.alg === 'Ed25519');
  bundle.manifest.signature_policy = edPolicy;
  const strippedTarget = boundary();
  const stripped = await run(bundle, strippedTarget, { source_signer_pins: sourcePins });
  assert.equal(stripped.receipt.result, 'REFUSED');
  assert.ok(stripped.receipt.reasons.some((entry) => entry.startsWith('artifact_signature_invalid:')));
  assert.equal(strippedTarget.consumptionCount(), 0);
});

test('hybrid import receipts verify offline and refuse algorithm-set stripping', async () => {
  const hybridImporter: ArtifactSigner = {
    principal_id: RECIPIENT_BOUNDARY,
    policy: hybridPolicy,
    keys: [
      { alg: 'Ed25519', key_id: 'importer-ed-1', private_key: importerEd.privateKey },
      { alg: 'ML-DSA-65', key_id: 'importer-pq-1', private_key: importerPq.secretKey },
    ],
    agility: { deterministic: true },
  };
  const bundle = await bundleFor([cogobj()]);
  const { receipt } = await run(bundle, boundary(), { importer_signer: hybridImporter });
  assert.equal(receipt.result, 'ACCEPTED');
  const hybridPins: ArtifactSignerPin[] = [importerPins[0], {
    alg: 'ML-DSA-65',
    key_id: 'importer-pq-1',
    public_key: importerPq.publicKey,
    status: 'active',
    principals: [RECIPIENT_BOUNDARY],
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: '2027-01-01T00:00:00Z',
  }];
  assert.deepEqual(await verifyPortableStateImportReceipt(receipt, hybridPins), { valid: true, reasons: [] });

  receipt.signatures = receipt.signatures.filter((entry) => entry.alg === 'Ed25519');
  receipt.signature_policy = edPolicy;
  const stripped = await verifyPortableStateImportReceipt(receipt, importerPins);
  assert.equal(stripped.valid, false);
  assert.ok(stripped.reasons.some((entry) => entry.startsWith('artifact_signature_invalid:')));
});

test('source retirement is a separate post-import action bound to the accepted receipt', async () => {
  const bundle = await bundleFor([cogobj()]);
  const { receipt } = await run(bundle);
  const retirement = buildSourceRetirementExpectation(bundle.manifest, receipt);
  assert.equal(retirement.action_object.action_type, PORTABLE_STATE_ACTIONS.RETIRE_SOURCE);
  assert.equal(retirement.action_object.import_receipt_digest, stateHandoffDigest(receipt));
  assert.equal(
    retirement.action_object.retirement_set_digest,
    stateHandoffDigest(bundle.manifest.objects.map((entry) => ({
      object_id: entry.object_id,
      object_digest: entry.object_digest,
    }))),
  );

  const changed = structuredClone(receipt);
  changed.completed_at = '2026-08-21T18:00:01Z';
  const other = buildSourceRetirementExpectation(bundle.manifest, changed);
  assert.notEqual(retirement.caid, other.caid);

  const optional = cogobj({ object_id: 'urn:cogobj:finance:optional-retirement' });
  const partialBundle = await bundleFor([cogobj(), optional], { optionalIds: [optional.object_id] });
  partialBundle.objects = [cogobj()];
  const partialReceipt = (await run(partialBundle)).receipt;
  const partialRetirement = buildSourceRetirementExpectation(partialBundle.manifest, partialReceipt);
  assert.equal(
    partialRetirement.action_object.retirement_set_digest,
    stateHandoffDigest(partialBundle.manifest.objects
      .filter((entry) => entry.object_id !== optional.object_id)
      .map((entry) => ({ object_id: entry.object_id, object_digest: entry.object_digest }))),
  );

  const unsafe = structuredClone(partialReceipt);
  unsafe.unavailable_objects = [];
  assert.throws(
    () => buildSourceRetirementExpectation(partialBundle.manifest, unsafe),
    /does not partition/,
  );
});

test('exact-action CAIDs change under recipient, manifest, and action substitution', async () => {
  const manifest = await manifestFor([cogobj()]);
  const exported = stateActionExpectation(manifest, PORTABLE_STATE_ACTIONS.EXPORT);
  const imported = stateActionExpectation(manifest, PORTABLE_STATE_ACTIONS.IMPORT);
  assert.notEqual(exported.caid, imported.caid);

  const changedUnsigned = { ...manifest, recipient_agent: 'urn:agent:other', signatures: undefined } as unknown as Omit<PortableStateManifest, 'signatures'>;
  delete (changedUnsigned as unknown as { signatures?: unknown }).signatures;
  changedUnsigned.scope_digest = stateHandoffDigest({
    transfer_mode: 'COPY',
    payload_profile: changedUnsigned.payload_profile,
    source_agent: SOURCE,
    source_boundary_id: SOURCE_BOUNDARY,
    recipient_agent: changedUnsigned.recipient_agent,
    recipient_boundary_id: RECIPIENT_BOUNDARY,
    relying_party_id: RELYING_PARTY,
    index_digest: changedUnsigned.index.index_digest,
  });
  const changed = await signPortableStateManifest(changedUnsigned, sourceSigner);
  assert.notEqual(exported.caid, stateActionExpectation(changed, PORTABLE_STATE_ACTIONS.EXPORT).caid);

  const boundaryUnsigned = {
    ...manifest,
    recipient_boundary_id: 'urn:ep:aeb:emilia:other-import',
    signatures: undefined,
  } as unknown as Omit<PortableStateManifest, 'signatures'>;
  delete (boundaryUnsigned as unknown as { signatures?: unknown }).signatures;
  boundaryUnsigned.scope_digest = stateHandoffDigest({
    transfer_mode: 'COPY',
    payload_profile: boundaryUnsigned.payload_profile,
    source_agent: SOURCE,
    source_boundary_id: SOURCE_BOUNDARY,
    recipient_agent: RECIPIENT,
    recipient_boundary_id: boundaryUnsigned.recipient_boundary_id,
    relying_party_id: RELYING_PARTY,
    index_digest: boundaryUnsigned.index.index_digest,
  });
  const changedBoundary = await signPortableStateManifest(boundaryUnsigned, sourceSigner);
  assert.notEqual(imported.caid, stateActionExpectation(changedBoundary, PORTABLE_STATE_ACTIONS.IMPORT).caid);
});

test('runtime CAID definitions match the governed public registry field-for-field', async () => {
  const registry = JSON.parse(await readFile(
    new URL('../../caid/registry/action-types.json', import.meta.url),
    'utf8',
  )) as { types: Array<Record<string, unknown>> };
  for (const runtime of STATE_HANDOFF_CAID_DEFINITIONS) {
    const published = registry.types.find((entry) => entry.action_type === runtime.action_type) as {
      required_fields?: Array<{ name: string; type: string }>;
      optional_fields?: Array<{ name: string; type: string }>;
    } | undefined;
    assert.ok(published, `missing registry definition for ${runtime.action_type}`);
    assert.deepEqual(
      published.required_fields?.map(({ name, type }) => ({ name, type })),
      runtime.required_fields.map(({ name, type }) => ({ name, type })),
    );
    assert.deepEqual(published.optional_fields ?? [], runtime.optional_fields);
  }
});

test('a tombstone is importable state evidence but never an erasure claim', async () => {
  const tombstone = cogobj({ disposition: 'TOMBSTONE', content: null });
  const { receipt } = await run(await bundleFor([tombstone]));
  assert.equal(receipt.result, 'ACCEPTED');
  assert.equal(receipt.nonclaims.physical_erasure, 'NOT_ESTABLISHED');
  assert.equal(receipt.nonclaims.trusted_time, 'NOT_ESTABLISHED');
});

test('receipt verifier rejects accepted state without a recipient atomic-admission record', async () => {
  const bundle = await bundleFor([cogobj()]);
  const { receipt } = await run(bundle);
  const forged = structuredClone(receipt);
  forged.admission_record_digest = null;
  assert.deepEqual(await verifyPortableStateImportReceipt(forged, importerPins), {
    valid: false,
    reasons: ['artifact_signature_invalid:Ed25519:signature_invalid', 'accepted_receipt_without_atomic_admission'],
  });
});

test('receipt verifier enforces result-specific terminal semantics', async () => {
  const bundle = await bundleFor([cogobj()]);
  const { receipt } = await run(bundle);
  const cases: Array<[PortableStateImportReceipt, string]> = [];

  const acceptedWithReason = structuredClone(receipt);
  acceptedWithReason.reasons = ['impossible_success_reason'];
  cases.push([acceptedWithReason, 'accepted_receipt_carries_failure_reasons']);

  const acceptedUnavailable = structuredClone(receipt);
  acceptedUnavailable.unavailable_objects = [{ object_id: 'urn:cogobj:missing', reason: 'missing' }];
  cases.push([acceptedUnavailable, 'accepted_receipt_claims_unavailable_state']);

  const partialWithoutGap = structuredClone(receipt);
  partialWithoutGap.result = 'PARTIAL';
  cases.push([partialWithoutGap, 'partial_receipt_without_unavailable_state']);

  const refusedWithoutReason = structuredClone(receipt);
  refusedWithoutReason.result = 'REFUSED';
  refusedWithoutReason.accepted_object_ids = [];
  refusedWithoutReason.authority_evidence = refusedWithoutReason.authority_evidence
    .filter((entry) => entry.stage === 'SOURCE_RELEASE');
  refusedWithoutReason.admission_record_digest = null;
  cases.push([refusedWithoutReason, 'failed_receipt_without_reason']);

  const issuedBeforeCompletion = structuredClone(receipt);
  issuedBeforeCompletion.issued_at = '2026-08-21T17:59:59Z';
  cases.push([issuedBeforeCompletion, 'receipt_issued_before_completion']);

  const failedReconciliation = structuredClone(refusedWithoutReason);
  failedReconciliation.receipt_kind = 'RECONCILIATION';
  cases.push([failedReconciliation, 'reconciliation_receipt_not_committed']);

  for (const [candidate, marker] of cases) {
    const checked = await verifyPortableStateImportReceipt(candidate, importerPins);
    assert.equal(checked.valid, false);
    assert.ok(checked.reasons.includes(marker), JSON.stringify(checked.reasons));
  }
});

test('manifest-aware receipt verification closes boundary, state-set, and CAID substitutions', async () => {
  const required = cogobj();
  const optional = cogobj({ object_id: 'urn:cogobj:finance:optional' });
  const bundle = await bundleFor([required, optional], { optionalIds: [optional.object_id] });
  bundle.objects = [required];
  const { receipt } = await run(bundle);
  assert.deepEqual(
    await verifyPortableStateImportReceiptForManifest(receipt, bundle.manifest, importerPins),
    { valid: true, reasons: [] },
  );

  const wrongBoundary = structuredClone(receipt);
  wrongBoundary.importer_boundary_id = 'urn:ep:aeb:emilia:substituted';
  const boundaryCheck = await verifyPortableStateImportReceiptForManifest(
    wrongBoundary,
    bundle.manifest,
    importerPins,
  );
  assert.equal(boundaryCheck.valid, false);
  assert.ok(boundaryCheck.reasons.includes('receipt_recipient_boundary_mismatch'));

  const dropped = structuredClone(receipt);
  dropped.accepted_object_ids = [];
  const setCheck = await verifyPortableStateImportReceiptForManifest(dropped, bundle.manifest, importerPins);
  assert.equal(setCheck.valid, false);
  assert.ok(setCheck.reasons.includes('receipt_state_set_mismatch'));

  const changedCaid = structuredClone(receipt);
  changedCaid.authority_evidence[0].caid = 'urn:caid:substituted';
  const caidCheck = await verifyPortableStateImportReceiptForManifest(
    changedCaid,
    bundle.manifest,
    importerPins,
  );
  assert.equal(caidCheck.valid, false);
  assert.ok(caidCheck.reasons.includes('receipt_authority_caid_mismatch'));
});

test('payload adapters are pinned exactly once', async () => {
  const bundle = await bundleFor([cogobj()]);
  const duplicate: StatePayloadAdapter = { ...somaCogobjPayloadAdapter };
  const { receipt } = await run(bundle, boundary(), {
    payload_adapters: [somaCogobjPayloadAdapter, duplicate],
  });
  assert.equal(receipt.result, 'INDETERMINATE');
  assert.ok(receipt.reasons.includes('required_payload_profile_unsupported'));
});

test('untrusted payload and verifier failures become signed terminal results, never authority', async () => {
  {
    const bundle = await bundleFor([cogobj()]);
    const cyclic: Record<string, unknown> = { object_id: cogobj().object_id };
    cyclic.self = cyclic;
    bundle.objects = [cyclic];
    const target = boundary();
    const { receipt } = await run(bundle, target);
    assert.equal(receipt.result, 'REFUSED');
    assert.ok(receipt.reasons.includes('payload_not_strict_bounded_json'));
    assert.equal(target.consumptionCount(), 0);
  }

  {
    const bundle = await bundleFor([cogobj()]);
    const target = boundary();
    const { receipt } = await run(bundle, target, {
      source_authority_verifier: {
        async verify() { throw new Error('source verifier unavailable'); },
      },
    });
    assert.equal(receipt.result, 'INDETERMINATE');
    assert.ok(receipt.reasons.includes('source_authority_verifier_failed'));
    assert.equal(target.consumptionCount(), 0);
  }

  {
    const bundle = await bundleFor([cogobj()]);
    const target = boundary();
    const throwingAdapter: StatePayloadAdapter = {
      profile: SOMA_COGOBJ_PAYLOAD_PROFILE,
      validateObject() { throw new Error('payload verifier unavailable'); },
    };
    const { receipt } = await run(bundle, target, { payload_adapters: [throwingAdapter] });
    assert.equal(receipt.result, 'INDETERMINATE');
    assert.ok(receipt.reasons.includes('payload_adapter_failed'));
    assert.equal(target.consumptionCount(), 0);
  }
});

test('recipient state failures preserve unknown and never trigger a blind retry', async () => {
  const delegate = boundary();
  const forFailure = (
    failedMethod: 'lookupAdmission' | 'readHead' | 'commitImport',
  ): RecipientStateBoundary => ({
    readHead(objectId) {
      if (failedMethod === 'readHead') throw new Error('head store unavailable');
      return delegate.readHead(objectId);
    },
    lookupAdmission(handoffId) {
      if (failedMethod === 'lookupAdmission') throw new Error('admission store unavailable');
      return delegate.lookupAdmission(handoffId);
    },
    async commitImport(request) {
      if (failedMethod === 'commitImport') throw new Error('commit response lost');
      return delegate.commitImport(request);
    },
  });

  for (const [method, marker] of [
    ['lookupAdmission', 'recipient_admission_lookup_failed'],
    ['readHead', 'recipient_head_read_indeterminate'],
    ['commitImport', 'recipient_commit_response_unknown'],
  ] as const) {
    const bundle = await bundleFor([cogobj()]);
    const receipt = await importPortableState(bundle, (() => {
      const options = importOptions(forFailure(method));
      authorizeBundle(bundle, options);
      return options;
    })());
    assert.equal(receipt.result, 'INDETERMINATE');
    assert.ok(receipt.reasons.includes(marker));
    assert.ok(receipt.reasons.includes('recipient_boundary_indeterminate'));
    assert.equal(delegate.consumptionCount(), 0);
  }
});

test('vault availability exceptions stay indeterminate before recipient authority consumption', async () => {
  const encrypted = cogobj({
    sensitivity: 'VAULT',
    protection: {
      mode: 'OPAQUE-CIPHERTEXT',
      profile: 'urn:example:hpke:v1',
      key_reference_digest: `sha256:${'a'.repeat(64)}`,
    },
    content: { ciphertext_b64u: Buffer.from('opaque').toString('base64url') },
  });
  const bundle = await bundleFor([encrypted]);
  const target = boundary();
  const { receipt } = await run(bundle, target, {
    async verify_vault_availability() { throw new Error('key service unavailable'); },
  });
  assert.equal(receipt.result, 'INDETERMINATE');
  assert.ok(receipt.reasons.includes('vault_availability_check_failed'));
  assert.ok(receipt.reasons.includes('vault_availability_indeterminate'));
  assert.equal(target.consumptionCount(), 0);
});

test('public receipt verifiers fail closed on hostile canonical input without throwing', async () => {
  const bundle = await bundleFor([cogobj()]);
  const { receipt } = await run(bundle);

  const hostileReceipt = structuredClone(receipt);
  hostileReceipt.accepted_object_ids = ['bad\ud800id'];
  assert.deepEqual(await verifyPortableStateImportReceipt(hostileReceipt, importerPins), {
    valid: false,
    reasons: ['receipt_not_strict_bounded_json'],
  });

  const hostileManifest = structuredClone(bundle.manifest);
  hostileManifest.objects[0].schema_uri = 'bad\ud800schema';
  const checked = await verifyPortableStateImportReceiptForManifest(
    receipt,
    hostileManifest,
    importerPins,
  );
  assert.equal(checked.valid, false);
  assert.ok(checked.reasons.includes('manifest_not_strict_bounded_json'));
});
