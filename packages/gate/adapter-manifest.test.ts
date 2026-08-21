// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  loadAdapterManifestRegistry,
  signAdapterManifest,
} from './adapter-manifest.js';

const NOW = '2026-08-20T18:00:00.000Z';
const D = (label: string) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;

function fixture(overrides: Record<string, any> = {}) {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const manifest = signAdapterManifest({
    adapter_id: 'adapter:stripe:payout:v1',
    system: 'stripe',
    version: 1,
    status: 'active',
    issued_at: '2026-08-20T17:55:00.000Z',
    valid_from: '2026-08-20T17:56:00.000Z',
    expires_at: '2026-08-21T18:00:00.000Z',
    external_spec: {
      name: 'stripe-api',
      revision: '2026-06-30.basil',
      digest: D('stripe-api:2026-06-30.basil'),
      uri: 'https://docs.stripe.com/api/versioning',
    },
    implementation: {
      artifact_digest: D('stripe-adapter-build'),
      source_commit: 'a'.repeat(40),
    },
    build_receipt_digest: D('stripe-adapter-build-receipt'),
    conformance: {
      profile_id: 'EP-ADAPTER-CONFORMANCE-v1',
      profile_revision: '1',
      receipt_digest: D('stripe-adapter-conformance-receipt'),
      passed_at: '2026-08-20T17:54:00.000Z',
    },
    supported_operations: ['payout.create', 'payout.retrieve'],
    ...overrides,
  }, {
    issuer_id: 'customer:finance',
    key_id: 'key:finance-adapter-registry',
    private_key: pair.privateKey,
  });
  return { manifest, trusted_keys: {
    'key:finance-adapter-registry': { issuer_id: 'customer:finance', public_key: publicKey },
  } };
}

test('registry resolves only a signed adapter at the pinned external and implementation revision', () => {
  const { manifest, trusted_keys } = fixture();
  const registry = loadAdapterManifestRegistry({ manifests: [manifest], trusted_keys, now: NOW });
  const resolved = registry.resolve({
    adapter_id: 'adapter:stripe:payout:v1',
    external_spec_digest: D('stripe-api:2026-06-30.basil'),
    implementation_digest: D('stripe-adapter-build'),
    operation: 'payout.create',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.manifest.external_spec.revision, '2026-06-30.basil');
  assert.equal(resolved.manifest.conformance.profile_id, 'EP-ADAPTER-CONFORMANCE-v1');
  assert.equal(registry.resolve({
    adapter_id: 'adapter:stripe:payout:v1',
    external_spec_digest: D('stripe-api:later'),
    implementation_digest: D('stripe-adapter-build'),
    operation: 'payout.create',
  }).reason, 'adapter_external_revision_drift');
  assert.equal(registry.resolve({
    adapter_id: 'adapter:stripe:payout:v1',
    external_spec_digest: D('stripe-api:2026-06-30.basil'),
    implementation_digest: D('different-build'),
    operation: 'payout.create',
  }).reason, 'adapter_implementation_drift');
});

test('registry refuses tampering, duplicate identities, unsupported operations, and withdrawn adapters', () => {
  const first = fixture();
  const tampered = structuredClone(first.manifest);
  tampered.external_spec.revision = 'attacker';
  assert.throws(() => loadAdapterManifestRegistry({
    manifests: [tampered], trusted_keys: first.trusted_keys, now: NOW,
  }), /signature|digest/i);
  assert.throws(() => loadAdapterManifestRegistry({
    manifests: [first.manifest, first.manifest], trusted_keys: first.trusted_keys, now: NOW,
  }), /duplicate/i);
  const registry = loadAdapterManifestRegistry({
    manifests: [first.manifest], trusted_keys: first.trusted_keys, now: NOW,
  });
  assert.equal(registry.resolve({
    adapter_id: 'adapter:stripe:payout:v1',
    external_spec_digest: D('stripe-api:2026-06-30.basil'),
    implementation_digest: D('stripe-adapter-build'),
    operation: 'refund.create',
  }).reason, 'adapter_operation_unsupported');

  const withdrawn = fixture({ status: 'withdrawn' });
  const withdrawnRegistry = loadAdapterManifestRegistry({
    manifests: [withdrawn.manifest], trusted_keys: withdrawn.trusted_keys, now: NOW,
  });
  assert.equal(withdrawnRegistry.resolve({
    adapter_id: 'adapter:stripe:payout:v1',
    external_spec_digest: D('stripe-api:2026-06-30.basil'),
    implementation_digest: D('stripe-adapter-build'),
    operation: 'payout.create',
  }).reason, 'adapter_not_active');
});
