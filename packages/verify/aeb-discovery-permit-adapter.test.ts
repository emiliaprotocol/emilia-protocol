// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DISCOVERY_PERMIT_BINDING_VERSION,
  DISCOVERY_PERMIT_DISCOVERY_VERSION,
  digestDiscoveryPermit,
  digestDiscoveryPermitRaw,
  evaluateDiscoveryPermitContinuity,
  pinDiscoveryPermitTrust,
} from './src/discovery-permit-contract.js';
import {
  AEB_DISCOVERY_PERMIT_ADAPTER_ID,
  AEB_DISCOVERY_PERMIT_ADAPTER_VERSION,
  AEB_DISCOVERY_PERMIT_CONFIG_VERSION,
  DISCOVERY_PERMIT_EVIDENCE_ROLE,
  createAebDiscoveryPermitAdapter,
} from './src/aeb-discovery-permit-adapter.js';

const NOW = '2026-07-24T12:00:00Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  amount: '125000.00',
  currency: 'USD',
});
const pins = pinDiscoveryPermitTrust({
  origin: 'https://authority.example',
  discovery_url: 'https://authority.example/.well-known/emilia-discovery-permit.json',
  permit_url: 'https://authority.example/permits/payment-release.json',
  discovery_schema_digest: `sha256:${'1'.repeat(64)}`,
  permit_schema_digest: `sha256:${'2'.repeat(64)}`,
  mapping_digest: `sha256:${'3'.repeat(64)}`,
  max_age_seconds: 300,
  redirect_map: {},
});

function resolution(status: 'active' | 'unknown' | 'deprecated' = 'active', issuedAt = '2026-07-24T11:59:00Z') {
  const source = {
    origin: pins.origin,
    discovery_url: pins.discovery_url,
    permit_url: pins.permit_url,
  };
  const schemaDigests = {
    discovery: pins.discovery_schema_digest,
    permit_binding: pins.permit_schema_digest,
  };
  const discovery = {
    '@type': DISCOVERY_PERMIT_DISCOVERY_VERSION,
    source,
    schema_digests: schemaDigests,
    mapping_digest: pins.mapping_digest,
    status,
    issued_at: issuedAt,
  };
  const binding = {
    '@type': DISCOVERY_PERMIT_BINDING_VERSION,
    source,
    schema_digests: schemaDigests,
    mapping_digest: pins.mapping_digest,
    status,
    issued_at: issuedAt,
    caid: CAID,
    action_digest: digestDiscoveryPermit(ACTION),
  };
  const provenanceFor = (
    role: 'discovery' | 'permit',
    url: string,
    document: unknown,
  ) => {
    const raw = JSON.stringify(document);
    return {
      role,
      requested_url: url,
      resolved_url: url,
      connected_address: '93.184.216.34',
      media_type: 'application/json' as const,
      byte_length: Buffer.byteLength(raw),
      raw_digest: digestDiscoveryPermitRaw(raw),
      canonical_digest: digestDiscoveryPermit(document),
      redirect_chain: [url],
    };
  };
  return evaluateDiscoveryPermitContinuity({
    pins,
    discovery,
    binding,
    caid: CAID,
    action: ACTION,
    now: NOW,
    provenance: {
      discovery: provenanceFor('discovery', pins.discovery_url, discovery),
      permit: provenanceFor('permit', pins.permit_url, binding),
    },
  });
}

function config(overrides: Record<string, unknown> = {}) {
  return {
    '@version': AEB_DISCOVERY_PERMIT_CONFIG_VERSION,
    source: {
      origin: pins.origin,
      discovery_url: pins.discovery_url,
      permit_url: pins.permit_url,
    },
    schema_digests: {
      discovery: pins.discovery_schema_digest,
      permit_binding: pins.permit_schema_digest,
    },
    mapping_digest: pins.mapping_digest,
    max_age_seconds: pins.max_age_seconds,
    evidence_role: DISCOVERY_PERMIT_EVIDENCE_ROLE,
    ...overrides,
  };
}

function input(artifact = resolution(), overrides: Record<string, unknown> = {}) {
  return {
    artifact,
    artifact_ref: 'discovery-permit:payment-release',
    status: {
      checked_at: NOW,
      expires_at: '2026-07-24T12:01:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: [],
    adapter_config: config(),
    expected_action: ACTION,
    now: NOW,
    ...overrides,
  };
}

test('native adapter emits a verified evidence-only AEB leg, never authorization', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  assert.equal(adapter.id, AEB_DISCOVERY_PERMIT_ADAPTER_ID);
  assert.equal(adapter.version, AEB_DISCOVERY_PERMIT_ADAPTER_VERSION);

  const native = adapter.verifyNative(input());
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.equal(native.evidence_role, DISCOVERY_PERMIT_EVIDENCE_ROLE);
  assert.equal(native.authorization, 'EVIDENCE_ONLY');
  assert.equal(native.authorizes_action, false);
  assert.match(native.evidence_digest, /^sha256:[0-9a-f]{64}$/);

  const mapped = adapter.mapAction({ ...input(), profile: {} as any, native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.equal(mapped.caid, CAID);
  assert.equal(mapped.action_digest, digestDiscoveryPermit(ACTION));
  assert.equal(Object.hasOwn(native, 'invoke_allowed'), false);
});

test('action substitution maps to MISMATCH and cannot inherit the discovered CAID', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const native = adapter.verifyNative(input());
  const expected_action = { ...ACTION, amount: '125001.00' };
  const mapped = adapter.mapAction({
    ...input(),
    expected_action,
    profile: {} as any,
    native,
  });
  assert.equal(mapped.mapping, 'MISMATCH');
  assert.equal(mapped.caid, null);
  assert.equal(mapped.action_digest, null);
});

test('stale and unknown discovery are indeterminate; deprecated discovery is rejected', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const stale = adapter.verifyNative(input(resolution('active', '2026-07-24T11:54:59Z')));
  const unknown = adapter.verifyNative(input(resolution('unknown')));
  const deprecated = adapter.verifyNative(input(resolution('deprecated')));

  assert.equal(stale.acceptance, 'INDETERMINATE');
  assert.equal(unknown.acceptance, 'INDETERMINATE');
  assert.equal(deprecated.acceptance, 'REJECTED');
  for (const result of [stale, unknown, deprecated]) {
    assert.equal(result.authorizes_action, false);
  }
});

test('adapter refuses unpinned source/config changes and any transaction trust roots', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const wrongMapping = adapter.verifyNative(input(
    resolution(),
    { adapter_config: config({ mapping_digest: `sha256:${'9'.repeat(64)}` }) },
  ));
  assert.equal(wrongMapping.acceptance, 'REJECTED');
  assert.ok(wrongMapping.reasons.includes('adapter_config_does_not_match_resolution'));

  const trustInjected = adapter.verifyNative(input(
    resolution(),
    { trust_roots: [{ issuer: 'attacker' }] },
  ));
  assert.equal(trustInjected.acceptance, 'REJECTED');
  assert.ok(trustInjected.reasons.includes('transaction_trust_roots_forbidden'));
  assert.equal(trustInjected.authorizes_action, false);
});

test('presenter-added trust pin fields invalidate the resolved artifact', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const artifact: any = structuredClone(resolution());
  artifact.mapping_digest_override = `sha256:${'9'.repeat(64)}`;
  artifact.redirect_map = { [pins.permit_url]: 'https://attacker.example/permit.json' };

  const result = adapter.verifyNative(input(artifact));
  assert.equal(result.native_verification, 'FAILED');
  assert.equal(result.acceptance, 'REJECTED');
  assert.ok(result.reasons.includes('resolution_shape_invalid'));
  assert.equal(result.authorizes_action, false);
});
