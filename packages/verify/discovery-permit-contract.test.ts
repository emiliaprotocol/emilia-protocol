// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DISCOVERY_PERMIT_BINDING_VERSION,
  DISCOVERY_PERMIT_DISCOVERY_VERSION,
  DISCOVERY_PERMIT_RESOLUTION_VERSION,
  canonicalizeDiscoveryPermit,
  digestDiscoveryPermit,
  digestDiscoveryPermitRaw,
  evaluateDiscoveryPermitContinuity,
  pinDiscoveryPermitTrust,
  type DiscoveryPermitDocumentProvenance,
  type DiscoveryPermitTrustPinsInput,
} from './discovery-permit-contract.js';

const NOW = '2026-07-24T12:00:00Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  amount: '125000.00',
  currency: 'USD',
  destination_digest: `sha256:${'d'.repeat(64)}`,
});
const DISCOVERY_SCHEMA_DIGEST = `sha256:${'1'.repeat(64)}` as const;
const PERMIT_SCHEMA_DIGEST = `sha256:${'2'.repeat(64)}` as const;
const MAPPING_DIGEST = `sha256:${'3'.repeat(64)}` as const;

function pinsInput(overrides: Partial<DiscoveryPermitTrustPinsInput> = {}): DiscoveryPermitTrustPinsInput {
  return {
    origin: 'https://authority.example',
    discovery_url: 'https://authority.example/.well-known/emilia-discovery-permit.json',
    permit_url: 'https://authority.example/permits/payment-release.json',
    discovery_schema_digest: DISCOVERY_SCHEMA_DIGEST,
    permit_schema_digest: PERMIT_SCHEMA_DIGEST,
    mapping_digest: MAPPING_DIGEST,
    max_age_seconds: 300,
    redirect_map: {},
    ...overrides,
  };
}

function documents(
  pins = pinDiscoveryPermitTrust(pinsInput()),
  overrides: {
    status?: 'active' | 'unknown' | 'deprecated';
    issued_at?: string;
    discovery?: Record<string, unknown>;
    binding?: Record<string, unknown>;
  } = {},
) {
  const source = {
    origin: pins.origin,
    discovery_url: pins.discovery_url,
    permit_url: pins.permit_url,
  };
  const schemaDigests = {
    discovery: pins.discovery_schema_digest,
    permit_binding: pins.permit_schema_digest,
  };
  const common = {
    source,
    schema_digests: schemaDigests,
    mapping_digest: pins.mapping_digest,
    status: overrides.status ?? 'active',
    issued_at: overrides.issued_at ?? '2026-07-24T11:59:00Z',
  };
  const discovery = {
    '@type': DISCOVERY_PERMIT_DISCOVERY_VERSION,
    ...common,
    ...overrides.discovery,
  };
  const binding = {
    '@type': DISCOVERY_PERMIT_BINDING_VERSION,
    ...common,
    caid: CAID,
    action_digest: digestDiscoveryPermit(ACTION),
    ...overrides.binding,
  };
  return { discovery, binding };
}

function documentProvenance(
  role: 'discovery' | 'permit',
  requestedUrl: string,
  resolvedUrl: string,
  document: unknown,
): DiscoveryPermitDocumentProvenance {
  const raw = JSON.stringify(document);
  return {
    role,
    requested_url: requestedUrl,
    resolved_url: resolvedUrl,
    connected_address: '93.184.216.34',
    media_type: 'application/json',
    byte_length: Buffer.byteLength(raw),
    raw_digest: digestDiscoveryPermitRaw(raw),
    canonical_digest: digestDiscoveryPermit(document),
    redirect_chain: Object.freeze([requestedUrl, ...(requestedUrl === resolvedUrl ? [] : [resolvedUrl])]),
  };
}

function evaluate(overrides: Parameters<typeof documents>[1] = {}) {
  const pins = pinDiscoveryPermitTrust(pinsInput());
  const { discovery, binding } = documents(pins, overrides);
  return evaluateDiscoveryPermitContinuity({
    pins,
    discovery,
    binding,
    caid: CAID,
    action: ACTION,
    now: NOW,
    provenance: {
      discovery: documentProvenance('discovery', pins.discovery_url, pins.discovery_url, discovery),
      permit: documentProvenance('permit', pins.permit_url, pins.permit_url, binding),
    },
  });
}

test('pins and resolution are immutable snapshots with raw and canonical provenance', () => {
  const mutable = pinsInput();
  const pins = pinDiscoveryPermitTrust(mutable);
  mutable.origin = 'https://attacker.example';
  mutable.redirect_map[pins.discovery_url] = 'https://attacker.example/discovery.json';

  assert.equal(pins.origin, 'https://authority.example');
  assert.deepEqual(pins.redirect_map, {});
  assert.equal(Object.isFrozen(pins), true);
  assert.equal(Object.isFrozen(pins.redirect_map), true);

  const resolution = evaluate();
  assert.equal(resolution['@type'], DISCOVERY_PERMIT_RESOLUTION_VERSION);
  assert.equal(resolution.disposition, 'current');
  assert.equal(resolution.usable_for_permit, true);
  assert.equal(resolution.authorizes_action, false);
  assert.match(resolution.provenance.discovery.raw_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(resolution.provenance.discovery.canonical_digest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(
    resolution.provenance.discovery.raw_digest,
    resolution.provenance.discovery.canonical_digest,
  );
  assert.equal(Object.isFrozen(resolution), true);
  assert.equal(Object.isFrozen(resolution.binding), true);
});

test('canonicalization is deterministic while the raw digest preserves source bytes', () => {
  const left = '{"b":2, "a":1}';
  const right = '{"a":1,"b":2}';
  assert.notEqual(digestDiscoveryPermitRaw(left), digestDiscoveryPermitRaw(right));
  assert.equal(
    digestDiscoveryPermit(JSON.parse(left)),
    digestDiscoveryPermit(JSON.parse(right)),
  );
  assert.equal(canonicalizeDiscoveryPermit(JSON.parse(left)), '{"a":1,"b":2}');
});

test('active, stale, unknown, and deprecated documents have closed dispositions', () => {
  assert.equal(evaluate().disposition, 'current');

  const stale = evaluate({ issued_at: '2026-07-24T11:54:59Z' });
  assert.equal(stale.disposition, 'stale');
  assert.equal(stale.usable_for_permit, false);

  const unknown = evaluate({ status: 'unknown' });
  assert.equal(unknown.disposition, 'unknown');
  assert.equal(unknown.usable_for_permit, false);

  const deprecated = evaluate({ status: 'deprecated' });
  assert.equal(deprecated.disposition, 'deprecated');
  assert.equal(deprecated.usable_for_permit, false);

  for (const resolution of [stale, unknown, deprecated]) {
    assert.equal(resolution.authorizes_action, false);
  }
});

test('discovery and permit sources, schema pins, mapping, CAID, and action must agree exactly', () => {
  const cases: Array<[string, Parameters<typeof documents>[1]]> = [
    ['source_agreement_failed', {
      binding: {
        source: {
          origin: 'https://attacker.example',
          discovery_url: pinsInput().discovery_url,
          permit_url: pinsInput().permit_url,
        },
      },
    }],
    ['schema_digest_mismatch', {
      discovery: {
        schema_digests: {
          discovery: `sha256:${'9'.repeat(64)}`,
          permit_binding: PERMIT_SCHEMA_DIGEST,
        },
      },
    }],
    ['mapping_digest_mismatch', {
      binding: { mapping_digest: `sha256:${'8'.repeat(64)}` },
    }],
    ['caid_mismatch', {
      binding: { caid: `caid:1:payment.release.1:jcs-sha256:${'B'.repeat(43)}` },
    }],
    ['action_digest_mismatch', {
      binding: { action_digest: `sha256:${'7'.repeat(64)}` },
    }],
  ];

  for (const [code, overrides] of cases) {
    assert.throws(
      () => evaluate(overrides),
      (error: any) => error?.code === code,
      code,
    );
  }
});

test('future timestamps, malformed CAIDs, and provenance substitution fail closed', () => {
  assert.throws(
    () => evaluate({ issued_at: '2026-07-24T12:00:01Z' }),
    (error: any) => error?.code === 'issued_at_in_future',
  );
  assert.throws(
    () => evaluate({ binding: { caid: 'caid:attacker' } }),
    (error: any) => error?.code === 'binding_shape_invalid',
  );

  const pins = pinDiscoveryPermitTrust(pinsInput());
  const { discovery, binding } = documents(pins);
  const provenance = {
    discovery: documentProvenance('discovery', pins.discovery_url, pins.discovery_url, discovery),
    permit: documentProvenance('permit', pins.permit_url, pins.permit_url, binding),
  };
  provenance.permit.canonical_digest = `sha256:${'f'.repeat(64)}`;
  assert.throws(
    () => evaluateDiscoveryPermitContinuity({
      pins,
      discovery,
      binding,
      caid: CAID,
      action: ACTION,
      now: NOW,
      provenance,
    }),
    (error: any) => error?.code === 'provenance_digest_mismatch',
  );
});
