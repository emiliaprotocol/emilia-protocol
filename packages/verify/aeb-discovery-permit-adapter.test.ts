// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import test from 'node:test';

import {
  DISCOVERY_PERMIT_BINDING_VERSION,
  DISCOVERY_PERMIT_DISCOVERY_VERSION,
  DISCOVERY_PERMIT_RESOLVER_ATTESTATION_DOMAIN,
  canonicalizeDiscoveryPermit,
  digestDiscoveryPermit,
  digestDiscoveryPermitRaw,
  evaluateDiscoveryPermitContinuity,
  pinDiscoveryPermitTrust,
  signDiscoveryPermitResolverAttestation,
} from './discovery-permit-contract.js';
import {
  AEB_DISCOVERY_PERMIT_ADAPTER_ID,
  AEB_DISCOVERY_PERMIT_ADAPTER_VERSION,
  AEB_DISCOVERY_PERMIT_CONFIG_VERSION,
  DISCOVERY_PERMIT_EVIDENCE_ROLE,
  createAebDiscoveryPermitAdapter,
} from './aeb-discovery-permit-adapter.js';

const NOW = '2026-07-24T12:00:00Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  amount: '125000.00',
  currency: 'USD',
});
const RESOLVER_ID = 'resolver:authority.example:discovery-permit';
const RESOLVER_KEY_ID = 'key:resolver:test';
const resolverKey = crypto.generateKeyPairSync('ed25519');
const attackerKey = crypto.generateKeyPairSync('ed25519');
const resolverPublicKey = resolverKey.publicKey.export({
  format: 'pem',
  type: 'spki',
}).toString();
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
    redirect_map: {},
    resolver: {
      id: RESOLVER_ID,
      key_id: RESOLVER_KEY_ID,
      public_key: resolverPublicKey,
      max_attestation_age_seconds: 60,
    },
    evidence_role: DISCOVERY_PERMIT_EVIDENCE_ROLE,
    ...overrides,
  };
}

function attestation(
  resolved = resolution(),
  adapterConfig = config(),
  options: { expires_at?: string; private_key?: KeyObject; key_id?: string } = {},
) {
  return signDiscoveryPermitResolverAttestation({
    resolver_id: RESOLVER_ID,
    evaluated_at: NOW,
    expires_at: options.expires_at ?? '2026-07-24T12:01:00Z',
    configuration_digest: digestDiscoveryPermit(adapterConfig),
    resolution: resolved,
  }, {
    key_id: options.key_id ?? RESOLVER_KEY_ID,
    private_key: options.private_key ?? resolverKey.privateKey,
  });
}

function resign(artifact: any, privateKey = resolverKey.privateKey): any {
  const { signature: _signature, ...body } = artifact;
  artifact.signature.value = crypto.sign(
    null,
    Buffer.from(
      `${DISCOVERY_PERMIT_RESOLVER_ATTESTATION_DOMAIN}${canonicalizeDiscoveryPermit(body)}`,
      'utf8',
    ),
    privateKey,
  ).toString('base64url');
  return artifact;
}

function input(artifact = attestation(), overrides: Record<string, unknown> = {}) {
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
  const stale = adapter.verifyNative(input(attestation(
    resolution('active', '2026-07-24T11:54:59Z'),
  )));
  const unknown = adapter.verifyNative(input(attestation(resolution('unknown'))));
  const deprecated = adapter.verifyNative(input(attestation(resolution('deprecated'))));

  assert.equal(stale.acceptance, 'INDETERMINATE');
  assert.equal(unknown.acceptance, 'INDETERMINATE');
  assert.equal(deprecated.acceptance, 'REJECTED');
  for (const result of [stale, unknown, deprecated]) {
    assert.equal(result.authorizes_action, false);
  }
});

test('adapter refuses unpinned source/config changes and any transaction trust roots', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const wrongConfig = config({ mapping_digest: `sha256:${'9'.repeat(64)}` });
  const wrongMapping = adapter.verifyNative(input(
    attestation(),
    { adapter_config: wrongConfig },
  ));
  assert.equal(wrongMapping.acceptance, 'REJECTED');
  assert.ok(wrongMapping.reasons.includes('resolver_attestation_config_mismatch'));

  const trustInjected = adapter.verifyNative(input(
    attestation(),
    { trust_roots: [{ issuer: 'attacker' }] },
  ));
  assert.equal(trustInjected.acceptance, 'REJECTED');
  assert.ok(trustInjected.reasons.includes('transaction_trust_roots_forbidden'));
  assert.equal(trustInjected.authorizes_action, false);
});

test('presenter-added trust pin fields invalidate the resolved artifact', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const artifact: any = structuredClone(attestation());
  artifact.mapping_digest_override = `sha256:${'9'.repeat(64)}`;
  artifact.redirect_map = { [pins.permit_url]: 'https://attacker.example/permit.json' };

  const result = adapter.verifyNative(input(artifact));
  assert.equal(result.native_verification, 'FAILED');
  assert.equal(result.acceptance, 'REJECTED');
  assert.ok(result.reasons.includes('resolver_attestation_shape_invalid'));
  assert.equal(result.authorizes_action, false);
});

test('bare presenter-controlled resolution is never treated as verified native evidence', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const result = adapter.verifyNative(input(resolution()));

  assert.equal(result.native_verification, 'FAILED');
  assert.equal(result.acceptance, 'REJECTED');
  assert.ok(result.reasons.includes('resolver_attestation_required'));
  assert.equal(result.authorizes_action, false);
});

test('signature, pinned key, source, provenance, evaluation time, and config mutation fail closed', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const cases: Array<[string, any, Record<string, unknown>]> = [];

  const signatureMutation: any = structuredClone(attestation());
  signatureMutation.signature.value =
    `${signatureMutation.signature.value.startsWith('A') ? 'B' : 'A'}`
    + signatureMutation.signature.value.slice(1);
  cases.push(['signature', signatureMutation, {}]);

  const sourceMutation: any = structuredClone(attestation());
  sourceMutation.source_digest = `sha256:${'8'.repeat(64)}`;
  cases.push(['source', sourceMutation, {}]);

  const provenanceMutation: any = structuredClone(attestation());
  provenanceMutation.provenance_digest = `sha256:${'7'.repeat(64)}`;
  cases.push(['provenance', provenanceMutation, {}]);

  const timeMutation: any = structuredClone(attestation());
  timeMutation.evaluated_at = '2026-07-24T12:00:01Z';
  cases.push(['evaluation time', timeMutation, {}]);

  cases.push(['key', attestation(), {
    adapter_config: config({
      resolver: {
        ...config().resolver,
        public_key: attackerKey.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    }),
  }]);
  cases.push(['config', attestation(), {
    adapter_config: config({ max_age_seconds: 301 }),
  }]);

  for (const [label, artifact, overrides] of cases) {
    const result = adapter.verifyNative(input(artifact, overrides));
    assert.equal(result.native_verification, 'FAILED', label);
    assert.equal(result.acceptance, 'REJECTED', label);
    assert.equal(result.authorizes_action, false, label);
  }
});

test('signed stale relabeling and evaluation-time replay cannot retain ACCEPTED', () => {
  const adapter = createAebDiscoveryPermitAdapter();
  const relabeled: any = structuredClone(attestation(
    resolution('active', '2026-07-24T11:54:59Z'),
  ));
  relabeled.resolution.age_seconds = 60;
  relabeled.resolution.disposition = 'current';
  relabeled.resolution.usable_for_permit = true;
  relabeled.resolution_digest = digestDiscoveryPermit(relabeled.resolution);
  resign(relabeled);

  const staleRelabel = adapter.verifyNative(input(relabeled));
  assert.equal(staleRelabel.native_verification, 'FAILED');
  assert.ok(staleRelabel.reasons.includes('resolver_resolution_rederivation_mismatch'));

  const replay = adapter.verifyNative(input(attestation(), {
    now: '2026-07-24T12:01:01Z',
  }));
  assert.equal(replay.native_verification, 'VERIFIED');
  assert.equal(replay.acceptance, 'INDETERMINATE');
  assert.ok(replay.reasons.includes('resolver_attestation_stale'));
  assert.equal(replay.authorizes_action, false);
});
