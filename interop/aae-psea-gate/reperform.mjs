// SPDX-License-Identifier: Apache-2.0

import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyGateAttemptPair } from './verify.mjs';

export const SOURCE_REPOSITORY = 'https://github.com/MoltyCel/aae-conformance-vectors';
export const SOURCE_COMMIT = 'e8c00e5014c52a4cb4ff51d24c360db5c82d599e';
export const SOURCE_VECTOR_COMMIT = '48450505c05c7182962c166781354e88412581e7';
export const LIVE_VECTOR_COMMIT = '27227b5c4944f57a033fb45851f9aae0659b9590';
export const LIVE_VECTOR_FLIP_COMMIT = '9e4ab541fd79938676ec92cc0f230987a9bc4b08';
export const WHO_CONFIRMATION_COMMIT = '8bed788b237d8aade36b26e443c1455f77ebaa5d';
export const FIXTURE_PATH = 'fixtures/aae-psea-proof-exchange-v1';
export const SOURCE_VECTOR_PATH = 'interop/psea/vectors/xp-1-aligned-principal.json';

const SOURCE_PINS = Object.freeze({
  [`${FIXTURE_PATH}/aae-envelope.jws`]:
    'c2db119de3f04a775a7c11afd1b78a6d6e03780ad84fc09f76ccb2ccac7c2b9b',
  [`${FIXTURE_PATH}/action-payload.json`]:
    'd6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606',
  [`${FIXTURE_PATH}/issuer-trust.json`]:
    '8ee59a17b9ff4b36dfe9f4dbfd49e12aafbe0443cc8477e243adec87aad4a2a9',
  [`${FIXTURE_PATH}/expected.json`]:
    '51e6ac125835573c44f63aeb0a0645f47cb4eef17756b4394c6f5a9c3544bb70',
  [`${FIXTURE_PATH}/manifest.json`]:
    '11cd5c6ff281c5253f28248b230d90dbb198a3435bf78d7a7e1a7c8c2fe14af2',
  [`${FIXTURE_PATH}/README.md`]:
    'fcf699e7dffa2570c7b7f1868d670bb1e5a75aedaa969a582002092b447149eb',
  [SOURCE_VECTOR_PATH]:
    '5405eff68026f02e8380d09075b07fbe6104448e2d1ec7c9be7d8c9085cc1d06',
});

const FIXTURE_PINS = Object.freeze(Object.fromEntries(
  Object.entries(SOURCE_PINS).filter(([path]) => path.startsWith(`${FIXTURE_PATH}/`)),
));

const LIVE_PINS = Object.freeze({
  ...FIXTURE_PINS,
  [SOURCE_VECTOR_PATH]:
    '7585368a327c4b33b03f0a8e5b2569c9aa21894bf6ba390fb07ddc64cbda63b2',
});

const HISTORICAL_WHO_STATUS = 'proposed convention, pending cross-run confirmation';
const CONFIRMED_WHO_STATUS =
  'confirmed at head 8bed788 (Mohamad Khalil-Yossif); WHO linkage established, PSEA conformance not established, kid-to-principal mapping supplied not derived';

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function json(bytes, path) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`${path} is not valid JSON`);
  }
}

function exact(value, expected, path) {
  if (value !== expected) fail(`${path}: expected ${expected}, got ${value}`);
}

function validUnicodeScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** RFC 8785 canonicalization for the I-JSON subset used by the exchange. */
export function canonicalize(value, seen = new WeakSet()) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    if (!validUnicodeScalarString(value)) fail('invalid Unicode scalar');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) fail('non-I-JSON number');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (!value || typeof value !== 'object') fail('non-JSON value');
  if (seen.has(value)) fail('cyclic JSON');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalize(entry, seen)).join(',')}]`;
    }
    const keys = Object.keys(value).sort();
    for (const key of keys) {
      if (!validUnicodeScalarString(key) || value[key] === undefined) {
        fail('non-I-JSON member');
      }
    }
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], seen)}`)
      .join(',')}}`;
  } finally {
    seen.delete(value);
  }
}

function resolveAssertionKey(header, trust) {
  exact(header.alg, 'EdDSA', 'JWS protected header alg');
  exact(header.cty, 'aae+json', 'JWS protected header cty');
  const kid = header.kid;
  if (typeof kid !== 'string' || !kid.includes('#')) fail('JWS kid is not a DID URL');
  exact(kid, trust.trust_decision.resolves_kid, 'JWS kid');
  const signingDid = kid.split('#', 1)[0];
  if (!trust.trust_decision.trusted_issuers.includes(signingDid)) {
    fail('JWS signing DID is not in the pinned trust decision');
  }
  const document = trust.did_documents.find((item) => item.id === signingDid);
  if (!document || !document.assertionMethod.includes(kid)) {
    fail('JWS kid is not authorized for assertionMethod');
  }
  const method = document.verificationMethod.find((item) => item.id === kid);
  const jwk = method?.publicKeyJwk;
  if (jwk?.kty !== 'OKP' || jwk?.crv !== 'Ed25519') {
    fail('JWS verification method is not Ed25519');
  }
  return { key: createPublicKey({ key: jwk, format: 'jwk' }), signingDid };
}

function verifyAaeFixture(jwsBytes, trust, sourceVector) {
  const compact = jwsBytes.toString('ascii');
  const parts = compact.split('.');
  if (parts.length !== 3) fail('AAE fixture is not a compact JWS');
  const [protectedB64u, payloadB64u, signatureB64u] = parts;
  const header = json(Buffer.from(protectedB64u, 'base64url'), 'JWS protected header');
  const payload = json(Buffer.from(payloadB64u, 'base64url'), 'JWS payload');
  const { key, signingDid } = resolveAssertionKey(header, trust);
  if (!verifySignature(
    null,
    Buffer.from(`${protectedB64u}.${payloadB64u}`, 'ascii'),
    key,
    Buffer.from(signatureB64u, 'base64url'),
  )) {
    fail('AAE Ed25519 signature is invalid');
  }

  exact(payload.issuer, signingDid, 'AAE issuer/signing authority');
  const aae = payload.credentialSubject?.aae;
  if (!aae?.mandate || !aae.constraints || !aae.validity) fail('AAE blocks are incomplete');

  const context = sourceVector.input?.context;
  if (!context?.subject_binding?.challenge_response_valid) fail('subject binding input is not satisfied');
  const now = Date.parse(context.current_time);
  const notBefore = Date.parse(aae.validity.not_before);
  const notAfter = Date.parse(aae.validity.not_after);
  if (!(now >= notBefore && now <= notAfter)) fail('AAE is outside the pinned validity window');
  if (aae.validity.single_use && sourceVector.input?.consumed_ids?.includes(payload.id)) {
    fail('AAE single-use identifier was already consumed');
  }
  if (!aae.mandate.actions.includes(context.requested_action)) {
    fail('requested action is outside the AAE mandate');
  }
  const transaction = aae.constraints.max_transaction_value;
  if (
    !transaction
    || context.action_context.currency !== transaction.currency
    || context.action_context.amount > transaction.value
  ) {
    fail('AAE max_transaction_value constraint is not satisfied');
  }
  if (aae.validity.revocation_check || aae.mandate.delegation) {
    fail('fixture unexpectedly requires conditional AAE steps 8 or 9');
  }
  return { header, payload, result: 'ACCEPT', verification_step: 7 };
}

export function verifyActionBinding(payloadBytes, aaePayload) {
  const parsed = json(payloadBytes, 'action payload');
  const canonical = Buffer.from(canonicalize(parsed), 'utf8');
  if (!canonical.equals(payloadBytes)) fail('action payload bytes are not exact RFC 8785 output');
  const digestBytes = createHash('sha256').update(payloadBytes).digest();
  const binding = aaePayload.credentialSubject?.aae?.mandate?.action_binding;
  if (!binding) fail('authenticated action_binding is missing');
  exact(binding.alg, 'sha-256', 'action_binding alg');
  exact(binding.canonicalization, 'JCS (RFC 8785)', 'action_binding canonicalization');
  exact(binding.payload_digest, `sha-256:${digestBytes.toString('base64url')}`, 'action_binding digest');
  return { hex: digestBytes.toString('hex'), b64u: digestBytes.toString('base64url') };
}

async function fetchSourceAt(commit, pins, fetchImpl) {
  if (typeof fetchImpl !== 'function') fail('fetch implementation is unavailable');
  const files = {};
  for (const [path, expectedDigest] of Object.entries(pins)) {
    const url = `https://raw.githubusercontent.com/MoltyCel/aae-conformance-vectors/${commit}/${path}`;
    const response = await fetchImpl(url);
    if (!response.ok) fail(`source fetch failed for ${path}: HTTP ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    exact(sha256(bytes), expectedDigest, `${path} sha256`);
    files[path] = bytes;
  }
  return files;
}

export async function fetchPinnedSource(fetchImpl = globalThis.fetch) {
  return fetchSourceAt(SOURCE_COMMIT, SOURCE_PINS, fetchImpl);
}

export async function fetchConfirmedLiveSource(fetchImpl = globalThis.fetch) {
  return fetchSourceAt(LIVE_VECTOR_COMMIT, LIVE_PINS, fetchImpl);
}

export function verifyPinnedSource(files, gateRecord) {
  for (const [path, expectedDigest] of Object.entries(SOURCE_PINS)) {
    if (!Buffer.isBuffer(files[path])) fail(`source file is missing: ${path}`);
    exact(sha256(files[path]), expectedDigest, `${path} sha256`);
  }

  const manifest = json(files[`${FIXTURE_PATH}/manifest.json`], 'source manifest');
  const expected = json(files[`${FIXTURE_PATH}/expected.json`], 'source expected result');
  const trust = json(files[`${FIXTURE_PATH}/issuer-trust.json`], 'issuer trust');
  const sourceVector = json(
    files[SOURCE_VECTOR_PATH],
    'source vector',
  );
  exact(manifest.head_commit, SOURCE_VECTOR_COMMIT, 'source manifest head_commit');
  exact(manifest.source_vector, SOURCE_VECTOR_PATH, 'source vector path');
  exact(manifest.jws_sha256, SOURCE_PINS[`${FIXTURE_PATH}/aae-envelope.jws`], 'manifest JWS digest');
  exact(
    manifest.action_payload_sha256,
    SOURCE_PINS[`${FIXTURE_PATH}/action-payload.json`],
    'manifest action payload digest',
  );

  const aae = verifyAaeFixture(files[`${FIXTURE_PATH}/aae-envelope.jws`], trust, sourceVector);
  exact(aae.result, expected.aae_native.result, 'AAE native result');
  exact(aae.verification_step, expected.aae_native.verification_step, 'AAE verification step');
  const action = verifyActionBinding(
    files[`${FIXTURE_PATH}/action-payload.json`],
    aae.payload,
  );
  exact(action.hex, manifest.action_payload_sha256, 'recomputed action digest');
  exact(
    action.hex,
    Buffer.from(sourceVector.input.join_what.secondary_digest.value, 'base64').toString('hex'),
    'source-vector secondary action digest',
  );

  exact(gateRecord.source_fixture.commit, SOURCE_COMMIT, 'Gate source commit');
  exact(
    gateRecord.source_fixture.jws_digest,
    `sha256:${manifest.jws_sha256}`,
    'Gate JWS digest',
  );
  exact(
    gateRecord.source_fixture.action_payload_digest,
    `sha256:${action.hex}`,
    'Gate action payload digest',
  );
  const gate = verifyGateAttemptPair(gateRecord);

  return {
    '@version': 'EMILIA-AAE-PSEA-INDEPENDENT-RETURN-v1',
    source: {
      repository: SOURCE_REPOSITORY,
      commit: SOURCE_COMMIT,
      fixture_path: `${FIXTURE_PATH}/`,
      source_vector_commit: SOURCE_VECTOR_COMMIT,
      files: Object.fromEntries(
        Object.entries(SOURCE_PINS).map(([path, digest]) => [path, `sha256:${digest}`]),
      ),
    },
    verification: {
      exact_source_bytes: 'VERIFIED',
      aae_signature: 'VALID',
      aae_native: `ACCEPT@${aae.verification_step}`,
      action_payload_jcs: 'EXACT',
      authenticated_action_binding: 'MATCH',
      action_digest: `sha256:${action.hex}`,
      gate_attempt_pair: gate.valid ? 'VALID' : 'INVALID',
      second_admission: `${gate.second_admission}/${gate.second_reason}`,
    },
    accepted_result: {
      action_linkage: 'EQUIVALENT',
      principal_linkage: 'PROPOSED',
      psea_conformance: 'NOT_ESTABLISHED',
      provider_effect: 'INDETERMINATE',
    },
  };
}

export function verifyConfirmedVectorDelta(historicalBytes, liveBytes) {
  const historical = json(historicalBytes, 'historical source vector');
  const live = json(liveBytes, 'confirmed live source vector');

  exact(historical.status, 'proposed', 'historical vector status');
  exact(historical.input?.join_who?.status, HISTORICAL_WHO_STATUS, 'historical WHO status');
  exact(live.status, 'confirmed', 'live vector status');
  exact(live.input?.join_who?.status, CONFIRMED_WHO_STATUS, 'live WHO status');
  exact(live.expected?.stages?.action_linkage?.value, 'EQUIVALENT', 'live action linkage');
  exact(live.expected?.stages?.principal_linkage?.value, 'SAME', 'live principal linkage');

  const normalizedLive = JSON.parse(JSON.stringify(live));
  normalizedLive.status = historical.status;
  normalizedLive.input.join_who.status = historical.input.join_who.status;
  exact(
    canonicalize(normalizedLive),
    canonicalize(historical),
    'historical-to-live vector delta',
  );

  return {
    action_linkage: live.expected.stages.action_linkage.value,
    principal_linkage: live.expected.stages.principal_linkage.value,
  };
}

export function verifyConfirmedLiveState(historicalFiles, liveFiles, gateRecord) {
  const historicalReturn = verifyPinnedSource(historicalFiles, gateRecord);

  for (const [path, expectedDigest] of Object.entries(LIVE_PINS)) {
    if (!Buffer.isBuffer(liveFiles[path])) fail(`live source file is missing: ${path}`);
    exact(sha256(liveFiles[path]), expectedDigest, `live ${path} sha256`);
  }
  for (const path of Object.keys(FIXTURE_PINS)) {
    if (!historicalFiles[path].equals(liveFiles[path])) {
      fail(`frozen fixture changed at live head: ${path}`);
    }
  }

  const confirmed = verifyConfirmedVectorDelta(
    historicalFiles[SOURCE_VECTOR_PATH],
    liveFiles[SOURCE_VECTOR_PATH],
  );

  return {
    '@version': 'EMILIA-AAE-PSEA-CONFIRMED-LIVE-STATE-v1',
    historical_return: {
      path: 'interop/aae-psea-gate/independent-return.v1.json',
      source_commit: SOURCE_COMMIT,
      source_vector_sha256: `sha256:${SOURCE_PINS[SOURCE_VECTOR_PATH]}`,
      exact_source_bytes: historicalReturn.verification.exact_source_bytes,
      principal_linkage_status: historicalReturn.accepted_result.principal_linkage,
    },
    live_vector: {
      repository: SOURCE_REPOSITORY,
      commit: LIVE_VECTOR_COMMIT,
      vector_flip_commit: LIVE_VECTOR_FLIP_COMMIT,
      confirmation_evidence_commit: WHO_CONFIRMATION_COMMIT,
      path: SOURCE_VECTOR_PATH,
      sha256: `sha256:${LIVE_PINS[SOURCE_VECTOR_PATH]}`,
    },
    verification: {
      frozen_fixture_files: 'BYTE_IDENTICAL',
      live_vector_bytes: 'VERIFIED',
      historical_to_live_delta: 'TWO_STATUS_FIELDS_ONLY',
    },
    confirmed_state: {
      action_linkage: confirmed.action_linkage,
      principal_linkage: confirmed.principal_linkage,
      principal_linkage_status: 'CONFIRMED',
      principal_mapping_basis: 'SUPPLIED_NOT_DERIVED',
      psea_conformance: 'NOT_ESTABLISHED',
    },
  };
}

export async function performIndependentReturn(fetchImpl = globalThis.fetch) {
  const files = await fetchPinnedSource(fetchImpl);
  const gatePath = fileURLToPath(new URL('./gate-attempt-pair.v1.json', import.meta.url));
  const gateRecord = JSON.parse(await readFile(gatePath, 'utf8'));
  return verifyPinnedSource(files, gateRecord);
}

export async function performConfirmedLiveState(fetchImpl = globalThis.fetch) {
  const [historicalFiles, liveFiles] = await Promise.all([
    fetchPinnedSource(fetchImpl),
    fetchConfirmedLiveSource(fetchImpl),
  ]);
  const gatePath = fileURLToPath(new URL('./gate-attempt-pair.v1.json', import.meta.url));
  const gateRecord = JSON.parse(await readFile(gatePath, 'utf8'));
  return verifyConfirmedLiveState(historicalFiles, liveFiles, gateRecord);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = process.argv.includes('--confirmed-live-state')
    ? await performConfirmedLiveState()
    : await performIndependentReturn();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
