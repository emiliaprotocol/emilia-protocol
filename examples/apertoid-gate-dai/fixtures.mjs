// SPDX-License-Identifier: Apache-2.0
//
// Deterministic fixtures for the ApertoID + EMILIA Gate + OAuth DAI
// composition example. Everything here is fixed: fixed timestamps, fixed
// Ed25519 seeds, and the already-signed MEMORY-PROJECTION-RECORD-v1
// positive vector from the joint ApertoMemory/EMILIA interop package. No
// Date.now anywhere; two runs produce byte-identical output.

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalContextRecordDigest } from '../../packages/gate/trusted-context.js';
import { signIdJagAssertion } from './dai-profile.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

// One shared evaluation instant for every leg. It matches the pinned
// verification_policy of the interop v1 vectors so the signed projection
// record verifies fresh at this exact instant.
export const VERIFICATION_TIME = '2026-07-29T17:01:00.000Z';
export const ADAPTER_STATUS_CHECKED_AT = '2026-07-29T17:00:00.000Z';

// ---------------------------------------------------------------------------
// Leg A: the memory/identity context. Reused, not re-implemented: the signed
// positive projection record and the pinned adapter key both come from
// interop/apertomemory-emilia/memory-projection-record.v1.vectors.json.
// ---------------------------------------------------------------------------

const vectors = JSON.parse(readFileSync(
  resolve(HERE, '../../interop/apertomemory-emilia/memory-projection-record.v1.vectors.json'),
  'utf8',
));

export const MEMORY_PROJECTION_RECORD = vectors.projection.record;

export const ADAPTER_KEYS = Object.freeze({
  [vectors.adapter_pin.key_id]: Object.freeze({
    public_key_spki_b64u: vectors.adapter_pin.public_key_spki_b64u,
    status: vectors.adapter_pin.status,
    valid_from: vectors.adapter_pin.valid_from,
    valid_to: vectors.adapter_pin.valid_to,
    revoked_at: vectors.adapter_pin.revoked_at,
  }),
});

export const MEMORY_VERIFICATION_LIMITS = Object.freeze({
  maxSignerStatusAgeSec: 300,
  maxProjectionAgeSec: vectors.verification_policy.max_projection_age_sec,
  maxTrustAgeSec: vectors.verification_policy.max_trust_age_sec,
});

export const PROJECTION_RECORD_DIGEST = canonicalContextRecordDigest(MEMORY_PROJECTION_RECORD);

// ---------------------------------------------------------------------------
// Leg B: the DAI-governed delegated authorization artifact. Cast and values
// follow Appendix C of draft-mcguinness-oauth-domain-authorized-issuer-00:
// Subject Authority acme.example, Assertion Issuer https://idp.example.net,
// Resource Authorization Server https://api.resource.example, end user
// alice@acme.example. The policy document is the Appendix C.5 pointer-form
// JSON (both entries, including the backup issuer).
// ---------------------------------------------------------------------------

export const SUBJECT_AUTHORITY = 'acme.example';
export const ASSERTION_ISSUER = 'https://idp.example.net';
export const RESOURCE = 'https://api.resource.example';
export const END_USER_EMAIL = 'alice@acme.example';

function ed25519FromSeed(seedHex) {
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(seedHex, 'hex'),
  ]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const publicSpkiB64u = crypto.createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' })
    .toString('base64url');
  return { privateKey, publicSpkiB64u };
}

// Fixed example-only seed; not a real credential.
const issuerKey = ed25519FromSeed(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
);
export const ISSUER_KID = 'idp-example-net-2026-07';

// Relying-party pinned issuer key table: { issuer: { kid: spki_b64u } }.
export const ISSUER_KEYS = Object.freeze({
  [ASSERTION_ISSUER]: Object.freeze({ [ISSUER_KID]: issuerKey.publicSpkiB64u }),
});

// Fixed instants around VERIFICATION_TIME (2026-07-29T17:01:00Z).
const IAT = Date.parse('2026-07-29T16:56:00Z') / 1000;
const EXP = Date.parse('2026-07-29T17:06:00Z') / 1000;

function idJagClaims({ aud, jti }) {
  // Claim set shape per Appendix C.3 of the pinned draft.
  return {
    iss: ASSERTION_ISSUER,
    aud,
    exp: EXP,
    iat: IAT,
    jti,
    sub: 'user-9241ab',
    email: END_USER_EMAIL,
    email_verified: true,
  };
}

export const ASSERTION = signIdJagAssertion(
  idJagClaims({ aud: RESOURCE, jti: 'jag-2026-07-29-0001' }),
  { privateKey: issuerKey.privateKey, kid: ISSUER_KID },
);

// The same issuer honestly minting an assertion for a DIFFERENT resource:
// individually valid, but not for this action.
export const ASSERTION_FOR_OTHER_RESOURCE = signIdJagAssertion(
  idJagClaims({ aud: 'https://api.other.example', jti: 'jag-2026-07-29-0002' }),
  { privateKey: issuerKey.privateKey, kid: ISSUER_KID },
);

// Issuer Authorization Policy: exactly the Appendix C.5 document.
export const POLICY_ENFORCE = Object.freeze({
  subject_authority: SUBJECT_AUTHORITY,
  authorized_issuers: Object.freeze([
    Object.freeze({
      issuer: ASSERTION_ISSUER,
      subject_identifier_formats: Object.freeze(['email']),
      valid_until: '2027-05-30T00:00:00Z',
    }),
    Object.freeze({
      issuer: 'https://idp-backup.example.net',
      subject_identifier_formats: Object.freeze(['email']),
    }),
  ]),
  last_updated: '2026-05-29T00:00:00Z',
});

// Monitor-mode variant whose issuer list does NOT contain the assertion
// issuer: per Section 6.1 the mismatch is logged and the Trust Method is
// nevertheless satisfied. The Gate's stricter admission floor is what
// refuses it downstream.
export const POLICY_MONITOR_MISMATCH = Object.freeze({
  subject_authority: SUBJECT_AUTHORITY,
  authorized_issuers: Object.freeze([
    Object.freeze({
      issuer: 'https://idp-other.example.net',
      subject_identifier_formats: Object.freeze(['email']),
    }),
  ]),
  mode: 'monitor',
  last_updated: '2026-05-29T00:00:00Z',
});

// Lookup fixtures, already classified at the transport level (Section 5.1).
export const LOOKUP_AFFIRMATIVE = Object.freeze({
  state: 'affirmative',
  channel: 'dns-pointer-https',
  policy: POLICY_ENFORCE,
});
export const LOOKUP_AFFIRMATIVE_MONITOR = Object.freeze({
  state: 'affirmative',
  channel: 'dns-pointer-https',
  policy: POLICY_MONITOR_MISMATCH,
});
export const LOOKUP_SERVFAIL = Object.freeze({
  state: 'indeterminate',
  channel: 'dns',
  detail: 'dns_servfail',
});

// ---------------------------------------------------------------------------
// The consequential action. The action object names the exact context it was
// prepared under (the projection-record digest) and the exact resource and
// subject the DAI leg must cover, so the CAID computed over the action
// covers all three join points.
// ---------------------------------------------------------------------------

export const ACTION = Object.freeze({
  action_type: 'records.release.v1',
  resource: RESOURCE,
  on_behalf_of: END_USER_EMAIL,
  parameters: Object.freeze({
    record_set: 'acme-2026-q2-vendor-ledger',
    destination: 'https://api.resource.example/exports/inbox',
  }),
  requested_at: '2026-07-29T17:00:30Z',
  context_binding: Object.freeze({
    projection_record_digest: PROJECTION_RECORD_DIGEST,
  }),
});

// The same action prepared under a DIFFERENT memory context: identical
// parameters, but bound to another projection-record digest. Presenting the
// real (validly signed) projection record against this action is the
// cross-leg substitution the join must refuse.
export const ACTION_OTHER_CONTEXT = Object.freeze({
  ...ACTION,
  context_binding: Object.freeze({
    projection_record_digest:
      'sha256:1111111111111111111111111111111111111111111111111111111111111111',
  }),
});
