// SPDX-License-Identifier: Apache-2.0
// EP-RELIANCE-AGREEMENT-v1 / EP-RELIANCE-EVENT-v1 — a signed, machine-readable
// agreement conditioning liability transfer / indemnity on authorization-evidence
// sufficiency (reliance profile by digest), plus the per-action reliance event.
// Multi-party required signatures, pinned keys, amounts-as-strings, fail-closed.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  signRelianceAgreement, signRelianceEvent,
  verifyRelianceAgreement, verifyRelianceEvent,
  relianceAgreementDigest, relianceResultDigest,
} from '../packages/verify/reliance-agreement.js';
import { canonicalize } from '../packages/verify/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const SUITE = JSON.parse(readFileSync(resolve(ROOT, 'conformance/vectors/reliance-agreement.v1.json'), 'utf8'));

// Deterministic Ed25519 keys (test-only; PKCS8 wrapping of a fixed 32-byte seed).
const keyFromSeed = (hexByte) => crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(hexByte.repeat(32), 'hex')]),
  format: 'der', type: 'pkcs8',
});
const pubOf = (priv) => crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64url');

const issuerKey = keyFromSeed('a1');
const rpKey = keyFromSeed('b2');
const uwKey = keyFromSeed('c3');

const PINS = Object.freeze({
  'ep:key:issuer-1': pubOf(issuerKey),
  'ep:key:rp-1': pubOf(rpKey),
  'ep:key:uw-1': pubOf(uwKey),
});

// The evidence condition: a reliance profile pinned BY DIGEST — the agreement
// never restates evidence policy, it points at the profile the kernel replays.
const PROFILE = {
  '@type': 'EP-RELIANCE-PROFILE-v1',
  required_assurance: 'class_a',
  required_authority: true,
  required_evidence: ['authority_proof', 'revocation_freshness'],
  max_revocation_staleness_sec: 300,
};
const PROFILE_DIGEST = `sha256:${crypto.createHash('sha256').update(canonicalize(PROFILE), 'utf8').digest('hex')}`;

const ACTION_DIGEST = `sha256:${'4e'.repeat(32)}`;
const NOW = '2026-07-08T12:00:00.000Z';

function basePayload() {
  return {
    version: 'EP-RELIANCE-AGREEMENT-v1',
    agreement_id: 'ra:example-issuer:example-bank:2026-001',
    parties: {
      issuer: { id: 'ep:org:example-issuer', key_id: 'ep:key:issuer-1' },
      relying_party: { id: 'ep:org:example-bank', key_id: 'ep:key:rp-1' },
      underwriter: { id: 'ep:org:example-underwriter', key_id: 'ep:key:uw-1' },
    },
    required_signers: ['issuer', 'relying_party', 'underwriter'],
    scope: {
      action_families: ['wire_transfer', 'ach_credit'],
      jurisdictions: ['US-NY'],
      validity: { not_before: '2026-01-01T00:00:00.000Z', not_after: '2027-01-01T00:00:00.000Z' },
    },
    condition: { reliance_profile_digest: PROFILE_DIGEST, min_assurance_class: 'A', max_staleness_sec: 300 },
    terms: {
      mode: 'indemnity',
      cap_amount: '1000000.00',
      currency: 'USD',
      per_action_cap: '250000.00',
      aggregate_cap: '1000000.00',
      deductible: '10000.00',
    },
    recourse_ref: 'https://example.com/master-agreement#annex-b',
  };
}

const ALL_SIGNERS = () => [
  { party: 'issuer', privateKey: issuerKey },
  { party: 'relying_party', privateKey: rpKey },
  { party: 'underwriter', privateKey: uwKey },
];

function baseAgreement() {
  return signRelianceAgreement(basePayload(), ALL_SIGNERS());
}

function baseResult(overrides = {}) {
  return {
    '@type': 'EP-RELIANCE-RESULT-v1',
    action_digest: ACTION_DIGEST,
    action_family: 'wire_transfer',
    verdict: 'rely',
    profile_digest: PROFILE_DIGEST,
    ...overrides,
  };
}

function baseEvent(agreement, result, { relied_at = '2026-07-08T11:59:00.000Z', signKey = rpKey } = {}) {
  return signRelianceEvent({
    version: 'EP-RELIANCE-EVENT-v1',
    event_id: 'rev:example-bank:2026-07-08:0001',
    agreement_digest: relianceAgreementDigest(agreement),
    action_digest: result.action_digest,
    reliance_result_digest: relianceResultDigest(result),
    relied_at,
  }, signKey);
}

function runAgreement(brk) {
  let agreement = baseAgreement();
  const opts = { trustedKeys: { ...PINS }, now: NOW };
  switch (brk) {
    case 'none': break;
    case 'drop_relying_party_signature':
      agreement.signatures = agreement.signatures.filter((s) => s.party !== 'relying_party');
      break;
    case 'now_after_expiry': opts.now = '2027-06-01T00:00:00.000Z'; break;
    case 'tamper_cap_amount': agreement.terms.cap_amount = '9000000.00'; break; // changed after signing
    case 'cap_amount_as_number': {
      const p = basePayload(); p.terms.cap_amount = 1000000;
      agreement = signRelianceAgreement(p, ALL_SIGNERS());
      break;
    }
    case 'unknown_terms_mode': {
      const p = basePayload(); p.terms.mode = 'best_effort';
      agreement = signRelianceAgreement(p, ALL_SIGNERS());
      break;
    }
    case 'unpin_issuer_key': delete opts.trustedKeys['ep:key:issuer-1']; break;
    case 'require_undeclared_underwriter': {
      const p = basePayload(); delete p.parties.underwriter;
      agreement = signRelianceAgreement(p, [{ party: 'issuer', privateKey: issuerKey }, { party: 'relying_party', privateKey: rpKey }]);
      break;
    }
    default: throw new Error(`unknown break ${brk}`);
  }
  return verifyRelianceAgreement(agreement, opts);
}

function runEvent(brk) {
  const agreement = baseAgreement();
  let result = baseResult();
  let event = baseEvent(agreement, result);
  const opts = { agreement, relianceResult: result, trustedKeys: { ...PINS }, now: NOW };
  switch (brk) {
    case 'none': break;
    case 'wrong_agreement_digest': {
      // A dishonest relying party binds (and honestly signs) an event naming a
      // DIFFERENT agreement digest — the binding check must fire, not the signature.
      event = signRelianceEvent({ ...event, agreement_digest: `sha256:${'ff'.repeat(32)}`, signature: undefined }, rpKey);
      break;
    }
    case 'sign_event_as_issuer': event = baseEvent(agreement, result, { signKey: issuerKey }); break;
    case 'result_for_different_action': {
      // A genuine rely verdict for action X, claimed for action Y: the event
      // self-consistently binds X's result but claims Y as its action.
      event = signRelianceEvent({ ...event, action_digest: `sha256:${'5f'.repeat(32)}`, signature: undefined }, rpKey);
      break;
    }
    case 'result_family_out_of_scope': {
      result = baseResult({ action_family: 'crypto_withdrawal' });
      event = baseEvent(agreement, result);
      opts.relianceResult = result;
      break;
    }
    case 'tamper_reliance_result': {
      opts.relianceResult = { ...result, verdict: 'do_not_rely_no_class_a' }; // altered after the event bound it
      break;
    }
    case 'relied_at_after_expiry': {
      event = baseEvent(agreement, result, { relied_at: '2027-02-01T00:00:00.000Z' });
      opts.now = '2027-07-01T00:00:00.000Z';
      break;
    }
    case 'result_different_profile_digest': {
      result = baseResult({ profile_digest: `sha256:${'aa'.repeat(32)}` });
      event = baseEvent(agreement, result);
      opts.relianceResult = result;
      break;
    }
    default: throw new Error(`unknown break ${brk}`);
  }
  return verifyRelianceEvent(event, opts);
}

describe('EP-RELIANCE-AGREEMENT-v1 conformance', () => {
  for (const v of SUITE.vectors) {
    it(`${v.id}`, () => {
      const r = v.object === 'agreement' ? runAgreement(v.break) : runEvent(v.break);
      expect(r.valid).toBe(v.expect.valid);
      if (v.expect.reason_contains) expect(r.reasons.join(' ')).toContain(v.expect.reason_contains);
    });
  }
});

describe('EP-RELIANCE-AGREEMENT-v1 invariants', () => {
  it('effectiveness follows the agreement OWN required_signers[]: an unrequired underwriter may abstain', () => {
    const p = basePayload();
    p.required_signers = ['issuer', 'relying_party'];
    const agreement = signRelianceAgreement(p, [{ party: 'issuer', privateKey: issuerKey }, { party: 'relying_party', privateKey: rpKey }]);
    const r = verifyRelianceAgreement(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(true);
    expect(r.required_signers).toEqual(['issuer', 'relying_party']);
  });

  it('a present-but-invalid unrequired signature still refuses (never ignorable)', () => {
    const p = basePayload();
    p.required_signers = ['issuer', 'relying_party'];
    const agreement = signRelianceAgreement(p, ALL_SIGNERS());
    agreement.signatures.find((s) => s.party === 'underwriter').signature_b64u = Buffer.from('00'.repeat(64), 'hex').toString('base64url');
    const r = verifyRelianceAgreement(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain("signature from 'underwriter' does not verify");
  });

  it('an agreement not yet in force (now before not_before) refuses', () => {
    const r = verifyRelianceAgreement(baseAgreement(), { trustedKeys: PINS, now: '2025-12-31T23:59:59.000Z' });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain('validity window');
  });

  it('the verifier signs nothing away: the pinned key set decides, never the carried public_key', () => {
    const agreement = baseAgreement();
    // Attacker swaps the carried public_key for their own; the pinned key still governs.
    const rogue = keyFromSeed('d4');
    agreement.signatures.find((s) => s.party === 'issuer').public_key = pubOf(rogue);
    const r = verifyRelianceAgreement(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(true); // carried key is inert metadata; pinned key verified the bytes
  });

  it('the agreement digest is stable and signature-envelope-independent', () => {
    const signedTwice = signRelianceAgreement(basePayload(), ALL_SIGNERS());
    expect(relianceAgreementDigest(signedTwice)).toBe(relianceAgreementDigest(basePayload()));
  });

  it('a valid event returns the agreement digest it bound', () => {
    const agreement = baseAgreement();
    const result = baseResult();
    const event = baseEvent(agreement, result);
    const r = verifyRelianceEvent(event, { agreement, relianceResult: result, trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(true);
    expect(r.agreement_digest).toBe(relianceAgreementDigest(agreement));
    expect(r.event_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('an event whose relied_at is in the future refuses', () => {
    const agreement = baseAgreement();
    const result = baseResult();
    const event = baseEvent(agreement, result, { relied_at: '2026-12-01T00:00:00.000Z' });
    const r = verifyRelianceEvent(event, { agreement, relianceResult: result, trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain('future');
  });

  it('malformed inputs fail closed with a reason, never throw', () => {
    for (const junk of [null, undefined, 42, 'x', [], { version: 'nope' }]) {
      const a = verifyRelianceAgreement(junk, { trustedKeys: PINS, now: NOW });
      expect(a.valid).toBe(false);
      expect(a.reasons.length).toBeGreaterThan(0);
      const e = verifyRelianceEvent(junk, { agreement: baseAgreement(), relianceResult: baseResult(), trustedKeys: PINS, now: NOW });
      expect(e.valid).toBe(false);
      expect(e.reasons.length).toBeGreaterThan(0);
    }
  });
});
