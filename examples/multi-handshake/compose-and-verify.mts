// SPDX-License-Identifier: Apache-2.0
//
// EMILIA - multi-handshake quorum composer (runnable, offline, zero new deps).
//
//   node examples/multi-handshake/compose-and-verify.mjs
//
// A reference COMPOSER for EP-QUORUM-v1 (draft-schrock-ep-quorum-02): it
// assembles a 2-of-3 ordered composition of member handshakes (each an
// unmodified EP signoff, a real Class-A-shaped WebAuthn assertion) over ONE
// canonical action, enforcing the spec's incremental admission rule
// (Section 6) so a non-conforming handshake never enters the trail, then
// hands the composed quorum document to the REAL verifier
// (packages/verify verifyQuorum, the same entry point the conformance
// runner calls) and prints its verdict.
//
// Demonstrated, in order:
//   ACCEPT   2-of-3 ordered composition          -> real verifier: valid true
//   REFUSE   out-of-order signature              -> admission-time: out_of_order
//   REFUSE   initiator self-approval             -> admission-time: self_approval
//   REFUSE   replayed member handshake           -> admission-time: challenge_reused
//            (plus the stale-challenge variant)  -> admission-time: stale_challenge
//   REFUSE   off-roster key                      -> admission-time: invalid_signature
//   REFUSE   off-roster member FORCED into trail -> verify-time: roles_admitted=false
//
// The script is itself a test: it exits non-zero if the expected acceptance
// fails or any expected refusal unexpectedly passes.
//
// Wire-shape note (honest): the JS reference verifier's ordered wire mode
// requires EVERY roster slot to sign (a full-roster escalation chain). A
// 2-of-3 composition that stops at the threshold is therefore expressed on
// the wire as a threshold policy; the declared roster order is enforced by
// the composer at admission time (spec Section 6, rule 5 semantics), and
// each member after the first commits to its predecessor inside its own
// signed context via prev_context_hash (the ordering commitment over the
// prior trail). The verifier and the conformance vectors are ground truth
// for the wire shape.

import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import {
  verifyQuorum,
  verifyWebAuthnSignoff,
  canonicalize,
  contextChainHash,
} from '../../packages/verify/index.js';

const RP_ID = 'emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';

// Deterministic demo clock (same base date as the conformance vectors).
const at = (min: number, sec = 0) =>
  new Date(Date.UTC(2026, 5, 11, 0, min, sec)).toISOString();
const addSec = (iso: string, sec: number) => new Date(Date.parse(iso) + sec * 1000).toISOString();

const b64uSha256 = (utf8: string) =>
  createHash('sha256').update(utf8, 'utf8').digest().toString('base64url');

// ---------------------------------------------------------------------------
// Simulated authenticator: one device-held P-256 key per participant.
// The real verifier (packages/verify index.js) verifies ECDSA P-256/SHA-256
// over authData || SHA-256(clientDataJSON) against the enrolled SPKI key, so
// the simulation emits exactly that wire shape (same as the vectors:
// rpIdHash = SHA-256("emiliaprotocol.ai"), flags UP|UV = 0x05, DER signature).
// ---------------------------------------------------------------------------
function makeAuthenticator() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  let counter = 0;
  return {
    publicKeySpkiB64u: spki,
    assert(challengeB64u) {
      counter += 1;
      const clientDataBytes = Buffer.from(
        JSON.stringify({ type: 'webauthn.get', challenge: challengeB64u, origin: ORIGIN }),
        'utf8',
      );
      const authData = Buffer.alloc(37);
      createHash('sha256').update(RP_ID, 'utf8').digest().copy(authData, 0);
      authData[32] = 0x05; // UP | UV: user present AND user verified
      authData.writeUInt32BE(counter, 33);
      const signedData = Buffer.concat([
        authData,
        createHash('sha256').update(clientDataBytes).digest(),
      ]);
      return {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientDataBytes.toString('base64url'),
        signature: sign('sha256', signedData, privateKey).toString('base64url'),
      };
    },
  };
}

// ---------------------------------------------------------------------------
// The COMPOSER. Faithful to draft-schrock-ep-quorum-02 Section 6 (canAccept):
// it evaluates the incremental admission rule BEFORE appending, so a
// non-conforming handshake never becomes part of the trail. FAIL CLOSED:
// any missing input, unknown challenge, or failed check refuses admission.
// ---------------------------------------------------------------------------
function rosterSlotKey(role, approver) {
  return JSON.stringify([role, approver]);
}

class QuorumComposer {
  policy: any;
  policyId: string;
  actionHash: string;
  initiator: string;
  enrollment: Map<string, string>;
  rosterSet: Set<string>;
  trail: any[];
  challenges: Map<string, any>;

  constructor({ policy, policyId, actionHash, initiator, enrollment }: { policy: any; policyId: string; actionHash: string; initiator: string; enrollment: Map<string, string> }) {
    if (!policy || policy.required < 1 || !Array.isArray(policy.approvers)
      || policy.approvers.length === 0 || !actionHash || !initiator || !enrollment) {
      throw new Error('no_policy: refusing to compose without a well-formed policy');
    }
    this.policy = policy;
    this.policyId = policyId;
    this.actionHash = actionHash;
    this.initiator = initiator;
    this.enrollment = enrollment;
    this.rosterSet = new Set(policy.approvers.map((e) => rosterSlotKey(e.role, e.approver)));
    this.trail = [];              // admitted members, in order
    this.challenges = new Map();  // nonce -> { context, state, expiresAtMs }
  }

  /**
   * Issue a fresh per-member challenge: a one-time nonce (128-bit), a bounded
   * validity window, binding to the exact action hash, and (for every member
   * after the first) the ordering commitment over the prior trail
   * (prev_context_hash = SHA-256 of the predecessor's canonical context).
   * The WebAuthn challenge is b64u(SHA-256(canonical(context))), exactly what
   * the real verifier recomputes.
   */
  issueChallenge({ approver, nowIso, validitySec = 600 }: { approver: string; nowIso: string; validitySec?: number }) {
    const nonce = `sig_${randomBytes(16).toString('hex')}`; // 128-bit one-time nonce
    const context: any = {
      ep_version: '1.0',
      context_type: 'ep.signoff.v1',
      action_hash: this.actionHash,
      policy: this.policyId,
      nonce,
      approver,
      initiator: this.initiator,
      issued_at: nowIso,
      expires_at: addSec(nowIso, validitySec),
    };
    if (this.trail.length > 0) {
      context.prev_context_hash =
        contextChainHash(this.trail[this.trail.length - 1].signoff.context);
    }
    this.challenges.set(nonce, {
      context,
      state: 'issued',
      expiresAtMs: Date.parse(context.expires_at),
    });
    return { context, challenge: b64uSha256(canonicalize(context)) };
  }

  /**
   * Incremental admission (spec Section 6). Returns { admitted: true } or
   * { admitted: false, stage: 'admission', reason }. A refused candidate is
   * NEVER appended, and its challenge is voided (one-shot presentation).
   */
  admit(member: any, nowIso: string) {
    const refuse = (reason: string, ch?: any) => {
      if (ch && ch.state === 'issued') ch.state = 'void';
      return { admitted: false, stage: 'admission', reason };
    };

    // 0. Malformed member: fail closed.
    const ctx = member?.signoff?.context;
    if (!ctx || !member?.signoff?.webauthn || typeof member?.role !== 'string') {
      return refuse('malformed_member');
    }

    // 1. Challenge freshness: the nonce must be one this composer issued,
    //    unconsumed, unexpired, and the presented context must be byte-for-byte
    //    (canonical form) the context that was issued. One-time consumption is
    //    composer-side state; offline verification cannot re-establish it.
    const ch = this.challenges.get(ctx.nonce);
    if (!ch) return refuse('unknown_challenge');
    if (ch.state !== 'issued') return refuse('challenge_reused', ch);
    if (Date.parse(nowIso) > ch.expiresAtMs) return refuse('stale_challenge', ch);
    if (canonicalize(ctx) !== canonicalize(ch.context)) return refuse('context_mismatch', ch);

    // 2. Action binding: the exact action hash, nothing else.
    if (ctx.action_hash !== this.actionHash) return refuse('action_mismatch', ch);

    // 3. Initiator MUST NOT fill an approver slot (Q3; the base draft's
    //    SelfApprovalImpossible at the composition layer).
    if (ctx.approver === this.initiator) return refuse('self_approval', ch);

    // 4. Roster admission: the (role, approver) pair must be an eligible slot.
    if (!this.rosterSet.has(rosterSlotKey(member.role, ctx.approver))) {
      return refuse('ineligible_role', ch);
    }

    // 5. Distinct humans / distinct device keys.
    if (this.policy.distinct_humans !== false) {
      if (this.trail.some((m) => m.signoff.context.approver === ctx.approver)) {
        return refuse('duplicate_human', ch);
      }
    }

    // 6. Declared order: the candidate must fill the NEXT unfilled roster slot.
    if (this.trail.length >= this.policy.required) return refuse('quorum_already_satisfied', ch);
    const expected = this.policy.approvers[this.trail.length];
    if (!expected || expected.role !== member.role || expected.approver !== ctx.approver) {
      return refuse('out_of_order', ch);
    }

    // 7. Window and monotonic time.
    if (this.trail.length > 0) {
      const first = Date.parse(this.trail[0].signoff.context.issued_at);
      const last = Date.parse(this.trail[this.trail.length - 1].signoff.context.issued_at);
      const t = Date.parse(ctx.issued_at);
      if (!(t - first <= this.policy.window_sec * 1000)) return refuse('window_exceeded', ch);
      if (!(t > last)) return refuse('non_increasing_time', ch);
    }

    // 8. Signature, verified with the REAL single-signoff verifier against the
    //    ENROLLED device key for this approver (never a presenter-supplied key).
    const enrolledKey = this.enrollment.get(ctx.approver);
    if (!enrolledKey) return refuse('not_enrolled', ch);
    if (member.approver_public_key !== enrolledKey) return refuse('key_not_enrolled', ch);
    if (this.trail.some((m) => m.approver_public_key === enrolledKey)) {
      return refuse('duplicate_key', ch);
    }
    if (!verifyWebAuthnSignoff(member.signoff, enrolledKey, { rpId: RP_ID }).valid) {
      return refuse('invalid_signature', ch);
    }

    // ADMIT: consume the challenge, append to the trail.
    ch.state = 'consumed';
    this.trail.push({
      role: member.role,
      approver_public_key: enrolledKey,
      signoff: member.signoff,
    });
    return { admitted: true };
  }

  /** Composed quorum document, in the exact wire shape the real verifier accepts. */
  compose() {
    if (this.trail.length < this.policy.required) {
      throw new Error('under_threshold: a partial trail confers no authority');
    }
    return {
      '@type': 'ep.quorum',
      action_hash: this.actionHash,
      policy: this.policy,
      members: this.trail.map((m) => ({
        role: m.role,
        approver_public_key: m.approver_public_key,
        signoff: m.signoff,
      })),
    };
  }
}

// ---------------------------------------------------------------------------
// Demo: roster, keys, one canonical action.
// ---------------------------------------------------------------------------
const INITIATOR = 'ent_agent_treasury_7';
const roster = [
  { role: 'treasury_controller', approver: 'ep:approver:controller_ada' },
  { role: 'chief_financial_officer', approver: 'ep:approver:cfo_bram' },
  { role: 'general_counsel', approver: 'ep:approver:counsel_chen' },
];
const policy = {
  mode: 'threshold',
  required: 2,
  approvers: roster,
  distinct_humans: true,
  window_sec: 900,
};

// Distinct device keys: one per approver, one for the initiating agent, and
// one rogue key for the off-roster-key refusal.
const devices = new Map(roster.map((e) => [e.approver, makeAuthenticator()]));
const initiatorDevice = makeAuthenticator();
const rogueDevice = makeAuthenticator();
const enrollment = new Map(
  [...devices].map(([id, d]) => [id, d.publicKeySpkiB64u]),
);

// One canonical action; its hash is what every member handshake binds to.
const action = {
  action_type: 'wire_transfer',
  amount: 250000,
  currency: 'USD',
  destination: 'acct_vendor_escrow_0042',
  reference: 'PO-2026-0611-firmware-recall',
};
const actionHash = contextChainHash(action); // sha256(canonicalize(action)), hex

const composer = new QuorumComposer({
  policy,
  policyId: 'policy_treasury_2of3',
  actionHash,
  initiator: INITIATOR,
  enrollment,
});

// Helper: obtain a challenge and produce the member handshake for it.
function handshakeFor(approverId: string, role: string, device: any, nowIso: string, opts: any = {}) {
  const { context, challenge } = composer.issueChallenge({
    approver: approverId,
    nowIso,
    validitySec: opts.validitySec,
  });
  const member = {
    role,
    approver_public_key: opts.claimKey ?? enrollment.get(approverId) ?? device.publicKeySpkiB64u,
    signoff: { '@type': 'ep.signoff', context, webauthn: device.assert(challenge) },
  };
  return member;
}

// ---------------------------------------------------------------------------
// Run the demonstration. The script asserts every expected outcome.
// ---------------------------------------------------------------------------
let failures = 0;
const check = (ok: boolean, label: string) => {
  console.log(`   ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failures += 1;
};

console.log('EP-QUORUM reference composer: 2-of-3 ordered composition');
console.log(`  action_hash  ${actionHash}`);
console.log(`  policy       threshold 2 of ${roster.length}, declared order enforced at admission, window ${policy.window_sec}s`);
console.log(`  roster       ${roster.map((e) => `${e.approver} (${e.role})`).join(' -> ')}`);
console.log(`  initiator    ${INITIATOR} (may not approve)\n`);

// REFUSAL 1: out-of-order signature. The CFO (declared slot 2) tries to sign
// before the Treasury Controller (declared slot 1).
{
  const m = handshakeFor('ep:approver:cfo_bram', 'chief_financial_officer',
    devices.get('ep:approver:cfo_bram'), at(0, 30));
  const r = composer.admit(m, at(0, 45)) as any;
  console.log(`1) out-of-order signature      -> stage=${r.stage} reason=${r.reason}`);
  check(!r.admitted && r.reason === 'out_of_order',
    'refused at admission with out_of_order (never appended)');
}

// ADMISSION 1: the Treasury Controller fills declared slot 1.
let controllerMember;
{
  controllerMember = handshakeFor('ep:approver:controller_ada', 'treasury_controller',
    devices.get('ep:approver:controller_ada'), at(1, 0));
  const r = composer.admit(controllerMember, at(1, 10));
  console.log(`\n+) slot 1 admitted             -> ep:approver:controller_ada`);
  check(r.admitted === true, 'treasury_controller admitted (trail length 1)');
}

// REFUSAL 2: initiator self-approval. The initiating agent presents its own
// device assertion for the next slot. Refused BEFORE appending.
{
  const m = handshakeFor(INITIATOR, 'chief_financial_officer', initiatorDevice, at(1, 30));
  const r = composer.admit(m, at(1, 40)) as any;
  console.log(`\n2) initiator self-approval     -> stage=${r.stage} reason=${r.reason}`);
  check(!r.admitted && r.reason === 'self_approval',
    'refused at admission with self_approval (initiator may not fill an approver slot)');
}

// REFUSAL 3: replayed member handshake. (a) The controller's already-consumed
// handshake is presented again: its one-time nonce was consumed at admission.
// (b) A stale challenge: presented after its validity window elapsed.
{
  const r = composer.admit(controllerMember, at(2, 0)) as any;
  console.log(`\n3) replayed member handshake   -> stage=${r.stage} reason=${r.reason}`);
  check(!r.admitted && r.reason === 'challenge_reused',
    'refused at admission with challenge_reused (one-time nonce already consumed)');

  const stale = handshakeFor('ep:approver:cfo_bram', 'chief_financial_officer',
    devices.get('ep:approver:cfo_bram'), at(2, 10), { validitySec: 60 });
  const r2 = composer.admit(stale, at(3, 20)) as any; // presented 70s after issue, 60s validity
  console.log(`   stale-challenge variant     -> stage=${r2.stage} reason=${r2.reason}`);
  check(!r2.admitted && r2.reason === 'stale_challenge',
    'refused at admission with stale_challenge (validity window elapsed)');
}

// REFUSAL 4: off-roster key. An attacker holding the CFO's slot obtains a
// fresh challenge but signs with a key that is NOT the CFO's enrolled device
// key (while claiming the enrolled key id). Admission verifies against the
// enrolled key from the server-side directory and refuses.
{
  const m = handshakeFor('ep:approver:cfo_bram', 'chief_financial_officer',
    rogueDevice, at(3, 30), { claimKey: enrollment.get('ep:approver:cfo_bram') });
  const r = composer.admit(m, at(3, 40)) as any;
  console.log(`\n4) off-roster key              -> stage=${r.stage} reason=${r.reason}`);
  check(!r.admitted && r.reason === 'invalid_signature',
    'refused at admission with invalid_signature (assertion does not verify against the enrolled key)');
}

// ADMISSION 2: the real CFO fills declared slot 2. The fresh challenge embeds
// prev_context_hash, the ordering commitment over the prior trail.
{
  const m = handshakeFor('ep:approver:cfo_bram', 'chief_financial_officer',
    devices.get('ep:approver:cfo_bram'), at(4, 0));
  console.log(`\n+) slot 2 admitted             -> ep:approver:cfo_bram`);
  console.log(`   ordering commitment         -> prev_context_hash=${m.signoff.context.prev_context_hash}`);
  const r = composer.admit(m, at(4, 10));
  check(r.admitted === true, 'chief_financial_officer admitted (trail length 2, threshold met)');
}

// COMPOSE and verify through the REAL verifier (the same function and options
// the conformance runner uses on conformance/vectors/quorum.v1.json).
const composed = composer.compose();
console.log('\nComposed quorum document (exact wire shape):');
console.log(JSON.stringify(composed, null, 2));

const verdict = verifyQuorum(composed, { rpId: RP_ID });
console.log('\nREAL verifier verdict (packages/verify verifyQuorum):');
console.log(`  valid: ${verdict.valid}`);
console.log(`  checks: ${JSON.stringify(verdict.checks)}`);
check(verdict.valid === true, 'real verifier accepts the composed 2-of-3 quorum');

// VERIFY-TIME enforcement: the executor re-evaluates the quorum gate and does
// not trust the composer. Force an off-roster member into the trail, bypassing
// admission entirely: the member's assertion is internally valid against the
// key it carries, but its (role, approver) is not an eligible slot.
{
  const malloryDevice = makeAuthenticator();
  const ctx = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash: actionHash,
    policy: 'policy_treasury_2of3',
    nonce: `sig_${randomBytes(16).toString('hex')}`,
    approver: 'ep:approver:mallory_intern',
    initiator: INITIATOR,
    issued_at: at(5, 0),
    expires_at: at(15, 0),
  };
  const forced = {
    ...composed,
    members: [
      ...composed.members,
      {
        role: 'inspector_general',
        approver_public_key: malloryDevice.publicKeySpkiB64u,
        signoff: {
          '@type': 'ep.signoff',
          context: ctx,
          webauthn: malloryDevice.assert(b64uSha256(canonicalize(ctx))),
        },
      },
    ],
  };
  const v = verifyQuorum(forced, { rpId: RP_ID });
  console.log('\n5) off-roster member FORCED past admission -> stage=verify');
  console.log(`   valid: ${v.valid}  roles_admitted: ${v.checks.roles_admitted}`);
  check(v.valid === false && v.checks.roles_admitted === false,
    'real verifier refuses the forced trail (roles_admitted=false), even though admission was bypassed');
}

console.log(`\n${failures === 0 ? 'OK' : 'FAILED'}: ${failures} unexpected outcome(s).`);
process.exit(failures === 0 ? 0 : 1);
