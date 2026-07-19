<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol mapping against the Command Authority Envelope (draft-morrison-ot-command-authority)

A row-by-row pass of EP artifacts against the CAE's five bindings, offered as
which slots EP fills as first-class artifacts and which it deliberately leaves
to other layers. EP fills the human-authorization slots precisely and composes
with the rest through the shared action digest. Carrier for the CAE slot is
draft-schrock-human-authorization-binding.

## The five bindings

| CAE binding | EP position | Carrier / evidence | Honest scope |
|---|---|---|---|
| **1. Agent Identity** (machine identity, resolvable independently of the conduit) | **Out of EP scope, by design.** EP is human authorization, not machine identity. An EP receipt verifies identically whichever agent presents it. | filled by WIMSE workload identity / RFC 9421 / DNSSEC discovery; EP composes with it through the action-digest join key, never carries it | EP never asserts agent identity; conflating the two is the "possession is not authority" error EP refuses |
| **2. Principal Reference** (the human on whose authority the agent acts) | **EP fills this.** The receipt names the accountable human approver; the Approver Directory binds that key to a named principal at a graded identity-proofing level. | EP-RECEIPT-v1 `approver`; Approver Directory entry (IAL/eIDAS/1311 grade carried) | the binding of key to natural person is only as strong as the enrollment ceremony's proofing; EP states that grade, it does not manufacture it |
| **3. Consent Grant** (scoped, revocable, naming asset + control verb + expiry) | **EP fills this. EP now SHIPS EP-CONSENT-GRANT-v1 as the first-class object for binding 3.** A standing, scoped, revocable grant naming exactly `{asset, control_verb, expiry}`, distinct from the per-action receipt, with a reference issuer, an offline verifier, and the receipt composition. See Question 1 below. | EP-CONSENT-GRANT-v1 (`packages/verify/consent-grant.js`; schema `public/schemas/ep-consent-grant.schema.json`; spec `docs/EP-CONSENT-GRANT-SPEC.md`); grant_hash bound + Ed25519 principal signature; a receipt acts under it by carrying grant_hash; revocable via an EP revocation statement against the grant_hash | the grant is standing authority; the per-action receipt is the binding moment. Offline verification of either is authenticity as of commit, not current validity, so revocation currency needs a fresh revocation snapshot (see Question 2) |
| **4. Binding Moment** (per-action human authorization at the moment of consequence, mutual veto) | **EP fills the durable evidence side.** `EP-RESOLUTION-v1` binds the exact envelope and action under a named principal's device key while preserving `approved`, `declined`, `amended`, and `rejected` as different signed outcomes. Only `approved`, plus a complete relying-party-pinned acceptance context (option mapping, nonce, initiator, time, RP ID, origin, and role key), can authorize the original action. Existing binary signoffs remain valid. | `EP-RESOLUTION-v1` (`packages/verify/resolution.js`; schema `public/schemas/ep-resolution.schema.json`; spec `docs/EP-RESOLUTION-SPEC.md`); EP-QUORUM remains the M-of-N layer | a valid negative outcome is durable evidence, never authority; offline verification establishes authenticity at signing, not current validity or one-time consumption |
| **5. Audit Record** (append-only, provenance-labelled, attribution across agent/principal/consent/time) | **EP composes here via SCITT, as you proposed.** The receipt is the statement; the append-only property comes from a transparency log run by others. | EP receipt + EP-AEG evidence graph + effect_attestation (executor-signed observed-effect digest) registered as SCITT Signed Statements (RFC 9943) | EP produces the statement the log ingests; it does not run the log. Transparency-log inclusion proves logging per the log's policy, never that a human authorized the action |

## Blake's three questions

**1. Standing consent (grant) versus per-action sign-off (binding moment).**
The EP receipt is the binding moment. The scoped, revocable STANDING grant is now
its own first-class artifact: EP ships EP-CONSENT-GRANT-v1, a named object that is
exactly a `{asset, control_verb, expiry}` grant, independently revocable, distinct
from the per-action receipt. The grant carries `{profile, grant_id, principal,
asset, control_verb, constraints?, issued_at, expires_at, grant_hash, signature}`,
where grant_hash is the JCS/SHA-256 hash over the grant body and the principal
signs those same bytes with the same Ed25519 convention EP uses everywhere. It has
a reference issuer, an offline verifier (`verifyConsentGrant`, fail-closed on bad
hash, unpinned or bad principal signature, out-of-window, or a valid revocation
statement against the grant_hash), and a composition (`verifyReceiptUnderGrant`)
in which a per-action receipt acts under the grant by carrying its grant_hash and
being covered by the grant's asset and control_verb. The pieces EP already had
(policy_hash the receipt references, Approver Directory scope, admissibility
profiles, delegation, revocation statements) still compose, but binding 3 no
longer depends on assembling them per call site: it is one named grant. See
`packages/verify/consent-grant.js`, `public/schemas/ep-consent-grant.schema.json`,
and `docs/EP-CONSENT-GRANT-SPEC.md`. It is a candidate profile to fold into the
authority / receipts drafts in a future revision, shipped in code today. Binding 3
is filled by a first-class object.

**2. Revocation against offline verifiability.**
EP is explicit that offline verification establishes authenticity as of commit,
never current validity or non-revocation. Proving the absence of a later
revocation event requires communication; that is a theorem, not a gap we can
engineer away. What EP does instead, and what fits an air-gapped OT executor:
(a) a per-action-class freshness bound. The receipt carries a validity window,
and EP's two-valued currency result returns `unknown` offline unless a fresh
signed head is present, and `fresh` or `stale` only against one, so an executor
that has not seen a recent head treats the grant as not-known-current rather than
current. (b) For true air-gap, the revocation set is pushed to the executor as a
signed, witnessed status-list snapshot; the executor verifies the snapshot
offline and the snapshot's own freshness is the bound. So the reconciliation is:
short validity window plus a pushed, signed revocation snapshot at the executor,
with the staleness of that snapshot as the priced residual. EP never claims the
offline receipt alone proves the grant is still live.

**3. Fail closed on authority, not on safety.**
Yes, this matches EP's intent exactly. EP's Verifying Executor fails closed on
authority: no valid authorization bundle, refuse the requested state-change,
deny by default. That is authority-fail-closed and nothing more. The safety
carve-out, never drive the OT into an unsafe state on missing authority where a
safety interlock is what matters, lives above EP, in your layer. EP deliberately
scopes its enforcement point to "may this authorized command proceed," not "what
is the safe physical state." They compose: EP says "no authority, do not perform
the command"; the safety layer decides the safe hold independently and is never
gated by an authority check. The receipt is the authority artifact; the interlock
is not EP's to define, and should not be.
