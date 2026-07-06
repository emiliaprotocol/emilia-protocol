<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol mapping against the Command Authority Envelope (draft-morrison-ot-command-authority)

A row-by-row pass of EP artifacts against the CAE's five bindings, offered as
"which slots EP fills, which it deliberately does not, and where a claim is a
gap rather than a pass." EP does not fill the whole envelope, and says so; it
fills the human-authorization slots and composes with the rest through the
shared action digest. Carrier for the CAE slot is
draft-schrock-human-authorization-binding.

## The five bindings

| CAE binding | EP position | Carrier / evidence | Honest scope |
|---|---|---|---|
| **1. Agent Identity** (machine identity, resolvable independently of the conduit) | **Out of EP scope, by design.** EP is human authorization, not machine identity. An EP receipt verifies identically whichever agent presents it. | filled by WIMSE workload identity / RFC 9421 / DNSSEC discovery; EP composes with it through the action-digest join key, never carries it | EP never asserts agent identity; conflating the two is the "possession is not authority" error EP refuses |
| **2. Principal Reference** (the human on whose authority the agent acts) | **EP fills this.** The receipt names the accountable human approver; the Approver Directory binds that key to a named principal at a graded identity-proofing level. | EP-RECEIPT-v1 `approver`; Approver Directory entry (IAL/eIDAS/1311 grade carried) | the binding of key to natural person is only as strong as the enrollment ceremony's proofing; EP states that grade, it does not manufacture it |
| **3. Consent Grant** (scoped, revocable, naming asset + control verb + expiry) | **Partial, expressed through the policy layer, not a single first-class object.** See Question 1 below. | the receipt's `policy` / policy_hash; Approver Directory scope; an EP admissibility profile (named, content-addressed, revocable-by-repin bar); optional EP delegation for a scoped grant; revocable via an EP revocation statement | EP does not today ship one artifact that is exactly a `{asset, control_verb, expiry}` consent grant; if the CAE wants that distinct from the per-action receipt, it is a profile EP can define |
| **4. Binding Moment** (per-action human authorization at the moment of consequence, mutual veto) | **EP fills this. This is what an EP receipt IS.** A named human's device-bound signature over the exact action, before execution. The mutual veto is native: an approval or a signed, terminal denial are the two outcomes, and the initiator cannot railroad the human (separation of duties, initiator MUST NOT approve). | EP-RECEIPT-v1 / EP signoff; signed DENIAL as a first-class terminal outcome; EP-QUORUM for M-of-N | offline verification establishes authenticity at the moment of signing, not current validity (see Question 2) |
| **5. Audit Record** (append-only, provenance-labelled, attribution across agent/principal/consent/time) | **EP composes here via SCITT, as you proposed.** The receipt is the statement; the append-only property comes from a transparency log run by others. | EP receipt + EP-AEG evidence graph + effect_attestation (executor-signed observed-effect digest) registered as SCITT Signed Statements (RFC 9943) | EP produces the statement the log ingests; it does not run the log. Transparency-log inclusion proves logging per the log's policy, never that a human authorized the action |

## Blake's three questions

**1. Standing consent (grant) versus per-action sign-off (binding moment).**
The EP receipt is the binding moment, not the consent grant. The scoped,
revocable grant is expressed through EP's policy layer: the policy_hash the
receipt references, the Approver Directory that scopes who may consent for which
action class, and an admissibility profile as a named, content-addressed,
revocable bar that names the requirements for an action family. Revocation is an
EP revocation statement against that policy or grant. What EP does not have today
is a single artifact that is exactly a `{asset, control_verb, expiry}` grant,
independently revocable, distinct from the per-action receipt. If the CAE wants
that as its own object, it is a clean profile to define; the pieces (scoping,
pinning, revocation) already exist, they are just not assembled into one named
grant. That is a gap, stated as one.

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
