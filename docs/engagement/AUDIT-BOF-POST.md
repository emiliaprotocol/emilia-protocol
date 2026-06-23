<!-- SPDX-License-Identifier: Apache-2.0 -->
# IETF agent2agent AUDIT BOF — list post

**List:** `agent2agent@ietf.org` (IETF non-WG list, "Standardization of AI Agent
Communications").
**Thread:** *"Proposed charter text for AUDIT BOF - Please provide feedback before Friday!"*
(Scott Courtney). Root: https://mailarchive.ietf.org/arch/msg/agent2agent/rQ5WMw9Bkwa5a1TxMGclM1f3ytw/
**⚠️ Caveat:** IETF lists typically only accept posts from **subscribed** addresses — subscribe
`team@emiliaprotocol.ai` at https://www.ietf.org/mailman/listinfo/agent2agent before sending, or
the post will be held/bounced. This is the live, unowned-receipt-gap forum (Kühlewind scoped
delegation out; Sweeney asked for exactly EP's artifact) — higher-leverage than the 30 Jun interim,
where EP is not scheduled. A Gmail draft is staged.

---

**Subject:** Re: Proposed charter text for AUDIT BOF - Please provide feedback before Friday!

Hi all,

+1 to chartering this work. The holistic, whole-chain framing in the architecture draft is the right altitude, and the layered "loose building blocks / DAG" decomposition Henk described maps cleanly onto how these records actually compose in practice.

I want to pick up one specific thread. Kieran asked for "a receipt/evidence format that binds to action payloads independently of whether the downstream resource speaks OAuth." With delegation chains scoped out of the audit work, that receipt/evidence-format gap is left open and, as far as I can tell, unowned. I think it is worth the group naming it as an explicit deliverable, because it is the join between "what was authorized" and "what actually happened" that makes a trajectory auditable end-to-end.

We have been building exactly this in the open and would be glad to contribute it as input rather than as a competing proposal. Three pieces are directly relevant:

- draft-schrock-ep-authorization-receipts — a named principal authorizes an exact action; the receipt is offline-verifiable, OAuth-independent, and requires no trust in the operator or any online introspection endpoint. This is a direct answer to Kieran's ask: it binds to the action payload regardless of what the downstream resource speaks.
- draft-schrock-ep-authorization-evidence-chain — composition of heterogeneous receipts across hops, which is precisely the "non-OAuth hop" case that falls out of scope once delegation-chain semantics are excluded.
- draft-schrock-ep-quorum — the multi-party authorization case.

To keep this grounded rather than aspirational: there are three independent verifiers (JavaScript, Python, Go) that agree over a public conformance suite, plus machine-checked TLA+/Alloy models of the core properties. And it has been independently run: an outside implementer recently verified the artifacts from a clean machine — the public one-liner produces the workpaper, the genuine receipt verifies offline, the forged copy is rejected, and the JS/Python/Go conformance vectors agree — and posted that result to the authorization-evidence survey thread. If the WG wants a verifier-side conformance target, the vectors already exist and have been checked by someone other than the author.

We also helped put together a short cross-draft survey that maps the adjacent efforts in this space (DRP/Nelson, PSEA, EP, and others) onto a single verifier-side matrix. That seems like useful prior art for the group to triage what is and isn't already covered, and where the real gaps are.

I see all of this as complementary: Mirja's audit-architecture as the frame, Henk's verifiable agent conversations / trajectories as the spine, and an OAuth-independent, action-bound, offline-verifiable receipt as one of the building blocks that hangs off it. Happy to share drafts, vectors, or the survey with anyone interested.

Thanks for driving this.

Best,
Iman Schrock · EMILIA Protocol · team@emiliaprotocol.ai
