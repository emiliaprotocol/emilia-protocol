# ApertoID-rooted context + OAuth DAI delegation + EMILIA Gate admission

This runnable example composes three independent claims about one
consequential action, each verified in its own trust boundary, joined only
by digests over the exact action:

| Leg | Claim | Trust anchor | Verified by |
|---|---|---|---|
| Memory/identity context | A pinned adapter committed to the exact context bytes delivered to the agent (MEMORY-PROJECTION-RECORD-v1, `draft-ferro-schrock-memory-projection-record`) | Adapter key pinned by the relying party | The existing ApertoMemory Trusted Context provider (`packages/gate/src/apertomemory-context.ts`), reused, not re-implemented |
| Delegated authorization | The subject's domain has authorized the assertion issuer for that namespace, and the issuer minted an ID-JAG-style assertion covering this resource and subject | Domain-published Issuer Authorization Policy plus issuer keys pinned by the relying party | This example's minimal model of the DAI Trust Method (`dai-profile.mjs`) |
| Admission | The exact action was admitted at most once with both legs present | The Gate's own consumption domain | `gate.mjs` |

The join is content identity, never evidence ingestion: the CAID is computed
over the action object, which itself names the projection-record digest and
the resource plus on-behalf-of subject. Neither verifier sees the other's
evidence; the Gate compares digests.

## Pinned DAI draft

The DAI leg was written against the exact text of:

- `draft-mcguinness-oauth-domain-authorized-issuer-00`
  ("OAuth Domain-Authorized Issuer Trust Method", K. McGuinness,
  4 July 2026, expires 5 January 2027; revision 00 is the latest on the
  Datatracker as of 2026-08-16)
- SHA-256 of the fetched `.txt`:
  `2520dd24a6ed6c7936b32c0b2bba01af48ca95b486cad145a282f109d5b9606c`

Cast, ID-JAG claim shape, and the Issuer Authorization Policy document are
taken from that draft's Appendix C end-to-end example (acme.example,
`https://idp.example.net`, `https://api.resource.example`,
alice@acme.example; the policy JSON is the Appendix C.5 pointer-form
document).

## Run

```bash
node examples/apertoid-gate-dai/demo.mjs
node --test examples/apertoid-gate-dai/demo.test.mjs
```

The demo is deterministic: fixed timestamps, fixed Ed25519 seeds, the
already-signed positive projection vector from
`interop/apertomemory-emilia/memory-projection-record.v1.vectors.json`, and
no `Date.now` anywhere. The single run covers:

1. **Happy path**: both legs verify, digests join, the Gate admits and the
   effect executes exactly once.
2. **Replay**: the identical exact action is refused (`replay_refused`).
3. **Leg unavailable, INDETERMINATE**: the adapter status source cannot be
   evaluated, so the memory leg is INDETERMINATE. INDETERMINATE never
   authorizes, and is not upgraded to a tamper claim.
4. **DAI lookup Indeterminate**: a DNS SERVFAIL fails closed per
   Section 5.1 of the pinned draft, with no fallback channel.
5. **Cross-leg substitution, memory side**: the presented projection record
   is validly signed and VERIFIES, but the action was prepared under a
   different context digest; the join refuses.
6. **Cross-leg substitution, DAI side**: an individually valid assertion
   from the same issuer, minted for a different resource, is refused.
7. **Monitor-mode floor**: under a monitor-mode policy a mismatch is logged
   and the Trust Method is nevertheless satisfied (draft Section 6.1); the
   Gate still refuses admission because its local floor requires an
   enforce-mode policy for consequential actions. That floor is a
   relying-party choice stacked on top of DAI, not a DAI requirement.

## Scope and non-claims

- This is a non-normative composition prototype against the pinned draft
  revision, not a DAI implementation claim and not an endorsement by or of
  that draft's author. DNS TXT parsing, HTTPS retrieval, caching
  (Section 7), `signed_policy` processing, duplicate-member wire rejection,
  and the parent OAuth Identity Assertion Trust Framework document are out
  of scope; lookup outcomes arrive as fixtures already classified at the
  transport level.
- The memory leg proves what the pinned adapter emitted, under the joint
  draft's four pinned nonclaims: it establishes none of model use, action
  linkage, action authorization, or execution outcome. Memory truthfulness
  remains the producer's accountability; the record makes the delivered
  bytes attributable, not true.
- The DAI leg proves the domain authorized the issuer and the issuer
  covered this resource and subject. It does not prove the action was wise,
  lawful, or executed.
- The admitted decision proves only that both pinned evidence requirements
  held for the same exact action at this Gate, once, at the fixed
  verification instant.
- The consumption store is process-local so the demo runs with no setup; it
  is not safe across replicas or restarts.
- Key-id ordering: this example performs no key-identifier ordering of its
  own. The consumed projection vector already uses the raw-byte ordering
  that ApertoMemory made normative in its trust-snapshot profile (commit
  `48be525`); the earlier base64url-text-vs-raw-byte ordering divergence
  between the two producers is documented in
  `interop/apertomemory-emilia/README.md` and is not touched here.
