<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-RECEIPT-SCITT-PROFILE-v1 — an EMILIA authorization receipt as a SCITT Signed Statement

**Status:** working profile for SCITT WG engagement. Maps the EMILIA authorization receipt onto
`draft-ietf-scitt-architecture` + `draft-ietf-scitt-scrapi`. Not yet posted to a list.

## What this profile does (and does not) claim

SCITT is **agnostic about who authorized a statement** — its Transparency Service registers signed
statements in an append-only log and returns an inclusion **Receipt** (proof a statement was logged).
EMILIA supplies the **authorization** SCITT leaves open: *a named human approved this exact action.*
This profile carries an EMILIA authorization receipt **as a SCITT Signed Statement**, so the two
compose without either claiming the other's job.

> Vocabulary, kept strict throughout: **authorization receipt** = EMILIA (who approved what);
> **transparency / inclusion receipt** = SCITT (proof it was logged). They are different artifacts.

## 1. The Signed Statement

A SCITT Signed Statement is a `COSE_Sign1` (RFC 9052) over an Issuer's assertion about an Artifact.

| COSE_Sign1 element | EP-RECEIPT-SCITT-PROFILE-v1 value |
|---|---|
| **payload** | the EMILIA receipt's RFC 8785 (JCS) canonical bytes — the exact bytes the native EP signature already covers (the `payload` object of `EP-RECEIPT-v1`) |
| protected `alg` (label 1) | `EdDSA` (-8); Ed25519 per RFC 8037 / RFC 8032 — the same key EP already uses |
| protected `content type` (label 3) | `application/ep-receipt+json` |
| protected `kid` (label 4) | the issuer key id (SHA-256/16 of the issuer SPKI; same derivation as the JWS profile) |
| protected `cwt`/issuer-subject (SCITT) | `issuer` = the authorizing authority; `subject` = the action identifier (`action_type` + bound target / `action_digest`) — so statements about one action collate |
| signature | Ed25519 over the COSE `Sig_structure` (`["Signature1", protected, ext_aad="", payload]`, RFC 9052 §4.4) |

The signer is the **same human/authority key** as the native receipt. A verifier therefore gets the
identical authorization claim whether it checks the native `EP-RECEIPT-v1`, the JWS profile, or this
COSE Signed Statement — three serializations, one canonical claim.

## 2. Registration (SCRAPI)

Register the Signed Statement with any conforming Transparency Service:

```
POST /entries                       (draft-ietf-scitt-scrapi)
Content-Type: application/cose
<COSE_Sign1 bytes>
```

The Transparency Service returns a **SCITT Receipt** (a COSE inclusion proof,
`draft-ietf-cose-merkle-tree-proofs`). Signed Statement + Receipt = a **Transparent Statement**: the
authorization is now both *attributable to a named human* (EMILIA) and *tamper-evidently logged*
(SCITT). EMILIA does not run the log; it produces the statement the log ingests.

## 3. Execution lineage (multi-hop)

The lineage chain is **EMILIA/COSA content, not a SCITT feature.** Each hop is its own Signed
Statement whose payload carries a `prev` field = the SHA-256 of the prior hop's canonical receipt
(EMILIA evidence-chain / AEC). Registering each hop yields external log transparency and inclusion
for every EP-linked hop:

```
hop₀ (receipt, prev=∅)  ─register→  Receipt₀
hop₁ (receipt, prev=H(hop₀)) ─register→ Receipt₁
hop₂ (receipt, prev=H(hop₁)) ─register→ Receipt₂
```

EMILIA defines and verifies the lineage link; SCITT proves each linked statement was logged in a
tamper-evident Transparency Service. Neither needs a monolithic lifecycle protocol — this is two
narrow profiles on accepted work.

## 4. Verification

1. Verify the `COSE_Sign1` signature against the issuer key (offline; no Transparency Service needed
   for the *authorization* check).
2. Parse the payload; confirm it is byte-identical EP-RECEIPT-v1 canonical (JCS) form, and that the
   bound action matches the action about to execute (action-binding).
3. If a SCITT Receipt is present, verify the inclusion proof against the Transparency Service's
   verifiable data structure (the *transparency* check — independent of step 1).

Steps 1–2 are the EMILIA authorization check and need no network. Step 3 is the SCITT transparency
check. Keep them conceptually separate.

## 5. Freshness ("decay")

Staleness/replay control is **freshness**, not a new mechanism: EMILIA's validity window +
observed-evidence freshness, plus one-time consumption, plus the Transparency Service's
non-equivocation (a re-registered/forked statement is detectable in the append-only log). State it in
those terms — not as "decay physics."

## 6. Status

- **EMILIA** — `draft-schrock-ep-authorization-receipts` (individual I-D, Apache-2.0). Reference
  verifiers JS/Python/Go; JWS profile shipped (`EP-RECEIPT-JWS-PROFILE-v1`).
- **SCITT** — `draft-ietf-scitt-architecture` + `draft-ietf-scitt-scrapi` + COSE Receipts
  (`draft-ietf-cose-merkle-tree-proofs`): active WG drafts (Microsoft Signing Transparency is GA, so
  the substrate is real). **Not** an endorsement by the SCITT WG; this is a complement profile.
- **COSE / Ed25519** — RFC 9052 / RFC 9053 / RFC 8032 (published).

Runnable examples (zero-dependency, signature-correct) are in `examples/scitt/`.

Local profile conformance harness:

```
node examples/scitt/ep-receipt-scitt-conformance.mjs
```

End-to-end reproducible CI harness:

```
node examples/scitt/ep-receipt-scitt-end-to-end.mjs
```

That path builds the EP receipt, wraps it as a `COSE_Sign1` Signed Statement, registers it through
the SCRAPI `/entries` shape against an in-process mock Transparency Service, returns a mock
transparency receipt, and verifies the receipt signature + statement hash + Merkle inclusion path.
The mock exists so the demo can run green forever in CI; it is deliberately **not** a SCITT WG
Receipt format claim.

Optional external SCRAPI registration target:

```
SCITT_URL=https://<transparency-service> node examples/scitt/ep-receipt-scitt-end-to-end.mjs
```

External mode proves EP/COSE construction and registration against the target. It must not be
described as full SCITT transparency verification until that target's returned Receipt is verified
against that service's parameters.

HTTP mock server, when a socket-level SCRAPI-shaped endpoint is useful:

```
node examples/scitt/mock-scrapi-transparency-service.mjs
```

Historical/community emulator target:

- `scitt-community/scitt-api-emulator` exists and may be useful as an interoperability target, but it
  is archived; do not call it the current IETF reference emulator unless the SCITT WG says so.
- The current primary standards target is the `draft-ietf-scitt-scrapi` specification and WG repo.

Legacy live smoke-test alias:

```
SCITT_TS_URL=https://<transparency-service> node examples/scitt/ep-receipt-scitt-conformance.mjs
```

The legacy conformance harness posts the generated `COSE_Sign1` to `POST /entries` and reports the
returned bytes. It still does **not** claim full SCITT Receipt verification until the returned
transparency / inclusion receipt is independently verified against that service's parameters.
