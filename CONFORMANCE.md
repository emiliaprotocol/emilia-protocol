# EMILIA Protocol — Conformance

EMILIA is a *protocol*, not just a product: the value is that **anyone can
implement it and anyone can verify it, identically, with no EP server in the
trust path.** This document defines what a conformant implementation is and how
to prove it.

---

## 1. Authorization-receipt conformance (EP-RECEIPT-v1)

This is the core of the protocol: a signed, offline-verifiable authorization
receipt. An implementation is **EP-RECEIPT-v1 conformant** if, for every vector
in [`conformance/vectors/receipts.v1.json`](conformance/vectors/receipts.v1.json),
its verifier returns `expect.valid`.

The vectors are an adversarial battery — each one pins a single protocol
invariant:

| Class | Vectors |
|---|---|
| **accept** | minimal receipt · deeply-nested payload (recursive canonicalization) · key-order-independence · valid Merkle anchor |
| **reject** | unsupported version · missing signature · tampered payload · wrong key · malformed signature · tampered Merkle anchor |

### Three cross-language reference verifiers, proven to agree

The repository ships JavaScript/TypeScript, Python, and Go reference verifiers
in one repository. They are a cross-language consistency check, not clean-room
independent implementations:

| Language | Package |
|---|---|
| JavaScript / TypeScript | [`packages/verify`](packages/verify) (Node + `/web` Web Crypto build) |
| Python | [`packages/python-verify`](packages/python-verify) |
| Go | [`packages/go-verify`](packages/go-verify) |

Run the cross-language conformance suite — it feeds the **same** vectors through
all three and asserts they agree with each other and with the expected outcome:

```bash
node conformance/run.mjs
```

```
EP-RECEIPT-v1                   — 13 vectors   JavaScript ✓   Python ✓   Go ✓
EP-SIGNOFF-v1                   — 13 vectors   JavaScript ✓   Python ✓   Go ✓
EP-RESOLUTION-v1                — 33 vectors   JavaScript ✓   Python ✓   Go ✓
EP-QUORUM-v1                    — 15 vectors   JavaScript ✓   Python ✓   Go ✓
EP-REVOCATION-v1               — 12 vectors   JavaScript ✓   Python ✓   Go ✓
EP-TIME-ATTESTATION-v1         —  6 vectors   JavaScript ✓   Python ✓   Go ✓
EP-TRUST-RECEIPT-v1 (§6.2)     — 14 vectors   JavaScript ✓   Python ✓   Go ✓
EP-TRUST-RECEIPT-v1 ts-profile —  7 vectors   JavaScript ✓   Python ✓   Go ✓
EP-PROVENANCE-CHAIN-v1         — 14 vectors   JavaScript ✓   Python ✓   Go ✓
EP-EVIDENCE-RECORD-v1          —  5 vectors   JavaScript ✓   Python ✓   Go ✓
EP-CANONICALIZATION-v1         — 35 vectors   JavaScript ✓   Python ✓   Go ✓
EP-BOUNDARY-v1                 —  5 vectors   JavaScript ✓   Python ✓   Go ✓
EP-AEC-ROLE-v1                 — 30 vectors   JavaScript ✓   Python ✓   Go ✓
EP-CURRENCY-v1                 — 13 vectors   JavaScript ✓   Python ✓   Go ✓
EP-INITIATOR-ATTESTATION-v1    — 11 vectors   JavaScript ✓   Python ✓   Go ✓
EP-SMT-CONSUME-v1              —  6 vectors   JavaScript ✓   Python ✓   Go ✓
EP-WITNESS-v1                  —  6 vectors   JavaScript ✓   Python ✓   Go ✓
EP-TIMESTAMP-PROOF-v1          — 13 vectors   JavaScript ✓   Python ✓   Go ✓

✅ 251 vectors · 18 suites — JavaScript, Python, and Go verifiers agree.
   (One team's three-language ports in one repository: a consistency check,
    not independent reimplementations.)
```

The externally portable clean-room bundle remains a separately pinned
16-suite/164-vector baseline; the newer 30-vector AEC acceptance and 33-vector
four-outcome resolution suites have not been attributed to that external
implementation. An externally authored Rust
verifier is evaluated in a separate CI lane from
the immutable source commit pinned in
[`conformance/external/rust-cleanroom-jdieselny.v1.json`](conformance/external/rust-cleanroom-jdieselny.v1.json).
It passes the pinned 16-suite/164-vector clean-room bundle. That is external interoperability
evidence, but not yet strict clean-room acceptance: the construction claim is
signed by the implementation organization rather than a separate attestor.
The evaluator-controlled rebuild also passes the pinned differential-hostility
campaign: 353 structured attacks plus 6 raw-parser refusals across Unicode,
timestamps, SPKI encodings, action permutations, hostile types, and evidence
graphs, with zero divergences. CI requires both results to pass. A separate
third-party-attested GUV'NOR result is not counted until its corrected manifest
and independently pinned attestor key are checked in and re-evaluated.

The CI job `aggregate-conformance-case` waits for both the same-team manifest
and the external Rust campaign, revalidates their source pins, suite hashes,
hostility corpus, evaluator commit, and construction-attestation boundary, then
emits and GitHub-attests `EP-CONFORMANCE-CASE-v1`. The current case reports three
same-team ports, one externally authored implementation passing its pinned 164 vectors and
359 hostile cases, and zero strict independently attested clean-room
acceptances. That counter can change only when checked-in evidence passes the
strict intake; prose cannot promote it.

The three cross-language verifiers agree across the core artifact surface:
not only Ed25519 authorization **receipts**, but Class-A WebAuthn device
**signoffs**, **EP-QUORUM-v1 multi-party approval** (M-of-N / ordered — the
"two-person rule," with a strong cryptographic ordering chain and distinct-key
checks, fail-closed), portable **revocation** statements, **trusted-time
attestations**, the full **§6.2 Trust Receipt** (signoff signatures + Merkle
inclusion + Ed25519-signed checkpoint), **provenance chains** (human-authority
root → delegation chain → action, with scope containment), **EP-AEC acceptance**
(executor-action binding, Class-A or quorum profiles, registry freshness), and five **opt-in
profiles**: **EP-CURRENCY-v1** (the two-valued authentic-as-of-commit vs
currency-at-T result, where `unknown` is the honest offline default),
**EP-INITIATOR-ATTESTATION-v1** (fail-closed field validation + hostile-text
neutralization), **EP-SMT-CONSUME-v1** (sparse-Merkle one-time-consumption
transition), **EP-WITNESS-v1** (k-of-n witness cosignatures over one
checkpoint head), and **EP-TIMESTAMP-PROOF-v1** (an INDEPENDENT RFC 3161
proof of WHEN: a pinned external TSA's TimeStampToken over the caller's expected
digest, fail-closed on any refusal). Publishing a public, cross-language
conformance suite of this breadth, re-proven on every push (CI job
`conformance`), is itself uncommon.

**timestamp-proof (RFC 3161) is now cross-language.** It began as a JavaScript-only
reference verifier (a purpose-built minimal DER/CMS reader in pure `node:crypto`)
because neither the Python dependency (`cryptography`) nor the Go standard
library exposes an RFC 3161 TimeStampToken / TSTInfo / CMS SignedData API that
returns the signed bytes. Rather than pull in a heavy CMS dependency, the same
minimal DER/CMS reader was ported faithfully to **pure Python** (the structural
parse is hand-rolled; `cryptography` is used only for the RSA/ECDSA signature
verification, so no new dependency) and to **pure-stdlib Go** (`crypto/rsa` +
`crypto/ecdsa` + `crypto/x509` for the verify). All three lanes now agree over
real `openssl`-minted TimeStampTokens in
[`conformance/vectors/timestamp-proof.v1.json`](conformance/vectors/timestamp-proof.v1.json),
including the exact per-vector refusal path (unpinned TSA, digest mismatch, wrong
pinned key, tampered signature, non-SignedData, unparseable token). Other
artifacts still remain outside the three-language run today (WYSIWYS rendering,
execution-integrity, the JWS profile) and are exercised in
JavaScript only; bringing them into the cross-language run, and independent
implementations, are the next bar. The
companion Internet-Drafts are
[`draft-schrock-ep-authorization-receipts`](standards/) and
[`draft-schrock-ep-quorum`](standards/).

### Canonicalization-malleability battery (EP-CANONICALIZATION-v1)

Every signed EP artifact is verified over recursive canonical JSON, so
canonicalization divergence between implementations is a signature-forgery
surface. [`conformance/vectors/canonicalization.v1.json`](conformance/vectors/canonicalization.v1.json)
is a differential battery of raw JSON texts that pins the RFC 8785 / I-JSON
behavior byte-for-byte across all three languages: Unicode normalization is NOT
applied (NFC and NFD spellings pin distinct digests on purpose), escaped and
literal spellings of the same code points pin the same digest, member names
sort by UTF-16 code units, integer-valued number tokens (`1`, `1.0`, `1e0`,
`-0`) pin one canonical serialization, and duplicate member names, unpaired
surrogate escapes, out-of-profile numbers, and nesting deeper than the
suite-pinned bound of 64 must all reject. Accept vectors carry a pinned SHA-256
of the canonical bytes, so agreement is proven on the exact bytes, not just the
verdict. Scope, stated honestly: the duplicate-name, surrogate, and depth gates
live in each conformance runner at the parse boundary (the verify packages
receive already-parsed values); the profile predicate, canonical serialization,
and digests exercise the verify packages themselves. Regenerate with
`node conformance/vectors/generate-canonicalization.mjs`.

> **Scope, stated honestly.** Multi-party quorum is a *verifiable protocol
> capability* with cross-language reference verifiers and a live in-browser demo
> ([`/try/multi-party`](https://www.emiliaprotocol.ai/try/multi-party)). The
> server-side enforcement is wired into the live authorization path and is
> **verified end-to-end**: an automated test drives three independent virtual
> authenticators through an ordered signoff (program officer → authorizing
> official → inspector general) and asserts a quorum-gated trust receipt
> *cannot* be consumed until the full quorum is satisfied — re-verified through
> the same fail-closed predicate (distinct humans, roles, order, window,
> action-binding, signatures), with an early-reject gate at signoff time
> ([`e2e/multi-party-quorum.spec.js`](e2e/multi-party-quorum.spec.js)). What
> remains before calling it *fielded*: a production deployment of that flow and
> (for defense) an accredited environment. The orchestration is built, merged,
> and end-to-end verified; the verifier proves a quorum is satisfiable and
> checkable offline.

### The format, in one paragraph

A receipt is `{ "@version": "EP-RECEIPT-v1", "payload": {…}, "signature":
{ "algorithm": "Ed25519", "value": <base64url> } }`, optionally with an
`anchor` (Merkle inclusion proof). Verification: (1) the version is recognized;
(2) the Ed25519 signature verifies over the **recursive key-sorted canonical
JSON** of `payload` (RFC 8785-style — sort keys at every depth, no whitespace);
(3) if an `anchor` is present, its proof folds the leaf hash through sorted-pair
SHA-256 steps to the claimed root. `valid = version ∧ signature ∧ (anchor ∈
{absent, true})`.

### Claiming conformance for a new implementation

1. Implement `verifyReceipt(document, publicKeyBase64url) → { valid }` for the
   format above.
2. Run your verifier against every vector in `receipts.v1.json`; return
   `expect.valid` for each.
3. Add a runner under `conformance/runners/` and wire it into `conformance/run.mjs`
   so your implementation is proven against the others on every push.

Conformance is self-certified against the published vectors. An implementation
that passes all vectors may state: **"EP-RECEIPT-v1 conformant — vectors v1.0.0."**

### Class A (device signoff) conformance — EP-SIGNOFF-v1

The Class-A human device-signoff primitive (a WebAuthn ECDSA P-256 assertion
whose challenge is the SHA-256 of the JCS-canonicalized authorization context)
has its own adversarial vector battery in
[`conformance/vectors/signoffs.v1.json`](conformance/vectors/signoffs.v1.json),
verified by the JavaScript reference in both Node and browser (Web Crypto)
builds:

```bash
node conformance/run-signoffs.mjs    # or: npm run conformance:signoffs
```

Each reject vector is tagged with its **failure class**, so the suite doubles as
a verifier decision table:

| Failure class | Vectors |
|---|---|
| structural | ceremony type is a registration, not an assertion |
| cryptographic | wrong approver key · malformed signature |
| action-binding | action-hash altered after signing · nonce (consumption key) altered — challenge no longer binds |
| operation / audience | assertion scoped to the wrong relying party |
| lifecycle / UV | user-verification absent (no biometric/PIN) · user-presence absent |

Scope note: these exercise the **offline** assertion verifier. Replay /
one-time consumption (the nonce is the global consumption key) and
enrollment-active are **server-state** checks, out of scope for offline
assertion vectors. The signoff verifiers agree across JavaScript, Python, and Go
today (see EP-SIGNOFF-v1 above); signoffs are part of the three-language interop
surface, not a pending milestone.

---

## 2. Legacy: scoring-layer conformance

The earlier trust-scoring layer (hashes, trust profiles, policy decisions) has
its own fixtures in `conformance/fixtures.json`, exercised by
`conformance/conformance.test.js` and `conformance/verify_hashes.py`.

| Level | Requirements |
|-------|-------------|
| **Hash-compatible** | All hash fixtures produce identical SHA-256 outputs |
| **Score-compatible** | All scoring fixtures produce outputs within ±0.1 tolerance |
| **Policy-compatible** | All policy fixtures produce identical Trust Decisions (allow/review/deny) |

### Scoring-layer invariants

1. **Hash determinism** — identical receipt inputs produce identical SHA-256 hashes regardless of language.
2. **Trust barrier** — pure unestablished volume cannot cross the establishment threshold.
3. **Policy monotonicity** — if an entity passes `strict`, it passes `standard`, `permissive`, and `discovery`.
4. **Appeal supremacy** — every negative trust effect must be challengeable.

---

## Reporting issues

If the reference implementations disagree, or contradict the spec, **that is a
bug worth a GitHub issue** — protocol correctness outranks backward
compatibility, and the cross-language suite exists precisely to catch it.
