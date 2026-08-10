# EMILIA Forgery Bounty — Readiness Assessment

Subject: whether the published `@emilia-protocol/verify` verifier is solid enough
to bond a public **$10,000 receipt-forgery bounty**, and the evidence + regression
corpus that decision needs.

Prepared on branch `verifier-hardening` (worktree copy of `origin/main`).
Base commit assessed: `24e2468e`. **The bounty MUST reference the tip of
`verifier-hardening`** (the commit that carries the two parity fixes and this
corpus), not the base — see §Findings.

## The in-scope claim (what an attacker must break to win)

> No one can produce a receipt that the **published verifier returns `valid:true`
> for**, when the named human/issuer did not produce the authorization signature
> over that **exact** action.

Concretely, a **win** is any input for which:

- `verifyReceipt(doc, PINNED_KEY)` returns `valid:true` while `doc.payload` (the
  action) was never Ed25519-signed by the holder of `PINNED_KEY`; **or**
- `verifyTrustReceipt(receipt, { approverKeys: PINNED, logPublicKey: PINNED })`
  returns `valid:true` while, for at least one counted approval, the pinned key's
  named `approver_id` did not sign (Class B: Ed25519 over the context digest;
  Class A: a WebAuthn assertion whose challenge binds that digest) a context that
  commits to the submitted action.

Both the Node (`.`) and browser (`./web`) entry points are in scope. For APIs
exported by both, including `verifyReceipt`, they MUST return the **same**
`valid` verdict for the same document. `verifyTrustReceipt` is Node-only and is
adjudicated only through the Node entry point.

## Public-key set the bond is defined against

The verifier holds **no built-in trust root**: every key is relying-party-pinned
and passed in at call time. The bounty is therefore defined against a **fixed,
published challenge**, not against "EMILIA's key":

1. Publish a frozen challenge bundle: one or more `PINNED_KEY` public keys
   (Ed25519 SPKI DER, base64url) for `verifyReceipt`, and a pinned
   `{approverKeys, logPublicKey}` directory for `verifyTrustReceipt`, generated
   for the bounty and with the private keys held only by EMILIA.
2. The attacker submits a `doc`/`receipt` (and, for trust receipts, may use the
   published pinned directory verbatim) that the verifier returns `valid:true`
   for, without EMILIA having signed the submitted action with the matching
   private key.
3. Verdict is decided by running the two published entry points at the pinned
   commit with the published pinned keys. Nothing else is trusted.

This must be spelled out in the bounty text; without a fixed pinned-key challenge
the claim is ambiguous (a hunter could "win" by pinning their own key, which is
not a forgery, only a misuse of the API contract).

## Out of scope (enumerated)

- Breaking Ed25519 or ECDSA-P256 as primitives (key recovery, discrete log,
  hash collisions in SHA-256).
- Theft, exfiltration, or misuse of a legitimate private key; phishing an
  approver; social engineering.
- Tricking an LLM/agent/classifier into *requesting* an action (the verifier
  proves the human authorization, not the wisdom of the request).
- Denial of service, resource exhaustion, ReDoS, memory/CPU (a refusal is a
  correct outcome; a slow refusal is not a forgery).
- Bugs in code that is **not** the verifier: the Gate enforcement plane, the
  transparency log server, issuance, SDK glue, `lib/signatures.ts` (marketplace
  provenance-tier scoring, a separate subsystem with its own canonicalizer),
  demo apps, the MCP server.
- Relying-party misuse of the API: pinning the attacker's own key, reading
  unsigned document fields as if signed, ignoring `decision_scope`
  (`authenticity_only`), or treating an authenticity `valid:true` as admission /
  replay prevention. Offline verification never claims currency or single-use.
- Theoretical findings with no working PoC against the published entry points.

## Findings from the hardening pass

Two CONFIRMED cross-runtime **parity** gaps. Neither is a forgery (in both, the
signer *did* sign the action; the divergence is on unsigned envelope shape), but
both had to be closed before the bond, because the claim says "the published
verifier" and there are two of them — a hunter making them disagree is a valid
class of submission. Both are FIXED in `src/web.ts` with regression tests.

| ID | Severity | Where | Before | After |
| --- | --- | --- | --- | --- |
| **F1** | parity / hardening | `src/web.ts` `verifyReceipt` | Web accepted a doc with an out-of-EP-profile **unsigned** sibling field (e.g. `meta.evil: 1e21`) that Node **refused** — two published verifiers, two answers | Web now runs the same `isStrictCanonicalJson(doc)` + payload gate as Node; both refuse |
| **F2** | robustness / parity | `src/web.ts` `verifyReceiptBundle` | Web **threw** an uncaught `TypeError` on a bundle missing `documents`; Node returned a clean failure | Web now mirrors Node's `Array.isArray` guard and returns a clean failure |

PoCs and the fixed behavior are pinned in
`tests/verifier-forgery/forgery.test.mjs` (tests `F1 FIXED`, `F2 FIXED`, and the
`parity sweep`).

### Everything else attempted — REFUSED (fails closed)

Each is a permanent test in the corpus:

- **(g) VERIFIED-without-authorization:** signature over action X submitted with
  action Y → refused (signature mismatch); trust-receipt action swapped under a
  real signature → `checks.action_hash:false`.
- **(c) key substitution / issuer confusion:** attacker-key signature vs pinned
  key → refused; pinned key whose `approver_id` ≠ context `approver` → refused;
  pinned key missing `approver_id` → refused.
- **(b) algorithm confusion / downgrade:** non-Ed25519 pinned key → refused
  fail-closed; Class-A pinned key cannot be downgraded to a bare Ed25519 signoff
  via `key_class:'B'` → refused. `doc.signature.algorithm`'s *value* is ignored
  (crypto is pinned by key type), so `alg:"none"` grants nothing — a valid
  Ed25519 signature over the exact payload is still required. **Documented, not
  changed:** an allowlist on the field would break legitimately-issued receipts
  whose `algorithm` is a descriptive string (`"Ed25519 over RFC 8785 (JCS)…"`,
  and some `"ES256"`), and would add no security because the field is not
  load-bearing.
- **(a) canonicalization ambiguity:** non-safe-integer numbers in signed material
  → refused (cross-language float hazard); key reordering → identical canonical
  bytes, same signature (not a forgery); duplicate JSON keys collapse under
  `JSON.parse` before the verifier sees them (the verifier consumes parsed
  objects), and the only raw-JSON surface (WebAuthn `clientDataJSON`) rejects
  duplicate keys via `strictJsonGate`.
- **(d) signature malleability:** bit-flipped signature → refused.
- **(i) truncation / extra data:** extra byte on a signature → refused;
  non-canonical base64url → refused; canonical DER enforced on P-256 WebAuthn
  signatures in the web path.
- **(f) type confusion:** `signature.value` as array/number/object/null/bool →
  refused; `context_hash` as array/number → does not bind a context → refused.
- **(e) missing/defaulted required fields:** missing version/payload/signature,
  empty contexts/signoffs, string or non-integer `required_approvals`, a signed
  **denial** counted as approval → all refused.
- **(h) replay:** verifier is authenticity-only; `decision_scope.replay_status`
  stays `not_evaluated`. Not claimed, so not a defect.
- **Merkle:** legacy EP-MERKLE-v1 refused by default; empty inclusion path with
  `tree_size>1` refused; a leaf lifted from another receipt refused (leaf is
  bound to the canonical payload, domain-separated v2 hashing).

## Verdict

**Yes — ready to bond a public $10K forgery bounty, at low residual risk,**
provided the bounty text (a) pins the exact commit at the tip of
`verifier-hardening`, (b) publishes a fixed pinned-key challenge as in
§Public-key set, and (c) scopes the claim to the two published entry points with
the out-of-scope list above.

Basis for the confidence, and its honest limits:

- **What was tested:** the implementation-level forgery surface of the
  published JavaScript verifier APIs — canonicalization, algorithm/key pinning, identity join,
  malleability, type confusion, missing-field defaulting, Merkle leaf/branch and
  empty-path confusion, Class-A/B downgrade, and Node-Web parity for APIs shared
  by both entry points — with executed
  PoCs, not readings. 31 forgery tests plus the pre-existing 766-test verify
  suite are green at the tip.
- **What was NOT exhaustively tested:** the optional additive gates (witness
  quorum, RFC 3161 timestamp, revocation, currency, consumption, federation,
  outcome-binding) were exercised only where they intersect the core verdict;
  a bounty that puts those opt-in paths in scope needs a dedicated pass. The
  Python (`packages/python-verify`, `ep-verify-py`) and Go (`packages/go-verify`)
  ports were **not** re-audited here — if the bond covers "any published
  verifier" they must get the same treatment (their cross-language parity is the
  most likely place a real discrepancy still hides, exactly the class F1 fell in).
- **What would still worry me:** (1) cross-language canonicalization drift
  between JS, Python, and Go on an exotic-but-in-profile value — the JS profile is
  tight, but I verified only the JS pair this pass; (2) a future change to
  issuance that starts putting a security-relevant value in an *unsigned* field,
  which no verifier would catch because it is not in the signed digest; (3) Node
  `crypto`/OpenSSL Ed25519 accepting a non-canonical signature encoding — out of
  scope by assumption (primitive soundness) but worth a canonical-`S` check if
  the bond is large.

Finding nothing that forges an authorization does not *prove* the verifier is
unforgeable; it proves that a hostile implementation-level pass across the JS
entry points, with executed PoCs for every named attack class, produced zero
authorization forgeries and two now-closed parity gaps. That is a defensible
basis for a $10K bond scoped as above; it is not a basis for an unbounded or
"any language, any option" bond without the additional passes named above.
