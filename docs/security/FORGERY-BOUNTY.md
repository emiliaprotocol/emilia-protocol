# EMILIA Forgery Bounty — program text (DRAFT)

> **STATUS: NOT LIVE. This bounty is not active.** No submissions are accepted
> and no reward is payable until an official launch announcement names a funded
> reward, a start and end date, and the frozen challenge bundle. Do not attempt
> to claim this before that announcement exists. This file is a staged draft of
> the program terms.

## The claim we are bonding

> No one can produce a receipt that the published EMILIA verifier returns
> `valid:true` for, when the named human or issuer did not produce the
> authorization signature over that exact action.

We are betting money that our verifier does not accept a forged authorization.
If you break that, we pay you and we fix it. If nobody breaks it, that is the
strongest statement we can make about the verifier.

## Scope: the JavaScript verifier, at one pinned commit

- Package: `@emilia-protocol/verify`. The launch announcement and frozen
  challenge manifest MUST name the same exact immutable commit containing the
  parity fixes and regression corpus. This staged text intentionally does not
  pin a moving branch hash.
- Both package entry points are in scope: Node (`.`) and browser (`./web`). For
  an API exported by both entry points, including `verifyReceipt`, the two MUST
  return the same `valid` verdict for the same document. `verifyTrustReceipt`
  is Node-only and is adjudicated only through the Node entry point.
- The Python and Go ports are **out of scope** for this program. They have not
  been through this hardening pass. A separate program may cover them later.

## What counts as a win

Any input for which, at the pinned commit and against the published pinned keys:

- `verifyReceipt(doc, PINNED_KEY)` returns `valid:true` while `doc.payload` (the
  action) was never Ed25519-signed by the holder of `PINNED_KEY`; or
- `verifyTrustReceipt(receipt, { approverKeys: PINNED, logPublicKey: PINNED })`
  returns `valid:true` while, for at least one counted approval, the pinned key's
  named `approver_id` did not sign a context that commits to the submitted
  action; or
- the Node and browser implementations of an API they both export return
  different `valid` verdicts for the same input.

## The frozen challenge

The verifier holds no built-in trust root: every key is supplied by the relying
party at call time. So the bounty is defined against a fixed, published challenge,
not against "EMILIA's key":

1. At launch we publish a challenge bundle: the `PINNED_KEY` public keys
   (Ed25519 SPKI DER, base64url) for `verifyReceipt`, and a pinned
   `{approverKeys, logPublicKey}` directory for `verifyTrustReceipt`. The
   matching private keys are held only by EMILIA and are never used to sign the
   action you are trying to forge.
2. You submit a document or receipt that the verifier returns `valid:true` for,
   using those published pinned keys, without EMILIA having signed your submitted
   action with the matching private key.
3. Adjudication is mechanical: we run every in-scope implementation of the
   submitted API at the pinned commit against the published pinned keys. Shared
   APIs run through Node and browser; `verifyTrustReceipt` runs through Node.
   The verifier output decides it. Nothing else is trusted, which protects you
   as much as us.

Pinning your own key, or reading unsigned document fields as if they were signed,
is a misuse of the API contract, not a forgery, and does not win.

## Out of scope

- Breaking Ed25519 or ECDSA-P256 as primitives (key recovery, discrete log,
  SHA-256 collisions).
- Theft, exfiltration, or misuse of a legitimate private key; phishing an
  approver; social engineering.
- Tricking an LLM, agent, or classifier into requesting an action. The verifier
  proves the human authorization, not the wisdom of the request. Fooling the
  model is expected: the model has no authority. That is the whole point.
- Denial of service, resource exhaustion, ReDoS. A refusal is a correct outcome;
  a slow refusal is not a forgery.
- Bugs in code that is not the verifier: the Gate enforcement plane, the
  transparency log server, issuance, SDK glue, the marketplace provenance-scoring
  canonicalizer, demo apps, the MCP server.
- Relying-party misuse: ignoring `decision_scope` (`authenticity_only`), or
  treating an authenticity `valid:true` as admission or replay prevention.
  Offline verification never claims currency or single-use.
- Theoretical findings with no working proof-of-concept against the published
  entry points.

## Rules

- Time-boxed window (dates set at launch). First valid submission wins. One
  reward per program window.
- Reward amount is set in the launch announcement and held in escrow before the
  window opens. No claim is payable against an unfunded or unannounced program.
- Report privately to the address in the launch announcement with a runnable
  proof-of-concept. Do not disclose publicly before we confirm and fix.

## The hardening loop

Every submission is run through the harness. A valid forgery is paid and fixed.
Every rejected or out-of-scope attempt is added to the regression corpus with the
verifier's own refusal reason, so attacks that do not win still make the verifier
stronger. The corpus lives at `tests/verifier-forgery/`.

## Honest limit

Finding no forgery does not prove the verifier cannot be forged. It proves that a
funded, adversarial, proof-of-concept-backed program over the pinned JavaScript
verifier produced no forgery. That is strong evidence, deliberately bounded, and
we state it as exactly that.
