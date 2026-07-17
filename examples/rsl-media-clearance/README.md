# RSL-MEDIA declaration to EMILIA exact-use clearance

This runnable reference demonstrates an adjacent composition:

1. an external RSL-MEDIA processor evaluates a standing rights declaration;
2. the rights holder signs an `EP-CONSENT-GRANT-v1` for a bounded campaign;
3. a Class-A-shaped WebAuthn ceremony signs one exact AI-generation action;
4. the executor verifies the receipt and grant under its own pinned keys;
5. the executor re-checks a current declaration view, consumes the action digest
   once, and refuses replay even when a second receipt was independently issued.

```sh
node examples/rsl-media-clearance/demo.mjs
```

Expected result: one exact use executes. Same-receipt replay, a second receipt
for the same action, concurrent presentation, a mutated signed action, a
separately signed out-of-scope territory, a changed declaration, a prohibited
declaration, an absent declaration, and a stale declaration each refuse.

## Why this is a separate layer

RSL-MEDIA defines machine-readable declarations and a path to an external
Clearance process. Its June 3, 2026 draft says OLP-MEDIA will define request
fields, authorization-token formats, payment flows, and related mechanics. This
example shows one possible clearance artifact without modifying RSL-MEDIA:

```text
standing declaration -> signed bounded grant -> exact-use receipt -> execute once
```

The declaration is discovery and current policy input. It does not authorize
execution by itself. The grant is standing authority. The receipt is the fresh
binding moment. The executor, not the presenter, pins the keys, re-checks the
declaration-to-grant join, evaluates every constraint, and consumes by action
digest rather than by receipt identifier.

## Scope and non-claims

- This is an independent compatibility prototype. RSL Media has not endorsed it.
- RSL-MEDIA 1.0 is a draft that says it MUST NOT be used in production.
- The fixture is synthetic. This example does not parse XML or claim RSL
  conformance; it consumes a normalized result from an external evaluator.
- The virtual WebAuthn authenticator exercises real P-256 signatures, challenge
  binding, RP ID, user-presence, and user-verification checks. It is not evidence
  of a real phone or real person.
- The consent-grant signature proves a pinned key signed the grant. Raw Ed25519
  does not by itself prove hardware custody or legal identity.
- A signed grant does not manufacture current declaration state. The executor
  requires a fresh normalized declaration view and exact source-digest join.
- Nothing here establishes rights ownership, legal permission, human
  comprehension, the truth of registry data, or the safety of generated output.

Primary draft reviewed: <https://rslmedia.org/media>.
