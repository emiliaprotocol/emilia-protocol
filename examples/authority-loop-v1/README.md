# Authority loop: the four verdicts of a Gate mandate

Consumer sentence: "Book travel under $500. Ask above. Never purchase alcohol."

Enterprise sentence: "Approve routine work inside policy. Escalate adverse
decisions. Never let the agent expand its own authority."

Both sentences compile to the same three deterministic artifacts: a mandate
grammar (which action types can even be named), an owner-signed Class-A
receipt over the mandate, and CAID-scoped capability envelopes carrying the
budgets. Every request an agent makes then ends in exactly one of four
terminal, signed, offline-verifiable verdicts.

Run it from the repository root:

```bash
npm run demo:authority-loop
```

## The four scenes

| Scene | Request | Verdict | Mechanism |
| --- | --- | --- | --- |
| 1 | 340 USD flight | ALLOW | CAID in scope, 340 reserved inside the 500 USD unattended budget, provider entered once, certificate verified offline |
| 2 | 620 USD flight | ASK | reservation refused with `budget_exceeded`; a fresh owner-signed capability pinned to exactly this CAID executes once; the identical replay is refused with `operation_already_committed` |
| 3 | 89 USD alcohol | REFUSE | the mandate grammar cannot resolve `purchase.alcohol`, so no CAID exists; the pinned resolver refuses with a reason before any reservation or provider entry |
| 4 | 120 USD flight, provider hangs | INDETERMINATE | the effect deadline aborts the provider; the reservation is committed as `indeterminate` (never silently reopened) and a blind retry is refused with `operation_already_committed` |

Every scene, including the refusals and the indeterminate outcome, ends in a
signed receipt-program certificate that an offline verifier checks against
the pinned signer key, the pinned mandate resolver, and the Gate evidence log.

## What is real here

Real policy evaluation (CAID grammar plus budget reservation in the
capability store), real one-time consumption (the 620 USD approval and the
120 USD operation are spendable exactly once, enforced by the store, not by
the demo script), and real offline certificate verification
(`verifyReceiptProgramCertificate` re-performs CAID resolution, signature,
context, step-structure, and evidence-inclusion checks).

## What is not claimed

This is a synthetic, local, deterministic demonstration of the cooperative
enforcement path: the agent routes its actions through the Gate kernel
voluntarily, and the providers are in-process simulations. It is not a
production deployment (stores are in-memory and explicitly test-mode; a real
deployment needs the durable PostgreSQL stores, KMS-held keys, and exact
tenant context). It is not a complete-mediation claim: nothing here prevents
a process from bypassing the Gate entirely. It is not proof of any real
provider effect: `ticketed` is a simulated answer, and the certificate is a
signed execution-and-binding statement, not proof the outside world changed.

One modeling shortcut is documented rather than hidden: the "fresh owner
approval" in scene 2 is a new owner-signed capability envelope pinned to the
exact action CAID, minted under the same standing mandate receipt. The
interactive ceremony that would mint a fresh per-action receipt and signoff
is out of scope for this demo; the one-time consumption it demonstrates is
real either way.
