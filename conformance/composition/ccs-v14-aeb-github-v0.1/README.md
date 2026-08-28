# CCS v1.4 + AEB GitHub consequence profile

This independent composition fixture pins Correctover's public CCS v1.4.0
conformance bundle, verifies its public ALLOW receipt, and maps a compatible CCS
ALLOW to one executor-owned GitHub issue-update action and CAID.

The CCS receipt is evidence that a machine-policy decision allowed a tool call.
It is not execution authority. Provider entry additionally requires a current
AEB evaluation for the exact action and a separate EMILIA relying-party
authorization decision.

Run:

```sh
npm run conformance:composition:ccs-v14-aeb-github
```

The eight deterministic cases prove that the valid composition enters the
counting provider once; receipt tampering, wrong relying party, stale status,
action substitution, and absent EMILIA authority enter it zero times; and a
lost provider response returns `INDETERMINATE` and prevents blind re-entry.

Limits: the checked-in upstream receipt uses Correctover's public deterministic
conformance key. The GitHub-shaped receipt is an EMILIA-authored compatible
fixture, not a Correctover certification. The provider is a test stub and does
not modify GitHub. The result is at-most-one provider entry, not exactly-once
physical execution; `INDETERMINATE` requires authenticated reconciliation.
