# Finance loss boundary reference

This local, synthetic example shows where EMILIA can mediate two finance
operations without contacting a provider or moving money.

It reproduces seven boundary cases:

1. An email-derived bank-account substitution is refused before effect.
2. The same untrusted email may supply a bounded memo field.
3. A customer-bounded payout reaches the local provider once.
4. A replay cannot create a second provider call.
5. A frozen customer control domain refuses before provider entry.
6. A provider `COMMITTED` outcome remains separate from an independently
   observed `DIVERGED` effect relation.
7. An unknown post-entry outcome becomes `INDETERMINATE`, consumes the
   execution right, and refuses a blind retry.

The protection plan is an unsigned owner draft and is explicitly inactive.
The example does not establish source truth, invoice validity, settlement,
payment-loss prevention, exactly-once physical execution, or production
deployment. It claims only the observed behavior of the completely mediated
local path.

Run the deterministic report and its test from the repository root:

```sh
node examples/finance-loss-boundary/scenario.mjs
node --test examples/finance-loss-boundary/scenario.test.mjs
```

The test compares the result with `report.reference.json`. A behavior change
therefore requires an explicit review and deliberate re-pin of the reference.
