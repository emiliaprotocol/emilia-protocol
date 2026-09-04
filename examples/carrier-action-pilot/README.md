# Payment-release carrier pilot

This is one narrow question in executable form: can a relying party assemble a carrier-readable technical record for one gated payment release, then get the same result when it checks the record again?

The happy path returns `TECHNICALLY_COMPLETE`. The same run also shows the cases that must not pass:

- the payee or exact action changes;
- the qualification is suspended or an older status is replayed behind a newer status head;
- a provider supplies only a digest instead of a signed Outcome Observation v2;
- the provider's answer is lost or unclear;
- the provider console is left outside the mediated surface set; or
- a loss is reported and someone tries to treat that fact as a coverage decision.

Run it from the repository root:

```sh
node --test examples/carrier-action-pilot/scenario.test.mjs
node examples/carrier-action-pilot/scenario.mjs
```

## What is real here

The example calls the repository's real implementations for:

- the hybrid Ed25519 and ML-DSA-65 action-risk control schedule;
- the independently signed qualification status and relying-party status head;
- two hybrid-signed Outcome Observation v2 records from separate control domains;
- the provider-outcome binding; and
- the content-addressed Action Evidence Packet verifier.

The schedule requires two different outcome sources and a two-of-two quorum. The provider event must fall inside each source's signed observation interval. An unclear result leaves the open-exposure state indeterminate and applies the schedule's `REFUSE_RETRY_PRESERVE_OPEN_EXPOSURE_REQUIRE_RECONCILIATION` rule.

## What is synthetic

Every identifier, key, payment, account, surface, timestamp, and artifact is fake. Fixed key seeds and fixed times keep the decisions reproducible. ML-DSA uses hedged signing, so raw signature bytes and packet digests are not promised to repeat across runs. That is why this directory does not commit a `reference-packet.json`; the stable reference is the tested decision output, not one randomized signature encoding.

The native component callbacks are small caller-controlled test adapters. They check content addresses, subject binding, expected state, and the declared two-surface inventory. They do not independently reperform a live AEB, admission log, provider console, financial ledger, or loss process. A production pilot must replace each callback with a relying-party-selected native verifier and its own trust pins, currentness rules, and durable state.

The v1 schedule itself pins only its issuer and qualification-status authority.
Native-component and provider-observer keys are separate relying-party inputs;
the schedule does not establish that those adapter pins agree with a signed
component-to-key map. That stronger link needs a typed future profile.

No carrier or provider has adopted this example. `TECHNICALLY_COMPLETE` is not authorization, a policy, coverage, pricing, liability allocation, claim adjudication, or a promise to pay. A reported loss remains a verified input only. The licensed or otherwise authorized parties keep their underwriting, distribution, risk-bearing, and claims decisions.
