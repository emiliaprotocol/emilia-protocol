# GRACE through the protected consequence boundary

This deterministic profile composes the existing synthetic GRACE mobile
authorization, actuator, meter, and settlement adapters with:

- a relying-party-pinned AEB mapping for the exact curtailment action;
- Gate's at-most-one provider-entry lifecycle;
- a hybrid-signed, state-domain-owned aggregate consequence envelope; and
- authenticated reconciliation that never reexecutes the provider call.

The hard aggregate decision is made from the requested curtailment before
provider entry. Telemetry, velocity, entropy, anomaly scores, modeled benefit,
and later meter observations cannot mint or enlarge capacity.

## Run

```sh
npm --prefix packages/verify run build
npm --prefix packages/gate run build
npm run build:standalone-runtimes
node --test conformance/composition/grace-consequence-boundary-v1/run.node-test.mjs
node conformance/composition/grace-consequence-boundary-v1/run.mjs
```

The run is synthetic. It proves the reference composition's authorization,
admission, capacity, replay, and reconciliation behavior. It does not prove
that a physical grid event occurred or that requested power was delivered.
