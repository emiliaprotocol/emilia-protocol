# Current-manifest differential hostility

The historical external Rust result remains bound to its frozen 16-suite,
164-vector bundle and its frozen hostility corpus. Do not use this lane to
change that result.

To build and run a new hostility campaign from the live conformance manifest:

```sh
node scripts/differential-hostility.mjs \
  --manifest conformance/conformance-manifest.json \
  --emit test-results/current-manifest-hostility.json
```

This mode verifies every suite byte hash, execution-companion hash, vector
count, and manifest total before generating cases. The report records the
exact suite revisions it covered. It also carries a required malformed
`predicted_effects` case whose only accepted outcome is `incomparable`; this
would reproduce the earlier cross-language divergence if that refusal
regressed in any port.

The built-in JavaScript, Python, and Go runs remain one-team differential
evidence. To evaluate an external runner, pass an `--external-runners` config
and preserve its runner hash with the emitted report. A new external result
must use the same current manifest and generated corpus bytes. It does not
enlarge or replace the historical result.

This script does not create a process or network sandbox. Run an external
campaign inside an offline, evaluator-controlled sandbox and record that
environment separately. Strict clean-room acceptance still requires the
implementer's signed construction statement and a separate accepted
independent-organization attestation.
