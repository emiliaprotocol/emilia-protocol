# Independent reproduction

Run this from a fresh clone at the exact candidate commit supplied for review.
The runner accepts no command overrides and refuses a dirty tracked worktree.
It executes the fixed commands embedded in `independent-runner.mjs` and emits
an unsigned JSON run record to standard output. The record includes Node and
npm versions, the package-lock digest, and clean tracked-worktree state before
and after the run.

```sh
git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol
git checkout --detach <exact-reviewed-commit>
npm ci
node conformance/composition/cedulon-aeb-crossing-v0.1/adoption/independent-runner.mjs \
  > /tmp/cedulon-aeb-independent-run.json
```

Do not pipe through a formatter before preserving the original bytes. Send:

1. `/tmp/cedulon-aeb-independent-run.json`;
2. the exact commit hash you were asked to review;
3. your completed identity/independence fields from
   `independent-run-attestation.template.json`; and
4. an external signature or signed email if you choose to attest the record.

The repository does not create or verify the reviewer's identity. `PASS` means
only that the fixed local commands exited successfully and the two profile
entry points returned the same checked-in deterministic report. It is not an
endorsement, certification, deployment result, or security audit.
