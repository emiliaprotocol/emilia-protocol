# ep-verify

Verify one EP authorization receipt from the command line. Offline, fail-closed,
no configuration beyond the issuer keys you pin. A thin CLI over
[`@emilia-protocol/verify`](../verify).

> **Status:** prepared for the `ep-verify` npm name; **not yet published**. From
> this repository, run `node packages/ep-verify/cli.mjs` wherever the examples
> say `ep-verify`.

## Install

```sh
npm install -g ep-verify   # once published
```

## Verify one receipt in one line

```sh
ep-verify receipt.json --keys keys.json
```

`keys.json` holds the issuer public key(s) **you** pin — a base64url SPKI
string, an array of them, or `{ "keys": [...] }`. Without `--keys` the answer
is always `REFUSED` (`no_pinned_keys`): a key that travels inside the receipt
proves integrity, not trust.

Output is two lines — `VERIFIED` or `REFUSED`, then one JSON line with a
machine-readable `reason` and the individual checks. Exit code 0 only on
VERIFIED; any error, missing input, or failed check exits 1.

## What VERIFIED means

The receipt's Ed25519 signature over its canonical payload verifies against a
key you pinned, and — if the receipt carries a Merkle anchor — the EP-MERKLE-v2
inclusion proof reconstructs the claimed root.

## What VERIFIED does NOT mean

- **Not business correctness.** Verification proves signature, binding, and
  anchor/log integrity — never that the authorized action was appropriate,
  lawful, or wise.
- **Not authority.** Whether a signing key *should* be trusted is your pinning
  decision; ep-verify checks against exactly the keys you supply.
- **Not revocation or freshness.** This is a point check of one document;
  replay defense and freshness windows belong to an enforcement point such as
  [`@emilia-protocol/gate`](../gate).
- **Not a conclusion.** EP is not an auditor, regulator, or insurer; this
  output supports a decision, it never concludes one.

Cross-implementation note: the JavaScript, Python, and Go verifiers live in one
repository — a consistency check, not independent implementations. A separately
authored Rust verifier is rebuilt from a pinned public commit and tree and passes
all 164 current vectors plus 359 hostile cases. Strict independently attested
construction acceptance remains zero. The EP receipt
formats are specified in active INDIVIDUAL Internet-Drafts, not IETF-adopted or
endorsed.

## License

Apache-2.0
