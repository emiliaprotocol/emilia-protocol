# EP Witness (cosigner)

A minimal, weekend-runnable HTTP service that an INDEPENDENT operator runs to
cosign a transparency-log checkpoint. It is step 3 of EP's transparency layer
(see `docs/security/TRANSPARENCY-LAYER-DESIGN.md` and
`packages/verify/consistency.js`). Witnesses make equivocation (a log showing a
split view) detectable by strangers.

## The problem it addresses

An EP transparency-log operator signs its own checkpoint
`{tree_size, root_hash, log_key_id, ...}`. A single operator signature does not
make a split view detectable: a malicious or buggy operator can sign two
internally-consistent but divergent heads and present one to each of two
verifiers. Neither verifier, on its own, can tell.

An independent witness re-signs the SAME committed checkpoint bytes it observed.
When several independent witnesses each cosign whatever head they saw, two
verifiers who later compare (gossip) their witness cosignatures can detect that
the log presented divergent heads at the same tree size.

## What a witness cosignature proves, and what it does NOT

A cosignature says:

> "I, witness `<witness_id>`, observed a checkpoint claiming this `tree_size` and
> this `root_hash` under this `log_key_id`, and I sign exactly these committed
> bytes."

It deliberately does NOT:

- vouch for the log's honesty or its append-only property. A witness signs the
  bytes it was shown; it does not re-derive the Merkle tree or check consistency.
- establish CURRENT validity. A cosignature attests to a head as observed at
  cosign time only. It is authentic-as-of-observation, not a claim that this head
  is the log's latest. Currency needs a fresh signed head or an online check.
- detect anything on its own. A single witness proves nothing about equivocation.
  Detection needs MULTIPLE independent witnesses plus later comparison of their
  views. This service provides the cosignature; comparing divergent views across
  witnesses (gossip) is the deploying party's job. The verifier helper
  `requireWitnessQuorum()` enforces the local half: that k distinct pinned
  witnesses agree on ONE head.

## Domain separation (why a witness cosignature cannot be confused with a log signature)

- The log signs `Ed25519( SHA-256( canonicalize(checkpoint-without-log_signature) ) )`.
- A witness signs `Ed25519( SHA-256( WITNESS_DOMAIN_TAG || canonicalize(checkpoint-without-log_signature) ) )`.

The witness prepends a domain tag (`EP-WITNESS-COSIGN-v1\0`) to the pre-image, so
the two signatures are computed over disjoint bytes. A log signature can never be
replayed as a witness cosignature, and vice versa, even if the same key were
misconfigured into both roles. The signing digest is imported directly from
`@emilia-protocol/verify` (`witness.js`), so a cosignature this service emits is
byte-identical to what `verifyWitnessCosignature()` checks.

## Run it in one command

Generate a key, then start the service (from this `witness/` directory):

```sh
node generate-key.mjs && node server.mjs
```

`generate-key.mjs` writes:

- `keys/witness-private.pem`: the secret (mode 0600). Never commit it.
- `keys/witness-public.json`: `{ witness_id, public_key, alg }` to hand to
  relying parties so they can PIN this witness.

The server loads the private key from (in order) `WITNESS_PRIVATE_KEY` (a PEM
literal) or `WITNESS_PRIVATE_KEY_FILE` (a path, default
`keys/witness-private.pem`). It never hardcodes a key: with none configured it
prints the reason and exits 1 (fail closed).

### With Docker

Build from the REPO ROOT (the image needs both `witness/` and
`packages/verify/`):

```sh
docker build -f witness/Dockerfile -t ep-witness .
docker run --rm -p 8787:8787 \
  -v "$PWD/witness/keys:/app/witness/keys:ro" \
  ep-witness
```

Or pass the key as an env literal instead of mounting a file:

```sh
docker run --rm -p 8787:8787 \
  -e WITNESS_PRIVATE_KEY="$(cat witness/keys/witness-private.pem)" \
  ep-witness
```

## Endpoints

### `GET /witness-key`

Returns the public key to pin and the stable witness id:

```json
{ "alg": "EP-WITNESS-v1", "witness_id": "witness:sha256:<16 hex>", "public_key": "<base64url SPKI DER>" }
```

The `witness_id` is self-certifying: it is `witness:sha256:` plus the first 16
hex of `SHA-256(public_key SPKI DER)`, so anyone holding the public key can
recompute and confirm it.

### `POST /cosign`

Body is a checkpoint (a bare object or `{ "checkpoint": { ... } }`):

```json
{ "tree_size": 42, "root_hash": "sha256:<hex>", "log_key_id": "ep:log:...", "merkle_alg": "EP-MERKLE-v2" }
```

It cosigns ONLY structurally-valid checkpoints. `tree_size` must be a
non-negative integer; `root_hash` and `log_key_id` must be non-empty strings.
Malformed input returns 400 and is never signed. On success it returns:

```json
{
  "cosignature": {
    "alg": "EP-WITNESS-v1",
    "witness_id": "witness:sha256:<16 hex>",
    "tree_size": 42,
    "root_hash": "sha256:<hex>",
    "log_key_id": "ep:log:...",
    "cosigned_at": "<RFC 3339 UTC>",
    "signature": "<base64url Ed25519>"
  }
}
```

The echoed `tree_size` / `root_hash` / `log_key_id` let a relying party refuse a
cosignature reused for a different checkpoint. `cosigned_at` is advisory: it is
NOT part of the signed bytes (the signature is over the log's committed
checkpoint, not over this envelope) and it does NOT establish currency.

### `GET /healthz`

`{ "ok": true }`.

## Verifying a cosignature

Relying parties verify offline with `@emilia-protocol/verify`:

```js
import { verifyWitnessCosignature, requireWitnessQuorum } from '@emilia-protocol/verify/witness.js';

// A single pinned witness:
const r = verifyWitnessCosignature(checkpoint, cosignature, pinnedWitnessKey);
// -> { verified, witness_id, reason? }

// k of n distinct pinned witnesses agreeing on ONE head:
const q = requireWitnessQuorum(checkpoint, cosignatures, pinnedWitnessKeys, k);
// -> { ok, met, required, witness_ids, reasons }
```

Both are fail-closed: an unknown or unpinned witness refuses, a signature over
different bytes refuses, a cosignature presented for a different checkpoint
refuses, and the quorum helper refuses on fewer than k DISTINCT pinned witnesses
(duplicate witness ids count once).

## Independence is the whole point

The security value comes from witnesses being operated by parties INDEPENDENT of
the log operator and of each other. Running one witness next to the log adds
almost nothing. The intended deployment is several witnesses on separate
infrastructure and administrative control, whose views are later compared. This
service is deliberately tiny so that bar is cheap to clear.
