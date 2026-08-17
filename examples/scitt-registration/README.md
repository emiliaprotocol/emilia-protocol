<!-- SPDX-License-Identifier: Apache-2.0 -->
# SCITT registration client (staged, never fired)

Builds an EP-SCITT-STATEMENT-v1 Signed Statement from an EMILIA authorization
receipt and prints the exact HTTP request that would register it with a
Transparency Service. It has never been fired. Nothing here has touched the
network.

The profile itself, its RFC requirement table, and its vectors live in
`conformance/scitt-statement/`.

## Status, stated plainly

- No Transparency Service has accepted a statement produced by this client.
- The Markovian submission endpoint is **not documented in this repository**.
  The only Markovian coordinate the repo holds is the c2sp signed-note origin
  string `markovianprotocol.com/log`, from
  `interop/markovian-emilia/MARKOVIAN-CROSS-RUN-20260729-001.json`. That is a
  log origin, not an HTTP submission URL. `register.mjs` therefore ships a
  placeholder endpoint, clearly marked, that must be replaced with a URL
  confirmed by Markovian before anything is sent.
- Sending is IMAN'S GATE: publishing to a third-party registry is an outbound
  act, and this client will not perform one by accident. See below.

## Files

| File | What it does | Network |
| --- | --- | --- |
| `register.mjs` | Builds the Signed Statement, verifies it offline, prints the request that would be sent. | None in dry run, which is the default. |
| `verify-inclusion.mjs` | Re-verifies the checked-in Markovian transparency-log return package. | None ever. |
| `generate-vectors.mjs` | Regenerates `conformance/scitt-statement/vectors.json`. | None ever. |

`register.mjs` and `generate-vectors.mjs` import the profile from TypeScript
source, because EP-SCITT-STATEMENT-v1 is not exported from the package index
yet. Run them with `tsx`. `verify-inclusion.mjs` has no such dependency and runs
on plain `node`.

## Dry run (the default, and the only mode that has been run)

```sh
npx tsx examples/scitt-registration/register.mjs --dry-run
```

It prints the CWT `iss` and `sub`, the `kid`, the payload digest, the protected
header bytes, the offline verification result with each check listed separately,
the pinned public keys a relying party needs, and then the request:

```
POST https://CONFIRM-WITH-MARKOVIAN.invalid/entries
Content-Type: application/scitt-statement+cose
Accept: application/json, application/cbor
Content-Length: 815

body: <the tagged COSE_Sign1 bytes>
```

`application/scitt-statement+cose` is the media type RFC 9943 Section 10.1
registers for a Signed Statement. A service that expects the more general
`application/cose` will say so; confirm this along with the endpoint.

The verification block always ends with `registered: false`. VERIFIED is not
REGISTERED. A statement is registered only once a Transparency Service has
accepted it into its verifiable data structure and returned a Receipt (RFC 9943
Section 6.3), and that Receipt has been verified.

## Proving the proof path runs

The client cannot demonstrate inclusion verification with its own output,
because none of its statements have been registered. So the proof machinery is
demonstrated against the one real transparency-log return the repository holds:
the 2026-07-29 Markovian cross-run.

```sh
node examples/scitt-registration/verify-inclusion.mjs
```

This runs two paths and requires them to agree:

- **Path A** runs `interop/markovian-emilia/verify_cross_run.py`, the offline
  verifier Markovian returned with the package. It is skipped, visibly, if
  `python3` with the `cryptography` package is unavailable.
- **Path B** re-implements the same checks on `node:crypto`: RFC 6962 inclusion
  and consistency, the c2sp.org signed note, and c2sp.org/tlog-cosignature v1
  witness cosignatures. It also runs a negative control, corrupting one proof
  node and requiring the corrupted proof to be rejected.

Observed result on this checkout: leaf index 4869 included at tree size 4881,
consistency 4881 to 4912, log signature valid and 7 of 7 pinned witness
cosignatures valid at both heads, both paths green.

This is a DIFFERENT Merkle construction from EP-MERKLE-v2 in
`packages/verify/src/consistency.ts`, which hashes ASCII hex strings rather than
raw digests. The two are not interchangeable and `verify-inclusion.mjs` does not
treat them as such: it implements RFC 6962 to match the artifact.

What a green run proves: those exact canonical leaf bytes were included in the
witnessed log and the later head is an append-only extension of the inclusion
head, under the pinned keys. What it does not prove: that the receipt's claims
are true, and anything at all about the EP-SCITT-STATEMENT-v1 statements this
client builds.

## The staged fire command: IMAN'S GATE

Do not run this. It is recorded so it is ready the moment the endpoint is
confirmed and the word is given.

```sh
# IMAN'S GATE. Publishing to a third-party registry.
# Replace <CONFIRMED-ENDPOINT> with the URL Markovian confirms. Do not guess it.
npx tsx examples/scitt-registration/register.mjs \
  --send \
  --endpoint=https://<CONFIRMED-ENDPOINT>/entries \
  --i-have-approval
```

All three flags are required together. `--send` on its own refuses and exits
non-zero, as does `--send` with the placeholder endpoint. The client always
prints the full dry-run block first, so the exact bytes are on screen before
anything leaves the machine.

Preconditions before that command is run, none of which are satisfied yet:

1. Markovian has confirmed the submission endpoint and the content type it
   expects for a SCITT Signed Statement.
2. The receipt being registered is a real one, not the fixed-seed conformance
   fixture the client currently builds.
3. Iman has said go.

After a send, the Transparency Service returns a Receipt. Until that Receipt is
verified, the correct word is "submitted", not "registered", and never
"transparent".
