# Authorization-Receipt Interop Pack — IETF 126 Side Meeting

Interop tooling for a plugfest on signed, offline-verifiable authorization
receipts and related artifacts (device signoffs, multi-party quorum, revocation,
time attestation, provenance chains, evidence records). This pack exists so any
implementation — in any language, from any organization — can run the same
public vectors and report its own results. It is interop tooling, not
marketing: no participant grades another, and running the vectors implies no
endorsement of any project.

The formats under test are specified in the `EP-*` documents in this repository
and in the companion Internet-Drafts (`draft-schrock-ep-authorization-receipts`,
`draft-schrock-ep-quorum`, `draft-schrock-ep-authorization-evidence-chain`).
These are active individual Internet-Drafts, not IETF-adopted or endorsed.

## What the pack contains

The vectors themselves live one directory up, in
[`../vectors/`](../vectors/). Each suite is a single self-contained JSON file:
every vector carries its own public key material and document — no server, no
network, no shared state. Reject vectors are adversarial: each one pins a
single invariant (tampered payload, wrong key, malformed signature, broken
anchor, missing user verification, quorum-ordering violation, …).

Suites and vector counts as of 2026-07-05 (the `SUITES` list in
[`../run.mjs`](../run.mjs) is authoritative if this table drifts):

| Suite file | Format | Vectors |
|---|---|---|
| `receipts.v1.json` | EP-RECEIPT-v1 (Ed25519 receipts) | 13 |
| `signoffs.v1.json` | EP-SIGNOFF-v1 (WebAuthn ECDSA P-256 device signoffs) | 9 |
| `quorum.v1.json` | EP-QUORUM-v1 (M-of-N / ordered multi-party approval) | 11 |
| `revocation.exec.v1.json` | EP-REVOCATION-v1 | 6 |
| `time-attestation.v1.json` | EP-TIME-ATTESTATION-v1 | 6 |
| `trust-receipt.exec.v1.json` | EP-TRUST-RECEIPT-v1 (§6.2) | 10 |
| `trust-receipt.timestamp-forms.v1.json` | EP-TRUST-RECEIPT-v1 timestamp profile (§6.2/§6.3) | 6 |
| `provenance.exec.v1.json` | EP-PROVENANCE-CHAIN-v1 | 6 |
| `evidence-record.v1.json` | EP-EVIDENCE-RECORD-v1 | 5 |
| `canonicalization.v1.json` | EP-CANONICALIZATION-v1 (differential RFC 8785 / I-JSON battery, digest-pinned) | 35 |

Format definitions, field-by-field: [`../../CONFORMANCE.md`](../../CONFORMANCE.md)
and [`../vectors/README.md`](../vectors/README.md). The optional JWS (RFC 7515)
serialization has its own vectors in `../vectors/jws.json` and can be verified
with any standard JOSE library.

## How any implementation runs the vectors

**1. Get the vectors.** Clone the repository (or download just the JSON files —
they are self-contained):

```bash
git clone https://github.com/emiliaprotocol/emilia-protocol
cd emilia-protocol
ls conformance/vectors/*.json
```

**2. Run your verifier over a suite.** The runner contract is deliberately
minimal: read a suite file, verify each vector with your implementation, and
print a JSON array of `{ "id": <vector id>, "valid": <bool> }` — one entry per
vector. (The in-repo runners under [`../runners/`](../runners/) follow this
contract and can serve as examples of how each vector type maps to a verifier
call.)

```bash
your-verifier conformance/vectors/receipts.v1.json > results.json
```

**3. Compare your results against the expected outcomes.** Each vector carries
`expect.valid`; a suite passes when your verifier returns it for every vector:

```bash
python3 -c "
import json, sys
suite = json.load(open('conformance/vectors/receipts.v1.json'))
got = {r['id']: r['valid'] for r in json.load(open('results.json'))}
bad = [v['id'] for v in suite['vectors'] if got.get(v['id']) != v['expect']['valid']]
print('PASS (%d vectors)' % len(suite['vectors']) if not bad else 'FAIL: ' + ', '.join(bad))
sys.exit(1 if bad else 0)
"
```

Repeat per suite. Implement as many or as few suites as interest you —
EP-RECEIPT-v1 alone is a meaningful interop result.

**One participating implementation set:** the repository's own verifiers run via

```bash
node conformance/run.mjs
```

That command feeds every suite through the repository's JavaScript, Python, and
Go verifiers. These are three languages in one repository — a consistency
check, not independent implementations; an independent clean-room
reimplementation (COSA) is underway. At the plugfest they are simply one
participating implementation set, reported in the matrix like everyone else's.

## Self-reported results matrix

Results are self-reported. Participants run the vectors themselves, on their
own machines, and report their own numbers — nobody grades anyone, and no
result in this table is verified by the meeting organizers. A "pass" means the
implementation returned each vector's `expect.valid`: it demonstrates
format-level agreement on signature, binding, and structural checks, never the
business correctness of any authorized action, and it is not a certification.

Copy a row per (implementation, suite) pair:

| Implementation (org / repo / language) | Suite | Pass/Fail | Notes |
|---|---|---|---|
| _example: acme-verify (Acme, Rust)_ | `receipts.v1.json` | pass (13/13) | anchor proofs not implemented; 2 anchor vectors skipped and counted as fail |
| _example: repo reference set (JS+Py+Go, one repo)_ | all 11 suites | pass (110/110) | consistency check across three languages, single repository |
|  |  |  |  |
|  |  |  |  |

Notes worth recording: partial-suite coverage, vectors your implementation
rejects for a *different* reason than the one pinned, spec ambiguities you hit
(those are the plugfest's most useful output), and library versions.

## Side-meeting logistics (placeholder)

- **When/where:** IETF 126, Vienna, 18–24 July 2026. Room and slot: **TBD** —
  will be listed on the IETF 126 side-meeting wiki once confirmed.
- **Sign-up:** TBD (wiki page link to follow).
- **Format:** bring a laptop with your implementation; the vectors run fully
  offline, so no venue network dependency. Rough agenda: 10 min format
  walkthrough, ~60 min running suites and filling in the matrix, remainder on
  divergences and spec-ambiguity findings.
- **Remote participation:** results may be submitted asynchronously by PR or
  email; the matrix does not require attendance.
- **Contact:** TBD.

## Reporting divergences

If two implementations disagree on a vector, or a vector contradicts the spec
text, that is the most valuable outcome a plugfest can produce — please open a
GitHub issue with the vector id and both results. Protocol correctness outranks
backward compatibility.

## License

The vectors, this pack, and the reference verifiers are Apache-2.0.
