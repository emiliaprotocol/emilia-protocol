<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEB-05 publication validation

Validated locally, submitted, author-confirmed, and posted on 2026-08-31 as
Datatracker submission 168394. The live Datatracker lists
`draft-schrock-action-evidence-boundary-05` as an active individual
Internet-Draft.

## Draft toolchain

- `xml2rfc 3.34.0` produced the text and HTML renderings.
- `idnits 3.1.0 -m submission` returned `PASS No nit found`.
- The XML intentionally omits `submissionType` because the existing
  Datatracker series has no assigned stream. `xml2rfc` reports that it will use
  its `IETF` rendering default; `idnits` accepts the streamless submission
  metadata. This is a metadata choice, not an adoption or stream claim.
- `shasum -a 256 -c SHA256SUMS` verifies the staged bytes.

## Publication verification

- XML SHA-256:
  `53b09b275fd3868dfbea11340a71e4827c38ad3cba2fdd12595cdcf42eb6c240`.
  The submitted, posted, and immutable IETF archive XML are byte-for-byte
  identical.
- TXT SHA-256:
  `402bbdb2ee0906193a188eda4a24f29882ec3604bb5447949cbd0e01f7b6f1cc`.
  The retained render and immutable IETF archive TXT are byte-for-byte
  identical.
- Local HTML SHA-256:
  `9794cd49c6819d3a9d21e1bfb2dc14b4f15939b3ef689b1474a55ad8a406aae8`.
  This is the clean checksum-pinned xml2rfc 3.34.0 render. The archive delivery
  path appends request-specific Cloudflare markup, so no unstable raw archive
  HTML hash is recorded.
- Posting establishes publication only. It does not establish native-owner
  review, completion of the multi-profile conformance gate, working-group
  adoption, RFC status, or IETF endorsement.

## Implementation evidence

- Native compiler SDK focused tests: 9/9 passed.
- Verify-package qualification suite with compiler coverage: 73/73 passed.
- AuthZEN-derived local PEP-observation profile: 9/9 cases and 15/15 profile
  tests passed. AuthZEN does not sign that local EMILIA envelope.
- OAuth Transaction Authorization Challenge profile: 9/9 deterministic cases
  and 18/18 combined adapter/profile tests passed. Two valid tokens with
  different `jti` values for the same protected-resource transaction share
  one replay unit. A `Promise.all` barrier sends both signed execution-mode
  evaluations to one in-process atomic store; exactly one reservation wins.
  The checked-in report digest is
  `sha256:bc3884857d2a6a82e05f429f13b87614ff03ebf8e4e5f1e6771ae8fd06dc55e9`.
  Network revalidation matched the pinned 70,435-byte `-00` source at
  `a50c1fee4ce4ae486aa6e6739e9927586dc5c14a209434f44f76200354a8cead`.
- AEB crossing-lifecycle regression: 3/3 tests and 10/10 cases passed after
  regenerating the OAuth replay-unit reference. The results digest is
  `sha256:10e3f676fdbcec8baf3a2064b47ce999c6214b802cd6d521e7b87d6018bdb3ba`.
- WPT-02 plus Transaction Tokens -11 profile: 18/18 deterministic cases and
  41/41 focused tests passed, comprising 26 adapter tests and 15 profile tests.
  The report digest is
  `sha256:10ff9732c900d36aeb8538ef2bfd9b7a90890bdf1c871b2b7c5a97e81851fde6`.
  The offline source lock covers six upstream archive objects and the executed
  local runtime closure; live revalidation matched all six. This is a strict
  Ed25519, canonical-HTTPS, origin-form, request-only application profile. It
  refuses unclassified `rctx`, emits but does not reserve the replay identity,
  and preserves the native WPT/Bearer `Authorization` collision.
- WIMSE R10 profile: 5/5 matrix rows, 11/11 cases, and 9/9 profile tests
  passed. Its successful row uses a candidate host carrier; current HAMR
  `required_evidence` remains `NOT_SUPPORTED`. The report digest is
  `sha256:7afd7b8c1981b937bbabb5f82af9296dbd7ab95aa1e4b66184975c53ae19f66a`.
These are same-team local results and establish three-path feasibility and two
direct external-native candidates, not a completed conformance gate. The
AuthZEN-derived path verifies an EMILIA-signed local PEP observation, not an
AuthZEN artifact. The OAuth and WPT/Transaction Token mappings still need
native-owner review. The published profiles also need an audited match against
every required hostile vector and paired control, and the two OAuth-adjacent
candidates need an explicit protocol-diversity judgment. The in-process twin
race does not establish distributed-store concurrency safety. The maintainer
made the filing decision on 2026-08-31; the remaining items stay visible as
review and conformance limitations. These results do not
establish an independent implementation, external adoption, working-group
agreement, complete mediation, production deployment, provider truth, or
effect truth.
