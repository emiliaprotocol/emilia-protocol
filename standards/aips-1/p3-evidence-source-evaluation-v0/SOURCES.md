# Source register

Access date: 2026-09-01. `source-lock.json` records the retrieval time,
commit, byte lengths, hashes, Git blob identifiers, and observed upstream
variance.

## A1. Official AIPS-1 site

- URL: https://aips-1.org/
- Role: current first-party status, document index, comment route, and comment
  deadline.
- Read: AIPS-1 is presented as a v0.1 draft for public comment. The page states
  that the comment period closes 30 November 2026. It describes P3 as trigger
  conditions expressed as predicates evaluable against declared Evidence
  Sources.
- Limit: this is a current web page, not an immutable revision. The exact bytes
  read are recorded in `source-lock.json`.

## A2. AIPS-1 Specification v0.1, official-site copy

- URL: https://aips-1.org/AIPS-1_Specification_v0_1.pdf
- Version and date: working paper v0.1, 6 June 2026.
- Status: draft, open for public comment.
- Relevant parts:
  - Section 2.2 defines a Trigger as a predicate condition that references one
    or more Evidence Sources and resolves objectively. It defines an Evidence
    Source as a defined, addressable source referenced by a Trigger.
  - Section 4 says P3 requires predicates evaluable against declared Evidence
    Sources. It excludes triggers depending solely on issuer opinion or on
    undefined external conditions.
  - Section 5 describes `triggers` only as an array of Trigger predicates with
    referenced Evidence Sources.
  - Section 7 says the JavaScript, smart-contract, and MCP reference verifiers
    are deferred to v0.2.
  - Section 13 asks whether Trigger predicates should use a defined predicate
    language or remain issuer-defined within a structural envelope. It gives
    30 November 2026 as the v0.1 comment deadline.
  - Appendix A contains one worked oracle predicate using `sourceRef`, `field`,
    `operator`, and `value`. It is an example, not a published schema or a
    complete predicate-language definition.
- Byte lock: SHA-256
  `01bf3d27ed21944f637ffbe1d968629f5dd491677852634e84436c562e3a3e0d`,
  190174 bytes.

## A3. Upstream GitHub repository

- Repository: https://github.com/Kadikoy1/aips-1
- Branch resolved: `main`.
- Commit: [`280a8ba0e9c2658ee6af10778e0f6a2fb669661d`](https://github.com/Kadikoy1/aips-1/commit/280a8ba0e9c2658ee6af10778e0f6a2fb669661d).
- Commit time: 2026-06-06T17:16:07Z.
- Role: reproducible upstream snapshot for the specification, README, and
  license.

Pinned files:

- [Specification PDF](https://raw.githubusercontent.com/Kadikoy1/aips-1/280a8ba0e9c2658ee6af10778e0f6a2fb669661d/docs/AIPS-1_Specification_v0_1.pdf):
  SHA-256
  `aeff5eda37b30bbd92b1d2008bd8c91a14479ccb8e8b97220f6d6e584bbee80c`,
  189878 bytes, Git blob `d1755be85f3e3a1e7071fe0c73f824b7e998df2e`.
- [README](https://raw.githubusercontent.com/Kadikoy1/aips-1/280a8ba0e9c2658ee6af10778e0f6a2fb669661d/README.md):
  SHA-256
  `a34fc7cb16ac7c5ead69e75f5b587f5341acac2991b6716ba1bad22d3afbc88d`,
  8338 bytes, Git blob `9444a21e88e2b76f471893e56f1ceb9c3f5c1ee5`.
- [Schemas status](https://raw.githubusercontent.com/Kadikoy1/aips-1/280a8ba0e9c2658ee6af10778e0f6a2fb669661d/schemas/README.md):
  SHA-256
  `cb9e8403919ea9a71536ae3595c602ba7a650e99f2a073a5aa7eea4385f9f63e`,
  1558 bytes, Git blob `196c81d05ac62744f32896fcffaa4dabba3af4d4`.
  It lists the Trigger predicate and other JSON Schemas as planned for v0.2;
  no schema file is present at the pinned tree.
- [Reference-verifier status](https://raw.githubusercontent.com/Kadikoy1/aips-1/280a8ba0e9c2658ee6af10778e0f6a2fb669661d/reference/README.md):
  SHA-256
  `01f361387e0509952969735ad6c486933cadcd8bb99605e5399a3f2b0ecd9cc5`,
  1652 bytes, Git blob `790e9a5761fe637af08f2fb7fbc7921208e32cc9`.
  It marks the reference verifiers as deferred to v0.2; no verifier module is
  present at the pinned tree.
- [LICENSE](https://raw.githubusercontent.com/Kadikoy1/aips-1/280a8ba0e9c2658ee6af10778e0f6a2fb669661d/LICENSE):
  SHA-256
  `1483739d4d4a5323e12d8cf6b69c21fd218fc0f3c60e581c719f7ca6d225de30`,
  6619 bytes, Git blob `90d1065546ed8420a50de14c8f4b5defbaa8f330`.

## Upstream variance

The official-site PDF and the commit-pinned repository PDF have the same title,
version, and date but different bytes. The current site copy adds AHS-1 and
healthcare material and contains editorial changes. The P3 passages, deferred
verifier statement, deadline, and predicate-language question used here have
the same substantive wording in both copies.

This package therefore uses the site PDF for current public wording and the
GitHub commit for reproducibility. It does not use the shared filename as a
revision identifier.

## License

The pinned upstream repository includes the CC0 1.0 Universal legal text
(`CC0-1.0`). AIPS-1 also labels the specification CC0. CC0 does not waive or
license rights such as trademarks and patents that its legal text expressly
excludes.

This EMILIA package is original commentary and test-lab material published
under the EMILIA Protocol repository's Apache-2.0 license. The upstream CC0
status does not change the license of this repository.

## Interpretation rules

1. AIPS-1 v0.1 supplies a high-level P3 requirement and one worked example. It
   does not supply a normative predicate grammar, Evidence Source schema,
   predicate-outcome model, or reference verifier.
2. This package's schema, operators, reason codes, and three-result model are a
   local proposal for public comment. They are not attributed to AIPS-1.
3. A P3 predicate result is not a coverage, liability, claim-acceptance,
   settlement, or payout decision.
4. Neither publication here nor a passing local test establishes AIPS-1
   review, adoption, endorsement, conformance, or interoperability.
