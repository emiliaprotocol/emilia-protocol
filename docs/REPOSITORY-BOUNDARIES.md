<!-- SPDX-License-Identifier: Apache-2.0 -->
# Public and private repository boundaries

EMILIA uses two repositories with different disclosure rules.

## `emiliaprotocol/emilia-protocol` — public technical commons

This public repository owns:

- Internet-Draft sources and posted revision snapshots;
- protocol schemas, registries, profiles, and conformance vectors;
- reference implementations, SDKs, examples, and tests;
- formal models and reproducible public security evidence; and
- public product and implementation documentation whose claims remain bounded
  by the repository's evidence discipline.

Everything tracked here is world-readable. A local branch is not a privacy
boundary once it is pushed.

## `emiliaprotocol/emilia-company` — private company material

The private companion repository owns:

- fundraising terms, valuation, use-of-funds plans, and confidential decks;
- GTM plans, target accounts, buyer maps, pricing strategy, and competitive
  assessments;
- private partner hypotheses, outreach, contact lists, and meeting materials;
- invention disclosures and attorney-preparation material;
- customer-, prospect-, pilot-, and deployment-specific documents; and
- internal operating decisions and submission operations.

The private repository is not a protocol dependency. Public builds, tests,
verification, conformance, and standards artifacts MUST remain reproducible
without access to it.

## Publication rule

Material moves from private to public only through a deliberate public pull
request after claim review, privacy and secret review, and removal of private
names, economics, local paths, and operational metadata. Technical accuracy
alone is not authorization to publish.

`npm run check:repository-boundary` enforces prohibited tracked paths and
confidential-document filename patterns in CI. It is a backstop, not a
substitute for review.
