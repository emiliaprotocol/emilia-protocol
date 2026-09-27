<!-- SPDX-License-Identifier: Apache-2.0 -->
# AuthZEN COAZ-MCP contribution

Status: submitted as `openid/authzen` pull request #626, "COAZ-MCP: bind
permits to evaluated operations", opened 2026-08-23 and merged into the
repository's `main` branch on 2026-09-10 (merge commit
`ca92c756eb889ec90b88b83f6bc99c4eb59b0d83`).

The merged change edits `profiles/authzen-coaz-mcp-binding-1_0.md`. Its wording
differs from the candidate text below, and the merged diff is authoritative.
It adds a rewrite and normalization step and a pre-permit operation-binding
check to PEP Behavior (candidate change 1), and a new section, "Authorization
Granularity and Omitted Inputs" (candidate change 2). Issue 603 was closed as
completed when the pull request merged.

Source basis: `openid/authzen` commit
`e287920eed842b227e38531c1735b712337ca44d`, fetched 2026-08-25. The
repository commit, two load-bearing Markdown files, rendered specifications,
Authorization API 1.0, and issue 603 as it stood on that date are pinned in
`source-lock.json`. The candidate text below was written against that commit.

## Candidate change 1: bind a permit to the operation used for evaluation

Add the following requirement to **PEP Behavior**, immediately before a
permitted message is allowed to proceed:

> A PEP MUST apply known rewrites that can affect mapping selection or resolved
> mapping values before it selects and resolves the mapping. Before a permit is
> used, the PEP MUST ensure that the final operation it will forward or execute
> has the same method, selected mapping, and resolved expression values that
> contributed to the AuthZEN request evaluated by the PDP. If any of those
> values changed after evaluation, the PEP MUST re-evaluate the final operation
> or refuse it; it MUST NOT reuse the earlier permit. This comparison is
> semantic and does not require raw JSON byte equality.

This is candidate text for the pre-execution boundary described in
`openid/authzen` issue 603, which was open when the text was written.

## Candidate change 2: make the projection boundary explicit

Add the following paragraph to **Mapping Integrity**:

> An AuthZEN decision applies to the request constructed by the selected
> mapping. A source input omitted by that mapping was not evaluated by the PDP.
> A deployment MUST project every source input on which authorization is
> intended to depend, or enforce the omitted condition independently before
> the operation is forwarded or executed. A permit MUST NOT be represented as
> a decision over source inputs that were absent from the constructed request.

This does not make a coarse-grained mapping defective. It states the boundary
of the decision produced from that mapping. Candidate change 1 prevents a
permit from being reused after a mapped value changes; candidate change 2
clarifies that deliberately unmapped values were never part of that decision.

## Executable support

Run:

```bash
node conformance/composition/coaz-translation-v0.1/run.mjs
npx vitest run conformance/composition/coaz-translation-v0.1/run.test.mjs
```

The nine-case corpus demonstrates a declared mapping that omits the
consequential `beneficiary_account`. Two materially different MCP calls then
construct byte-identical AuthZEN requests and receive the same decision from
the toy PDP. This is expected: the PDP sees only the projected request.

The corpus also demonstrates an optional relying-party control in which
`context.caid` carries a typed identifier over the complete source action. The
substituted beneficiary is then distinguishable and refused at the enforcement
boundary. CAID is supporting evidence for the projection-boundary proposal,
not a normative dependency of either candidate change.

## Claim boundary

- No deployed AuthZEN, COAZ, MCP, gateway, or PDP product is claimed
  vulnerable.
- The lossy declared mapping and toy PDP were created for this corpus.
- The corpus reproduces EMILIA's own implementation. It is not independent
  implementation evidence.
- A CAID establishes typed content correlation only. It does not establish
  authorization, execution, safety, source truth, or policy compliance.
- The only upstream event this file records is the merge of pull request
  #626 into the `openid/authzen` repository. It is not evidence of
  working-group consensus, approval of a final specification, adoption of any
  other text, or implementation of the profile.
