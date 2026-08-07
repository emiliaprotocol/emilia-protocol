<!-- SPDX-License-Identifier: Apache-2.0 -->
# AI-Assisted Development Policy

EMILIA permits the use of AI development tools. They are tools, not accountable
contributors. A natural person must select the work, review and edit the result,
run the required checks, and accept responsibility for every contribution.

## Attribution and accountability

- Commits must identify the accountable human author and carry that person's
  Developer Certificate of Origin sign-off.
- Do not identify an AI system in a `Co-authored-by` trailer. If disclosure is
  useful, `Assisted-by: <tool name>` may be used as non-authorship metadata.
- An AI system must not be listed as an officer, employee, maintainer of record,
  reviewer, standards author, scientific author, patent inventor, copyright
  claimant, or DCO signer.
- Human review is not satisfied by asking a second AI system to approve the
  first system's output. The accountable contributor must understand the change
  and its security and licensing consequences.

Historical AI `Co-authored-by` trailers are retained as repository provenance.
They do not confer corporate office, ownership, inventorship, approval authority,
or maintainer status. Rewriting published history would invalidate commit and
tag identities and would weaken, rather than improve, release provenance.

## Acceptance requirements

AI-assisted code is held to the same requirements as any other contribution:

1. traceable human authorship and DCO sign-off;
2. applicable tests, conformance vectors, and generated-evidence checks;
3. security and dependency review proportional to the change;
4. license-compatible inputs and no confidential or third-party restricted data;
5. pull-request review under the repository's protected-branch rules.

Tool output is never accepted solely because a provider represents it as accurate,
secure, or non-infringing. The human contributor remains responsible for checking
those claims and for preserving the boundary between public repository material
and private customer, employee, security, or patent information.

## Corporate and intellectual-property records

The public Git history is technical provenance, not a complete chain-of-title
record. The operating company should retain, in its private diligence data room:

- founder, employee, and contractor invention-assignment agreements;
- any required employer-conflict disclosures or written carve-outs;
- the applicable commercial terms and account ownership for AI tools used;
- patent inventorship records naming natural persons only; and
- board, officer, cap-table, and authority records naming humans and legal
  entities only.

This policy reflects the repository's attribution practice; it is not legal
advice and does not replace counsel's chain-of-title review.
