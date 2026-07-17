# EMILIA Protocol — A European Trust Layer for Accountable AI

*A short brief for policymakers focused on European digital sovereignty and the protection of citizens in the age of autonomous AI.*

## The problem, in one sentence

AI agents are starting to take **irreversible actions** — moving money, changing official records, deploying code, cutting off services — while many deployments still rely on operator-controlled records to show that human authorization occurred.

## What EMILIA is

EMILIA is an open **authorization-receipt layer**: before an AI agent performs a consequential action, an enrolled approver can sign that exact action with a user-verified authenticator. Afterwards, a relying party can verify the authorization offline against its pinned trust inputs, without calling the operator or EMILIA. A deployment can enforce: *no valid receipt, no execution.*

## Why this matters for Europe — and why it is undeniable

1. **It supplies one inspectable Article 14 evidence mechanism.** The Act requires effective human oversight of high-risk AI but does not prescribe one authorization-receipt format. EMILIA provides a portable, tamper-evident record a regulator or court can check against pinned trust inputs. It is directly relevant to Article 12 logging and Article 14 oversight; it is not the complete compliance assessment.

2. **It supports sovereign verification.** Verification can be performed offline on European infrastructure using the relying party's own pinned keys and policy. The software is open (Apache-2.0) and self-hostable, so checking the artifact does not require an EMILIA service or a foreign cloud.

3. **It gives citizens and reviewers a more portable record.** When automation touches benefits, records, money, or rights, a correctly configured deployment can require an enrolled approver before execution and preserve the resulting evidence outside the acting operator's database.

4. **It is a chance for Europe to help shape the standard, not import it.** EMILIA is being contributed through open IETF Internet-Drafts, with running code and conformance tests. Europe — and Bulgaria — can be **early authors of the accountability standard** the world will need, rather than adopting one written elsewhere.

## What it is *not* (so the claim stays honest)

EMILIA verifies a narrower technical fact: a pinned approver key signed the exact action under the checked policy context. The strength of the human attribution depends on enrollment and authenticator assurance. It does **not** establish that the decision was wise, lawful, understood, or sufficient for Article 14.

## The ask / the opening

A short conversation on where verifiable human authorization fits in Europe's AI sovereignty agenda — and whether a European public-sector pilot (a ministry, a grid operator, a public registry) would be a fit. EMILIA does not charge public institutions for the core protocol; the goal is adoption of the standard.

---
*EMILIA Protocol · open source (Apache-2.0) · github.com/emiliaprotocol/emilia-protocol · emiliaprotocol.ai · team@emiliaprotocol.ai*
