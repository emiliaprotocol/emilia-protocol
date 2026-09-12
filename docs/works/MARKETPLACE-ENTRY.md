<!-- SPDX-License-Identifier: Apache-2.0 -->
# Marketplace entry: jobs, proposals and agent listings

The marketplace helps buyers describe work and builders respond to it. Scanning,
Gate setup and qualification are separate steps. A job post does not hire a
worker, a purchase does not grant authority, and a scan is not a safety certificate.

| Route | What it does | What it does not establish |
| --- | --- | --- |
| `/works` | Lists builder-supplied agent records, with examples and other work separate | Availability for hire, endorsement, customer adoption or permission to execute |
| `/works/opportunities/new` | Prepares a local job preview, then publishes with explicit consent and an email-verified Works account or existing entity key | Funding verification, an award, payment or runtime authority |
| `/works/opportunities` | Lists real job posts separately from read-only examples; counts public proposals only | Total private proposal volume or guaranteed work |
| `/works/opportunities/:id/inbox` | Shows proposals to the job's authenticated owner or an administrator | An award, acceptance or permission to execute |
| `/works/submissions` | Finds one proposal by ID through the existing authenticated single-record API | A public directory of private proposals or access based on knowing an ID |
| `/works/account` | Creates or signs into a Works account by email code | A verified company, agent identity or protocol API credential |
| `/works/workspace` | Manages owned jobs, listings, proposals, assignments and in-app updates | Provider access, hosted execution, payment or an independently verified rating |
| `/works/assignments/:id` | Records agreed scope, builder confirmation, delivery, changes and buyer acceptance | Payment settlement, a safety certificate or execution authority |
| `/works/scan` | Inspects supported JSON declarations in the browser and downloads a digest-bound report | Actual behavior, complete tool coverage, deployed enforcement or certification |
| `/works/gate` | Opens an editable request for separately quoted setup and support; links the free MCP starter | An order, charge, subscription, installed Gate or qualification |
| `/works/qualification` | Submits a supported signed evidence bundle for verification under operator-pinned scope and status | General agent safety, good performance, accreditation or permission to act |

All Works pages and APIs require `WORKS_V0=1`. Navigation uses the corresponding
`NEXT_PUBLIC_WORKS_V0=1` build flag. No deployment or flag change is implied by a
source merge.

## Free scan

Supported inputs are a plain actions array, an object with an `actions` array,
an MCP `tools/list` result (direct or JSON-RPC envelope), or OpenAPI 3.x / Swagger
2.0 JSON. The browser uses the existing `packages/scan` classifier, not a second
risk taxonomy. Names, descriptions, advisory annotations and declared HTTP
operations inform the result. Tool schemas, prompts, code, runtime credentials,
callbacks and external references are not analyzed.

The scanner does not fetch URLs, run agents, contact providers, persist the
input, upload it or publish a listing. A user-triggered download writes a local
JSON report. Its SHA-256 identifies the exact pasted UTF-8 text, not a repository
revision or a running deployment. Input and results remain in browser memory
until cleared or the page closes. Handle local report files as potentially
sensitive; descriptions can contain information supplied by the user.

Limits: 1 MiB input, 500 actions, 32 nesting levels and 20,000 JSON values.
Duplicate object keys, reserved prototype keys, ambiguous declaration formats,
invalid advisory hints and duplicate normalized action names are refused.
Unknown behavior remains a review item. Read-like declarations are never
labeled safe. An empty declaration does not prove an agent has no capabilities.

## Listings and owner consent

The main inventory counts only records with `kind: agent`, `status: active` and
`example: false`. Active is the poster's status, not independently verified
availability. Apps, projects, paused or archived work and examples are separate.
Storage failure is shown as unavailable, not an empty market.

A local scan does not automatically create a public record. The existing
Authority Record ownership, correction, exact-content approval, withdrawal and
freshness rules remain in force. A buyer posting a job uses the existing
opportunity workflow. Hiring, payment and acceptance terms remain separate; this
change does not introduce payouts, escrow or hosted agent execution.

## Job drafts and returning to proposals

Buyers can describe a job and review its public fields before signing in.
Previewing makes no network request and does not save a draft to browser
storage. Keep a separate copy if the draft must survive closing the page.
Publishing requires a verified Works session or existing entity key and explicit consent. The server
sets the poster name from that authenticated account. Sponsor statements remain
assertions or unknowns, not independently verified facts.

A publication attempt keeps the same job ID, content and statement timestamps
when retried. A lost response or duplicate ID is checked through the exact
owner-authenticated record route; finding the ID in a public list is not proof
that this account published this draft. Changed content or an unconfirmed owner
must not produce a success message. A confirmed post links directly to its
workspace and public brief.

Builders receive a link back to their proposal. The link contains only its ID;
it does not carry access. The lookup uses the signed-in account or an explicitly supplied key, retrieves one record
through the existing API, validates the returned record and ID, and offers a
clear action to hide it. The author, job owner and administrator retain their
existing access; public visibility still requires the author's separate opt-in.
Keys and retrieved proposals are not saved to browser storage. Hiding or leaving
the view cancels the request and prevents an older response from restoring it.

The jobs board distinguishes a successful empty result from an unavailable
store. Public proposal counts never imply that private proposals are absent.
Read-only examples are not counted as real jobs and do not invite responses.

The [operating workflow](OPERATING-WORKFLOW.md) adds selection, confirmation,
delivery and owner review. Updates are in-app; notification email is not enabled.
Commercial payment remains directly between the parties. Production readiness
requires the account provider, migrations, durable rate limiter and deployed
routes, not only a successful source build.

## Paid Gate work

`lib/works/gate-offer.ts` defines a quote-required setup/support offer for one
agreed action in one supported tool integration. Price is null and checkout is
disabled. The email link contains only a fixed editable brief. It does not send
mail or attach scan data automatically.

Before enabling self-service billing, approve price and service terms, bind the
correct Stripe product, verify checkout and signed webhook reconciliation, and
test cancellation and fulfillment. Existing Authority Record monitoring billing
is a different product and must not grant Gate or qualification entitlements.
The open Gate and verifier remain free to use. Payment buys agreed work, not a
passing finding.

Production setup still needs a credential-owning execution path, complete
mediation of the covered calls, durable shared state, pinned authority and
tested refusal/recovery. Installing a plugin alone does not prove any of these.

## Scoped qualification

The new surface reuses Gate Qualification v2. It does not define new signatures,
mint a qualification statement, issue a public mark or operate an accredited
certification program. See [the qualification policy](GATE-QUALIFICATION-POLICY.md)
for the server-pinned contract and readiness requirements, and
[the certification scheme boundary](../EP-CERTIFICATION-SCHEME.md).

Hosted verification requires trusted operator configuration and a working
durable limiter. Missing configuration, missing current status or invalid
evidence must never be rendered as a favorable result. Caller-supplied payment,
installation, verdict, keys and status fields cannot create qualification.

## Local verification

Run the new focused tests, the existing Works regression suites, application
typecheck and production build. Exercise the browser scan on desktop and mobile,
including its synthetic example, malformed input, editing after a result, clear,
download and no input-bearing network requests. Exercise qualification with
missing operator configuration and hostile evidence. Keep source, tests,
deployment, payment and qualified evidence as separate release states.

Commit the reviewed source before running `npm run sync:proof-stats`, because
package reproducibility requires a clean reviewed checkout. The writer runs the
full test suite and emits the security case from its live execution before
updating the counts. `npm run check:proof-stats` remains read-only and rejects
stale evidence. Regenerate and check the LLM context after a successful refresh;
do not publish partially regenerated artifacts from a failed command.
