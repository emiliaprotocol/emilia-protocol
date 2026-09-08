<!-- SPDX-License-Identifier: Apache-2.0 -->
# Works operating workflow

Works brings the buyer and builder back to one place after an introduction.
The buyer posts a job, reviews proposals and proposes an assignment. The builder
confirms the frozen scope, acceptance criteria and terms before submitting a
delivery link. The buyer can request changes or accept the work. The history
retains every submitted delivery and the buyer's recorded decision.

This is coordination and an attributed work history. It does not host an agent,
move money, establish independent quality, certify safety or grant operating
authority. Payment is arranged directly. Gate setup remains a separate,
explicitly scoped integration.

## Account and privacy boundaries

Email-code accounts are limited to Works. Email verification establishes
control of the mailbox, not employment, organization ownership or agent identity.
The mapped entity is inactive and unverified, has no capabilities or operator
privilege, and receives no reusable protocol credential. Existing API keys remain
supported; an explicit key never silently falls back to the browser account.

Codes expire after ten minutes, work once and allow at most five failed attempts.
Email and client rate counters, challenge exchange and session revocation use
durable database state. A keyed email digest supports returning users; the
address is passed to the mail provider for delivery but is not stored in these
account tables. Codes and session tokens are stored only as digests. Sessions
use a Secure, HttpOnly, SameSite=Strict host-only cookie with a seven-day expiry.
Browser writes require the configured site origin. Signing out revokes the
current session. Private responses use `private, no-store` and vary by cookie
and authorization header. Public job/listing fields still require explicit
publication consent.

Proposals default private. Their author, the job owner and authorized existing
administrators retain the established proposal-read access. Assignment reads
and commands are restricted to the two parties. In-app notifications are stored
for the recipient; email delivery of workflow updates is not enabled. There
is no email-notification opt-in offered until delivery is implemented.

## State and retry rules

- Listings: active, paused or archived. State changes require the current revision.
- Jobs: open, closed or assigned. Closed/assigned jobs refuse new proposals.
- Proposals: submitted, declined or selected. Selecting one freezes its job and
  proposal snapshots in a proposed assignment and closes the job to competitors.
- Assignments: proposed, confirmed, delivery submitted, changes requested,
  completed, declined or cancelled. Only the builder confirms or delivers; only
  the buyer requests changes or accepts completion. Neither party can rewrite
  the frozen agreement or the append-only event history.

Each command binds an idempotency key to the authenticated actor and exact
request. A retry returns the recorded response; using that key with changed
content is refused. Revision checks and a shared job row lock serialize competing
selections, with a unique active-assignment index as a second fence. Closing a
job and inserting a proposal use the same row lock. An uncertain browser response
does not become a fresh action with a new key.

Buyer acceptance is evidence that this buyer accepted this delivery against this
agreement. It is not a general agent score or an independent finding of quality.

## Deployment requirements

Apply these additive migrations in order before routing traffic to the new UI:

1. `20260907235809_works_accounts.sql`
2. `20260907235858_works_workflow.sql`

Keep `WORKS_V0=1` and `NEXT_PUBLIC_WORKS_V0=1`. Configure the existing Supabase
service credentials and durable rate limiter. Add `WORKS_ACCOUNT_HMAC_SECRET`
(a random secret of at least 32 bytes) and an EMILIA-authorized `RESEND_API_KEY`.
`WORKS_FROM_EMAIL` defaults to `EMILIA Works <works@emiliaprotocol.ai>` and must
be permitted by the sending provider. Set `WORKS_PUBLIC_ORIGIN` to the exact
site origin, or verify its fallback to `NEXT_PUBLIC_APP_URL`,
`NEXT_PUBLIC_SITE_URL`, then `https://www.emiliaprotocol.ai`.

Never print secrets, put them in a public environment variable or commit them.
Changing the HMAC secret changes email lookup digests; keep the original secret
recoverable through the deployment's secret management and plan a migration
before rotating it. Public entity registration stays closed. Email provider
failure must return an unavailable result, not a claim that sign-in succeeded.

The account/operating workflow requires PostgreSQL in production. File-backed
directory fixtures are not an alternative production account or assignment store.
The inert service-only email lease metadata does not itself send notifications.

## Verification

Run the account, session, workspace, workflow and existing Works suites, route
rate-limit coverage, application typecheck and production build. Use
`scripts/verify-works-operating-postgres.mjs` against its explicitly constrained
local Unix socket to exercise migrations, concurrent sign-ups, one-use codes,
private views, competing selections, null payload refusals, exact retries,
delivery history and database privilege boundaries. It creates an isolated test
database and refuses deployment connection strings.

Before calling a deployment self-service, verify a real permitted sign-in email,
returning login, logout, and the buyer/builder journey on the deployed revision.
A source merge, test run, migration and deployment are separate facts.
