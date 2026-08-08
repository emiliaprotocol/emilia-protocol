# EMILIA consequence actuator service

This service is the credential-owning half of the complete-mediation boundary.
The decision service can authorize and sign a short-lived execution envelope,
but only this separately deployed process owns provider credentials or can call
the configured provider.

`POST /v1/execute` accepts one strict action body plus its closed, signed
execution envelope. The service verifies every bound field, atomically reserves
the envelope through the Gate consequence-actuator store before provider entry,
and permanently consumes it as `COMMITTED` or `INDETERMINATE`. Its response
contains a separately signed observation that the decision service can verify
offline during reconciliation.

The PostgreSQL login must be a tenant-mapped member of
`consequence_actuator_executor` provisioned by migration
`20260725010000_consequence_actuator_store.sql`. Provider and observation
private keys belong only in this service's secret manager.

## GitHub deployment-protection boundary (experimental)

The service now includes a narrow GitHub App integration for one consequential
action: allowing a workflow run to enter a protected GitHub environment.

The integration is split into three modules:

- `github-deployment-webhook` authenticates the untouched webhook bytes with
  `X-Hub-Signature-256`, pins the App installation and repository, validates
  the callback URL, re-reads the workflow run, and constructs the exact action.
- `github-deployment-queue` persists the authenticated raw delivery before
  acknowledgment, leases it to one worker with `SKIP LOCKED`, and permits retry
  only for pre-admission unavailability. `INDETERMINATE` is terminal.
- `@emilia-protocol/gate/adapters/github` verifies a server-owned signed
  allowance, reserves and consumes its one-time capability, and only then
  reviews the deployment protection rule.
- `github-deployment-server` is a hardened raw-body HTTP boundary at
  `/v1/github/deployment-protection`.

The material action binds the decision, repository ID and name, environment,
workflow, ref, SHA, trigger event, and workflow-run ID. The semantic operation
ID is deterministic for that tuple. A second delivery or a fresh wrapper cannot
approve the same run/environment action twice. A lost or non-204 GitHub
callback response is `INDETERMINATE`; it is never blindly retried.

GitHub's webhook and review API do not identify a workflow run attempt or an
individual job. This profile therefore defines the protected action honestly as
one run/environment admission aggregate. It does not claim exact-attempt,
exact-job, artifact-deployment, or physical-effect enforcement. A refusal
withholds EMILIA approval; it does not issue an unguarded GitHub rejection.

Configure the GitHub App with Actions read, Deployments read/write, and the
`deployment_protection_rule` webhook subscription. GitHub currently marks
custom deployment protection rules as public preview. They are available in
public repositories on all plans; private or internal repository use requires
GitHub Enterprise. Check GitHub's current documentation before deployment:

- <https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/create-custom-protection-rules>
- <https://docs.github.com/en/rest/actions/workflow-runs#review-custom-deployment-protection-rules-for-a-workflow-run>

Production wiring must provide all of the following from outside the protected
repository:

- a pinned webhook secret and installation/repository allowlist;
- an installation-authenticated Octokit client scoped to the repository;
- the signed Gate allowance, capability secret, trusted issuer pins, real
  receipt and allowance-currentness verifiers, and a durable capability store;
- the private PostgreSQL delivery queue from migration
  `20260808233000_github_deployment_delivery_queue.sql`; and
- a bounded worker loop around `createGitHubDeploymentDeliveryWorker()`.

`createMemoryGitHubWebhookDeliveryStore()` and
`createMemoryGitHubDeploymentDeliveryQueue()` are deliberately marked
non-durable and are accepted only under explicit test flags. The synchronous
gate remains useful for conformance tests. Production wiring must put
`createGitHubDeploymentWebhookInbox()` at the HTTP boundary and process its
leased records through `createGitHubDeploymentWebhookProcessor()`; it must not
acknowledge directly from the synchronous reference gate.

This integration does not make every GitHub mutation non-bypassable. It covers
only jobs that target an environment where this App is enabled, and GitHub
administrators can bypass protection rules unless the environment disables
bypass. The Authority Map Action under
`integrations/github-authority-map-action` discovers review paths; it is not
the enforcement point.
