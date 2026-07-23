# EMILIA consequence-control service

Authenticated HTTP custody for the Proposal-to-Effect lifecycle. The service
binds a server-issued proposal to one principal, verifies a receipt and a
re-derivable AEB evaluation, reserves durable one-time authority before the
provider call, and leaves an uncertain provider outcome non-replayable until
authenticated reconciliation.

The first production profile is deliberately narrow: a GitHub App installed on
one disposable private repository may update one configured issue. A second,
server-selected smoke profile performs the same update and then forces the
response path to become indeterminate. It exists to prove that an effect which
may have happened is not blindly replayed. GitHub's authenticated current-state
observation is retained as evidence, but because GitHub does not persist the
attempt ID as immutable issue evidence, this adapter escalates rather than
claiming the observation proves which attempt caused the effect.

## Boundaries

- Application authentication is required before proposal or lifecycle work.
- The authenticated principal, proposal ID, tenant, executor, provider account,
  effect adapter, attempt owner, and recovery authority are server-selected.
- Presented artifacts and status objects are untrusted inputs. They are
  re-verified under the server-pinned AEB and EP-STATUS configuration.
- GitHub credentials are short-lived installation tokens minted from a GitHub
  App key. The App should have Issues read/write on one repository only.
- The PostgreSQL executor and recovery URLs must authenticate as different,
  tenant-bound least-privilege roles.
- `INDETERMINATE` means retry is refused. Reconciliation observes the configured
  issue through the GitHub App and binds that evidence to the expected attempt,
  but terminates as `ESCALATED`; equal current state alone is not attempt
  attribution.

## Routes

See [`openapi.json`](./openapi.json). Health is available at `/v1/live` and
readiness at `/v1/ready`. All lifecycle routes use strict JSON and reject
duplicate object members.

## Start

```sh
EMILIA_CONSEQUENCE_CONFIG=apps/consequence-control-service/src/production-config.js \
  node apps/consequence-control-service/src/server.js
```

Production values are supplied through a secret manager. Do not place database
passwords, API tokens, evaluator private keys, revoker private keys, or GitHub
App private keys in either repository.

## Claim boundary

This app is the reference managed-service profile and the candidate for the
first EMILIA-operated production canary. A live canary demonstrates only the
configured EMILIA-operated path; it is not an
independent implementation, customer deployment, independent audit, or a claim
that arbitrary providers have been integrated.
