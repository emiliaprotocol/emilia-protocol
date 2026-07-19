<!-- SPDX-License-Identifier: Apache-2.0 -->
# `x-emilia-action` — OpenAPI for consequences

> APIs were built for callers. Agents need consequences. `x-emilia-action` is the
> per-endpoint declaration of what a consequential operation does, and what
> authorization it requires, so an agent can weigh consequences and satisfy the
> requirement *before* it acts.

This is the **inline, per-operation** form of an EMILIA agent-action-control
declaration ([`draft-schrock-agent-action-manifest`](../standards/draft-schrock-agent-action-manifest-00.md),
served in aggregate at `/.well-known/agent-action-control.json`). It carries the
same fields, expressed directly on an OpenAPI operation, so an agent that already
reads the API's OpenAPI spec sees the consequence declaration with no second
fetch. An API MAY publish the well-known manifest, annotate inline, or both.

- Schema: [`public/schemas/x-emilia-action.schema.json`](../public/schemas/x-emilia-action.schema.json)
- Example: [`examples/openapi/x-emilia-action.example.yaml`](../examples/openapi/x-emilia-action.example.yaml) (validated in CI, `tests/x-emilia-action-example.test.js`)
- Vocabulary: [`EP-ACTION-TYPE-PROFILE-REGISTRY.md`](./standards-engagement/EP-ACTION-TYPE-PROFILE-REGISTRY.md) (the `urn:ep:action:*` namespace)

## Why an OpenAPI extension (and not a new protocol)

The adjacent standards work declares *objects* — SCITT logs statements, permits
carry policy decisions, receipts carry approvals — but none is the thing an API
author adds to their **existing spec** to say "this endpoint changes the world,
here's the proof it needs." An `x-*` vendor extension is that surface: zero new
runtime, no framework adoption, it rides the OpenAPI document teams already ship.
That is what turns the manifest from a spec EMILIA publishes into a **dependency**
other layers reference — SCITT receipts cite the action URN, an OAuth transaction
challenge renders the effects, a gateway enforces the authority block, an auditor
queries by action URN, an agent plans against the consequence.

Scope discipline (unchanged): this is the **demand-side** declaration. It composes
above — it does not replace — the human-authorization receipt (the apex), the
evidence chain (composition), identity (WIMSE), or policy (permit). The `effects`
block is **advisory**; the `authority` block is the control, fail-closed at the
enforcement point. A declaration never lowers what enforcement requires.

## The object

Placed under `x-emilia-action` on an OpenAPI operation object:

| field | meaning |
|---|---|
| `action` (req) | canonical action URN, `urn:ep:action:<family>.<action>` (see registry) |
| `effects` (req) | **advisory** preview: `reversibility`, `data_exposure`, `cost_class`, `downstream[]`, `consent_required` |
| `authority` (req) | the **control**: `receipt_required`, `assurance_class`, `receipt_profile`, `max_age_sec`, `enforcement_point`, `challenge_status` |
| `execution_binding` | material `required_fields` observed from the `system_of_record` (stops parameter drift between approval and execution) |
| `replay` | `one_time_consumption` + `receipt_id_required` |
| `evidence` | post-boundary evidence anchors: `execution_attestation`, `reliance_packet`, `blocked_attempts`, optional `transparency` |
| `rollback` | `supported` + the reversing `operation_id`, paired with `effects.reversibility` |

See the example for a `finance.wire_transfer` operation. The two questions the
object separates: **effects** answer "what will this do and how consequential is
it"; **authority** answers "what evidence is required and how is it enforced." A
runtime uses the first to decide whether to seek the second.

## Canonical action URNs — owning the vocabulary

Action ids are URNs in the EP namespace: `urn:ep:action:<family>.<action>`
(e.g. `urn:ep:action:finance.wire_transfer`, `urn:ep:action:devops.deploy`,
`urn:ep:action:gov.benefit_disbursement`). The families are the ones staked in
[the action-type registry](./standards-engagement/EP-ACTION-TYPE-PROFILE-REGISTRY.md).
A stable, citable action vocabulary is the piece the adjacent drafts explicitly
punt on (the intent-admission work states it does not define a global taxonomy of
high-impact actions) — so it is EP's to own, and it is what lets a SCITT receipt,
an OAuth challenge, and a gateway all name the same action.

## Status

Authored and CI-validated (schema + example agree). **Not yet an I-D** — it ships
as the demand-side companion to the receipts story and is timed to file after the
apex consolidates (see the July-22 filing reminder). The natural home is a short
section of, or a companion to, `draft-schrock-agent-action-manifest`, plus an
IANA-style registration of the `urn:ep:action` namespace.

## Missing / next (honest)

- **Not yet filed** as an I-D (gated on the receipts-story batch, post-IETF-126).
- **No `urn:ep:action` IANA/registry mechanics** — the registry is a land-claim doc; a real URN-namespace registration + a machine-readable registry file (like `ep-actions.json`) is the follow-on.
- **No adoption yet** — the extension needs one external API annotating a real endpoint to become a dependency rather than a proposal (the require-receipt/402 rail is the demand hook that pulls it).
- **No conformance tooling** — a linter that checks an OpenAPI doc's `x-emilia-action` blocks against the schema (a `spectral` ruleset or a CLI) would make it turnkey for adopters.
- **Rollback semantics are declaration-only** — `rollback.operation_id` names the reversing op; it does not yet define a verifiable rollback-evidence artifact.
