# Product marketing context

Updated: 2026-09-05. Public-facing message contract. Private commercial strategy,
fundraising assumptions and customer records belong in the company repository.

## The story

**Headline:** Your AI workforce needs management.

**Promise:** Give every agent a job, set its authority, and know what happened.

**Category:** Authorization infrastructure for agentic AI.

EMILIA is building the workspace for the people responsible for AI work. Define
the job and its limits, keep the allowance and unresolved work accounted for
when an agent is replaced, and review what happened on the configured path.

“HR for AI agents” is a useful explanation for assigning work, setting authority,
reviewing results and retiring an assignment. It is not an employment service or
a claim of novelty. Agents are software; a person or institution remains accountable.

## Company, product and open Protocol

- **EMILIA is the company.** It builds the operational product and supplies
  integration, deployment, support and evidence operations under agreed terms.
- **EMILIA Gate is the commercial product.** The workforce workspace organizes
  jobs, agent assignments, authority and work records around Gate's covered
  execution paths. It is not a second authorization engine or a new protocol.
- **EMILIA Protocol is open.** Formats, verifiers, reference code and conformance
  artifacts can be used without buying from EMILIA. Individual Internet-Drafts
  are proposals, not RFCs or IETF endorsement.
- **The customer owns the authority.** The customer selects limits, credentials,
  trust roots, exception owners and acceptance criteria.

The Protocol makes evidence portable. Gate enforces the customer's authority
on configured paths that actually reach the credential-owning execution boundary.
An approval screen, agent registry or receipt alone does not enforce that boundary.

## What is built, and what is not

The workforce workspace is an **implemented private local alpha**, not a hosted
multi-tenant service, customer deployment or validated ROI. The alpha includes a
named job owner, versioned assignments, replacement and revocation, a local
SQLite-backed authority account using the existing AuthorityAccountGate, and
separately sourced outcome and review records.

Its demo uses synthetic identities, authority, provider records and reviews. It
does not move money or call a real provider. Do not publish a local operator URL,
demo key or install/signup promise for this private experience.

The alpha requires one trusted host and a local filesystem. It does not provide
high availability, rollback resistance, disaster recovery or protection against
a compromised host. Production credential custody, source authentication,
complete mediation and recovery require a separate deployment review.

No native Workday, Agent 365, ServiceNow or live provider integration is established
by the workforce alpha. Do not confuse existing public SDKs, fixture adapters or
separate prototype routes with a deployed workforce service.

## The example

A finance owner gives the refunds job a $10,000 allowance. The first agent
consumes $3,000; another $400 has an unresolved provider outcome. The job has
$6,600 available, assuming no other reservations.

Replacing the agent does not issue another $10,000. The $400 stays unavailable
while unresolved, the earlier work stays in the record, and the retired assignment
cannot start another covered action. Replacement and revocation cannot undo an
action that has already entered the provider boundary.

These are synthetic figures, not customer funds or measured savings. Consumed
authority does not prove settlement or successful business work.

## Message order and audience

Start with the person responsible for one consequential workflow. The first
evaluation is a finance team's refunds workflow; the external team, owner and
provider are not yet selected. Terms, pricing and production acceptance must be
agreed separately. Do not advertise an old fixed-price pilot as this evaluation.

1. Give the agent a job and name its owner.
2. Set the allowance, limits and exception path.
3. Replace the agent without resetting the allowance or unresolved work.
4. Show Gate's decision, the provider report and the business review separately.
5. Explain the covered execution path and open evidence underneath.
6. Invite the buyer to discuss one real workflow.

**Primary CTA:** Discuss your workflow → `/contact#workforce`.

**Product path:** See the workforce product → `/workforce`.

**Developer paths:** Keep the public docs, local scanner, Gate quickstart, open
verifier, protocol and engineering evidence accessible. A local scan or wrapper
is not proof of production enforcement.

## Claim boundaries

- A path outside the configured credential-owning Gate can bypass enforcement.
- Persistent authority applies to one implemented shared account domain, not
  every agent, provider or credential system in a customer's business.
- Native identity, delegated scope, machine policy, human authorization,
  exact-action matching, local admission, provider evidence and business
  acceptance are distinct. Do not promise exactly-once physical execution.
- An agent's own score is not business acceptance. A signed observation identifies
  its source and protects its bytes; it does not make the source true.
- Missing performance measurements stay unknown. A refusal is not automatically
  a loss avoided; a synthetic demo is not savings or ROI evidence.
- Compliance records support review. They do not establish legal compliance,
  certification, an audit opinion, insurance or freedom from fraud.
- Use current machine evidence for technical counts and the live Datatracker
  for draft status. Same-team ports are not independent implementations.

## Composition

Supporting tools keep their existing roles. EMILIA Host is the local deployment
form of Gate for activated covered HTTP and MCP paths, not a separate workforce
product or a general reverse proxy. Authority Brain maps supported declared
actions; Approver captures an exact-action decision when required; assurance
procedures support scoped review without issuing an audit opinion.

Keep useful identity, policy, approval, workforce and provider systems in place.
Assess the customer's actual workflow before proposing an additional supplier.
Other agent-management vendors have real control offerings; do not dismiss them
as dashboards. “Designed to compose” does not mean “integrated,” and an open
format is not a partnership, endorsement or obligation to adopt EMILIA.

## Voice and presentation

Write like a person explaining a specific job. Prefer “job,” “owner,” “allowance,”
“refund” and “unresolved” to vague trust claims. Lead with the product, then show
its mechanism and evidence. Keep the limit beside the claim.

Use light surfaces, readable dark type and real, explicitly labeled alpha records.
Avoid decorative circle-and-arrow diagrams, cartoon workers, fake screens and
unsubstantiated compliance badges. The website and decks should tell the same
story while keeping roadmap, engineering evidence and outside adoption separate.
