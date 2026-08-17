# EMILIA — the authority toll booth for autonomous work

*Product brief · 2026-07 · EMILIA Protocol, Inc.*

> **Every consequential agent action enters with authority and exits with a receipt.**

**The frame:** EMILIA is building the universal authority toll booth for autonomous work. A human or institution
defines a finite operating mandate—mission, limits, evidence, expiry, delegation, and exception
rules—and agents work unattended inside it. **EMILIA Gate** is the commercial Consequence Firewall
that enforces each exact unit of work at the **actuator boundary**—before API calls, deploys,
payments, deletes, exports; before robot motion, tool use, doors, lifts, vehicles; before energy
curtailment posture changes; before autonomous systems execute bounded actions — **not inside the
model.**

**The category sentence:**
*In a world where machines perform work, EMILIA makes their authority finite, executable, and
verifiable at the point of consequence.* A human decision is one authority source and an exception
path, not the default execution model. EMILIA does not stop every unguarded system; it protects only
the paths where a resource owner deploys Gate with complete mediation.

**The commercial sentence:** *EMILIA charges where authorized intent becomes consequential action.*
This names the value location. Current pricing remains protected-workflow pilot, implementation,
and annual Gate plus Assurance. It is not a claim of current per-action revenue or global network
operation.

## The category

Firewalls ask "is this packet allowed?" WAFs ask "is this request malicious?" EDR asks "is this
process behaving badly?" **EMILIA Gate asks a question none of them do:**

> *Is this action inside current authority, and can you prove that before it mutates the world?*

It is a **policy-enforcement point for consequential machine action**: deny by default and allow only
on verifiable authority for *this exact action*, whether that authority comes from a bounded mandate,
a required human decision, or a quorum. Not authentication, not permissions, not anomaly detection —
**pre-execution authority at the protected boundary.** The decision follows explicit evidence and
policy rather than an anomaly score; its prevention claim remains limited to covered Gate paths.

## How it composes with the authorization stack

> **AgentROA governs calls. ORPRG proves policy permitted the effect. EMILIA verifies the exact
> authority and any required approver evidence under the relying party’s pinned rules, then controls
> admission at covered consequence boundaries.**

This is an interoperability position, not a replacement claim. EMILIA verifies
AgentROA and the concrete `ORPRG-JSON-JCS-ED25519-v1` profile under separate
relying-party pins, maps their native action descriptions to one CAID only under
exact pinned mapping profiles, and can require them beside EP Class-A or quorum
evidence. Native verification, material-action matching, evidence satisfaction,
candidate qualification, local authorization, admission, and execution remain
separate steps.

## Gate Qualification v2: portable evidence, local authority

> **Qualification travels. Authorization stays local. Gate controls the consequence.**

Gate Qualification v2 is a public experimental implementation profile that converts accepted
evaluation evidence into a **portable, time-bounded qualification for one exact measured candidate
and assignment**. The qualification remains bound to the complete evaluation campaign, current
status, qualification policy, runtime candidate measurement, assignment, and protected request.

`QUALIFIED` means those evidence and binding checks passed under the relying party's pinned trust
inputs. It does not mean `AUTHORIZED`, and it cannot reserve resources, call a provider, or establish
an effect. The relying party separately requires any AEB and AEC evidence and applies local policy to
the exact action; Gate separately admits the operation and controls provider entry.

This profile is not an authorization, certification, deployment claim, audit opinion, or proof that
the candidate or resulting action is wise, legal, safe, or successful.

## What it gates (consequences, not prompts)

money movement · database export · production deploy · permission/role change · repo or resource
deletion · secret access · destructive SQL · grid curtailment · robot/physical actuation · regulated
decision. It does **not** judge "good vs bad AI"; it requires authorization for the act.

## How it works

When a protected workflow requires evaluated-candidate evidence, Gate first verifies that the
qualification remains current for the exact measured candidate, assignment, and request. That pure
decision is side-effect free and supplies only one evidence leg to local Gate composition.

A guarded action runs only if its operating mandate and required evidence are **valid** under pinned
native rules, **in-scope** for the exact action, **sufficient** under the relying party's requirement,
**fresh**, and **unused** where one-time semantics apply. A profile that requires a fresh human
decision can use the shipped `Receipt-Required` challenge (HTTP 428) to tell the agent what to bring;
other profiles can use bounded capabilities or natively verified evidence without manufacturing a
human click. Every admission decision is appended to a tamper-evident evidence log.

When a human ceremony is required, assurance tiers are `software` < `class_a` (device signoff /
WebAuthn) < `quorum` (m-of-n, two-person rule). The relying party sets the floor.

For a bounded capability, Gate also reserves the exact action and spend before
entering the provider boundary. Overspend and replay fail closed. Success
commits the operation. If the provider executes but its response is lost, Gate
records `indeterminate`, does not refund or blindly replay, and reconciles only
authenticated provider evidence bound to the same operation and action.

## Product proof: Action Escrow

Action Escrow is the customer-facing proof that these layers remain separate
under a real consequence. A signed agreement does not authorize payment. The
reference experience separately verifies document execution, exact release
approvals from both parties, custodian state, one-time Gate admission, and the
portable evidence package for one milestone release.

The simulated adapters and custodian move no real money and imply no provider
partnership, endorsement, or license. What the reference proves is the
cryptographic and state-machine boundary: only the exact mutually approved
release can enter the protected effect once.

## One approval-profile loop

When a mandate requires fresh exact-action human authority, Gate can challenge for a receipt and run
this loop:

```
request action → 428 challenge → human/quorum signs exact action → verify
  (authority · policy · freshness · WYSIWYS · tenant · quorum · replay) → invoke → bound execution record
```

This is one supported authority profile, not the whole protocol and not a claim that every action
needs a human. The two halves ship in `@emilia-protocol/gate`: `check()` does the pre-execution authorization
(challenge → verify, deny-by-default); `recordExecution()` emits an execution-evidence record bound
to the exact authorization decision and the wrapper's stated outcome. That binding preserves what
the local runtime reported and detects action substitution. It does not by itself prove provider
entry, provider commitment, or external effect; those claims require evidence accepted under a
relying-party-pinned provider or effect profile. `guard()` runs the loop around any function. This
is what lets EP-aware systems challenge, verify, and emit compatible evidence without collapsing
authorization into outcome truth.

## It's deployed by the defender (this is the key framing)

The Gate is installed by the **resource owner** — the bank, the cloud API, the database, the robot
controller, the grid operator — in front of what can be mutated. An agent wanting to act must present
the mandate and evidence the owner's pinned requirement demands for that exact work. There is no
"EP must talk to EP everywhere" mandate. The
first deployment protects its resource owner without ecosystem-wide adoption. An acceptance effect
may emerge later if consequential rails require compatible evidence and agents adopt issuance to
reach them. That is a future adoption hypothesis analogous to TLS acceptance, not a present network,
central transaction rail, or proof of external adoption.

## What's built (this is assembly, not green-field)

| Layer | Package | Status |
|-------|---------|--------|
| Receipt verify + manifest + 428 challenge + Express middleware + RR-1 conformance | `@emilia-protocol/require-receipt` | shipped |
| **Unified gate core: assurance tiers + one-time consumption + evidence log + `check`/`middleware`/`guard`** | **`@emilia-protocol/gate`** | **built and hardened; covered by the package, mutation, and release suites** |
| **BYOC Gate service: complete mediation for GitHub repository deletion** | **`apps/gate-service`** | **built; exact system-of-record binding, replay refusal, indeterminate outcomes, and authenticated access** |
| **Durable replay + evidence state** | **Postgres consumption and atomic evidence backends** | **built; ownership-fenced consumption, tenant/gate scoping, fork detection, and database immutability controls** |
| **Bounded capability enforcement** | **Exact-action/CAID scope, atomic budget reservation, operation binding, replay refusal, authenticated reconciliation** | **built in the Gate path with memory and PostgreSQL stores; executable provider-timeout scenario and negative evidence tests** |
| **Adjacent authorization adapters** | **AgentROA native verifier + concrete ORPRG JCS/Ed25519 verifier** | **built fail closed; shared-CAID suite composes both with genuine EP Class-A quorum evidence** |
| **Gate Qualification v2** | **Candidate/campaign/status verifier, evaluation-only adapter, Gate composer/orchestrator, admission-store references, conformance fixtures, and bounded model** | **public experimental reference implementation; qualification is not authorization or certification, and durable operated integration remains deployment work** |
| **Attestation verifier + coverage inventory** | **Source-pinned rebuild chain, strict TPM quote verifier, signed active probes, and five-state coverage kernel** | **verifier and kernel built; TPM interoperability uses a software fixture. No physical TPM, manufacturer EK chain, measured boot, or production-host attestation is claimed** |
| **Network witness profile** | **Signed, privacy-minimized observation profile with durable sequence ingestion** | **local profile and testnet built; pinned sensor/capture/config, action binding, freshness, replay/rollback/equivocation refusal. No independently administered operator has produced external witness evidence** |
| **Control plane + settlement eligibility** | **Coverage, evidence joins, outcome verification, metering, and closed settlement verdicts** | **built reference kernel and operator view; managed operation and real partner adapters remain deployment work** |
| MCP gateway | `@emilia-protocol/mcp-guard` | shipped |
| Framework and actuator adapters | GitHub, Stripe, AWS, Supabase, OpenAI, LangChain, MCP | adapter libraries built; GitHub has the deployable reference service |
| Offline verifiers (JS/Python/Go) | `@emilia-protocol/verify`, `python-verify`, `go-verify` | shipped |
| Issuer / signoff | `@emilia-protocol/issue` | shipped |
| Native approval capture | iOS and Android reference apps + SDKs | built on the mobile integration branch; production signing and store review remain deployment gates |

**Commercial layer:** managed policy, approver-directory integrations, evidence export, deployment
operations, continuous conformance, and warranties. The open verifier and enforcement semantics
remain reproducible. Customer-operated and EMILIA-managed Gate are parallel deployment choices. In
either mode, the customer controls authority, trust roots, policy, provider-credential custody,
acceptance rules, and portable evidence. Managed Gate is scoped and quoted for a defined customer
deployment after implementation acceptance; the public repository does not establish a generally
available live service.

## Gate deployment surfaces (the land-grab order)

Plant the gate at every actuator boundary, widest-adoption-first:

1. **MCP** — wrap agent tools; dangerous action without a receipt returns `428`. *(shipped: `mcp-guard` + `gate`)*
2. **APIs** — middleware for Express / FastAPI / Next / Go; protect POST/PUT/PATCH/DELETE. *(shipped: `gate.middleware`)*
3. **Cloud** — GitHub, Vercel, AWS/IAM, Kubernetes, Terraform, Supabase, Stripe. *(GitHub BYOC service + GitHub/Stripe/AWS/Supabase adapters built; additional complete-mediation services follow)*
4. **Robots** — a local daemon/sidecar at the actuator boundary, before motion/tool/door/vehicle commands; simulated first, then real hardware. *(build)*
5. **EP-Gated conformance badge** — earned, not asserted: missing receipt refused · valid runs · replay refused · forged refused. *(EG-1 reference harness built; public certification program remains future work)*
6. **Attestation-verifier profile** — a relying-party-pinned verifier checks workload/image/config/policy measurements, while a separately pinned active probe proves the declared route returns 428. *(reference verifier and software-TPM interoperability fixture built; physical production-host attestation remains external deployment evidence)*
7. **Network witness** — a TAP, packet broker, or service observer signs privacy-minimized action-bound observations. It remains an evidence plane and can never establish enforcement by itself. *(local vendor-neutral profile and replay-safe testnet built; no independent operator is claimed)*

## Build order (for the managed product)

1. **BYOC consequence firewall** — deploy the GitHub reference service with customer-owned keys and Postgres state. *(built)*
2. **MCP and HTTP entry points** — one enforcement contract across agent tools and ordinary APIs. *(core built; product packaging next)*
3. **Native approval capture** — controlled material-field display plus platform attestation. *(reference apps built; signing/release hardening remains)*
4. **Policy and coverage inventory** — show each declared surface as `gated`, `witness_only`, `ungated`, `stale`, or `unknown`; only fresh attestation plus an active refusal probe earns `gated`. *(built reference kernel and UI)*
5. **Evidence operations** — searchable export, retention, fork alerts, insurer/auditor packages, network-witness ingestion, and evidence-complete settlement decisions. *(kernels built; managed operation next)*
6. **Managed fleet** — directory integrations, rollout, drift detection, continuous conformance, partner hardware adapters, risk pricing, and a separately contracted warranty. *(commercial expansion)*

## Standards

The governed repository inventory currently tracks 23 active Datatracker records: 20
`draft-schrock-*` records and three coauthored records. Current snapshots include AE-CHALLENGE -03,
AEB -03, CAID -02, Architecture -02, AEC -05, Authorization Receipts -10, Bounded Capability
Receipts -03, Quorum -03, and Model-to-Matter -04. `standards/STATUS.json` is the repository source
and the live Datatracker is authoritative for current revision and status. None is an RFC, an adopted
working-group item, or IETF endorsement. Conformance is earned by executable harnesses, not asserted
by draft status.

Gate Qualification v2 is an implementation profile over existing public formats and extension
points. It is not a new Internet-Draft and must not be described as IETF submission, review, adoption,
or endorsement.

Formal assurance is scoped the same way. Machine-checked models establish named
properties within their declared bounds and assumptions; they do not prove the
deployed service, provider, or physical world. The Assurance Plane packages and
re-performs those model results beside runtime evidence and conformance records
without issuing an audit opinion or accredited certification.

## Boundary (state it honestly)

EMILIA Gate cannot stop a malicious operator who controls their own stack from simply not deploying
it. What it does: make legitimate infrastructure refuse consequential actions that lack the valid
authority evidence required by the resource owner, and let clouds, rails, regulators, and insurers
require a suitable evidence profile. Necessary, not sufficient. That is how a standard wins: first
it protects the careful, then it becomes a procurement requirement, then unprotected systems look
reckless.

A portable qualification does not change that limit. It establishes only that accepted evaluation
evidence remains current for the exact measured candidate, assignment, and request under pinned
inputs. The resource owner still authorizes locally, and only a deployed Gate on a completely mediated
path can control the consequence.

A network TAP or packet broker does not change that boundary. It can provide a separately pinned,
signed observation row, but a passive observer cannot block an action. The control plane therefore
reports an observed surface without active enforcement proof as `witness_only` and refuses any
settlement profile that requires a gated route.

## Where it sits in the roadmap

EMILIA Gate is the **horizontal product**; the verticals are profiles of it:
**Receipt-Required** (MCP/dev) is the adoption wedge that seeds Gate deployment · **GRACE** is the
energy vertical · **defense/autonomy** is the physical-action vertical. One company, one sentence:
**the authority control plane for autonomous work.**
