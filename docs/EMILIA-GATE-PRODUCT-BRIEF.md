# EMILIA Gate — the Consequence Firewall

*Product brief · 2026-07 · EMILIA Protocol, Inc.*

> **If an agent cannot produce a valid receipt, it cannot change money, code, permissions, data,
> infrastructure, energy, or physical state.**

**The frame:** *Antivirus scanned files. Firewalls filtered packets. EMILIA verifies actions before
machines change the world.* The category is the **Consequence Firewall**: it sits at the
**actuator boundary** — before API calls, deploys,
payments, deletes, exports; before robot motion, tool use, doors, lifts, vehicles; before energy
curtailment posture changes; before autonomous systems execute bounded actions — **not inside the
model.**

**The world-saving sentence (sober enough for serious rooms, big enough to carry the mission):**
*In a world where machines can act, EMILIA makes consequential action require accountable human
authorization before execution.* EMILIA does not stop every evil system — a bad actor can build an
unguarded machine. It makes **unreceipted systems untrusted**, so legitimate infrastructure, robots,
APIs, clouds, and critical equipment refuse consequential actions without a valid receipt. That is
how TLS, code signing, and SOC 2 won: not by stopping every bad actor, but by making serious buyers
reject systems that lack the control.

## The category

Firewalls ask "is this packet allowed?" WAFs ask "is this request malicious?" EDR asks "is this
process behaving badly?" **EMILIA Gate asks a question none of them do:**

> *Is this action allowed to happen, and can you prove who authorized it — before it mutates the world?*

It is a **policy-enforcement point for consequential machine action**: deny by default, allow only
on proof that a named, accountable human (or quorum) authorized *this exact action*. Not
authentication, not permissions, not anomaly detection — **pre-execution authorization proof.** No
model, no signatures-of-badness, no false positives: receipt or no execution.

## How it composes with the authorization stack

> **AgentROA governs calls. ORPRG proves policy permitted the effect. EMILIA proves exact authorization
> by an enrolled approver under the relying party’s pinned directory, then safely controls
> consequential outcomes.**

This is an interoperability position, not a replacement claim. EMILIA verifies
AgentROA and the concrete `ORPRG-JSON-JCS-ED25519-v1` profile under separate
relying-party pins, maps their native action descriptions to one CAID only under
exact pinned mapping profiles, and can require them beside EP Class-A or quorum
evidence. Native verification, material-action matching, evidence satisfaction,
local authorization, and execution are five separate steps.

## What it gates (consequences, not prompts)

money movement · database export · production deploy · permission/role change · repo or resource
deletion · secret access · destructive SQL · grid curtailment · robot/physical actuation · regulated
decision. It does **not** judge "good vs bad AI"; it requires authorization for the act.

## How it works

A guarded action runs only if its receipt is **valid** (Ed25519 / canonical JSON, pinned issuer),
**in-scope** (bound to the exact action), **sufficiently assured** (meets the action's tier),
**fresh**, and **unused** (one-time). Otherwise: a machine-readable `Receipt-Required` challenge
(HTTP 428) telling the agent exactly what to bring. Every decision is appended to a **tamper-evident
evidence log** — the compliance/insurance artifact.

Assurance tiers: `software` < `class_a` (device signoff / WebAuthn) < `quorum` (m-of-n, two-person
rule). The action's risk sets the floor.

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

## The EP-to-EP handshake (this is the protocol)

Legitimate machines should speak in receipts. A serious system shouldn't just receive a command — it
should ask "where is the receipt? who authorized this? under what policy? was it already used? what
proof do I emit after I act?" That is the EP-Gate handshake, and it's the full firewall loop:

```
request action → 428 challenge → human/quorum signs exact action → verify
  (authority · policy · freshness · WYSIWYS · tenant · quorum · replay) → execute → execution receipt
```

The two halves both ship in `@emilia-protocol/gate`: `check()` does the pre-execution authorization
(challenge → verify, deny-by-default); `recordExecution()` emits the **execution receipt** — proof,
bound to the exact authorization decision, that the action actually ran (maps onto EP execution
evidence and a SCITT seal). `guard()` runs the whole loop around any function. This is what lets EP-aware systems
prefer each other: they can challenge, verify, and emit — machines that speak receipts.

## It's deployed by the defender (this is the key framing)

The Gate is installed by the **resource owner** — the bank, the cloud API, the database, the robot
controller, the grid operator — in front of what can be mutated. An agent wanting to act must
**bring a receipt** the gate verifies. There is no "EP must talk to EP everywhere" mandate. The
network effect emerges: once consequential rails require receipts, every legitimate agent adopts EP
issuance to be able to act at all — exactly how TLS won (servers required certs, so everyone got
certs).

## What's built (this is assembly, not green-field)

| Layer | Package | Status |
|-------|---------|--------|
| Receipt verify + manifest + 428 challenge + Express middleware + RR-1 conformance | `@emilia-protocol/require-receipt` | shipped |
| **Unified gate core: assurance tiers + one-time consumption + evidence log + `check`/`middleware`/`guard`** | **`@emilia-protocol/gate`** | **built and hardened; covered by the package, mutation, and release suites** |
| **BYOC Gate service: complete mediation for GitHub repository deletion** | **`apps/gate-service`** | **built; exact system-of-record binding, replay refusal, indeterminate outcomes, and authenticated access** |
| **Durable replay + evidence state** | **Postgres consumption and atomic evidence backends** | **built; ownership-fenced consumption, tenant/gate scoping, fork detection, and database immutability controls** |
| **Bounded capability enforcement** | **Exact-action/CAID scope, atomic budget reservation, operation binding, replay refusal, authenticated reconciliation** | **built in the Gate path with memory and PostgreSQL stores; executable provider-timeout scenario and negative evidence tests** |
| **Adjacent authorization adapters** | **AgentROA native verifier + concrete ORPRG JCS/Ed25519 verifier** | **built fail closed; shared-CAID suite composes both with genuine EP Class-A quorum evidence** |
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
remain reproducible; customers pay EMILIA to operate the control across a fleet.

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

The public standards basis includes the individual Internet-Drafts for the
Enforcement Point, Authorization Receipts, Quorum, and AEC. They are not RFCs,
working-group-adopted documents, or IETF endorsement. CAID -00 is a render-clean
filing candidate but is not posted. Bounded Capability is implemented EMILIA
architecture and must not be represented as a posted standard. Conformance is
earned by executable harnesses, not asserted by draft status.

Formal assurance is scoped the same way. Machine-checked models establish named
properties within their declared bounds and assumptions; they do not prove the
deployed service, provider, or physical world. The Assurance Plane packages and
re-performs those model results beside runtime evidence and conformance records
without issuing an audit opinion or accredited certification.

## Boundary (state it honestly)

EMILIA Gate cannot stop a malicious operator who controls their own stack from simply not deploying
it. What it does: make legitimate infrastructure refuse unreceipted consequential actions by default,
and let clouds/rails/regulators/insurers *require* the receipt — so bad actors get shut out of the
rails that adopt it. Necessary, not sufficient. That is how a standard wins: first it protects the
careful, then it becomes a procurement requirement, then unprotected systems look reckless.

A network TAP or packet broker does not change that boundary. It can provide a separately pinned,
signed observation row, but a passive observer cannot block an action. The control plane therefore
reports an observed surface without active enforcement proof as `witness_only` and refuses any
settlement profile that requires a gated route.

## Where it sits in the roadmap

EMILIA Gate is the **horizontal product**; the verticals are profiles of it:
**Receipt-Required** (MCP/dev) is the adoption wedge that seeds Gate deployment · **GRACE** is the
energy vertical · **defense/autonomy** is the physical-action vertical. One company, one sentence:
**the pre-execution trust layer for machines that can change the world.**
