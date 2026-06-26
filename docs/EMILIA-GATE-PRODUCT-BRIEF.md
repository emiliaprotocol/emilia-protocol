# EMILIA Gate — the Trusted Action Firewall

*Product brief · 2026-06 · EMILIA Protocol, Inc.*

> **If an agent cannot produce a valid receipt, it cannot change money, code, permissions, data,
> infrastructure, energy, or physical state.**

**The frame:** *Antivirus scanned files. Firewalls filtered packets. EMILIA verifies actions before
machines change the world.* The category is the **Consequence Firewall** (a.k.a. Trusted Action
Firewall for Autonomous Systems): it sits at the **actuator boundary** — before API calls, deploys,
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
bound to the exact authorization decision, that the action actually ran (maps onto the EP Commit /
SCITT seal). `guard()` runs the whole loop around any function. This is what lets EP-aware systems
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
| **Unified gate core: assurance tiers + one-time consumption + evidence log + `check`/`middleware`/`guard`** | **`@emilia-protocol/gate`** | **built (10 tests green, demo runs)** |
| MCP gateway | `@emilia-protocol/mcp-guard` | shipped |
| Framework adapters | `@emilia-protocol/openai-guard`, `@emilia-protocol/langchain`, examples/*_guard | shipped |
| Offline verifiers (JS/Python/Go) | `@emilia-protocol/verify`, `python-verify`, `go-verify` | shipped |
| Issuer / signoff | `@emilia-protocol/issue` | shipped |

**To build (the business):** the managed control plane — hosted issuer, approver directory, policy
UI, transparency log, compliance export, fleet-grade consumption store. Open-core gate, paid control
plane (same model as GRACE).

## Gate deployment surfaces (the land-grab order)

Plant the gate at every actuator boundary, widest-adoption-first:

1. **MCP** — wrap agent tools; dangerous action without a receipt returns `428`. *(shipped: `mcp-guard` + `gate`)*
2. **APIs** — middleware for Express / FastAPI / Next / Go; protect POST/PUT/PATCH/DELETE. *(shipped: `gate.middleware`)*
3. **Cloud** — GitHub, Vercel, AWS/IAM, Kubernetes, Terraform, Supabase, Stripe. *(adapters — build)*
4. **Robots** — a local daemon/sidecar at the actuator boundary, before motion/tool/door/vehicle commands; simulated first, then real hardware. *(build)*
5. **EP-Gated conformance badge** — earned, not asserted: missing receipt refused · valid runs · replay refused · forged refused. *(shipped: RR-1 via `receiptRequiredConformance`)*
6. **Attested Gate** — prove the gate is actually installed and running via device/workload attestation (compose WIMSE/SPIFFE). Crucial for robots and air-gapped/critical equipment. *(build)*

## Build order (for the managed product)

1. **MCP Gateway** as the flagship dev-wedge entry (wrap MCP servers; 428 on dangerous unreceipted calls).
2. **Guard SDK** — one `wrap()` across runtimes, all sharing the gate core.
3. **HTTP middleware** for arbitrary APIs (ships in the gate core).
4. **Policy UI** — manage the action-risk manifest + tiers without editing JSON.
5. **Evidence pipeline** — durable, queryable, exportable audit (compliance/insurance value).
6. **Managed control plane** — approver directory, transparency log, integrations.

## Standards

The mechanism is the IETF work, not a new draft: `draft-schrock-ep-enforcement-point` (the
Receipt-Required rail) over `draft-schrock-ep-authorization-receipts`, with assurance tiers via the
quorum and signoff specs. Conformance is **RR-1** (`receiptRequiredConformance()`), earned not
asserted. EMILIA Gate is the *productization* of the enforcement point — no new I-D required.

## Boundary (state it honestly)

EMILIA Gate cannot stop a malicious operator who controls their own stack from simply not deploying
it. What it does: make legitimate infrastructure refuse unreceipted consequential actions by default,
and let clouds/rails/regulators/insurers *require* the receipt — so bad actors get shut out of the
rails that adopt it. Necessary, not sufficient. That is how a standard wins: first it protects the
careful, then it becomes a procurement requirement, then unprotected systems look reckless.

## Where it sits in the roadmap

EMILIA Gate is the **horizontal product**; the verticals are profiles of it:
**Receipt-Required** (MCP/dev) is the adoption wedge that seeds Gate deployment · **GRACE** is the
energy vertical · **defense/autonomy** is the physical-action vertical. One company, one sentence:
**the pre-execution trust layer for machines that can change the world.**
