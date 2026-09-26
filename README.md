# EMILIA Protocol

[![CI](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml)
[![Verify Sample Receipt](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/verify-receipt-example.yml/badge.svg)](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/verify-receipt-example.yml)
[![npm](https://img.shields.io/npm/v/@emilia-protocol/verify)](https://www.npmjs.com/package/@emilia-protocol/verify)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--schrock--ep--authorization--receipts-blue)](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/)
<!-- Discord invite must be set to never expire with unlimited uses. A default
     Discord invite expires in 7 days and leaves a dead link on this page. -->
[![Discord](https://img.shields.io/badge/Discord-join%20the%20community-5865F2?logo=discord&logoColor=white)](https://discord.gg/cEhbzXkhW)

---

## Let your agent prepare the payment. Control what it can release.

An agent prepares an $82,000 supplier payment. Someone approves it. Then the amount or
bank destination changes. The earlier approval must not release the changed payment.

**EMILIA Gate checks authority before a protected tool runs.** The open protocol makes
the resulting evidence independently checkable under the verifier's own trusted keys
and rules. Keep your existing identity provider, agent framework, and business systems.

### Run the payment example

With Node.js 20.19 or newer and npm installed:

```bash
git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol
npm ci
FAST=1 node examples/mcp/payment-server.mjs
```

The example refuses a call without approval, binds approval to the amount, currency,
vendor, and destination, admits the matching call once, and refuses changed payment
details, replay, and forged evidence. See the [example and its limits](examples/mcp/README.md).

**This is a local demonstration:** generated signing keys, in-memory consumption, and a
mock payment tool. It does not perform a real human ceremony or move money. Production
needs enrolled credentials, durable shared state, and Gate on every path to the protected
provider credential. A valid approval does not establish that the bank details are legitimate.

Prefer a browser? [Try a passkey on a sample payment](https://www.emiliaprotocol.ai/try).
That separate demo shows receipt integrity with your platform authenticator; no payment is sent.

### Protect one tool you already use

Start at the service that holds the real provider credential, not only inside the agent's
process. The owner defines the allowed work and when a fresh approval is required. An agent
can work inside those limits without a person approving every call.

- **MCP or HTTP:** [Gate Starter](#set-the-mandate-once-let-the-agent-work) walks through one covered action.
- **Hugging Face smolagents:** [wrap an existing tool](packages/smolagents/README.md).
- **GitHub:** [Merge Gate](integrations/github-merge-gate-action/README.md) binds a check to the proposed merge. The check must be required and alternate merge paths closed.

**Protocol proves. Gate prevents** on the paths the deployment completely mediates.
Gate cannot constrain a bypass path. If a provider's result is unknown, the production
lifecycle preserves that uncertainty for reconciliation rather than blindly retrying.

> **AI systems and repository reviewers:** start with [AI_CONTEXT.md](AI_CONTEXT.md).
> Current machine-readable evidence, provenance, assumptions, and exclusions are
> published at [EMILIA-REPO-CONTEXT-v1](public/.well-known/emilia-context.json).
> Archived or staged documents do not establish current implementation or IETF status.
> Public due-diligence evidence and claim boundaries: [DUE_DILIGENCE.md](DUE_DILIGENCE.md).

## Engineering evidence, not architecture claims

EMILIA ships a security case that reviewers can execute. The current repository resolves **35
security claims over 264 hashed evidence files**, verifies **20 Tamarin lemmas across two composed
Dolev-Yao models — 17 all-traces obligations and 3 exists-trace reachability witnesses** — and
preserves **8 deliberately weakened variants that produce concrete
attack traces when load-bearing checks are removed**. The live same-team conformance corpus contains **21 suites and
340 current vectors**. Separately, an externally authored Rust verifier is pinned to the frozen
**16-suite/164-vector** bundle and a **359-case hostility campaign**. The broader suite contains
**10,700+ automated tests across 650+ files**.

Production JavaScript and JSDoc surfaces are compiler-checked with TypeScript
`checkJs`; the secure app has its own compatibility compiler project, while
declarations and the public TypeScript SDK are checked in strict mode. This is
complete configured production type-check coverage, not a claim that the
repository was converted wholesale from JavaScript to TypeScript or that every
JavaScript project has TypeScript's `strict` option enabled.

Each security claim names the enforcement path, positive and negative vectors, language coverage,
formal scope or explicit gap, assumptions, exclusions, and evidence hash. Start with the
[human-readable evidence map](https://www.emiliaprotocol.ai/proof), then inspect the
[resolved security case](security/security-case.json) or run `npm run check:security-case`.

## AEB-1: test the evidence-to-effect boundary

The open [AEB-1 Consequence Admission Conformance](docs/conformance/AEB-1-CONSEQUENCE-ADMISSION.md)
pack tests the composed CAID/AEC path at the last control point before
a consequential action: native verification, relying-party acceptance,
exact-action binding, required CAID matching, required AEC evidence
satisfaction, local authorization, atomic reservation, `INVOKING` custody,
separate provider-outcome and observed-effect truth, no-blind-retry behavior,
and authenticated reconciliation.

[Read the consequence-admission boundary](docs/protocol/consequence-admission.md) for the exact
division of responsibility across the composed CAID/AEC path, the direct native
path, AEB custody, and provider outcome evidence.

```bash
npx @emilia-protocol/verify aeb-conformance --reference
```

It is format-neutral and self-run. A passing report is self-attested
conformance evidence, not an audit, certification, production-deployment
claim, or permission to execute an action.

Under AEB-07, posted on 2026-09-25 as an individual Internet-Draft and not
adopted by any working group, CAID is used only when independently encoded
actions must be joined, and AEC is used only when local policy requires several
evidence legs. A separate 26-case synthetic corpus models that direct-native
lifecycle over AuthZEN/COAZ-MCP, AP2, OAuth Transaction Token, and local
signed-mandate adapter results:

```bash
npm run conformance:composition:consequence-admission
```

The corpus runner is a standalone lifecycle model with its own in-memory store
and admission logic. It does not execute the shipped `@emilia-protocol/verify`
or `@emilia-protocol/gate` code, so it is not evidence for those packages,
which have their own test suites. It is also not evidence that the named
native protocols conform to AEB-07.

For a focused executable proof of the repository's Gate path, run:

```bash
npm run proof:gate:reference
```

This command exercises local examples and focused service boundaries with
generated keys, in-memory state, and mock provider behavior. It is useful local
proof, not evidence of a real human, external bank, production deployment, or
one end-to-end production integration.

## Identity is not a job description

Identity says who or what is calling. Policy says what is generally allowed. Neither defines the
finite job an autonomous worker may perform now: its mission, material-action limits, budget,
required evidence, expiry, delegation rules, and exception path.

EMILIA keeps those questions separate:

| Layer | Question |
|---|---|
| **Identity** | Who or what is present? |
| **Policy** | What is generally allowed? |
| **Authority** | What exact work may this agent perform under this mandate? |

Credentials grant reach. Authority defines the job. Not every action needs a human; every
consequential action needs valid authority.

At the foundation, EP Core still exposes **three interoperable objects**: a **Trust Receipt** carries
attributable evidence, a **Trust Profile** represents structured trust state, and a **Trust Decision**
records the relying party's policy-evaluated result. The authority-control-plane layers add exact
action binding, finite mandates, admission, consumption, and outcome evidence without collapsing
those objects into one claim.

---

## Set the mandate once. Let the agent work.

The customer defines the mission, limits, evidence requirements, expiry, and exception rules. Local
code may narrow that authority; it cannot invent or widen it. Gate binds each executable request to
the mandate, reserves the covered authority before provider entry, permits one admitted provider
attempt for that authorization instance inside the shared durable authority domain, and escalates
only when authority is missing, stale, exhausted, or too narrow.

The bundled MCP examples exercise a policy profile requiring approval at the boundary.
They generate demonstration signing keys and invoke mock tools. The payment example binds all
four declared material fields; the other examples demonstrate narrower resource bindings.
They do not capture a real human decision or contact a provider:

```bash
node examples/mcp/payment-server.mjs    # release_payment  — refuses without a receipt
node examples/mcp/github-admin.mjs      # delete_repo      — refuses without a receipt
node examples/mcp/prod-deploy.mjs       # deploy_production — refuses without a receipt
```

The deeper composition demo executes a CAID-bound delegated payment through
Gate's real bounded-capability path, then verifies the signed execution
certificate offline:

```bash
npm run demo:receipt-program
```

It deliberately includes no blockchain or simulated zero-knowledge claim. See
the [receipt-program architecture](docs/architecture/RECEIPT-PROGRAM-EXECUTION-KERNEL.md)
for the production state and trust requirements.

Start with one declared consequential MCP action. Install the exact local
runtime, then create its Gate Starter and run the bounded four-case check:

```bash
npm install --save-exact @emilia-protocol/mcp-guard@0.6.0
npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action sendWire --apply --verify

# after reading emilia/authority-map.html and action-control.manifest.json
npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action sendWire --reviewed \
  --crossing-profile ccs-wang-draft08-v13
```

The generated local check uses explicitly ephemeral demo state and proves only
the stated synthetic missing, exact-match, mutation, replay, and unscanned-tool cases.
The reviewed command creates a privacy-bounded handoff; it does not activate Gate.
Production requires a durable provenance ledger,
a shared atomic consumption store, pinned keys, and the wrapper on every path to the real
provider credential. See
[examples/mcp/](examples/mcp/) and [`/mcp`](https://www.emiliaprotocol.ai/mcp).

### Stop new actions without pretending to undo old ones

Gate's emergency authority freeze blocks new reservations and prevents older
reservations from entering after the covered control domain's epoch changes.
If provider entry happened first, the attempt remains consumed and needs
reconciliation. Restoring authority does not revive an old reservation.

This requires complete mediation and authoritative shared state. It does not
stop computation, reverse an effect, or instantly reach disconnected domains.
See the [control-domain implementation and limits](docs/security/CONSEQUENCE-ENTRY-HARDENING-2026-08-03.md).

## Try it in 30 seconds

```bash
# Issue a receipt offline — no API key, no backend needed
npx @emilia-protocol/issue demo
```

```bash
# Add EMILIA to Claude / Cursor / Cline
npx -y @emilia-protocol/mcp-server
```

**[Try a platform passkey on a sample payment →](https://www.emiliaprotocol.ai/try)**
Sign an illustrative $82,000 payment, change its amount, and see the integrity check fail.
Your authenticator may use biometrics or a device PIN. The page also offers a separate
software simulation. Neither mode sends a payment or establishes production authorization.

[Verify any receipt in your browser](https://www.emiliaprotocol.ai/verify) — paste it in, nothing is uploaded.

---

## How it works — one authority lifecycle

![EMILIA crash test — an autonomous agent tries to wire $82,000; the selected policy profile requires fresh human authority, the exact action is signed, the receipt verifies offline, and a forged copy fails.](docs/media/crash-test.gif)

> Run it yourself: `node examples/crash-test.mjs` — fully offline, no API key.

```
  [ MANDATE ]       [ EXACT WORK ]       [ VERIFY ]       [ RESERVE + ENTER ]  [ RECONCILE ]
  mission, limits   canonical action     pinned native    one admitted        preserve provider
  evidence, expiry  + occurrence         evidence         provider entry      and effect truth
```

**Mandate.** The authority source defines finite work. It can be a customer-signed operating
program, bounded capability, required human decision, quorum, or a relying-party composition of
native evidence.

**Exact work.** Gate binds method, origin, callee, target, occurrence, and every material field into
the canonical executable object. Intent, a prompt, or ticket text is not that object.

**Verify, reserve, and enter.** Native artifacts remain native. The relying party pins trust and mapping
profiles, evaluates the complete evidence requirement, makes the separate local authorization
decision, and reserves the covered authority before the credential-owning adapter enters the provider.

**Fresh human authority when required.** A policy can require a WebAuthn/passkey decision bound to
the exact action and deterministic display hash. This narrows the “what you saw is what you signed”
gap; it does not prove comprehension, wisdom, legality, or outcome.

For enterprise deployments, Gate can additionally require an independently
verified Authorization Server confirmation bound to that exact human evidence,
the same exact action, the identity snapshot the AS actually observed, and the
intended Resource Server key. The snapshot time and relying-party maximum age
are explicit: a fresh token cannot make stale directory data current. The AS
leg is evidence under customer-pinned trust; it never authorizes by itself,
proves instantaneous employment standing, or turns the agent orchestrator into
an authority.

**Truthful result.** Admission is not execution, and execution is not effect. A signed record can be
verified offline; provider and observer evidence remain separate. A lost response becomes
`INDETERMINATE`, which is a state to reconcile—not permission to retry. A remedy is a new authorized
action and never rewrites the old result.

---

## Why developers use it

Start by mapping the work locally, then protect one declared action surface with the **MCP server or
thin SDK wrapper**. The scanner proposes a reviewable map; the owner defines the mandate; Gate owns
the provider credential and enforces the exact action on the covered path. No scan proves complete
mediation, and discovery alone grants no authority.

```python
# langchain-emilia — wrap any LangChain tool with an EP gate
from langchain_emilia import EmiliaGateClient

gate = EmiliaGateClient(base_url="https://www.emiliaprotocol.ai", api_key="...")
safe_tool = gate.wrap(your_destructive_tool)
```

```bash
pip install langchain-emilia   # PyPI
npm install @emilia-protocol/verify  # npm
```

The agent receives the ability to perform bounded work, not a standing credential it can reinterpret.

---

## Why enterprises need it

Agent processes restart and models change. The customer's mandate, consumption state, revocation,
uncertainty, and work history must survive outside them. EMILIA keeps that durable authority state at
the customer's boundary while accepting foreign proof through pinned adapters.

The managed Gate and Assurance Plane add mandate operations, integrations, evidence operations,
re-performance, support, and service levels around the open protocol. The customer retains control
of authority, trust roots, credentials, policy, and portable evidence.

---

## The standard

EMILIA Protocol is open and Apache-2.0. Its standards work is published as a
portfolio of individual Internet-Drafts. A published Internet-Draft is not an
RFC, an adopted working-group item, or IETF endorsement; Datatracker is
authoritative for revision and status.

### One consequence-boundary surface

The current published
[AEB-07](standards/posted/draft-schrock-action-evidence-boundary-07.xml),
posted on 2026-09-25 as an individual Internet-Draft and not adopted, makes AEB
the composition point after a native decision. OAuth, AuthZEN, COAZ, AP2, and
local systems keep ownership of their credentials, operation mappings, and
authorization decisions. AIMS (`draft-ietf-wimse-aims`) is an Informational
WIMSE working-group document that profiles existing standards such as WIMSE
and OAuth; it does not itself issue credentials or decisions. AEB applies the
native decision at the protected provider boundary: it binds the final action
when needed, derives one native replay identity per grant, reserves before
provider entry, refuses a second attempt at the same action while an earlier
one is in flight or uncertain, and keeps an uncertain result locked until
authenticated reconciliation.

[CAID-02](standards/posted/draft-schrock-canonical-action-identifier-02.xml)
is used when independently encoded representations must be compared. It is not
a mandatory second mapping when the consequence-owning PEP already derives and
enforces a current decision over the final operation.
[AEC-06](standards/staged/NEXT-AEC-06/UPLOAD-THIS/draft-schrock-ep-authorization-evidence-chain-06.xml)
is used when the relying party requires several evidence legs. Authorization
Receipts, Human Authorization Binding, and Authority Introduction remain
available profiles for deployments that need them; they are not prerequisites
for every AEB integration. Architecture-03 remains the navigation document.

[The consequence-admission guide](docs/protocol/consequence-admission.md) states
the implementation boundary and the cases where AEB is unnecessary.
The [direct native handoff profile](docs/protocol/aeb-native-authorization-handoff-v1.md)
is a repository implementation profile that shows how an existing permit
reaches Gate without a second CAID or AEC layer. AEB-07 specifies what such a
gateway handoff attests and how the boundary verifies it, but leaves the
encoding to deployment pins; it cites a pinned snapshot of this profile as one
informative reference encoding. The exact submitted -07 bytes and their
publication record are retained in
[`standards/staged/NEXT-AEB-07`](standards/staged/NEXT-AEB-07).

The complete active portfolio remains 24 Datatracker records: 20 sole-authored
records and four coauthored records, each with its own scope and revision
history. See the [standards guide](standards/README.md),
[portfolio](standards/PORTFOLIO.md), and machine-readable
[status inventory](standards/STATUS.json).

| | |
|---|---|
| **IETF Internet-Drafts** | Current local snapshot paths: [status inventory](standards/STATUS.json) · sole-authored [posted inventory](standards/posted/README.md) · authoritative live status: [IETF Datatracker](https://datatracker.ietf.org/) |
| **Cross-language verifiers** | JavaScript · Python · Go — all three proven to agree on adversarial conformance vectors, every push (`npm run conformance`). A consistency check across one team's ports, not clean-room independent implementations. Separately, an externally authored from-spec Rust implementation ([source public](https://github.com/jdieselny/ecr-wg/tree/main/rust/ep-cleanroom-verifier)) passes the pinned 16-suite/164-vector bundle and the pinned 359-case hostility campaign under an evaluator-controlled rebuild from an immutable source tree. Its checked-in construction evidence remains implementer-signed, not third-party-attested ([signed statement](examples/external-verification/statements/rust-cleanroom/)); strict clean-room acceptance waits for the corrected third-party-attested manifest and independently pinned attestor key. |
| **Formal-model evidence** | 26 bounded TLA+ safety properties held in their configured state spaces; this is not implementation refinement or an unbounded proof · 35 Alloy facts, 32 assertions across four models · two composed symbolic Dolev-Yao models covering challenge, CAID, two approvals, issuer and authority pins, registry view, revocation, consumption, execution, and six dedicated claim boundaries. Twenty Tamarin lemmas verify — 17 all-traces obligations and 3 exists-trace witnesses; eight deliberately weakened variants produce concrete attack traces when load-bearing checks are removed ([formal/tamarin/](formal/tamarin/)). |
| **MCP distribution** | npm package `@emilia-protocol/mcp-server` · official Registry publication is tracked separately in [MCP-REGISTRY.md](docs/MCP-REGISTRY.md); aggregator listings are not inferred from either state |
| **License** | Apache-2.0 |

Three same-team reference ports (JS / Python / Go) agree across all 21 suites and 340 vectors. Separately, an externally authored Rust implementation rebuilt from a pinned public source tree passes the pinned 16-suite/164-vector clean-room bundle and a 359-case hostility campaign, re-run in its own CI lane on every change. The newer AEC acceptance and four-outcome resolution suites are not attributed to Rust. That is external interoperability evidence, not strict clean-room construction acceptance; the aggregate CI case records the strict acceptance count as zero pending independent attestation. See [CONFORMANCE.md](CONFORMANCE.md), or verify a receipt yourself at [emiliaprotocol.ai/verify](https://www.emiliaprotocol.ai/verify).

---

## The authority stack

| Layer | What it does |
|---|---|
| **Mandate** | Defines mission, limits, evidence, expiry, delegation, and exception rules. |
| **CAID / exact action** | Compares material meaning when authorization and execution use independently encoded representations; it does not authorize. |
| **AEC** | When required, evaluates whether independently verified and matched evidence satisfies the relying party's multi-leg requirement; it does not authorize. |
| **AEB / Gate** | Applies the native or local authorization decision at the consequence boundary, reserves the covered authority, and controls provider entry. |
| **Outcome evidence** | Keeps invocation, provider response, observed effect, and uncertainty distinct. |

---

## Proof points

| Metric | Value |
|---|---|
| Automated test cases | 10,700+ across 650+ files; all platform-applicable cases must pass |
| TLA+ safety properties | 26 bounded invariants held in the configured state space; not an implementation-refinement or unbounded proof — see [PROOF_STATUS.md](formal/PROOF_STATUS.md) |
| Alloy relational assertions | 35 facts + 32 assertions across four models — verified in CI |
| Red-team cases cataloged | 86 — [RED_TEAM_CASES.md](docs/conformance/RED_TEAM_CASES.md) |
| Release security status | Repository security checks pass; every Strix finding on the audited changes is remediated with regression coverage and its review thread resolved |
| Conformance (7/7) | `node conformance/ep-conformance-test.js https://www.emiliaprotocol.ai` |
| Cross-language conformance | 340 vectors · 21 suites: receipts · device signoffs · four-outcome resolution · multi-party quorum · revocation · Outcome Binding (semantic + real-crypto) · Authority Document/Proof issuer join · time-attestation · trust-receipt (x2 profiles) · provenance · evidence-record · canonicalization · boundary · AEC acceptance · currency · initiator-attestation · consumption-proof · witness · timestamp-proof (RFC 3161). JS / Python / Go verifiers agree (`node conformance/run.mjs`). The external Rust baseline remains 164 vectors / 16 suites. See [CONFORMANCE.md](CONFORMANCE.md). |
| Handshake create p95 | 575ms at 50 VUs — [PERFORMANCE_PROOF.md](docs/operations/PERFORMANCE_PROOF.md) |

## Cryptographic longevity (with explicit deployment boundaries)

Evidence meant to be verified years later must outlive the algorithms it was
signed under. EP ships four bounded capabilities for that, each with an exact
boundary that is part of the claim:

- **Hybrid signatures (EP-RECEIPT-HYBRID-v1).** Ed25519 and ML-DSA-65 over the same
  canonical bytes, with the required algorithm set committed into the signed
  bytes so stripping a leg breaks the surviving signature. The capability is
  opt-in at deployment; once an approved dual signer is registered and policy
  permits its PQ leg, an unpinned Gate posture resolves to dual issuance by
  default. Otherwise it stays classical-only with a named reason. v1 verifiers
  refuse hybrid receipts cleanly rather than accepting one leg. The external
  signer contract and AWS KMS adapter are implemented, but no live AWS signing
  call, production key, relying-party verification, or ML-DSA FIPS validation
  is claimed. See `conformance/hybrid-receipts/` and `lib/pq-custody-aws-kms.ts`.
- **SCITT Signed Statement profile (EP-SCITT-STATEMENT-v1).** A complete
  RFC 9943 Signed Statement shape for EP receipts, including the CWT Claims
  protected header. Boundary: no Transparency Service has accepted an
  EP statement; external registration is a separate, gated step and none has
  been performed. See [EP-RECEIPT-SCITT-PROFILE.md](docs/EP-RECEIPT-SCITT-PROFILE.md).
- **Re-attestation (EP-EVIDENCE-REATTESTATION-v1).** Evidence signed under an
  aging algorithm can be re-anchored under a current one before the old one
  weakens. Boundary: re-attestation must precede compromise; it cannot repair
  evidence after the fact.
- **FIPS deployment mode (EP-FIPS-MODE-v1).** Runs classical operations
  through an operator-supplied FIPS 140-3 validated provider, with the
  ML-DSA path gated behind an explicit unvalidated-implementation
  acknowledgment. Boundary: this earns "FIPS-based algorithms, with a
  validated-provider deployment mode" and depends on the operator's provider
  and declared certificate boundary; it is not a blanket compliance claim,
  and nothing here is FIPS validated. See [FIPS-MODE.md](docs/deployment/FIPS-MODE.md).

The stack-wide hybrid program (every internal signature surface) is mapped in
[pq-hybrid-program.md](docs/protocol/pq-hybrid-program.md) and is not
complete; until it is, no blanket claim about the whole stack is made.

---

## Core protocol objects

| Object | What it is |
|---|---|
| **Authority program / bounded capability** | A finite mandate with explicit scope, budget or units, expiry, delegation, and consumption rules. |
| **CAID** | A canonical identifier for one material action under a named mapping profile; matching is not authorization. |
| **Evidence requirement and AEC result** | The relying party's pinned rule and its `SATISFIED`, `UNSATISFIED`, or `INDETERMINATE` evaluation. |
| **AEB admission and custody record** | The executor-side record of authorization, reservation, provider entry, and reconciliation state. |
| **Authorization and outcome evidence** | Portable native or EP artifacts that retain their exact issuer, scope, and claim boundary. |

---

## Quickstart

1. Install the exact local guard runtime, then run `npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action sendWire --apply --verify`, replacing `sendWire` with one exact declared consequential tool.
2. Review the generated Authority Map, action manifest, material fields, selected boundary, and named blind spots.
3. Run the separate `--reviewed --crossing-profile <launch-profile>` command to create the owner-only handoff and unsealed Lab workspace from those unchanged bytes.
4. Install Gate on the path that owns the provider credential and durable consumption state.
5. Define the operating mandate and any fresh-human or quorum exception rules.
6. Run the refusal, exact-action, replay, timeout, and reconciliation cases before enabling enforcement.

**[90-second demo](https://www.emiliaprotocol.ai/mcp)** · **[Quickstart](https://www.emiliaprotocol.ai/quickstart)** · **[Agent walkthrough](https://www.emiliaprotocol.ai/use-cases/ai-agent)** · **[IETF Draft](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/)** · **[Discord](https://discord.gg/cEhbzXkhW)**

---

## What EP is — and is not

EMILIA is authority infrastructure for autonomous work, not an identity system, wallet, reputation
score, settlement rail, or universal policy engine.

- **Is**: a control plane for finite operating mandates, exact-action verification, durable
  admission state, truthful uncertainty, and portable evidence on covered executor paths.
- **Is not**: a replacement for OAuth/OIDC, workload identity, or policy engines. Those remain native
  inputs under the relying party's pins.
- **Is not**: a requirement that a human approve every action. A mandate may permit automatic work
  inside finite bounds and demand fresh authority only at the edge.
- **Is not**: proof that an admitted action executed successfully or caused the intended effect.
- **Is not**: proprietary protocol control. The core is Apache-2.0 and the Internet-Drafts are
  individual submissions, not RFCs or IETF endorsement.

See [CONFORMANCE.md](CONFORMANCE.md) · [SECURITY.md](SECURITY.md) · [THREAT_MODEL.md](THREAT_MODEL.md) · [GOVERNANCE.md](GOVERNANCE.md) · [Neutrality Covenant](docs/NEUTRALITY-COVENANT.md)
