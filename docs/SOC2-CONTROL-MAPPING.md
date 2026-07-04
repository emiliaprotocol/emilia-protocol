# EMILIA Gate — SOC 2 Trust Services Criteria control mapping

*Mapping version: `EP-GATE-SOC2-MAPPING-v1` · 2026-07 · maps to the AICPA 2017 Trust Services
Criteria (with revised points of focus, 2022)*

> **What this document is — and is not.**
> This mapping shows which SOC 2 Trust Services Criteria the mechanisms implemented in
> `@emilia-protocol/gate` can **support** when a deploying organization designs its control
> environment. It exists so an auditor, or a client's compliance team, can slot Gate mechanisms
> into an existing control matrix with accurate citations to where each mechanism lives and what
> evidence it emits.
>
> It is **not** an attestation, a certification, or a claim that any system is "SOC 2 compliant
> out of the box." EMILIA Protocol is not an auditor. SOC 2 scoping, control design, control
> operation, and the description of the system belong to the **service organization**; the
> examination and opinion belong to its **CPA firm**. A mechanism listed here contributes to a
> control only if the deploying organization actually routes the relevant actions through the
> Gate, retains the evidence, and operates the surrounding processes (identity proofing, incident
> response, backup, recovery) that the Gate deliberately does not own. Every row carries an
> **honest boundary** column stating what the mechanism does *not* cover — read it before citing
> the row.

## How to read the tables

| Column | Meaning |
|---|---|
| **TSC criterion** | The 2017 TSC criterion (CC = Common Criteria, PI = Processing Integrity, A = Availability) the mechanism can support. Support means "relevant to points of focus under this criterion," not "satisfies the criterion." |
| **Gate mechanism** | What the code actually does, in the code's own terms. |
| **Where implemented** | Repo-relative file/module. All paths verified to exist as of this mapping's date. |
| **Evidence artifact an auditor can pull** | A concrete, exportable artifact: a report format, a log export, or a runnable conformance result. |
| **Honest boundary** | What the mechanism does not claim, and what remains the deploying organization's responsibility. |

Terminology used below (from `packages/gate/index.js`): a **guarded action** runs only with a
receipt that is *valid* (Ed25519 over canonical JSON, pinned issuer), *in-scope* (bound to the
exact action), *sufficiently assured* (cryptographically verified tier: `software` / `class_a`
WebAuthn device signoff / `quorum` M-of-N distinct humans), *fresh*, and *unused* (one-time
consumption). Otherwise it is refused with a machine-readable Receipt-Required challenge
(HTTP 428), and every decision — allow or deny — is appended to a tamper-evident evidence log.

---

## CC6 — Logical and physical access controls

| TSC criterion | Gate mechanism | Where implemented | Evidence artifact an auditor can pull | Honest boundary |
|---|---|---|---|---|
| **CC6.1** (logical access security over protected assets) | Deny-by-default receipt gating: a guarded consequential action executes only with a valid, in-scope, sufficiently assured, fresh, unused receipt; everything else is refused with a 428 challenge. | `packages/gate/index.js` (core `check`/`guard`/`run`); action families declared in `packages/gate/action-packs.js` | Evidence-log export (`evidence.all()` + `verify()` chain result); EG-1 conformance run (`packages/gate/eg1-conformance.js`, 8 refuse/allow checks) demonstrating enforcement rather than claim | The Gate is a policy-enforcement point, explicitly **not** authentication ("who are you") and **not** permissions ("are you allowed here") — the deployer's IAM stack still owns those. Only actions routed through the Gate are covered. |
| **CC6.1** (restrict access via credentials/keys) | Issuer key registry: rotation windows (`not_before`/`not_after`) and hard revocation — a revoked issuer key signs nothing the Gate accepts, regardless of claimed issuance time. Fail closed. | `packages/gate/key-registry.js` | Registry entry list (kid, window, `revoked_at`); evidence-log entries showing receipt refusals after revocation; `packages/gate/custody.test.js` results | Key custody (where private keys live, HSM/KMS usage) and the key-issuance ceremony are the deployer's. The registry governs the **verifier's** trust set only. |
| **CC6.2** (register/authorize users before credential issuance; remove when no longer authorized) | Signer-roster sync from an enterprise IdP (`EP-GATE-ROSTER-v1`): only `active === true` users' keys pin; a user absent from the import has every previously pinned key revoked on the next sync; contested kids pin nothing; an import that would leave zero active signers requires an explicit `allowEmpty` acknowledgment. | `packages/gate/roster.js` (reconciling against `packages/gate/key-registry.js`) | Versioned roster artifact with `integrity_warnings`; `diffRoster` output; the exact `revoked` list returned by `applyRosterToRegistry`; `packages/gate/roster.test.js` results | "WHO may approve is an HR fact, not a crypto fact" — the roster is only as correct as the IdP export, and identity proofing / joiner-mover-leaver process is the IdP's and the deployer's. Revocation takes effect **on the next sync**, so sync cadence is a deployer control parameter. |
| **CC6.3** (role-based access; segregation of duties) | Assurance-tier enforcement per action: the manifest pins each action family to a required tier, and the credited tier is **cryptographically verified**, never read from self-asserted payload fields — `class_a` requires a valid WebAuthn device signoff; `quorum` requires a valid `EP-QUORUM-v1` (distinct humans + distinct keys + threshold + per-signer assertions). Quorum is the cryptographic two-person rule. | Tier enforcement in `packages/gate/index.js`; per-signer verification in `packages/verify/index.js` and `packages/verify/quorum.js`; per-action tiers in `packages/gate/action-packs.js` | Evidence-log entries carrying the verified tier per allow; tier distribution tables in the Art. 14 pack and underwriter attestation (below); `packages/gate/redteam.test.js` (fabricated-quorum / self-asserted-tier refusals) | Quorum proves M distinct **keys** with per-signer assertions signed; mapping keys to genuinely distinct humans depends on the deployer's roster discipline (CC6.2 row). Role design — *which* actions need *which* tier — is the deployer's manifest decision. |
| **CC6.1 / CC6.6** (protect against unauthorized reuse of credentials) | One-time consumption (replay defense): a receipt authorizes one action, once; the Gate consumes the receipt id on first use and refuses every later presentation; `reserve`/`commit`/`release` blocks concurrent replay while an action is in flight. | `packages/gate/store.js` (`MemoryConsumptionStore`, `createDurableConsumptionStore`) | `replay_refused` evidence-log entries; EG-1 check 5 (replay of the same receipt refused); `packages/gate/gate.test.js` and `packages/gate/custody.test.js` results | Fleet-safe replay defense requires the deployer to supply a durable backend with an **atomic** insert-if-absent (Redis `SET NX`, Postgres `ON CONFLICT DO NOTHING`); the in-memory default protects a single process only. |

## CC7 — System operations

| TSC criterion | Gate mechanism | Where implemented | Evidence artifact an auditor can pull | Honest boundary |
|---|---|---|---|---|
| **CC7.2** (monitor system components; capture security events) | Tamper-evident evidence log: every decision — allow or deny — appends a hash-chained record over canonical JSON; removing or altering any record breaks the chain and `verify()` catches it. In `strict` mode the log fails **closed**: if the durable sink write fails, the Gate never authorizes an action it cannot durably account for. | `packages/gate/evidence.js` | Full log export (`evidence.all()`); chain-verification result (`verify()` → ok/length/head, or the exact seq and reason of the break) | Default sink is in-memory; durability across restarts requires a deployer-supplied sink. The chain proves **integrity of what was recorded**, not completeness of what the deployer chose to route through the Gate. |
| **CC7.2** (monitoring feeds / SOC visibility) | SIEM export of the evidence log (`EP-GATE-SIEM-EXPORT-v1`): static offline mappings to OCSF class 6003 (API Activity) and CEF; deterministic — a fixed entry maps to a byte-identical event on every host. A malformed entry never throws: it becomes a structured error event (`malformed_evidence_entry`) so corruption is visible in the SIEM, not silently dropped. | `packages/gate/siem.js` | Exported OCSF/CEF event stream in the deployer's Splunk/Sentinel/Datadog; `packages/gate/siem.test.js` results | Export is observability, not enforcement — detection rules, alerting, and response run in the deployer's SOC. The **evidence log**, not the SIEM copy, is the enforcement record. |
| **CC7.3** (evaluate security events) | Machine-readable refusal reasons mapped to named failing predicates (`receipt_required`, `replay_refused`, `assurance_too_low`, `execution_binding_failed`, `evidence_log_failed`, …); unmapped reasons surface as `unmapped:<reason>`, visible, never genericized away. | Reason emission in `packages/gate/index.js`; predicate mapping in `packages/gate/reports/art14.js` (`failingPredicate`) | Interventions/refusals tables in the Art. 14 evidence pack; the raw reason field on every deny entry in the evidence log | The Gate classifies **why it refused**; deciding whether a refusal pattern is a security incident, and responding to it, is the deployer's CC7.3–CC7.4 process. |
| **CC7.4 / CC7.5** (period review of control operation) | Period reports computed purely from the evidence log: (a) underwriter control attestation (`EP-GATE-UNDERWRITER-ATTESTATION-v1`) — evidence that a deny-by-default authorization control was in force and operating over a period; (b) EU AI Act Art. 14 evidence pack (`EP-GATE-ART14-PACK-v1`) — who authorized what at which verified tier, which refusals fired, which replay/tamper attempts were blocked, and the coverage ratio of guarded decisions. Both exclude entries they cannot verify and surface them as `integrity_warnings`; both carry mandatory honesty notices (the Art. 14 renderer refuses a pack whose notice was altered or removed). | `packages/gate/reports/underwriter.js`, `packages/gate/reports/art14.js` | The two report JSON artifacts themselves (deterministic: same entries + options → identical output); `packages/gate/reports/underwriter.test.js`, `packages/gate/reports/art14.test.js` results | Both reports attest **control operation only** — never the business correctness of any authorized action. Principal identities are as pinned by the deployer, not independently verified. Neither is an insurance or compliance document until adopted by the relevant carrier/assessor. |
| **CC7.2** (operational metrics) | Usage metering (`EP-GATE-USAGE-v1`): deterministic counts of protected actions (allows **and** denies both consume enforcement) over an explicit half-open period window; malformed entries surfaced in `integrity_warnings`, never silently dropped; statements are content-hashed (sha256) for reconciliation. | `packages/gate/metering.js` | Usage statement JSON (sorted keys + content hash); `packages/gate/metering.test.js` results | Statements are **unsigned** — the deployer signs; the content hash binds that signature to exactly these numbers. Metering is a billing/ops metric, not a security monitor. |
| **CC7.x supporting** (audit-record lifecycle) | Retention policy over the evidence log: classify records HOT/COLD/EXPIRED against configurable horizons (`EP_AUDIT_HOT_DAYS`/`EP_AUDIT_COLD_DAYS`, default cold horizon 6y) with a legal hold that pins records so they are never expired. | `packages/gate/retention.js` | `classifyRetention` buckets + summary; `buildRetentionExport` output | The Gate never deletes anything itself — it tells the operator what is **eligible**. Executing retention/disposal, and defending the legal-hold list, is the deployer's records program. |

## CC8 — Change management

| TSC criterion | Gate mechanism | Where implemented | Evidence artifact an auditor can pull | Honest boundary |
|---|---|---|---|---|
| **CC8.1** (authorize and approve changes — production deploys) | Default high-risk action pack pins `deploy.production` to `quorum` ("the cryptographic two-person rule for hard operational cuts") with execution binding over `repo`, `commit_sha`, `environment`, `artifact_digest` — an approved deploy of one commit cannot be swapped for another. | `packages/gate/action-packs.js` (pack `production.deploy`); enforcement in `packages/gate/index.js` | Allow entries at verified `quorum` tier bound to the exact `commit_sha`/`artifact_digest`; reliance packets (`packages/gate/reliance-packet.js`) for individual deploys | Covers deploys **routed through the Gate**. An out-of-band deploy path is invisible to it — the Art. 14 pack's coverage ratio makes that boundary measurable, and closing it is the deployer's pipeline design. |
| **CC8.1** (infrastructure changes) | System-of-record adapters gate irreversible infrastructure operations: Terraform `destroy`/`state rm`/`workspace delete` (destroy plan bound by hash, so an approved small destroy cannot be swapped for a full teardown); Kubernetes namespace delete, workload delete, RBAC binding, secret delete — none reach the API server without a receipt bound to that workspace/namespace/resource. | `packages/gate/adapters/terraform.js`, `packages/gate/adapters/k8s.js` | Evidence-log entries with bound execution fields (`workspace`, `plan_hash`, `namespace`, …); adapter test results (`packages/gate/adapters/cloud.test.js`) | Adapters guard the wrapped client only; direct CLI/console access bypasses them. Guarding that bypass (IAM boundaries, break-glass) is the deployer's. |
| **CC8.1** (source-of-truth / repo changes) | GitHub adapter wraps destructive Octokit operations so the mutation never reaches GitHub without a valid, sufficiently assured, non-replayed receipt bound to that repo; success returns a reliance packet proving what was authorized and what executed. | `packages/gate/adapters/github.js` | Reliance packets per mutation; `packages/gate/adapters/github.test.js` results | Same bypass boundary as above; also does not replace code review — it gates **destructive operations**, not PR content quality. |
| **CC8.1** (configuration / privilege changes) | `permission.admin.change` pack requires `quorum` ("changes who can act next deserve stronger proof than the session that requested them"); `data.export` and bank-detail changes require `class_a` with recipient/purpose or account fields bound to the approval. | `packages/gate/action-packs.js` | Allow/deny entries per action family with verified tier and bound fields | Manifest coverage is a deployer decision: the packs are defaults, and criteria coverage exists only for the action families the deployer actually declares and routes. |

## PI1 — Processing integrity

| TSC criterion | Gate mechanism | Where implemented | Evidence artifact an auditor can pull | Honest boundary |
|---|---|---|---|---|
| **PI1.3** (processing is authorized) | Exact-action binding: a receipt is in-scope only for the exact action the manifest guards; assurance is verified, freshness enforced, consumption one-time. Refusals are fail-closed and machine-readable (HTTP 428 Receipt-Required challenge). | `packages/gate/index.js` | Evidence log (every allow shows the verified basis; every deny shows the failing predicate); EG-1 result (checks 1–6) | Authorization is proven for the **declared action fields** — the Gate cannot know about semantics it was never shown. Business appropriateness of an authorized action is not attested (underwriter/Art. 14 honesty notices repeat this). |
| **PI1.2 / PI1.3** (inputs processed as intended; no unauthorized alteration in processing) | Execution-field binding (`EP-GATE-EXECUTION-BINDING-v1`): the executor-side control that prevents "the signed claim said X, the system mutated Y" — declared `required_fields` of the observed execution must match the authorized claim (canonical-hash comparison), else refusal. | `packages/gate/execution-binding.js`; per-action `execution_binding.required_fields` in `packages/gate/action-packs.js` | `execution_binding` results inside evidence entries and reliance packets; EG-1 check 3 (execution drift refused) | Only fields listed in `required_fields` are checked. Field selection is the deployer's manifest design; an undeclared material field is unbound by construction. |
| **PI1.3** (fail-closed on inability to account) | The Gate never authorizes an action it cannot durably record: with a strict evidence sink, a failed sink write refuses the action (`evidence_log_failed`) instead of proceeding unlogged. | `packages/gate/index.js` + `packages/gate/evidence.js` (`strict` mode) | `evidence_log_failed` refusal entries; `packages/gate/gate.test.js` results | Fail-closed here trades availability for accountability by design — see A1. Non-strict (observe) mode exists and is best-effort; the deployer chooses the mode. |
| **PI1.4 / PI1.5** (outputs and stored items complete and accurate) | Deterministic, integrity-guarded derived outputs: reports and usage statements are pure functions over the log (same input → identical bytes), exclude what they cannot verify, and surface exclusions as `integrity_warnings` — a report cannot quietly understate what the log holds. Reliance packets let a third party recompute the verdict offline. | `packages/gate/reports/art14.js`, `packages/gate/reports/underwriter.js`, `packages/gate/metering.js`, `packages/gate/reliance-packet.js` | The artifacts themselves plus their `integrity_warnings` arrays; CF-1 check `evidence_verifies_offline` (`packages/gate/cf1-conformance.js`) | Completeness is relative to the log the deployer retained. A destroyed log segment is detectable (broken chain) but not reconstructable by the Gate. |

## A1 — Availability (what the Gate deliberately does NOT claim)

The Gate is deny-by-default and fail-closed. Its designed failure mode is **refusal, not
downtime tolerance**: when a dependency breaks (evidence sink, consumption store, key material),
guarded actions stop being authorized. That is a security property purchased at availability's
expense, and this section says so plainly rather than mapping around it.

| TSC criterion | Gate mechanism | Where implemented | Evidence artifact an auditor can pull | Honest boundary |
|---|---|---|---|---|
| **A1.1 / A1.2** (capacity, backup, recovery infrastructure) | **No mechanism claimed.** The Gate makes no availability, capacity, redundancy, backup, or recovery commitments. High availability of the Gate process, the durable consumption-store backend, and the evidence sink is entirely the deploying organization's infrastructure. | — (deliberately absent) | — | Do not cite the Gate in A1 rows of a control matrix. Under dependency failure the Gate refuses guarded actions (see PI1 fail-closed row); the deployer must decide whether that refusal posture is acceptable for each action family and engineer availability around it. |
| **A1.2** (supporting: licensing failure cannot take the control down) | Open-core fail-direction split: the **core gate is never bricked** — a missing, expired, tampered, or unknown-kid entitlement resolves to community tier with a machine-readable reason, and community tier always works; enterprise **features** fail closed. | `packages/gate/enterprise.js` (`EP-GATE-ENTITLEMENT-v1`) | Entitlement verdict objects (`{ valid, tier, reason }`); `packages/gate/enterprise.test.js` results | This is a liveness statement about the **licensing layer only** — it is not an SLA and does not extend to any other dependency. |
| **A1.2 / A1.3** (evidence durability and recovery) | **No mechanism claimed** beyond the interfaces: the evidence log accepts a deployer-supplied durable sink; the retention module classifies but never deletes. Backup, replication, and recovery testing of evidence storage are the deployer's. | Interfaces in `packages/gate/evidence.js`, `packages/gate/retention.js` | Chain verification after a restore (`verify()`) can demonstrate that recovered evidence is intact — that is the extent of the Gate's contribution | The Gate can prove a restored log **was not tampered with**; it cannot make the log survive. |

---

## Standing conformance evidence

Independent of any single period report, an auditor can ask the deployer to run the shipped
conformance suites against the live integration:

| Suite | What it demonstrates | Where |
|---|---|---|
| **EG-1** (8 checks) | The integration actually **enforces** the gate — refuses no-receipt, under-assured, drifted, replayed, and tampered attempts; runs valid ones; emits bound execution proof and a "rely"-verdict reliance packet. | `packages/gate/eg1-conformance.js` |
| **CF-1** (EG-1 + 3) | The category claim is honest: the consequential action is declared by policy (not only default-deny), a gate pinned to the wrong issuer key cannot be talked into authorizing, and an allowed run's evidence verifies **offline** without trusting the operator. | `packages/gate/cf1-conformance.js` |
| Package test suite | `node --test` in `packages/gate` (see `docs/CAPABILITY-MAP.md` for the current count). | `packages/gate/*.test.js`, `packages/gate/reports/*.test.js` |

## Related documents

- `docs/EMILIA-GATE-PRODUCT-BRIEF.md` — product framing of the Consequence Firewall category.
- `docs/CAPABILITY-MAP.md` — current build/ship status of every mechanism cited here.
- `packages/gate/README.md` — integration guide.

*Change control for this mapping: any edit that adds a criterion claim must add the corresponding
honest-boundary entry in the same change; a row without a boundary is not a valid
`EP-GATE-SOC2-MAPPING-v1` row.*
