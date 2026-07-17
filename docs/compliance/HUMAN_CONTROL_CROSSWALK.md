# Human-Control Compliance Crosswalk

**How EMILIA authorization evidence can support assessments under DoD Directive
3000.09, EU AI Act Article 14, and NIST AI RMF.**

Scope note: EMILIA provides the **evidence** that human oversight occurred at a defined
scope, currency, and authority. It is a *necessary, not sufficient* control — it does not
establish comprehension, lawfulness, or freedom from coercion. This crosswalk maps the
**evidentiary** requirements only. See [PIP-013](../../PIPs/PIP-013-human-oversight-profile.md).

## DoD Directive 3000.09 (Autonomy in Weapon Systems)

| 3000.09 requirement (paraphrased) | EMILIA evidence |
|---|---|
| "Appropriate levels of human judgment over the use of force" | A receipt can establish that one or more pinned approver keys authorized the exact action / engagement envelope; natural-person attribution depends on enrollment and authenticator assurance |
| Authorization by trained, authorized personnel | Class-A device-bound signoff binds the authorization to a specific enrolled approver, not a shared login |
| Operation within a defined envelope / ROE | `authorization_scope` (effect class, target set, geofence, window) + signed ROE/policy reference; PEP fails closed outside scope |
| Human ability to terminate engagement | Revocation + continuous evaluation; a revoked authorization fails closed |
| Auditability / traceability of decisions | Tamper-evident, non-repudiable, third-party-verifiable without trusting the operator |
| Two-person / multi-party authorization where required | Quorum (m-of-n distinct humans, ordered chain) |

## EU AI Act — Article 14 (Human Oversight)

> **Scope caveat (read first).** The EU AI Act (Reg. 2024/1689, Art. 2(3)) **excludes
> AI systems used exclusively for military, defense, or national-security purposes.**
> Use this mapping for **civilian high-risk autonomy** (critical infrastructure,
> biometrics, justice, employment, essential services) — it is a strong *civilian*
> tailwind, **not** a defense compliance hook. For defense systems, **DoD Directive
> 3000.09** is the governing instrument (above).

| Art. 14 provision | EMILIA evidence |
|---|---|
| 14(1) high-risk AI "effectively overseen by natural persons" | A receipt can establish that an enrolled approver key authorized the exact action; a regulator can reproduce that check offline using the deployment's pinned trust inputs |
| 14(4)(a) oversight person can understand capacities/limits & monitor | A controlled approval surface can display the material action fields and bind an attestation to the signature; this is evidence about the surface, not proof of comprehension |
| 14(4)(d) ability to "decide not to use" or disregard output | A deployment can configure the Gate to refuse a covered action when required authorization evidence is absent or invalid |
| 14(4)(e) ability to intervene/interrupt ("stop button") | Revocation plus continuous evaluation can halt future actions under an authorized envelope; deployment design determines whether and how an in-flight effect can be stopped |
| Record-keeping / logging (Art. 12) interplay | Receipts are portable, verifiable evidence records, not operator-mutable logs |

## NIST AI RMF (1.0)

| RMF function | EMILIA evidence |
|---|---|
| GOVERN — accountability & oversight structures documented | Receipts are the auditable record of *who* authorized *what*, under *which* policy |
| MAP — context & authorities established | `authorization_scope` + `roe_ref`/`policy_hash` bind authority to context |
| MEASURE — oversight is verifiable, not asserted | Third-party offline verification; quorum, freshness, revocation are checkable |
| MANAGE — response & decommissioning | Revocation/continuous-evaluation provides the halt + change-of-authority trail |

## Mapping to EMILIA artifacts

- Core receipt + Class-A signoff: PIP-001, PIP-003
- Two-person rule: EP-QUORUM
- Rules-of-engagement scoping: delegation constraints + `roe_ref` (PIP-013 §2)
- Currency of authorization: validity window + `observed_at` freshness (PIP-008 §2.1)
- Halt / revoke: PIP-011 (revocation & continuous evaluation)
- "Human saw the real action": PIP-010 (WYSIWYS)
- Offline / air-gap verification: Core §6.3 verifier + air-gap installer

*Not legal advice. A compliance mapping for program and counsel review; deployment in
defense/classified contexts is subject to applicable export-control and security regimes.*
