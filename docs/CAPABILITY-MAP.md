# EMILIA Protocol — Capability Map

**The canonical "what we actually have."** Last audited: 2026-06-22.

Purpose: a single source of truth for what EP can do, where it lives in code, and where it is surfaced publicly — so the website, deck, and content stay reconciled to the real product and we never again under-represent it. **Rule: before shipping website / deck / content claims, reconcile against this map. If a capability isn't listed, it isn't real; if it's listed and not surfaced, that's a surface bug to fix.**

| Capability | Status | Code | Public surface |
|---|---|---|---|
| Offline verification (receipts, Merkle anchor) | shipped | `packages/verify`, `packages/python-verify`, `packages/go-verify` | `/verify`, `/auditors`, npm |
| Verifier CLI (auto-detects receipt / bundle / proof / signoff / quorum) | shipped | `packages/verify/cli.js` | `npx @emilia-protocol/verify` |
| Multi-party quorum (M-of-N / ordered, two-person rule) | shipped + E2E-verified | `lib/signoff/quorum-session.js`, `packages/verify/quorum.js`, `app/api/v1/trust-receipts/[receiptId]/consume` | `/quorum`, `/try/multi-party` |
| Quorum: distinct device keys + strong cryptographic ordering chain (`ordered_chain`, `prev_context_hash`) | shipped (JS/Python/Go agree; 11 conformance vectors) | `packages/verify/quorum.js` + `python-verify`/`go-verify`, `conformance/vectors/quorum.v1.json` | `/quorum` |
| No-symmetric-key invariant on the verification trust path (CI-enforced) | shipped | `packages/verify/no-symmetric.test.js` | `/spec` §11.10 |
| One-command crash test + Auditor Workpaper (GAGAS-mapped) | shipped | `packages/crash-test` | `/quorum`, homepage; `npx @emilia-protocol/crash-test` |
| Observe-mode "accountability-gap" report (N-of-M would-have-held) | shipped | `app/api/pilot/sandbox/report/route.js`, `app/pilot/sandbox` | `/govguard`, `/pilot/sandbox` |
| Class-A WebAuthn device signoff (biometric, user-verification-gated) | shipped | `app/api/v1/approvers/webauthn/*`, `packages/verify` | `/try` |
| Enrollment + SSO (SAML / OIDC); second-party attestation on enroll | shipped | `app/api/sso/*`, `app/api/v1/approvers/webauthn/register-*` | — |
| Revocation (portable offline statement + server-state) | shipped in the published verifier | `lib/revocation/`, `lib/signoff/revoke.js`, `packages/verify/revocation.js`, `docs/EP-REVOCATION-SPEC.md` | `npx @emilia-protocol/verify revocation …` |
| Federation / cross-operator verification (PIP-006) | mechanism shipped; **both operators EMILIA-run** | `packages/verify/federation.js`, `conformance/operator2/` | `docs/conformance/FEDERATION-PROOF.md` |
| Compliance mappings — NIST AI RMF (38/38), EU AI Act, SOC 2, **GAGAS / GAO Green Book / Uniform Guidance** | shipped (docs + PDFs) | `docs/compliance/` | `/auditors`, `/eu-ai-act`, `/compliance/*.pdf` |
| Standards — I-D authorization-receipts (-01) + quorum (-00); Zenodo DOI | posted | `standards/` | `/spec`, datatracker |
| Formal models (26 TLA+ theorems / Alloy) + conformance vectors | shipped, run in CI | `formal/`, `conformance/vectors/` | `/spec`, repo |
| MCP-native gating + guards (openai / mcp / langchain / require-receipt) | shipped | `packages/openai-guard`, `packages/mcp-guard`, `packages/langchain`, `packages/require-receipt`, `mcp-server/` | `/mcp` |

## Known gaps (per the 2026-06-21 audit, for the government-oversight wedge)

| Gap | Bucket |
|---|---|
| GAGAS / Green Book / Uniform Guidance mapping | **CLOSED 2026-06-21** (`docs/compliance/GAGAS-GREENBOOK-UNIFORM-GUIDANCE-MAPPING.md` + `/compliance/emilia-gagas-greenbook-government.pdf`) |
| Independent (non-EMILIA) operator verifies a live receipt | **The one real structural gap** — a milestone needing an external party, not a feature. Engineer via a survey co-author / design partner. |
| Revocation freshness / absence-of-revocation service (CRL/OCSP-style) | Later — deferred to relying party per spec |
| Workpaper export API at scale | Build with first customer; first pilot uses crash-test / observe-report |
| Auditor-specific observe-report shaping; SCIM; PIV/CAC/Login.gov | Profile specced (`docs/EP-IDENTITY-BINDING-PROFILE.md`); implement WITH the first auditor/customer |

## The honest headline
On the protocol/cryptographic core (offline verification, multi-party quorum, formal proofs, tri-language conformance) EP is best-in-class for the government-oversight wedge. The product was never the blocker; the binding constraint is the **reliance event** — an external auditor relying on a receipt in a live review.
