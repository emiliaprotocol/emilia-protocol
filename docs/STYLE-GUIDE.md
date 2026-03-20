# EP Style Guide — Canonical Vocabulary

## Use these everywhere

- **EMILIA Protocol (EP)**
- **Portable trust for machine counterparties and third-party software**
- **Trust evaluation and appeals for counterparties, software, and machine actors**
- **Trust profiles, not scores. Policies, not thresholds. Appeals, not black boxes.**
- **Install preflight** (for software trust)
- **Compatibility score** or **legacy compatibility score** — only when referring to the numeric field, always labeled legacy
- **Constitutional principle: trust must never be more powerful than appeal.**
- **Handshake** — transaction-scoped identity verification and disclosure ceremony

## Retire from active docs

| Retired term | Replace with |
|---|---|
| trust attestation | trust evaluation, trust evaluation and appeals |
| reputation system | trust system, trust protocol |
| score layer | trust protocol |
| trust layer | trust protocol |
| agentic commerce (as primary identity) | machine counterparties and software, or machine-mediated systems |
| agent_satisfaction (public-facing) | behavioral signal, behavioral outcome |
| check score | view trust profile, evaluate trust, run install preflight |
| the scorer | the submitter, the evaluating agent |
| scored / gets scored | evaluated, trust-profiled |
| bad score / recover from a bad score | degraded trust, rebuild trust |
| zero-knowledge proof (public-facing) | commitment proof, privacy-preserving proof | The implementation uses HMAC-SHA256 commitments, not cryptographic ZK circuits. "ZK" is acceptable only in internal code references (e.g., function names, file names) for backward compatibility. |

## When "score" is acceptable

- In JSON field names: `compat_score`, `emilia_score`, `composite_score`
- In code/SQL: `compute_emilia_score()`, `submitter_score`
- In explicit legacy context: "compatibility score (legacy)"
- In the triad: "Trust profiles, not scores"
- In technical spec tables documenting field weights

## Deprecated terms in new decision paths

| Deprecated usage | Replace with | Context |
|---|---|---|
| "trust score" as a primary decision input | "trust profile" or "policy evaluation" | Raw score MUST NOT gate trust-critical decisions. See PROTOCOL-STANDARD.md §20. |
| `emilia_score` in new decision paths | "policy result" or "confidence" | New code MUST use `evaluateTrustPolicy()` or confidence state, not raw score. |
| `min_score` as a trust gate | `trust_policy` + `min_confidence` | Score thresholds are legacy sort keys. Policy evaluation is the canonical decision mechanism. |
| "score > N means trusted" | "policy evaluation passed" or "confidence is emerging/confident" | Single-number thresholds destroy information. Use multi-dimensional profiles. |

## Document classification

| Status | Meaning |
|---|---|
| **Canonical** | Reflects current protocol identity. Must use approved vocabulary. |
| **Archived** | Historical. Lives in `docs/archive/`. Banner at top. |
