# Why EP

Identity is not authorization. Authentication is not action control.

Most damaging fraud and abuse occurs inside approved-looking workflows: authenticated users, valid sessions, legitimate access, weak action-level constraints.

EP closes that gap by enforcing trust before high-risk action. It binds actor identity, authority chain, action parameters, policy version and hash, nonce, expiry, and one-time consumption into a single replay-resistant authorization flow.

---

**How it works.** Five endpoints. One lifecycle.

| Endpoint | Function |
|---|---|
| `POST /api/handshake` | Bind actor + action + policy into a canonical hash |
| `GET /api/handshake/{id}` | Query status at any point in the lifecycle |
| `POST /api/handshake/{id}/present` | Submit authority credentials for verification |
| `POST /api/handshake/{id}/verify` | Verify all invariants, consume the binding exactly once |
| `POST /api/handshake/{id}/revoke` | Revoke at any lifecycle stage |

Binding hash: SHA-256 over action type, resource, policy (version + hash), parties, payload, nonce, and expiry. Modify any field and the hash changes. Replay a consumed binding and it fails. Present an expired or revoked authority and it fails. Weaken the policy between initiation and verification and it fails. There is no fallback, no default-allow, no bypass path.

---

**Proof.** EP is formally verified against 10 security invariants and tested by 1,172 automated checks across 48 test files (JS + Python conformance, adversarial, end-to-end). The canonical write path (`lib/protocol-write.js`) is the sole entry point for all trust-changing operations, enforced by three-layer write discipline: runtime proxy, CI import guard, CI pattern guard. Append-only event tables with database triggers preventing UPDATE and DELETE. One-time consumption enforced by database-level conditional update and unique constraint.

---

**Integration.** Five REST endpoints, standard JSON payloads. No SDK required (SDKs available in TypeScript and Python for convenience). No key management ceremony. No PKI deployment. The handshake executes within existing approval workflows -- zero UX change for legitimate operators. Typical integration: 30 minutes to first handshake, 1--2 weeks to production for a single workflow.

---

**Who it is for.**

| Vertical | Use Case | Mode |
|---|---|---|
| Government | Payment destination change, benefits redirect, delegated approvals | `basic` or `delegated` |
| Financial services | Vendor remittance change, wire transfer authorization, treasury approvals | `mutual` (dual-party) |
| AI agent governance | Agent-initiated high-value actions with principal delegation and scope constraints | `delegated` |

Same protocol. Same endpoints. Same invariants. Different policies.

---

**The numbers.**

- BEC/payment redirect fraud: **$2.9 billion** in reported losses in 2023 (FBI IC3)
- Government improper payments: **$236 billion** in FY2023 (GAO)
- Average BEC loss per incident: **$125,000** (FBI IC3)
- EP handshake latency: **< 50ms**
- EP test coverage: **1,172 tests**, 48 test files, cross-language conformance
- Integration surface: **5 endpoints**, 30-minute quickstart

---

Open source. Apache 2.0. Protocol Standard v1.0 (17 sections). Constitutional principle: trust must never be more powerful than appeal.

*EMILIA Protocol -- emiliaprotocol.ai -- github.com/emiliaprotocol/emilia-protocol*
