# EP Outreach Emails

## General introduction

Subject: EMILIA Protocol — trust before high-risk action

Hi [Name],

EMILIA Protocol (EP) is a protocol-grade trust substrate for high-risk action enforcement.

Most systems verify who is acting. EP verifies whether this exact action should be allowed, under this exact policy, by this exact actor, right now.

EP binds:
- actor identity
- authority chain
- exact action context
- policy version and hash
- replay resistance
- one-time consumption
- immutable event traceability

When policy requires named human ownership, EP can also require Accountable Signoff before execution.

We think this is especially relevant for:
- government fraud prevention
- payment-change and treasury controls
- delegated approvals
- operator overrides
- AI / agent execution governance

If helpful, I can send the current protocol materials and a proposed pilot scope.

**Proof:**
- Independent code audit: 100/100 (2026-04-02) — all 10 categories at maximum
- 3,277 automated tests across 125 files; Stryker.js mutation testing at ≥80% kill threshold
- 20 TLA+ safety properties verified (TLC 2.19, 7,857 states, 0 errors); 32 Alloy facts + 15 assertions (Alloy 6.1.0) — both enforced in CI
- 116 red team cases documented; 31 security findings identified and remediated
- Full 7-step Accountable Signoff chain proven end-to-end under load
- 329 complete chains executed with zero correctness violations
- Zero duplicate consumptions, zero orphaned bindings, zero missing events
- All endpoints use single-roundtrip atomic RPCs; handshake create p95 87ms at 500 concurrent users
- 27 CI quality gates across 12 automated workflows, all Actions SHA-pinned for supply chain security
- MCP-native: 34 tools across the full EP surface; TypeScript and Python SDKs
- Apache 2.0, all source public, SBOM + provenance attestation on every release

Best,
[Your Name]
