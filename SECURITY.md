# Security

## Supported Versions

Security patches apply to the latest release on the `main` branch and to the latest published version of each package. Older versions are not backported.

| Component | Supported |
|---|---|
| Protocol spec (`EP-CORE-v1.0`, `EP-RECEIPT-v1`) | Current draft |
| `@emilia-protocol/verify` (npm) | 1.x |
| `@emilia-protocol/issue` (npm) | Latest |
| `packages/python-verify`, `packages/go-verify` | Latest |
| Hosted service (`emiliaprotocol.ai`) | Always — current production |
| < 1.0 / pre-release | No |

## Reporting Vulnerabilities

Email **security@emiliaprotocol.ai** with:

- A description of the vulnerability
- Steps to reproduce
- Expected vs actual behavior
- Impact assessment (if known)

We will acknowledge within **48 hours** and provide an initial assessment within **7 days**.

**Do not open public GitHub issues for security vulnerabilities.**

## Responsible Disclosure Process

1. **Report** the vulnerability via the email above.
2. **Acknowledgement** within 48 hours with a tracking reference.
3. **Assessment** within 7 days — we will confirm the severity and estimated fix timeline.
4. **Fix development** — a patch is developed privately and tested against the conformance suite.
5. **Coordinated disclosure** — once the fix is released, we will credit the reporter (unless anonymity is requested) and publish a security advisory.
6. **90-day disclosure window** — if we have not addressed the issue within 90 days, the reporter may disclose publicly.

We follow the principle of coordinated disclosure. Please do not disclose vulnerabilities publicly before a fix is available.

## Scope

In scope:

- **The protocol.** Flaws in `EP-RECEIPT-v1` / `EP-CORE-v1.0` that allow forging, replaying, or bypassing an authorization receipt; weaknesses in the offline verification algorithm; federation (PIP-006) cross-verification flaws.
- **The packages.** `@emilia-protocol/verify`, `@emilia-protocol/issue`, `packages/python-verify`, `packages/go-verify`, the MCP server, and the published SDKs.
- **The site and hosted service.** `emiliaprotocol.ai` and its APIs — authentication, authorization, rate limiting, write-discipline bypass, data exposure.

Out of scope (report only if you can show concrete impact): findings against third-party dependencies without an EP-specific exploit path, volumetric DoS, social-engineering of staff, and reports generated solely by automated scanners with no demonstrated impact.

## Safe Harbor

We will not pursue or support legal action against researchers who, in good faith:

- Make a sincere effort to avoid privacy violations, data destruction, and service degradation.
- Access only the minimum data necessary to demonstrate a vulnerability, and do not exfiltrate, retain, or share it.
- Report promptly and privately via the contact below, and give us a reasonable window to remediate before public disclosure.
- Do not exploit a finding beyond what is needed to prove it (no pivoting, no lateral movement, no persistence).

Activity conducted consistently with this policy is considered authorized, and we will work with you rather than against you. If legal action is initiated by a third party against you for activity that complied with this policy, we will make this authorization known. This safe harbor does not extend to actions that violate applicable law or harm third parties.

## Security Contact

- **Email:** security@emiliaprotocol.ai
- **PGP:** Available on request for encrypted communications.
- **Response SLA:** 48-hour acknowledgement, 7-day initial assessment.

## Security Measures in Place

### Write Discipline (Append-Only Architecture)

- **Append-only ledger:** Receipts are never deleted, only neutralized via dispute reversal.
- **Write guard:** Runtime enforcement via `getGuardedClient()` — all trust-bearing tables (`receipts`, `commits`, `disputes`, `trust_reports`, `protocol_events`, `handshakes`, etc.) are blocked from direct mutation. All writes MUST go through `protocolWrite()`.
- **Immutability triggers:** Database triggers prevent modification of receipt fields after creation.
- **Idempotent writes:** Duplicate `transaction_ref` returns the existing receipt, not a new one.

### Rate Limiting

- **Identity-aware throttling:** Write operations use API key prefix + IP; read operations use IP only.
- **Per-category limits:** Registration (10/hr), submissions (30/min), reads (120/min), disputes (5/hr), reports (3/hr), anchoring (1/6hr).
- **Cloud route limits:** Cloud reads (100/min), cloud writes (30/min), cloud admin (10/min).
- **Fail-closed on outage:** Sensitive write categories reject requests when the rate-limiting backend is unavailable.
- **Route policy table:** Every mutating endpoint is explicitly classified in `middleware.js` — unclassified write routes trigger console warnings.

### Content Security Policy (CSP)

- `default-src 'self'` — no third-party resources unless explicitly allowed.
- `frame-ancestors 'none'` — prevents clickjacking (equivalent to X-Frame-Options: DENY).
- `connect-src` restricted to Supabase and Base L2 RPC endpoints.
- `font-src` allows Google Fonts (`fonts.gstatic.com`) only.
- `img-src` restricted to self, data URIs, and blobs.

### Security Headers

- **X-Frame-Options: DENY** — prevents embedding in iframes.
- **X-Content-Type-Options: nosniff** — prevents MIME type sniffing.
- **Referrer-Policy: strict-origin-when-cross-origin** — limits referrer leakage.
- **Permissions-Policy:** Camera, microphone, and geolocation disabled.
- **X-DNS-Prefetch-Control: on** — enables DNS prefetching for performance.

### Cryptographic Integrity

- **Receipt hashing:** SHA-256 with canonical JSON (sorted keys, no whitespace).
- **Chain linking:** Each receipt includes the previous receipt's hash.
- **Batch anchoring:** Merkle tree root published on Base L2.
- **API key derivation:** `crypto.randomBytes(32)`, stored as SHA-256 hash.
- **Owner ID:** `crypto.randomUUID()` — portable, not IP-derived.

### Trust Evaluation Safeguards

- **Four-factor weighting:** submitter x time x graph x provenance — all four must be favorable for high trust.
- **Sybil resistance:** Unestablished submitters carry 0.1x weight; quality gate caps unestablished evidence at 2.0.
- **Graph analysis:** Thin-graph (0.5x), closed-loop (0.4x), cluster (0.1x) penalties.
- **Time decay:** 90-day half-life on receipt evidence weight.

## Threat Model

### Receipt Forgery
**Attack:** Submitter fabricates a receipt for a transaction that never happened.
**Mitigations:**
- Receipts are SHA-256 hashed with canonical JSON (sorted keys, no whitespace)
- Chain-linked: each receipt includes the previous receipt's hash
- Merkle root anchored on Base L2 — tampering is cryptographically detectable
- Bilateral attestations: counterparty can confirm or dispute
- Provenance tiers: self-attested receipts carry 0.3x weight vs bilateral at 0.8x

**Status:** Implemented. Tested in conformance suite (JS + Python cross-language verification).

### Sybil Farms (Fake Identity Volume)
**Attack:** Create many fake entities to submit favorable receipts and inflate trust.
**Mitigations:**
- Unestablished submitters carry 0.1x weight
- Sybil quality gate caps unestablished evidence at 2.0 for dampening — pure volume cannot overcome the trust barrier
- Registration rate limiting (10/hour per IP)
- Portable random owner_id (`ep_owner_<uuid>`) assigned at registration; durable identity established through explicit principal binding via `/api/identity/bind`
- Graph analysis: thin-graph (0.5x), closed-loop (0.4x), cluster (0.1x) penalties

**Status:** Implemented. 14 adversarial tests verify damage ceilings.

### Reciprocal Loops (A scores B, B scores A)
**Attack:** Two entities trade favorable receipts to inflate each other's trust.
**Mitigations:**
- Graph analysis detects closed loops and applies 0.4x weight penalty
- Cluster detection applies 0.1x penalty for tight rings
- Effective evidence dampening means even high-weight reciprocal receipts are capped

**Status:** Implemented. Adversarial tests verify.

### Trust Farming (Slow Buildup)
**Attack:** Gradually submit fake receipts over months to avoid velocity detection.
**Mitigations:**
- 90-day half-life time decay: old receipts lose weight naturally
- Anomaly detection: tracks score velocity and flags sudden changes
- Establishment requires quality_gated_evidence >= 5.0 AND unique_submitters >= 3 (pure unestablished volume capped at 2.0 contribution)

**Status:** Implemented. Adversarial tests verify old receipts decay below threshold.

### Appeal/Report Spam
**Attack:** Flood the dispute/report system to overwhelm operators or suppress legitimate entities.
**Mitigations:**
- Dispute filing: 5/hour per API key
- Human reports: 3/hour per IP
- Reports do not directly affect trust — they create review objects only
- Constitutional principle: humans may trigger review, but do not directly write trust truth

**Status:** Implemented. Rate limiting enforced in middleware.

### Operator Misuse
**Attack:** A rogue operator reverses legitimate receipts or dismisses valid disputes.
**Mitigations:**
- Reversed receipts are neutralized (graph_weight -> 0), never deleted — audit trail preserved
- Score recomputation happens immediately on reversal
- All dispute states are queryable via public API
- Evidence redaction tiers protect privacy while maintaining transparency

**Status:** Implemented. E2E tests verify reversal propagation.

### Context Poisoning
**Attack:** Entity performs well in one context to earn trust, then exploits it in another.
**Mitigations:**
- Context-aware evaluation: trust profiles can be filtered by category, geo, value band
- Policy evaluation includes context — "trusted for electronics" does not mean "trusted for furniture"
- Pre-action enforcement evaluates software entities against host-specific policies

**Status:** Implemented. Adversarial tests verify split-behavior detection.

## Architecture Security Properties

- **Append-only ledger:** Receipts are never deleted, only neutralized via dispute reversal
- **Immutability triggers:** Database triggers prevent modification of receipt fields after creation
- **Four-factor weighting:** submitter x time x graph x provenance — all four must be favorable for high trust
- **Identity-aware throttling:** Write operations use API key prefix + IP; read operations use IP only
- **Idempotent writes:** Duplicate transaction_ref returns existing receipt, not a new one

## What EP Does Not Protect Against

- **Real-world fraud:** EP evaluates digital trust signals. It cannot verify physical delivery or product quality directly — that requires oracle adapters (future work).
- **Compromised API keys:** If an entity's API key is stolen, the attacker can submit receipts as that entity. Rotate keys if compromised.
- **Coordinated state-level attacks:** EP is designed for commercial and software trust, not nation-state adversaries.

## Cryptographic Specifications

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Receipt hashing | SHA-256 | Canonical JSON input (sorted keys) |
| Chain linking | SHA-256 | Each receipt includes previous_hash |
| Batch anchoring | Merkle tree -> Base L2 | Root published on-chain |
| API key derivation | crypto.randomBytes(32) | Stored as SHA-256 hash |
| Owner ID | crypto.randomUUID() | ep_owner_<uuid> (portable, not IP-derived) |

## Security Posture

- **Independent penetration testing completed** (Shannon AI Penetration Testing Framework, 2026-03-23)
- **31 findings identified and remediated** (5 critical, 12 high, 8 medium, 6 low)
- **CI pipeline includes 16 automated quality gates** including secret scanning (gitleaks), write discipline enforcement, invariant coverage, and language governance
- **Security checklist** maintained at `docs/conformance/SECURITY_CHECKLIST.md`

### Threat model and adversarial testing

- **Threat model** — `docs/security/THREAT_MODEL.md` and `THREAT_MODEL.md` (root).
- **Red-team case catalog** — `docs/conformance/RED_TEAM_CASES.md` (85 cataloged adversarial cases, RT-001 through RT-085).
- **Protocol-level security considerations** — the Internet-Draft, `standards/draft-schrock-ep-authorization-receipts-00.md` §11 (operator compromise, presentation attacks, log equivocation, directory authority, separation-of-duties limits, approver fatigue), stated plainly rather than claimed away.
- **What a receipt proves and does not prove** — `docs/RECEIPT-CLAIMS.md`.

## Conformance

Any implementation claiming EP compatibility must pass the conformance suite:
- `conformance/fixtures.json` — canonical hash vectors, provenance weights, four-factor weight vectors
- `conformance/conformance.test.js` — JavaScript verification
- `conformance/verify_hashes.py` — Python cross-language verification
