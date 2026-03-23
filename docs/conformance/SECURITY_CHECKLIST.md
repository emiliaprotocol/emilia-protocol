# Security Checklist

This is a living checklist for contributors and auditors. All items must be satisfied before merging security-relevant changes.

Last updated: 2026-03-23 (post-penetration test remediation)

---

## Authentication

- [ ] All API routes call `authenticateRequest()`
- [ ] Auth failures return generic 401 (no lifecycle leakage)
- [ ] Reserved entity IDs blocked at registration
- [ ] API key secrets never stored in plaintext

## Authorization

- [ ] All signoff functions validate actor ownership
- [ ] Handshake operations verify party membership
- [ ] Identity continuity requires `dispute.review` permission
- [ ] Cloud routes enforce tenant isolation
- [ ] NULL permissions default to `[]` (deny-by-default)
- [ ] No header-based role authorization

## Input Validation

- [ ] No `.or()` with unsanitized user input (PostgREST DSL)
- [ ] No `.ilike()` with unescaped user input
- [ ] Reserved entity IDs checked at registration
- [ ] Request body validated before processing

## Network Security

- [ ] No outbound `fetch()` without private IP validation
- [ ] Webhook URLs validated against RFC 1918 ranges
- [ ] DNS rebinding protection (validate at delivery time, not just registration)
- [ ] MCP adapter URLs validated

## Headers & Transport

- [ ] HSTS present with `includeSubDomains` and `preload`
- [ ] CSP present without `unsafe-eval`
- [ ] `base-uri` and `form-action` directives set
- [ ] `Cache-Control: no-store` on API routes
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY`

## Cryptographic

- [ ] `timingSafeEqual` for all secret comparison
- [ ] SHA-256 for API key hashing
- [ ] Ed25519 for commit signing

## CI/CD

- [ ] gitleaks secret scanning on every push
- [ ] Write discipline check (zero `SERVICE_CLIENT_ALLOWLIST` exceptions)
- [ ] Invariant coverage gate (19 invariants, 4 layers)
- [ ] Language governance check
