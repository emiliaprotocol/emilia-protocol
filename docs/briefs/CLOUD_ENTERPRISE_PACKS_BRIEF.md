# Cloud, Enterprise, and Packs Brief

## What's new (June 2026)
- **18 suites / 251 vectors:** JavaScript, Python, and Go same-team ports agree on the public suite; a separately authored Rust verifier rebuilt from pinned public source passes the pinned 16-suite/164-vector clean-room bundle plus 359 hostile cases. Strict independently attested construction acceptance remains pending.
- **Composition (EP-AEC):** EP now composes delegation, policy-permit, and human-authorization receipts into one offline ALLOW/DENY — the convergence layer for the emerging IETF agent-authorization standards. A pack or policy can require a machine policy check *and* a named human's authorization, bound to the same action.
- **Regulated-domain reach:** EU AI Act Article 14 alignment plus a healthcare profile (the mandated independent double-check, PHI-free receipts) extend the same primitive across verticals.

## Open protocol below
- EP Core
- Handshake
- Accountable Signoff
- Emilia Eye

## Managed control plane above
- policy registry
- hosted verification
- signoff orchestration
- event explorer
- audit exports
- tenant controls

## Hardened deployment above that
- private cloud / VPC
- SSO / SCIM
- advanced RBAC
- delegated admin
- data residency
- regulator support

## Vertical packs on top
- Government Pack
- Financial Pack
- Agent Governance Pack

## Proof

The protocol layer beneath has been exercised end-to-end: 6,615 automated test cases across 344 files with every platform-applicable case required to pass, 329 complete Accountable Signoff chains with zero correctness violations, all endpoints using single-roundtrip atomic RPCs, and 46 EP-only database tables with zero foreign artifacts.

This is the business model: open protocol below, managed trust infrastructure above, vertical control systems on top.
