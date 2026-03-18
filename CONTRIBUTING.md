# Contributing to EMILIA Protocol

Thank you for your interest in contributing to EP. This document explains how to contribute to the spec, reference implementation, and conformance suite.

## What we need most right now

1. **External implementations** — Build an EP-compatible trust engine in any language. Use `conformance/fixtures.json` to verify hash compatibility.
2. **Conformance test contributions** — Add edge case fixtures, cross-language verification vectors, policy replay tests.
3. **Spec feedback** — Review `docs/EP-CORE-RFC.md` and file issues for ambiguities, gaps, or contradictions.
4. **Integration examples** — Wire EP into your agent framework, commerce platform, or MCP client.

## How to contribute

### Bug fixes and improvements

1. Fork the repository
2. Create a feature branch: `git checkout -b fix/description`
3. Make your changes
4. Run tests: `npm run test:run`
5. Run conformance suite: `npm run test:run -- conformance/`
6. Submit a pull request

### Spec changes

Spec changes follow the governance process in `GOVERNANCE.md`:

1. Open a GitHub issue describing the proposed change and motivation
2. Include a reference implementation (or describe what it would require)
3. Include conformance test updates
4. Allow 14 days for community review
5. Working group reviews and decides

### Adding conformance fixtures

1. Define the input in `conformance/fixtures.json`
2. Generate the expected output using the reference implementation
3. Add a test in `conformance/conformance.test.js`
4. Submit a pull request

## Development setup

### Prerequisites
- Node.js >= 18
- npm >= 9

```bash
git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol
npm install
npm run test:run             # Run all tests (single pass, CI mode)
npm test                     # Run all tests in watch mode
npm run test:run conformance/  # Run conformance suite only
```

Expected output: 670 tests passing across 28 test files.

### MCP Server (standalone)
```bash
cd mcp-server
npm install
node index.js
```

Or via npx (no install required):
```bash
npx @emilia-protocol/mcp-server
```

### Environment Variables
Copy `.env.example` to `.env.local` and fill in:
- `SUPABASE_URL` — your Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` — service role key (server-only)
- `SUPABASE_ANON_KEY` — anon key (public)
- `EP_API_URL` — EP API base (default: https://emiliaprotocol.ai)

Tests run without any environment variables — all external services are mocked.

## Project structure

```
lib/
  canonical-evaluator.js  — ONE read brain (all trust queries route here)
  canonical-writer.js     — ONE write brain (all trust-changing writes route here)
  scoring-v2.js           — behavioral-first trust profiles + policy evaluation
  scoring.js              — v1 compatibility scoring + receipt hashing
  procedural-justice.js   — roles, state machines, abuse detection, audit trail
  ep-ix.js                — identity continuity operations
  create-receipt.js       — canonical receipt pipeline
  blockchain.js           — Merkle root anchoring (Base L2)
  sybil.js                — fraud detection + graph analysis
  rate-limit.js           — Upstash Redis + in-memory fallback
  adapters/               — host adapters (GitHub, npm, MCP, Chrome)

app/api/
  trust/profile/          — GET canonical trust profile (primary read surface)
  trust/evaluate/         — POST policy evaluation (primary decision surface)
  trust/install-preflight/ — POST software install preflight (EP-SX)
  score/                  — GET compatibility score (legacy)
  receipts/submit/        — POST receipt submission
  disputes/               — file, status, report
  entities/               — register, search
  policies/               — GET policy registry
  leaderboard/            — GET ranked entities
  cron/expire/            — deadline enforcement

conformance/
  fixtures.json           — canonical test vectors
  conformance.test.js     — conformance test runner
  verify_hashes.py        — cross-language hash verification
  README.md               — how to use the conformance suite

tests/
  scoring.test.js         — v1 scoring tests
  scoring-v2.test.js      — v2 trust profile + policy tests
  protocol.test.js        — protocol surface + hash determinism tests
  integration.test.js     — route-level integration tests
  adversarial.test.js     — Sybil, reciprocal, cluster, trust farming tests
  e2e-flows.test.js       — full lifecycle end-to-end tests

docs/
  EP-CORE-RFC.md          — canonical specification (v1.1)
  EP-SX-SOFTWARE-TRUST.md — software trust extension
  EP-IX-IDENTITY-CONTINUITY.md — identity continuity spec
  AAIF-PROPOSAL-v2.md     — AAIF working group proposal
```

## Style

- No TypeScript in the reference implementation (maximizes portability)
- ES modules (`import`/`export`)
- Vitest for testing
- Keep functions pure where possible — side effects in route handlers, not in libraries

## What NOT to contribute (yet)

- **Alternative scoring algorithms** — the weight model is published and versioned; changes go through the spec process
- **UI/UX redesigns** — the landing page and entity explorer are product surfaces, not protocol surfaces
- **Breaking schema changes** — receipt schema and trust profile format changes require a formal spec proposal

## License

By contributing, you agree that your contributions are licensed under Apache-2.0.

## Questions?

Open a GitHub issue or email team@emiliaprotocol.ai.
