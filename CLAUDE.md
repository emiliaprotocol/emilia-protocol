# EMILIA Protocol - Repo Guide

## Required context
- Read `AGENTS.md` and `AI_CONTEXT.md` before analyzing or editing this repository.
- Use `public/.well-known/emilia-context.json` for current evidence counts and provenance.
- Do not infer current behavior or standards status from archived, staged, private, or randomly sampled documents.

## Critical
- **This repo is PUBLIC.** Everything tracked is world-readable. Business, strategy, GTM, investor, fundraising, outreach, competitive, and pitch material belongs in the private `emiliaprotocol/emilia-company` repository, never in tracked paths here. `docs/strategy-private/` remains ignored only as a compatibility safeguard, not as a source of truth. Run `npm run check:repository-boundary` before publishing. When in doubt, don't `git add` it.
- **main == production within minutes.** Multiple agent sessions commit and push this same checkout in near-real-time, so a local commit is NOT a hold. Anything that must not publish yet goes on a branch or stays outside the repo. Re-fetch before reasoning about origin state.
- Branch protection is off by owner decision: work directly on main and push each verified chunk.

## Build & ship
- Run the full production build before pushing, not just tsc/eslint/tests.
- Don't sit and watch CI after pushing; push and continue, fix only if it fails.

## Outbound & claims
This repo owns the VERIFIED-vs-ACCEPTED and reproduction-vs-independent distinctions, so its own outbound is held to them. Before any EMILIA/IETF/standards email, list post, or draft:
- **Read the exact artifact before you describe it.** Run or read the specific file in `examples/` or `conformance/` that backs each claim, never a memory of how it works. The seam is precise: in `examples/scitt/capsule-seam-vector.mjs` the capsule verifier checks the capsule and the EP verifier checks the receipt offline, joined only by the shared action digest. Say that, not "both verified together."
- **The five traps:** (1) an external party re-running an `@emilia-protocol` package is REPRODUCTION, never an "independent implementation." (2) VERIFIED (crypto checks pass) never collapses into ACCEPTED (trusted under a pinned root). (3) "fail-closed" means malformed or attacker input returns a reason, not a crash: prove it against the bad input. (4) composition legs join by a shared action digest, never by one verifier ingesting another's evidence into its trust boundary. (5) no EP Internet-Draft is IETF-adopted or endorsed.

## Database
- Prod Supabase schema and repo migrations drift. Verify actual prod columns (information_schema) before shipping schema-dependent code; apply missing migrations in dependency order, with backfill, before merging code that reads new columns.
- Two Supabase MCP bindings exist on this machine and point at DIFFERENT projects. Confirm project identity before applying any migration here; the single-project binding is NOT this repo's database.

## Layout signposts
- Spec and standards drafts: standards/ (posted revisions in standards/posted/)
- Conformance suites: conformance/ (JS/Py/Go)
- Worked examples and interop/seam vectors (read these before claiming what they show): examples/ (e.g. examples/scitt/capsule-seam-vector.mjs, examples/wimse-pep/, examples/external-verification/)
- Gate (productized enforcement point): packages/gate
- MCP server: mcp-server/
- Capability map: docs/CAPABILITY-MAP.md
- Repository disclosure boundary: docs/REPOSITORY-BOUNDARIES.md
