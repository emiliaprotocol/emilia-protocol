# EMILIA Protocol — Repo Guide

## Critical
- **This repo is PUBLIC.** Everything tracked is world-readable. Business, strategy, GTM, investor, fundraising, outreach, competitive, and pitch material never goes in tracked paths; it belongs in docs/strategy-private/ (gitignored) or outside the repo entirely. When in doubt, don't `git add` it.
- **main == production within minutes.** Multiple agent sessions commit and push this same checkout in near-real-time, so a local commit is NOT a hold. Anything that must not publish yet goes on a branch or stays outside the repo. Re-fetch before reasoning about origin state.
- Branch protection is off by owner decision: work directly on main and push each verified chunk.

## Build & ship
- Run the full production build before pushing, not just tsc/eslint/tests.
- Don't sit and watch CI after pushing; push and continue, fix only if it fails.

## Database
- Prod Supabase schema and repo migrations drift. Verify actual prod columns (information_schema) before shipping schema-dependent code; apply missing migrations in dependency order, with backfill, before merging code that reads new columns.
- Two Supabase MCP bindings exist on this machine and point at DIFFERENT projects. Confirm project identity before applying any migration here; the single-project binding is NOT this repo's database.

## Layout signposts
- Spec and standards drafts: standards/ (posted revisions in standards/posted/)
- Conformance suites: conformance/ (JS/Py/Go)
- Gate (productized enforcement point): packages/gate
- MCP server: mcp-server/
- Capability map: docs/CAPABILITY-MAP.md
