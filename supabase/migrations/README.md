# EP Database Migrations

Run in order in Supabase SQL Editor. Each migration is idempotent where possible.

## Migration Index

| # | File | What it does |
|---|------|-------------|
| 001 | `001_emilia_core_schema.sql` | Base tables: entities, receipts, needs, api_keys, score_history |
| 002 | `002_embeddings.sql` | Vector embeddings for semantic search |
| 003 | `003_waitlist.sql` | Waitlist table |
| 004 | `004_entity_enhancements.sql` | Entity capabilities, A2A/UCP fields |
| 005 | `005_needs_matching.sql` | Need matching RPC functions |
| 006 | `006_v2_receipts.sql` | Claims, evidence, submitter credibility columns |
| 007 | `007_rewrite_scoring.sql` | Superseded by 009 |
| 008 | `008_protocol_hardening.sql` | NOT NULL on transaction_ref, immutability triggers, `is_entity_established()` |
| 009 | `009_scoring_effective_evidence.sql` | graph_weight column, effective-evidence `compute_emilia_score()` |
| 010 | `010_context_keys.sql` | Context JSONB on receipts, GIN index, updated immutability trigger |
| 011 | `011_policy_native_needs.sql` | trust_policy JSONB on needs |
| 012 | `012_needs_context_jsonb.sql` | **needs.context TEXT → JSONB** (structured context keys) |
| 013 | `013_disputes.sql` | Disputes table, trust_reports table, dispute lifecycle, receipt dispute_status |
| 014 | `014_bilateral_provenance.sql` | Provenance tiers on receipts, bilateral confirmation fields |
| 015 | `015_software_entity_types.sql` | EP-SX: software entity types, software_meta JSONB, software transaction types |

## Important schema notes for new implementers

- `needs.context` — defined as TEXT in 001, upgraded to JSONB in 012. Final type is **JSONB**.
- `needs.trust_policy` — added as JSONB in 011. Accepts string policy names or full JSON policy objects.
- `receipts.context` — added as JSONB in 010. Included in canonical hash.
- `receipts.graph_weight` — added in 009. Used in four-factor receipt weighting.
- `receipts.dispute_status` — added in 013. Tracks challenge lifecycle.
- `entities.dispute_count` — added in 013. Auto-incremented by trigger.
- `receipts.provenance_tier` — added in 014. Six tiers from self_attested to oracle_verified.
- `receipts.bilateral_status` — added in 014. Tracks bilateral confirmation lifecycle.
- `receipts.confirmed_by` — added in 014. UUID of confirming entity.

## For fresh installs

Run all migrations 001-013 in order. The final schema will be correct.

## For existing installs

Run only the migrations you haven't applied yet, in order.
