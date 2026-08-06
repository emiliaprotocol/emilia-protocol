# Executor Authority Regression Matrix

This matrix turns the recurring framework-integration failures surfaced during
the Anton/Claude Cookbook collaboration into repository-wide release checks.
The unit of authorization is the exact executor call, not a callback boolean,
tool family, UI acknowledgement, or mutable payload description.

| Failure pattern | Required result | Executable coverage |
| --- | --- | --- |
| Application callback returns `{ approved: true }` | Tool does not execute; exact-action receipt required | `packages/langchain/index.test.ts` |
| Receipt authorizes action A; executor receives changed arguments B | Refuse with action mismatch before tool entry | `packages/langchain/index.test.ts`, `packages/crewai/tests/test_crewai.py`, `tests/mcp-guard-boundary.test.ts` |
| Two OpenAI sibling calls have identical tool and arguments but different call IDs | Receipt for one call cannot authorize the other | `packages/openai-agents/index.test.ts`, `packages/require-receipt/action-binding.test.js` |
| Receipt carrier changes while material arguments stay identical | Authority and loop fingerprints do not change | `packages/require-receipt/action-binding.test.js`, `tests/mcp-guard-boundary.test.ts` |
| Caller or selector mutates arguments after binding begins | Execute the detached canonical snapshot; selector receives only a copy | `packages/langchain/index.test.ts`, `packages/openai-agents/index.test.ts`, `packages/crewai/tests/test_crewai.py`, `tests/mcp-guard-boundary.test.ts` |
| Durable consumption fails | Executor boundary is never entered | `packages/openai-agents/index.test.ts`, `integrations/langchain-emilia/tests/test_client.py` |
| Tool returns but execution attestation cannot be confirmed | Return `INDETERMINATE`, say do not retry, and do not claim execution evidence | `integrations/langchain-emilia/tests/test_tools.py` |
| Identical MCP call loops inside the configured window | Local circuit opens with truthful 429; handler count stops | `tests/mcp-guard-boundary.test.ts` |
| Cloud pending query uses a nonexistent generic `pending` state or includes expired challenges | Query only `challenge_issued` / `challenge_viewed` and unexpired rows | `tests/cloud-signoff-operations.test.ts` |
| Notification endpoint has no subscribed delivery path | Return conflict/unavailable; never claim queued | `tests/cloud-webhooks.test.ts`, `tests/cloud-signoff-operations.test.ts` |
| Webhook delivery is persisted but remote delivery is delayed | Return `retrying`, not delivered | `tests/cloud-webhooks.test.ts`, `tests/cloud-signoff-operations.test.ts` |
| Escalation endpoint merely acknowledges a request | Persist an audit event and return its identity | `tests/cloud-signoff-operations.test.ts` |
| Two escalations race for the same challenge | Database unique invariant admits at most one | `supabase/migrations/20260805120000_cloud_signoff_escalation_once.sql` |

Release rule: a framework adapter may add a semantic action selector, but it
must not permit that selector to omit the complete executor input. A status API
may report only evidence-backed states it can distinguish.
