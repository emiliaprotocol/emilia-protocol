# EP Deprecations

## Active Deprecations

### Boolean Evaluation (deprecated since v0.9)
**Old:** `{ pass: boolean, failures: string[], warnings: string[] }`
**New:** `TrustDecision { decision: 'allow' | 'review' | 'deny', reasons: Reason[], ... }`
**Migration:** Replace `pass === true` checks with `decision === 'allow'`
**Removal target:** v1.1

### PolicyEvaluationResponse Schema (deprecated since v0.9)
**Old:** `PolicyEvaluationResponse` with `pass: boolean`
**New:** `TrustDecision` with `decision: string`
**Migration:** Use `TrustDecision` directly
**Removal target:** v1.1

### compat_score Field (deprecated since v0.8)
**Old:** `compat_score: number` in various response objects
**New:** `confidence: number` in `TrustDecision`
**Migration:** Replace `compat_score` reads with `confidence`
**Removal target:** v1.0

### api_key_hash Column (deprecated since v0.7)
**Old:** Direct API key hash storage in core schema
**New:** Key management through control plane
**Migration:** N/A -- column preserved for backward compat
**Removal target:** v1.1

### Blockchain Anchoring (de-emphasized since v0.8)
**Status:** Still functional but not a core protocol concern
**Current role:** Optional extension for audit trail anchoring
**Note:** Not removed, but should not dominate protocol narrative
