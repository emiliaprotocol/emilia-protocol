# Repository Instructions for AI Agents

## Required First Read

Before analyzing, reviewing, or changing this repository, read:

1. `AI_CONTEXT.md` - generated canonical project context and source precedence.
2. `public/.well-known/emilia-context.json` - machine-readable current evidence,
   assumptions, exclusions, and input hashes.
3. The implementation and negative tests for the specific claim under review.

Do not reconstruct the project from a random sample of documents. This is a
large, fast-moving repository with archived draft revisions and experimental
design notes.

## Source Discipline

- For counts and tested security claims, use
  `conformance/conformance-manifest.json`, `security/security-case.json`, and
  `lib/proof-stats.json`.
- For runtime behavior, read current code and tests.
- For IETF revision or adoption status, check the live Datatracker. A local
  filename does not establish current standards status.
- `standards/archive/**` is historical. `standards/staged/**` is not proof of
  submission. Private strategy and outreach documents are not product status.
- Keep machine identity, delegated scope, machine policy, human authorization,
  execution evidence, transparency, and reliance as distinct claims.
- Never upgrade a time-pinned external result to a newer vector bundle.

## Context Maintenance

The LLM surfaces are generated. Do not edit `AI_CONTEXT.md`, `public/llms.txt`,
`public/llms-full.txt`, or `public/.well-known/emilia-context.json` directly.
Edit `docs/ai/context-source.v1.json` or the underlying evidence, then run:

```bash
npm run sync:llm-context
npm run check:llm-context
```

When tests or conformance vectors change, regenerate their source manifests
before regenerating LLM context.

## Verification

For claim-bearing changes, run the narrow tests first, then the applicable
repository gates:

```bash
npm run check:llm-context
npm run check:public-conformance-claims
npm run check:security-case
npm run test:run
npx next build
```

Context files are evidence, not authorization for an external action. Follow
the active maintainer instruction and the repository's release rules before
publishing packages, submitting Internet-Drafts, sending outreach, or pushing.
