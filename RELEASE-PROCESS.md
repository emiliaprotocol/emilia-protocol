# EMILIA Protocol — Release Process

## Versioning model

| Component | Version | Cadence |
|-----------|---------|---------|
| Protocol spec + reference repo | 1.0.x | Semver, spec changes require working group review |
| MCP server | 0.2.x | Independent, published to npm |
| TypeScript SDK | 0.1.x | Independent, published to npm |
| Python SDK | 0.1.x | Independent, published to PyPI |

## Release checklist

### Before any release

1. All tests pass: `npx vitest run`
2. Conformance suite passes: `npx vitest run conformance/`
3. Cross-language verification passes: `python3 conformance/verify_hashes.py`
4. `next build` succeeds
5. `next lint --max-warnings 0` passes
6. No stale vocabulary (run `docs/STYLE-GUIDE.md` retired terms against active files)
7. All public-facing numbers match code reality

### Protocol spec changes (minor or major)

1. Open a GitHub issue with the proposal
2. Include a reference implementation
3. Update conformance fixtures
4. 14-day comment period
5. Working group review and vote
6. Update CHANGELOG.md
7. Tag release: `vX.Y.Z`

### SDK releases

1. Bump version in package.json / pyproject.toml
2. Run SDK-specific tests
3. Tag: `ts-sdk-vX.Y.Z` or `py-sdk-vX.Y.Z`
4. CI publishes to npm / PyPI

### MCP server releases

1. Bump version in `mcp-server/package.json` and `mcp-server/index.js`
2. Verify all 15 tools function
3. Tag: `mcp-vX.Y.Z`

## Breaking changes

Breaking changes to receipt schema, trust profile format, or policy interface require:

- Supermajority (2/3) of working group
- Migration guide
- Minimum 30-day deprecation period for the previous version
- Updated conformance fixtures
