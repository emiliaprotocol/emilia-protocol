# EMILIA Authority Map

Map privileged GitHub Actions paths before you protect them.

EMILIA Authority Map is a zero-dependency Node 24 GitHub Action that statically inventories `.github/workflows/*.yml` and `.github/workflows/*.yaml` from `GITHUB_WORKSPACE`.

Our first run against the EMILIA Protocol repository surfaced five critical
static review paths whose mutation jobs had no environment: three Python
publishers, a reusable PyPI publisher, and Dependabot's merge job. We moved the
protection to the exact mutation jobs and reran the scanner to zero critical
findings. That result identified control placement; it did not prove an exploit.

It emits JSON and Markdown covering:

- workflow triggers;
- job environment references and textual production references;
- top-level and job-level `write-all` or scoped `write` permissions;
- `pull_request_target` and `self-hosted` runner hazards;
- third-party action or reusable-workflow references not pinned to a full 40- or 64-character commit SHA;
- workflows with jobs that have effective declared GitHub token write permission but no environment; and
- every ambiguity or supported-YAML boundary the scanner encounters.

## Boundary

This is static discovery, not an authorization or enforcement mechanism. It does not block mutations, is not complete mediation, and does not use repository configuration as authority.

A clean report does not prove that mutations are impossible or mediated. Static workflow files cannot establish runtime credentials, action internals, called-workflow behavior, external-system authority, or mutations performed with non-GitHub credentials. Without suitable GitHub API permissions, this Action also cannot know GitHub environment protection settings, GitHub rulesets, or bypass actors and settings.

The scanner recognizes common block and flow forms for triggers, permissions, runners, and environments. YAML anchors, aliases, merge keys, expressions in security-relevant fields, tags, complex keys, duplicate keys, and unsupported forms are preserved as ambiguity records. They are never silently converted into authority claims.

## Usage

For a quick evaluation, use the maintained `v1` release line:

```yaml
name: Authority discovery

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  authority-map:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>
      - id: authority-map
        uses: emiliaprotocol/github-authority-map@v1
        with:
          fail-on: critical
```

For production, replace `v1` with the reviewed full commit SHA. The moving
major tag is convenient for evaluation; it is not an immutable dependency pin.

By default, the Action writes `emilia-authority-map.json` and `emilia-authority-map.md` to `RUNNER_TEMP`, appends the Markdown report to the job summary, and exposes these outputs:

- `json-path`
- `markdown-path`
- `critical-findings`
- `ambiguity-count`

Set `json-output` or `markdown-output` to choose another absolute path or a path relative to `GITHUB_WORKSPACE`.

### Fail policy

`fail-on` accepts only:

- `never` (default): always exit successfully after report generation; or
- `critical`: emit both reports, then exit with status 1 when one or more critical findings exist.

Critical findings are deliberately narrow and visible in the report: top-level
or job-level `write-all`, an unpinned third-party action, a contributor-triggered
self-hosted runner, `pull_request_target` composed with candidate execution, or
an obvious publish/deploy/release/push/merge sink with no statically identified
environment. Bare `pull_request_target` and scoped write permissions without an
environment are warning-level review paths. Scanner/configuration errors exit
with status 2.

Failure is a reporting policy, not mutation prevention.

Start with `fail-on: never`, review the report, and protect or document each
real mutation path. Switch to `critical` only after the baseline is understood.

## Local CLI

No install or root-package change is required:

```bash
node scan.mjs \
  --workspace /path/to/repository \
  --json /tmp/emilia-authority-map.json \
  --markdown /tmp/emilia-authority-map.md \
  --fail-on never
```

Run the scoped tests with:

```bash
node --test tests/*.node-test.mjs
```

## JSON shape

The JSON report contains stable top-level sections:

- `boundary`: explicit non-enforcement, non-authority, and API-visibility limits;
- `summary`: workflow, finding, critical, warning, ambiguity, and mutation-without-environment counts;
- `workflows`: per-file triggers, environments, production references, permissions, hazards, mutation signals, and ambiguities; and
- `findings`: source-located normalized findings with severity and code.

`mutation.hasDeclaredWriteCapability` and `mutation.withoutEnvironment` are based only on effective declared `GITHUB_TOKEN` write permissions. The report states this basis so it is not confused with proof about all possible credentials or side effects.
