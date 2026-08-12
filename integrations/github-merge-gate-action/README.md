# EMILIA Merge Gate

EMILIA Merge Gate is a narrow protected-merge check. It admits a pull request
only when all of the following agree:

- a repository-owned mandate loaded from the exact base commit;
- the exact repository, base ref, base SHA, and head SHA;
- the changed paths and bounded diff size;
- a recomputed CAID for that material merge action; and
- a detached EP receipt signed by a relying-party-pinned Ed25519 issuer key.

The receipt can represent a bounded program, an approval service, or another
trusted authority source. This Action does not claim that every receipt is a
human approval.

## Enforcement boundary

This Action does not merge a pull request and cannot prevent an administrator
or another path from merging around it. It becomes a prevention control only
when its check is configured as a required status check in branch protection or
a GitHub ruleset, the workflow and Action are pinned to reviewed code, and every
covered merge path is subject to that rule.

The Action does not claim one-time receipt consumption. A check may rerun for
the same exact head commit. GitHub owns the final merge transition. The receipt
cannot be replayed for another repository, base, head, mandate, or CAID.

## Detached evidence

The receipt must be created after the head commit exists, so it cannot be a file
inside that same commit without creating a circular hash dependency. Acquire it
through an approval workflow or service and place it in `RUNNER_TEMP`. Never
take the issuer public key from candidate-controlled content. Pin that key in a
GitHub environment, repository variable, or another administrator-controlled
configuration source.

## Mandate

Commit `.emilia/merge-mandate.json` on the protected base branch:

```json
{
  "@version": "EP-GITHUB-MERGE-MANDATE-v1",
  "repository": "acme/payments",
  "allowed_base_refs": ["refs/heads/main"],
  "allowed_path_prefixes": ["src/", "docs/"],
  "denied_path_prefixes": [".github/", ".emilia/"],
  "max_changed_files": 25,
  "max_additions": 1000,
  "max_deletions": 1000,
  "max_changed_bytes": 1048576,
  "max_receipt_age_seconds": 900,
  "issuer_id": "customer:acme:security",
  "issuer_key_id": "key:merge-authority:1"
}
```

Unknown fields, duplicate JSON members, binary diffs, missing commits, a
non-ancestor base, and unsupported path forms fail closed.

## Workflow shape

Pin both checkout and this Action to a reviewed full commit SHA. The step that
acquires the detached receipt is deployment-specific and must not execute
candidate code with privileged credentials.

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@<full-commit-sha>
    with:
      ref: ${{ github.event.pull_request.head.sha }}
      fetch-depth: 0
      persist-credentials: false
  - name: Acquire detached receipt without executing candidate code
    run: your-approved-receipt-fetcher > "$RUNNER_TEMP/merge-receipt.json"
  - id: merge-gate
    uses: emiliaprotocol/emilia-protocol/integrations/github-merge-gate-action@<full-commit-sha>
    with:
      base-sha: ${{ github.event.pull_request.base.sha }}
      head-sha: ${{ github.event.pull_request.head.sha }}
      repository: ${{ github.repository }}
      base-ref: refs/heads/${{ github.base_ref }}
      receipt-path: ${{ runner.temp }}/merge-receipt.json
      issuer-public-key: ${{ vars.EMILIA_MERGE_ISSUER_PUBLIC_KEY }}
```

Run the hostile local suite with:

```sh
node --test integrations/github-merge-gate-action/tests/*.node-test.mjs
```
