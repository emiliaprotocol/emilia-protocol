# `@emilia-protocol/verify` — npm Publish Checklist (1.0.1)

**Status:** READY TO PUBLISH — execute now if you haven't already.
**Why:** v1.0.0 on npm has the shallow-canonicalization regression. Until
1.0.1 publishes, every cold buyer running `npm install
@emilia-protocol/verify` gets the buggy version. The whole "verify
yourself" pitch on `/r/example` falls apart on day one of outreach.

---

## Pre-flight (already done, double-check)

- [x] `packages/verify/package.json` version is `1.0.1`
- [x] `packages/verify/index.js` uses recursive `canonicalize()`
- [x] `packages/verify/test.js` exists with 11 passing tests
- [x] `cd packages/verify && node --test test.js` → all green
- [x] `node scripts/verify-demo-receipt.js` → all green

---

## Publish (do this now)

```bash
cd /Users/imanschrock/Documents/GitHub.nosync/emilia-protocol/packages/verify

# 1. Sanity-check the version one more time
cat package.json | grep '"version"'
# → "version": "1.0.1",

# 2. Confirm npm identity
npm whoami
# → emiliaprotocol

# 3. Publish
npm publish --access public
# → 2FA prompt: enter OTP from authenticator app
# → "+ @emilia-protocol/verify@1.0.1"

# 4. Verify it landed
curl -s https://registry.npmjs.org/@emilia-protocol/verify | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('latest:', d['dist-tags']['latest']); print('versions:', list(d['versions'].keys()))"
# → latest: 1.0.1
# → versions: ['1.0.0', '1.0.1']
```

---

## Deprecate the broken 1.0.0

The 1.0.0 release stays on npm forever (npm policy). Anyone with
a pinned `"@emilia-protocol/verify": "1.0.0"` (no caret) keeps getting
the bug unless we mark the version deprecated. **Do this immediately
after the 1.0.1 publish:**

```bash
npm deprecate '@emilia-protocol/verify@1.0.0' \
  'Shallow canonicalization regression — nested fields not deterministically signed. Upgrade to >=1.0.1.'
```

Anyone who pinned `==1.0.0` will see a yellow warning when they install.
Anyone using `^1.0.0` semver auto-upgrades to 1.0.1.

---

## Smoke-test the published package

After the publish + deprecate land, do a 1-minute smoke test from a
clean directory to prove a cold buyer's flow works:

```bash
mkdir -p /tmp/ep-verify-smoketest && cd /tmp/ep-verify-smoketest
npm init -y >/dev/null
npm install @emilia-protocol/verify@^1.0.1 2>&1 | tail -3

cat > smoke.mjs <<'EOF'
import { verifyReceipt } from '@emilia-protocol/verify';

const evidence = await fetch(
  'https://emiliaprotocol.ai/api/demo/trust-receipts/tr_example/evidence'
).then(r => r.json());

const result = verifyReceipt(evidence.document, evidence.public_key);
console.log('Verify:', result);
EOF

node smoke.mjs
# Expected: { valid: true, checks: { version: true, signature: true, anchor: null } }

cd / && rm -rf /tmp/ep-verify-smoketest
```

If the smoke test passes, the "verify yourself" pitch on `/r/example`
is genuinely live for any cold buyer who follows it.

---

## After publish

1. Tag the release in git:
   ```bash
   cd /Users/imanschrock/Documents/GitHub.nosync/emilia-protocol
   git tag -a 'verify-v1.0.1' -m '@emilia-protocol/verify@1.0.1 — recursive canonicalize'
   git push origin verify-v1.0.1
   ```

2. Post a one-line update wherever you track shipped artifacts (the
   AAIF working-group thread, the AWS application supplement, the
   /partners design-partner page once that exists).

3. Update `docs/AAIF-PROPOSAL-v3.md` and `docs/AWS-GRANT-APPLICATION.md`
   to reference `^1.0.1` (or just `latest`) — both currently say
   `1.0.0`. Mechanical find/replace.

---

## What goes wrong and what to do

| Symptom | Cause | Fix |
|---|---|---|
| `npm publish` returns 403 | Token missing publish scope | Use a granular token with write access on `@emilia-protocol/*` |
| `npm publish` returns 401 | 2FA OTP wrong / expired | Generate a fresh OTP from the authenticator app, retry |
| `npm publish` says "you cannot publish over the previously published versions" | Version already exists | You already published; check `npm view @emilia-protocol/verify version` |
| Smoke test returns `valid: false` | Demo deploy not picked up canonicalize fix | Confirm latest deploy includes commit `b320101` or later |
| Registry propagation delay | npm CDN lag | Wait 60s, retry — the publish itself succeeded if no error |

---

## Why this isn't automated

`npm publish` requires a 2FA OTP (deliberate). Wiring an automation
flow that bypasses 2FA defeats the security model the OTP exists to
enforce, and the threat model EMILIA's protocol is designed for is
"don't trust packages without a human authorizing the publish." Eat
your own dogfood — keep this manual.
