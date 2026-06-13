# 60-Second Live Demo — Spectrum-Release Authorization Receipt

**Goal:** issue a receipt for a mock "spectrum release authorization," mutate one field
(the frequency), and show verification fail. Fully offline. Real published packages —
`@emilia-protocol/issue` 0.2.0 and `@emilia-protocol/verify` 1.4.0.

This script was executed against the in-repo packages on 2026-06-13; the expected output
below is captured from that run, not invented. The CLI surface is:

- `ep-issue keygen | issue | demo` (bin `ep-issue`, from `@emilia-protocol/issue`).
- `npx @emilia-protocol/verify <file.json> [--verification verification.json]`
  (bin `emilia-verify`).

> A §6.2 authorization receipt — the shape `ep-issue` emits — verifies with
> `--verification verification.json` (which carries the approver public keys + the log
> public key). No network, no EP backend, ever.

---

## Fastest path (one command, zero files) — the safest live fallback

If you want the shortest possible on-stage demo, this single command generates throwaway
keys, issues a receipt for a sample irreversible action, and verifies it — printing all
seven checks:

```bash
npx -y @emilia-protocol/issue demo
```

Expected tail:

```
4. Verifying with @emilia-protocol/verify
  ✓ action_hash
  ✓ context_commitments
  ✓ signoff_signatures
  ✓ sod
  ✓ inclusion
  ✓ checkpoint_signature
  ✓ windows

✅ VERIFIED — all 7 §6.3 checks passed.
```

It does **not** show the tamper step, so for the full "mutate one field → fail" beat use
the spectrum-specific script below.

---

## The full Spectrum Strike demo (issue → mutate → fail)

Run these in a scratch directory. Total wall time is a few seconds; the talk track is the
60 seconds.

### 0. Setup

```bash
mkdir -p /tmp/spectrum-strike-demo && cd /tmp/spectrum-strike-demo

# If the published packages are installed (recommended for a clean demo):
#   npm i @emilia-protocol/issue @emilia-protocol/verify
# Then ISSUE/VERIFY below become:  npx @emilia-protocol/issue  and  npx @emilia-protocol/verify
#
# From a repo checkout, point at the package CLIs directly:
ISSUE="node $REPO/packages/issue/cli.js"      # $REPO = path to the emilia-protocol checkout
VERIFY="node $REPO/packages/verify/cli.js"
```

### 1. Generate local issuer keys (the spectrum authority's signing keys)

```bash
$ISSUE keygen \
  --out issuer-keys.json \
  --approver-id ep:approver:spectrum-authority \
  --approver-key-id ep:key:spectrum-authority#1 \
  --log-name spectrum-strike
```

Expected output:

```
Wrote issuer keys to issuer-keys.json
  approver:    ep:approver:spectrum-authority (ep:key:spectrum-authority#1, Class B)
  log key id:  ep:log:spectrum-strike#1
Keep this file secret. Publish only the verification material or the public keys.
```

> Note: this CLI issues **Class B/C** software-key signoffs. **Class A** device-bound
> WebAuthn signoffs (a biometric/PIN-verified hardware key, the operator never holds it)
> are produced by EP's hosted ceremony, not the CLI. The demo shows the same hash-binding
> property either way — the tamper detection below is identical.

### 2. Define the action (a mock spectrum release) and the escalation attestation

`action.json` — the exact irreversible action a human is authorizing:

```bash
cat > action.json <<'JSON'
{
  "ep_version": "1.0",
  "action_type": "spectrum_release_authorization",
  "target": { "system": "spectrum.coord", "resource": "emission/AOR-7" },
  "parameters": {
    "frequency_mhz": 2401.0,
    "bandwidth_mhz": 20,
    "geo_box": "AOR-7-NE",
    "effect": "active_emission",
    "irreversible": true
  },
  "initiator": "ep:entity:spectrum-triage-agent",
  "policy_id": "ep:policy:spectrum-release@v3",
  "requested_at": "2026-06-13T12:00:00Z"
}
JSON
```

`attestation.json` — PIP-007: the triage agent's own signed reason for escalating
(a claim the protocol identifies but never trusts), bound into what the human signs:

```bash
cat > attestation.json <<'JSON'
{
  "escalation_trigger": "irreversibility",
  "policy_basis": "ep:policy:spectrum-release@v3/rule:active-emission-human-required",
  "statement": "Active emission in a contested AOR is irreversible once radiated; policy requires a named human authorization."
}
JSON
```

### 3. Issue the receipt

```bash
$ISSUE issue \
  --keys issuer-keys.json \
  --action action.json \
  --attestation attestation.json \
  --out receipt.json \
  --verification verification.json
```

Expected output:

```
Wrote authorization receipt to receipt.json
Wrote verification material to verification.json
Verify it anywhere with @emilia-protocol/verify:
  verifyTrustReceipt(receipt, { approverKeys, logPublicKey }) — supply both from verification.json.
```

### 4. Verify the genuine receipt — 7/7, fully offline

```bash
$VERIFY receipt.json --verification verification.json
```

Expected output:

```
✅ VERIFIED — authorization receipt (§6.2) — receipt.json
  ✓ action_hash
  ✓ context_commitments
  ✓ signoff_signatures
  ✓ sod
  ✓ inclusion
  ✓ checkpoint_signature
  ✓ windows
  attestation: present, consistent across contexts
```

Exit code: `0`. Say out loud: *"Seven of seven checks, offline, with only the approver's
public key. A named human authorized this exact emission — 2401 MHz, AOR-7 — before it ran."*

### 5. Mutate ONE field — retarget the emission

An adversary (or a bug) changes the frequency from 2401 MHz to 2455 MHz. Edit `receipt.json`
by hand, or run:

```bash
node -e '
const fs=require("fs");
const r=JSON.parse(fs.readFileSync("receipt.json","utf8"));
r.action.parameters.frequency_mhz = 2455;   // changed from 2401 — emission retargeted
fs.writeFileSync("receipt-tampered.json", JSON.stringify(r,null,2)+"\n");
console.log("Mutated frequency_mhz: 2401 -> 2455 (target retargeted)");
'
```

### 6. Verify the tampered receipt — it collapses

```bash
$VERIFY receipt-tampered.json --verification verification.json
```

Expected output:

```
⛔ NOT VERIFIED — authorization receipt (§6.2) — receipt-tampered.json
  ✕ action_hash
  ✕ context_commitments
  ✓ signoff_signatures
  ✓ sod
  ✕ inclusion
  ✓ checkpoint_signature
  ✓ windows
  attestation: present, consistent across contexts
```

Exit code: `1`. Closing line: *"One number changed and the proof is gone. The human's
signature was over the exact action hash. You cannot retarget the emission and keep the
authorization — the receipt tells you, offline, that the action no longer matches what a
named human approved."*

---

## Browser fallback (no terminal, or terminal blocked)

If a shell isn't available on stage, the offline verifier also runs in the browser at
**emiliaprotocol.ai/verify** — drag in `receipt.json` + the verification material and it
prints the same checks; do the genuine one (all green), then drag in `receipt-tampered.json`
to show the red `action_hash` failure. (The browser build uses Web Crypto and is the same
verifier logic as the package.)

## If fully offline (no npm registry access)

- Pre-install the two packages into the demo dir **before** going offline:
  `npm i @emilia-protocol/issue @emilia-protocol/verify` (then `npx` resolves locally), **or**
- Carry a repo checkout and use the `node $REPO/packages/.../cli.js` form shown in step 0 —
  no registry needed, and
- Pre-generate `receipt.json`, `receipt-tampered.json`, and `verification.json` ahead of
  time so step 4 and step 6 are pure `verify` calls that need no network at all. (Verification
  is offline by design — only first-time package install needs the registry.)

---

## Timing crib (target: 60 seconds)

| Beat | Say | ~sec |
|---|---|---|
| Issue | "A spectrum-triage agent escalates an irreversible release; a named human signs it." | 10 |
| Verify good | "Seven of seven checks, offline, just a public key." | 15 |
| Mutate | "An adversary retargets the emission — one number, 2401 to 2455." | 10 |
| Verify bad | "Verification collapses. The proof was bound to the exact action." | 20 |
| Land | "That's the audit teeth behind the 0%-false-negative bar." | 5 |
