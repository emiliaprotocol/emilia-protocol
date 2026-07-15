# @emilia-protocol/cli

Command-line interface for EMILIA Protocol. Verify portable authorization evidence fully offline, or call the hosted trust-profile and dispute APIs.

## Install

```bash
npx @emilia-protocol/cli --help
```

Or install globally:

```bash
npm install -g @emilia-protocol/cli
ep --help
```

## Setup

```bash
export EP_BASE_URL=https://emiliaprotocol.ai   # default
export EP_API_KEY=ep_live_your_key_here         # for write operations
```

## Commands

```bash
# Verify locally. The receipt never leaves your machine.
ep verify receipt.json
ep verify receipt.json --key MCowBQYDK2VwAyEA...

# The verifier also recognizes bundles, commitment proofs, WebAuthn signoffs,
# multi-party quorum documents, provenance chains, and Section 6.2 receipts.
ep verify packet.json --verification verification.json

# Hosted read operations (no API key needed)
ep verify-remote ep_rcpt_abc123
ep profile merchant-xyz
ep evaluate merchant-xyz --policy strict
ep preflight mcp-server-abc --policy mcp_server_safe_v1
ep score merchant-xyz
ep dispute ep_disp_abc123
ep policies
ep health

# Hosted write operations (EP_API_KEY required)
ep register my-agent --name "My Shopping Agent" --type agent
ep submit merchant-xyz --ref order_123 --behavior completed
ep dispute file ep_rcpt_abc123 --reason "Action was not authorized"
ep appeal ep_disp_abc123 --reason "New evidence attached"
```

`ep verify` delegates to the version-pinned `@emilia-protocol/verify` package. It does not call an EMILIA service, fetch keys, or silently substitute hosted verification.

## Offline example

```
$ ep verify receipt.json
VERIFIED - receipt - receipt.json
  version
  signature
```

The verifier prints every applicable check and exits nonzero for malformed, tampered, unpinned, or otherwise unverifiable evidence.

## License

Apache 2.0
