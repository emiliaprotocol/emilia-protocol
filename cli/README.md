# @emilia-protocol/cli

Command-line interface for EMILIA Protocol — query trust profiles, evaluate policies, submit receipts, and run install preflight from your terminal.

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
# Public operations (no API key needed)
ep register my-agent --name "My Shopping Agent" --type agent
ep profile merchant-xyz
ep evaluate merchant-xyz --policy strict
ep preflight mcp-server-abc --policy mcp_server_safe_v1
ep score merchant-xyz
ep dispute ep_disp_abc123
ep policies
ep health

# Authenticated write operations (EP_API_KEY required)
ep submit merchant-xyz --ref order_123 --behavior completed
```

## Example output

```
$ ep profile merchant-xyz

  ElectroMart Pro
  Confidence: emerging
  Score: 87.3/100
  Evidence: 12.4 (quality-gated: 12.4)
  Established: Yes
  Receipts: 47

  Behavioral:
    Completion: 94.3%
    Dispute:    0.7%

$ ep evaluate merchant-xyz --policy strict

  Policy: strict
  Pass: ✓ YES
  Score: 87.3/100
  Confidence: emerging

$ ep preflight mcp-server-abc --policy mcp_server_safe_v1

  ✓ ALLOW — mcp-server-abc
  Policy: mcp_server_safe_v1
    ✓ publisher_verified
    ✓ provenance_verified
    ✓ permission_class_acceptable
```

## License

Apache 2.0
