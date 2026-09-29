// SPDX-License-Identifier: Apache-2.0
// Parses the gateway's shorthand policy audit lines from its stdout log, e.g.
//
//   ... ocsf: sandbox_id=<id> CONFIG:APPROVED [INFO] gateway approved draft chunk <id>: <summary> [version:v2 hash:<64 hex>]
//   ... ocsf: sandbox_id=<id> CONFIG:APPROVED [INFO] auto-approved: ... chunk <id>: ... [auto:true source:mechanistic ... version:v7 hash:<64 hex>]
//   ... ocsf: sandbox_id=<id> CONFIG:MERGED [INFO] gateway bulk-approved 2 draft chunk(s) and skipped 0 [version:v4 hash:<64 hex>]
//
// These are text lines on the gateway's `ocsf` tracing target, not structured
// OCSF JSON. Only lines that carry sandbox_id are used: a line without it
// cannot be attributed to a sandbox and is counted, not guessed at.

export interface GatewayPolicyEvent {
  line: number;
  sandbox_id: string;
  state: string;
  auto: boolean;
  source: string | null;
  chunk_id: string | null;
  version: number;
  policy_hash: string;
  bulk_summary: boolean;
  message: string;
}

export interface ParsedGatewayLog {
  events: GatewayPolicyEvent[];
  lines_without_sandbox_id: number;
  unparsed_config_lines: number[];
}

const ANSI = /\u001b\[[0-9;]*[A-Za-z]/g;
const CONFIG = /(?:sandbox_id=(\S+)\s+)?CONFIG:([A-Z_]+)\s+\[[A-Z]+\]\s+(.*)$/;

export function parseGatewayLog(text: string): ParsedGatewayLog {
  const out: ParsedGatewayLog = { events: [], lines_without_sandbox_id: 0, unparsed_config_lines: [] };
  if (typeof text !== 'string') return out;
  const lines = text.split('\n');
  lines.forEach((rawLine, index) => {
    if (!rawLine.includes('CONFIG:')) return;
    const line = rawLine.replace(ANSI, '').trimEnd();
    const match = CONFIG.exec(line);
    if (!match) {
      out.unparsed_config_lines.push(index + 1);
      return;
    }
    const [, sandboxId, state, rest] = match;
    const open = rest.lastIndexOf('[');
    if (!rest.endsWith(']') || open < 0) {
      // e.g. "bulk-approved 0 draft chunk(s)" with no new version: no transition.
      if (!sandboxId) out.lines_without_sandbox_id += 1;
      return;
    }
    const tags = new Map<string, string>();
    for (const token of rest.slice(open + 1, -1).split(/\s+/)) {
      const colon = token.indexOf(':');
      if (colon > 0) tags.set(token.slice(0, colon), token.slice(colon + 1));
    }
    const versionTag = /^v(\d{1,9})$/.exec(tags.get('version') ?? '');
    const hash = tags.get('hash') ?? '';
    if (!versionTag || !/^[0-9a-f]{64}$/.test(hash)) {
      out.unparsed_config_lines.push(index + 1);
      return;
    }
    if (!sandboxId) {
      out.lines_without_sandbox_id += 1;
      return;
    }
    const message = rest.slice(0, open).trim();
    const chunk = /chunk ([0-9A-Za-z-]{8,64}):/.exec(message);
    out.events.push({
      line: index + 1,
      sandbox_id: sandboxId,
      state,
      auto: tags.get('auto') === 'true',
      source: tags.get('source') ?? null,
      chunk_id: chunk ? chunk[1] : null,
      version: Number(versionTag[1]),
      policy_hash: hash,
      bulk_summary: /^gateway bulk-approved \d+ draft chunk/.test(message),
      message,
    });
  });
  return out;
}
