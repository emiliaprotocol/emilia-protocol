// SPDX-License-Identifier: Apache-2.0
// Parses the gateway's shorthand policy audit lines from its stdout log, e.g.
//
//   ... ocsf: sandbox_id=<id> CONFIG:APPROVED [INFO] gateway approved draft chunk <id>: <summary> [version:v2 hash:<64 hex>]
//   ... ocsf: sandbox_id=<id> CONFIG:APPROVED [INFO] auto-approved: ... chunk <id>: ... [auto:true source:mechanistic ... version:v7 hash:<64 hex>]
//   ... ocsf: sandbox_id=<id> CONFIG:MERGED [INFO] gateway bulk-approved 2 draft chunk(s) and skipped 0 [version:v4 hash:<64 hex>]
//
// These are text lines on the gateway's `ocsf` tracing target, not structured
// OCSF JSON, and nothing authenticates them: whoever runs the gateway can edit
// the file. Only lines that carry sandbox_id are used. A line that records a
// policy version but has no sandbox_id cannot be attributed to a sandbox; it
// is counted (the check reports it), not guessed at.
//
// Parsing is linear in the input. A line longer than MAX_CONFIG_LINE is not
// parsed and is reported as unparsed.

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
  /** Lines that record a policy version but carry no sandbox_id. */
  lines_without_sandbox_id: number;
  unparsed_config_lines: number[];
}

export const MAX_CONFIG_LINE = 64 * 1024;

const ANSI = /\u001b\[[0-9;]*[A-Za-z]/g;
// Anchored at "CONFIG:" and bounded, so a hostile line cannot make the
// match backtrack. The `s` flag lets the tail take any character, so it
// never has to give text back to the preceding \s+.
const CONFIG = /^CONFIG:([A-Z_]{1,32})\s+\[[A-Z]{1,16}\]\s+(.*)$/s;
const SANDBOX_TOKEN = /^sandbox_id=(\S{1,128})$/;
const MAX_SANDBOX_TOKEN = 'sandbox_id='.length + 128;

/** The sandbox id when the token right before "CONFIG:" is sandbox_id=<id>. */
function sandboxIdBefore(prefix: string): string | null {
  if (prefix !== '' && !/\s$/.test(prefix)) return null;
  const trimmed = prefix.trimEnd();
  let start = trimmed.length;
  while (start > 0 && !/\s/.test(trimmed[start - 1])) {
    start -= 1;
    if (trimmed.length - start > MAX_SANDBOX_TOKEN) return null;
  }
  const match = SANDBOX_TOKEN.exec(trimmed.slice(start));
  return match ? match[1] : null;
}

export function parseGatewayLog(text: string): ParsedGatewayLog {
  const out: ParsedGatewayLog = { events: [], lines_without_sandbox_id: 0, unparsed_config_lines: [] };
  if (typeof text !== 'string') return out;
  const lines = text.split('\n');
  lines.forEach((rawLine, index) => {
    if (!rawLine.includes('CONFIG:')) return;
    if (rawLine.length > MAX_CONFIG_LINE) {
      out.unparsed_config_lines.push(index + 1);
      return;
    }
    const line = rawLine.replace(ANSI, '').trimEnd();
    const at = line.indexOf('CONFIG:');
    const match = at < 0 ? null : CONFIG.exec(line.slice(at));
    if (!match) {
      out.unparsed_config_lines.push(index + 1);
      return;
    }
    const sandboxId = sandboxIdBefore(line.slice(0, at));
    const [, state, rest] = match;
    const open = rest.lastIndexOf('[');
    if (!rest.endsWith(']') || open < 0) {
      // e.g. "bulk-approved 0 draft chunk(s)" with no new version: no transition.
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
