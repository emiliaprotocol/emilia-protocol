// SPDX-License-Identifier: Apache-2.0
// What `sign` shows the approver before signing, and the JSON the CLI prints.
//
// Every string that reaches a terminal goes through displaySafe. Characters a
// terminal acts on (C0 and C1 controls, DEL) or that reorder or hide text
// (bidi controls, zero-width and other format characters, line and paragraph
// separators, lone surrogates) are shown as \u escapes instead. JSON.stringify
// alone escapes only C0, so a rule, a note or a log line could otherwise move
// the cursor and redraw what the approver is reading.
//
// The prompt shows only what the receipt covers (rule name, the canonical rule
// text behind rule_digest, the review token) plus this tool's own checks of
// that rule text. OpenShell's security notes are not covered by the receipt;
// they are shown, escaped, only when they come from the gateway directly.

import type { ChunkView, PolicyRevisionView } from './gateway-client.ts';
import type { Json } from './struct-json.ts';

const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu;

function unitEscapes(ch: string): string {
  let out = '';
  for (let i = 0; i < ch.length; i += 1) out += `\\u${ch.charCodeAt(i).toString(16).padStart(4, '0')}`;
  return out;
}

/** Text safe to write to a terminal. With keepNewlines, "\n" stays a line break. */
export function displaySafe(text: string, opts: { keepNewlines?: boolean } = {}): string {
  return String(text).replace(UNSAFE, (ch) => (opts.keepNewlines && ch === '\n' ? ch : unitEscapes(ch)));
}

/**
 * Pretty JSON with every unsafe character inside strings written as a \u
 * escape. The output is still valid JSON for the same value: outside strings,
 * JSON.stringify emits only ASCII punctuation, digits, letters and "\n".
 */
export function safeJson(value: unknown): string {
  return JSON.stringify(value, null, 2).replace(UNSAFE, (ch) => (ch === '\n' ? ch : unitEscapes(ch)));
}

type Obj = { [key: string]: Json };

function isObj(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * This tool's own checks of a canonical rule. They are not OpenShell's
 * security notes and do not claim to reproduce them; they flag the rule-text
 * features an approver most needs to see, from the text the digest covers.
 */
export function localRuleChecks(rule: Obj | null): string[] {
  if (!rule) return [];
  const flags: string[] = [];
  const endpoints = Array.isArray(rule.endpoints) ? rule.endpoints.filter(isObj) : [];
  for (const e of endpoints) {
    const host = typeof e.host === 'string' ? e.host : '';
    const where = host === '' ? 'an endpoint with no host' : `host ${JSON.stringify(host)}`;
    const ips = Array.isArray(e.allowed_ips) && e.allowed_ips.length > 0;
    if (host === '') flags.push(ips ? 'endpoint with no host: any domain that resolves into its allowed_ips' : 'endpoint with no host');
    else if (host.includes('*')) flags.push(`wildcard host ${JSON.stringify(host)}`);
    if (e.allow_uninspected_credentials === true) flags.push(`allow_uninspected_credentials on ${where}: credential-bearing traffic OpenShell cannot inspect`);
    if (ips) flags.push(`allowed_ips ${JSON.stringify(e.allowed_ips)} on ${where}: replaces the internal-address check`);
    if (isObj(e.credential_binding)) flags.push(`credential_binding ${JSON.stringify(e.credential_binding)} on ${where}`);
  }
  const binaries = Array.isArray(rule.binaries) ? rule.binaries.filter(isObj) : [];
  for (const b of binaries) {
    if (typeof b.path === 'string' && b.path.includes('*')) flags.push(`binary path with "*": ${JSON.stringify(b.path)}`);
  }
  if (binaries.length === 0) flags.push('no binaries: an any-binary rule, usable by every binary in the sandbox');
  return flags;
}

export type Freshness =
  | { status: 'current'; message: string }
  | { status: 'stale'; message: string }
  | { status: 'unchecked'; message: string };

/**
 * Whether the chunk's stored review token can still commit. The gateway
 * computes the token over, among other inputs, the hash of the sandbox's
 * effective policy at evaluation time (current_effective_policy_hash), and
 * GetDraftPolicy returns the stored token without re-evaluating it. When
 * another approval has since moved the sandbox to a newer policy revision,
 * the stored token is dead: the gateway refuses it, refreshes the evaluation,
 * and only then does GetDraftPolicy return a token that can commit.
 *
 * Without provider layers the effective policy is the newest revision, so
 * the two hashes must be equal. With provider layers they can differ even
 * when the token is current, so a mismatch there is reported, not decided.
 */
export function tokenFreshness(chunk: ChunkView, sandbox: string, revisions: PolicyRevisionView[], providers: string[]): Freshness {
  const head = revisions.length > 0 ? revisions.reduce((a, b) => (b.version > a.version ? b : a)) : null;
  if (!head) return { status: 'unchecked', message: 'not checked: the sandbox has no policy revision to compare against' };
  if (!chunk.current_effective_policy_hash) return { status: 'unchecked', message: 'not checked: the gateway did not report the chunk\'s current_effective_policy_hash' };
  if (chunk.current_effective_policy_hash === head.policy_hash) {
    return { status: 'current', message: `current (evaluated against policy v${head.version})` };
  }
  const base = `the review token predates policy v${head.version}: the chunk was evaluated against effective policy ${chunk.current_effective_policy_hash.slice(0, 12)}, and the sandbox is now at v${head.version} ${head.policy_hash.slice(0, 12)}`;
  if (providers.length > 0) {
    return {
      status: 'stale',
      message: `${base}. This sandbox has provider layers (${providers.length}), so the two hashes can differ even when the token is current, and \`openshell rule approve\` would then commit. Pass --allow-policy-hash-mismatch to sign anyway.`,
    };
  }
  return {
    status: 'stale',
    message: `${base}. The gateway will refuse this token. Run \`openshell rule approve ${sandbox} --chunk-id ${chunk.chunk_id}\` once (the gateway refuses it and refreshes the token), then sign again.`,
  };
}

export function describeRule(chunk: ChunkView, opts: { notes: 'gateway' | 'offline'; freshness: string }): string {
  const rule = chunk.proposed_rule ?? {};
  const endpoints = Array.isArray(rule.endpoints) ? rule.endpoints : [];
  const binaries = Array.isArray(rule.binaries) ? rule.binaries : [];
  const checks = localRuleChecks(chunk.proposed_rule);
  const lines = [
    `  sandbox rule    ${chunk.rule_name}`,
    ...(typeof rule.name === 'string' && rule.name !== chunk.rule_name ? [`  rule text name  ${rule.name}`] : []),
    ...endpoints.map((e) => `  endpoint        ${JSON.stringify(e)}`),
    ...binaries.map((b) => `  binary          ${JSON.stringify(b)}`),
    `  local checks    ${checks.length > 0 ? checks.join('; ') : '(none)'}`,
    opts.notes === 'gateway'
      ? `  security notes  ${chunk.security_notes || '(none)'}  [from the gateway; not covered by the receipt]`
      : '  security notes  not shown: an offline export\'s notes are not covered by the receipt',
    `  rule digest     ${chunk.rule_digest ?? '(none)'}`,
    `  review token    ${chunk.review_token}`,
    `  token freshness ${opts.freshness}`,
  ];
  return lines.map((line) => displaySafe(line)).join('\n');
}
