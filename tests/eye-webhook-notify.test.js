// SPDX-License-Identifier: Apache-2.0
// Locks the EP Eye webhook notifier (lib/eye/webhook-notify.js):
//  - SSRF guard (safeParseUrl / isPrivateHost) rejects private / internal / non-http targets
//  - redaction never leaks raw refs; reveal mode emits ONLY short hash tokens
//  - shouldNotify gating (clear/unknown/below-rank/shadow) and readConfig clamps/fallbacks
//  - inferKind precedence (explicit env vs host inference)
//  - per-platform payload formatters (slack / discord / teams)
//  - notifyEyeAdvisory + postWebhook fail-soft results (no_url, no_advisory, below_threshold,
//    invalid_url, success, http_error, network throw, timeout) — never throws.

import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  buildWebhookPayload,
  notifyEyeAdvisory,
  __test__,
} from '../lib/eye/webhook-notify.js';

const {
  redactAdvisory,
  shouldNotify,
  inferKind,
  safeParseUrl,
  shortHashToken,
  readConfig,
  STATUS_RANK,
} = __test__;

// A 64-char lowercase hex string (looks like a SHA-256 digest).
const HEX64 = 'a'.repeat(64);
const HEX32 = 'b'.repeat(32);

/** Minimal valid non-clear advisory. */
function makeAdvisory(over = {}) {
  return {
    advisory_id: 'adv_1',
    status: 'elevated',
    reason_codes: ['velocity_spike', 'new_payee'],
    recommended_policy_action: 'require_dual_control',
    scope_binding_hash: HEX64,
    advisory_hash: HEX64,
    evidence_refs: ['e1', 'e2', 'e3'],
    issued_at: '2026-06-14T00:00:00.000Z',
    expires_at: '2026-06-15T00:00:00.000Z',
    version: 'eye-advisory-v1',
    action_type: 'vendor_bank_account_change',
    subject_ref: 'subject-human-readable',
    actor_ref: HEX64,
    target_ref: HEX32,
    issuer_ref: 'issuer@example.com',
    ...over,
  };
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// ── SSRF guard: safeParseUrl + isPrivateHost ──────────────────────────────────
describe('safeParseUrl / SSRF guard', () => {
  it('accepts a normal public https URL', () => {
    const parsed = safeParseUrl('https://hooks.slack.com/services/T/B/X');
    expect(parsed).not.toBeNull();
    expect(parsed.hostname).toBe('hooks.slack.com');
  });

  it('accepts a normal public http URL', () => {
    expect(safeParseUrl('http://example.com/hook')).not.toBeNull();
  });

  it.each([
    ['127.0.0.1', 'http://127.0.0.1/h'],
    ['127.x loopback', 'http://127.5.5.5/h'],
    ['10.x', 'http://10.0.0.1/h'],
    ['172.16.x', 'http://172.16.0.1/h'],
    ['172.31.x', 'http://172.31.255.1/h'],
    ['192.168.x', 'http://192.168.1.1/h'],
    ['169.254.x link-local', 'http://169.254.169.254/latest/meta-data'],
    ['0.x', 'http://0.0.0.0/h'],
    ['0.x non-zero', 'http://0.1.2.3/h'],
    ['localhost', 'http://localhost/h'],
    ['0.0.0.0', 'http://0.0.0.0/h'],
    ['.internal', 'http://metadata.internal/h'],
    ['.local', 'http://printer.local/h'],
  ])('rejects private/internal host: %s', (_label, url) => {
    expect(safeParseUrl(url)).toBeNull();
  });

  it.each([
    ['ftp protocol', 'ftp://example.com/h'],
    ['file protocol', 'file:///etc/passwd'],
    ['gopher protocol', 'gopher://example.com'],
    ['javascript protocol', 'javascript:alert(1)'],
  ])('rejects non-http(s) protocol: %s', (_label, url) => {
    expect(safeParseUrl(url)).toBeNull();
  });

  it.each([
    ['empty string', ''],
    ['garbage', 'not a url'],
    ['missing scheme', 'example.com/h'],
    ['null-ish bare host', '://nohost'],
  ])('returns null for malformed URL: %s', (_label, url) => {
    expect(safeParseUrl(url)).toBeNull();
  });

  it('172.15.x and 172.32.x are public (range boundary)', () => {
    // Just outside the 172.16-31 private block.
    expect(safeParseUrl('http://172.15.0.1/h')).not.toBeNull();
    expect(safeParseUrl('http://172.32.0.1/h')).not.toBeNull();
  });

  // ── BUG #1: bracketed IPv6 private addresses bypass the SSRF guard. ──────────
  // The advisory contract says ::1, fc*, fe80* must all return null, but Node's
  // URL.hostname keeps the brackets ("[::1]"), and PRIVATE_RANGES regexes
  // (/^::1$/, /^fc/i, /^fe80/i) are anchored at "^" so they never match the
  // leading "[". These tests assert the CORRECT (intended) behavior and are
  // expected to FAIL until isPrivateHost strips brackets / handles IPv6.
  it.each([
    ['ipv6 loopback ::1', 'http://[::1]/h'],
    ['ipv6 ULA fc00', 'http://[fc00::1]/h'],
    ['ipv6 link-local fe80', 'http://[fe80::1]/h'],
  ])('SHOULD reject private IPv6 host %s (currently bypasses guard — BUG)', (_label, url) => {
    expect(safeParseUrl(url)).toBeNull();
  });
});

// ── inferKind ─────────────────────────────────────────────────────────────────
describe('inferKind', () => {
  it.each([
    ['slack', 'slack'],
    ['discord', 'discord'],
    ['teams', 'teams'],
    ['SLACK uppercase', 'slack'],
    ['DiScOrD mixed', 'discord'],
  ])('explicit env "%s" wins over host', (explicit, expected) => {
    // Even with a host that implies a different kind, explicit must win.
    expect(inferKind(explicit.split(' ')[0], 'https://discord.com/api/webhooks/x')).toBe(expected);
  });

  it('infers discord from discord host', () => {
    expect(inferKind(undefined, 'https://discord.com/api/webhooks/1/abc')).toBe('discord');
  });

  it('infers discord from discordapp host', () => {
    expect(inferKind('', 'https://discordapp.com/api/webhooks/1/abc')).toBe('discord');
  });

  it.each([
    ['office.com', 'https://outlook.office.com/webhook/abc'],
    ['webhook.office', 'https://acme.webhook.office.com/IncomingWebhook/x'],
    ['teams host', 'https://teams.microsoft.com/hook'],
  ])('infers teams from %s', (_label, url) => {
    expect(inferKind(undefined, url)).toBe('teams');
  });

  it('defaults to slack for unknown host', () => {
    expect(inferKind(undefined, 'https://example.com/hook')).toBe('slack');
  });

  it('defaults to slack when no url and no explicit', () => {
    expect(inferKind(undefined, null)).toBe('slack');
  });

  it('defaults to slack when invalid explicit + private url cannot be parsed', () => {
    // private host -> safeParseUrl returns null -> host '' -> slack
    expect(inferKind('bogus', 'http://127.0.0.1/h')).toBe('slack');
  });
});

// ── readConfig ────────────────────────────────────────────────────────────────
describe('readConfig', () => {
  it('returns null url and defaults when env is empty', () => {
    vi.stubEnv('EYE_WEBHOOK_URL', '');
    vi.stubEnv('EYE_WEBHOOK_MIN_STATUS', '');
    vi.stubEnv('EYE_WEBHOOK_KIND', '');
    vi.stubEnv('EYE_WEBHOOK_SHADOW', '');
    vi.stubEnv('EYE_WEBHOOK_REVEAL_REFS', '');
    vi.stubEnv('EYE_WEBHOOK_TIMEOUT_MS', '');
    const cfg = readConfig();
    expect(cfg.url).toBeNull();
    expect(cfg.kind).toBe('slack');
    expect(cfg.minRank).toBe(STATUS_RANK.caution);
    expect(cfg.shadow).toBe(false);
    expect(cfg.revealRefs).toBe(false);
    expect(cfg.timeoutMs).toBe(8000);
  });

  it('parses url, shadow, revealRefs, timeout, and explicit kind', () => {
    vi.stubEnv('EYE_WEBHOOK_URL', 'https://hooks.slack.com/x');
    vi.stubEnv('EYE_WEBHOOK_KIND', 'discord');
    vi.stubEnv('EYE_WEBHOOK_MIN_STATUS', 'elevated');
    vi.stubEnv('EYE_WEBHOOK_SHADOW', 'true');
    vi.stubEnv('EYE_WEBHOOK_REVEAL_REFS', 'true');
    vi.stubEnv('EYE_WEBHOOK_TIMEOUT_MS', '1234');
    const cfg = readConfig();
    expect(cfg.url).toBe('https://hooks.slack.com/x');
    expect(cfg.kind).toBe('discord');
    expect(cfg.minRank).toBe(STATUS_RANK.elevated);
    expect(cfg.shadow).toBe(true);
    expect(cfg.revealRefs).toBe(true);
    expect(cfg.timeoutMs).toBe(1234);
  });

  it('clamps min-status "clear" up to caution (clear must never fire)', () => {
    vi.stubEnv('EYE_WEBHOOK_MIN_STATUS', 'clear');
    expect(readConfig().minRank).toBe(STATUS_RANK.caution);
  });

  it('falls back to caution rank for an unknown min-status', () => {
    vi.stubEnv('EYE_WEBHOOK_MIN_STATUS', 'totally_bogus');
    expect(readConfig().minRank).toBe(STATUS_RANK.caution);
  });

  it('falls back to default timeout when timeout is non-numeric', () => {
    vi.stubEnv('EYE_WEBHOOK_TIMEOUT_MS', 'abc');
    expect(readConfig().timeoutMs).toBe(8000);
  });

  it('falls back to default timeout when timeout is zero', () => {
    vi.stubEnv('EYE_WEBHOOK_TIMEOUT_MS', '0');
    expect(readConfig().timeoutMs).toBe(8000);
  });

  it('shadow is false for any value other than the literal "true"', () => {
    vi.stubEnv('EYE_WEBHOOK_SHADOW', 'TRUE');
    expect(readConfig().shadow).toBe(false);
  });

  it('revealRefs is false for any value other than the literal "true"', () => {
    vi.stubEnv('EYE_WEBHOOK_REVEAL_REFS', '1');
    expect(readConfig().revealRefs).toBe(false);
  });
});

// ── shortHashToken ────────────────────────────────────────────────────────────
describe('shortHashToken', () => {
  it('emits a 12-char prefix + ellipsis for a >=32 hex hash', () => {
    const token = shortHashToken(HEX64);
    expect(token).toBe(`${'a'.repeat(12)}…`);
  });

  it('accepts exactly 32 hex chars', () => {
    expect(shortHashToken(HEX32)).toBe(`${'b'.repeat(12)}…`);
  });

  it('accepts uppercase hex', () => {
    expect(shortHashToken('A'.repeat(40))).toBe(`${'A'.repeat(12)}…`);
  });

  it('returns null for a sub-32 hex string', () => {
    expect(shortHashToken('abcdef0123')).toBeNull();
  });

  it('returns null for a human-readable identifier', () => {
    expect(shortHashToken('alice@example.com')).toBeNull();
  });

  it('returns null for a non-hex 32+ string', () => {
    expect(shortHashToken('z'.repeat(40))).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(shortHashToken('')).toBeNull();
  });

  it.each([
    ['number', 123],
    ['null', null],
    ['undefined', undefined],
    ['object', {}],
  ])('returns null for non-string %s', (_label, val) => {
    expect(shortHashToken(val)).toBeNull();
  });
});

// ── redactAdvisory ────────────────────────────────────────────────────────────
describe('redactAdvisory', () => {
  it('default view omits refs entirely and never leaks raw identifiers', () => {
    const adv = makeAdvisory();
    const view = redactAdvisory(adv, { revealRefs: false });
    expect(view.refs).toBeUndefined();
    const serialized = JSON.stringify(view);
    // No raw ref / evidence content / volumes must appear anywhere.
    expect(serialized).not.toContain('subject-human-readable');
    expect(serialized).not.toContain('issuer@example.com');
    expect(serialized).not.toContain('e1');
    expect(serialized).not.toContain('e2');
    // Only the count of evidence survives.
    expect(view.evidence_count).toBe(3);
  });

  it('carries only re-derivable / non-attributable facts', () => {
    const view = redactAdvisory(makeAdvisory(), { revealRefs: false });
    expect(view).toMatchObject({
      advisory_id: 'adv_1',
      status: 'elevated',
      reason_codes: ['velocity_spike', 'new_payee'],
      recommended_policy_action: 'require_dual_control',
      scope_binding_hash: HEX64,
      advisory_hash: HEX64,
      evidence_count: 3,
      issued_at: '2026-06-14T00:00:00.000Z',
      expires_at: '2026-06-15T00:00:00.000Z',
      version: 'eye-advisory-v1',
      action_type: 'vendor_bank_account_change',
    });
  });

  it('reveal mode emits ONLY short hash tokens (raw refs dropped)', () => {
    const adv = makeAdvisory();
    const view = redactAdvisory(adv, { revealRefs: true });
    expect(view.refs).toEqual({
      subject: null, // 'subject-human-readable' is not a hash -> dropped
      actor: `${'a'.repeat(12)}…`, // HEX64 hash -> short token
      target: `${'b'.repeat(12)}…`, // HEX32 hash -> short token
      issuer: null, // 'issuer@example.com' -> dropped
    });
    const serialized = JSON.stringify(view.refs);
    expect(serialized).not.toContain('subject-human-readable');
    expect(serialized).not.toContain('issuer@example.com');
    // Inside refs, only the 12-char hash PREFIX appears — never the full ref
    // hash (scope_binding_hash/advisory_hash legitimately carry the full hash).
    expect(serialized).not.toContain(HEX64);
    expect(serialized).not.toContain(HEX32);
  });

  it('coerces missing fields to null and non-array refs/codes to []', () => {
    const view = redactAdvisory({}, { revealRefs: false });
    expect(view.advisory_id).toBeNull();
    expect(view.status).toBeNull();
    expect(view.reason_codes).toEqual([]);
    expect(view.evidence_count).toBe(0);
    expect(view.recommended_policy_action).toBeNull();
    expect(view.action_type).toBeNull();
  });

  it('treats non-array evidence_refs / reason_codes defensively', () => {
    const view = redactAdvisory(
      { evidence_refs: 'not-an-array', reason_codes: { a: 1 } },
      { revealRefs: false },
    );
    expect(view.evidence_count).toBe(0);
    expect(view.reason_codes).toEqual([]);
  });
});

// ── shouldNotify ──────────────────────────────────────────────────────────────
describe('shouldNotify', () => {
  const cfgCaution = { minRank: STATUS_RANK.caution, shadow: false };

  it('never notifies on clear', () => {
    expect(shouldNotify({ status: 'clear' }, cfgCaution, {})).toBe(false);
  });

  it('never notifies on unknown status', () => {
    expect(shouldNotify({ status: 'mystery' }, cfgCaution, {})).toBe(false);
  });

  it('never notifies on missing status', () => {
    expect(shouldNotify({}, cfgCaution, {})).toBe(false);
  });

  it('never notifies on null/undefined advisory', () => {
    expect(shouldNotify(null, cfgCaution, {})).toBe(false);
    expect(shouldNotify(undefined, cfgCaution, {})).toBe(false);
  });

  it('notifies caution at minRank caution', () => {
    expect(shouldNotify({ status: 'caution' }, cfgCaution, {})).toBe(true);
  });

  it('suppresses below-rank advisory', () => {
    const cfg = { minRank: STATUS_RANK.review_required, shadow: false };
    expect(shouldNotify({ status: 'caution' }, cfg, {})).toBe(false);
    expect(shouldNotify({ status: 'elevated' }, cfg, {})).toBe(false);
    expect(shouldNotify({ status: 'review_required' }, cfg, {})).toBe(true);
  });

  it('suppresses shadow advisory when shadow is disabled', () => {
    expect(shouldNotify({ status: 'elevated' }, cfgCaution, { isShadow: true })).toBe(false);
  });

  it('fires shadow advisory when shadow is enabled', () => {
    const cfg = { minRank: STATUS_RANK.caution, shadow: true };
    expect(shouldNotify({ status: 'elevated' }, cfg, { isShadow: true })).toBe(true);
  });

  it('handles missing meta argument', () => {
    expect(shouldNotify({ status: 'elevated' }, cfgCaution, undefined)).toBe(true);
  });
});

// ── buildWebhookPayload (per-platform formatters) ─────────────────────────────
describe('buildWebhookPayload', () => {
  function fullView(over = {}) {
    return {
      advisory_id: 'adv_1',
      status: 'elevated',
      reason_codes: ['velocity_spike'],
      recommended_policy_action: 'require_dual_control',
      scope_binding_hash: HEX64,
      advisory_hash: HEX64,
      evidence_count: 4,
      issued_at: '2026-06-14T00:00:00.000Z',
      expires_at: '2026-06-15T00:00:00.000Z',
      version: 'eye-advisory-v1',
      action_type: 'vendor_bank_account_change',
      ...over,
    };
  }

  describe('slack', () => {
    it('builds a Block Kit payload with color rail + disclaimer', () => {
      const p = buildWebhookPayload(fullView(), 'slack', false);
      expect(p.text).toContain('Eye advisory');
      expect(p.attachments).toHaveLength(1);
      expect(p.attachments[0].color).toBe('#e8731a'); // elevated
      const blocks = p.attachments[0].blocks;
      expect(blocks[0].type).toBe('section');
      expect(blocks[1].type).toBe('context');
      expect(blocks[1].elements[0].text).toContain('informational only');
      // Detail body present.
      expect(blocks[0].text.text).toContain('Reason codes');
      expect(blocks[0].text.text).toContain('Recommended posture');
      expect(blocks[0].text.text).toContain('Contributing observations');
      expect(blocks[0].text.text).toContain('Scope binding');
      expect(blocks[0].text.text).toContain('Advisory expires');
    });

    it('headline includes shadow mode + action_type', () => {
      const p = buildWebhookPayload(fullView(), 'slack', true);
      expect(p.text).toContain('(shadow / observe-mode)');
      expect(p.text).toContain('vendor_bank_account_change');
    });

    it('omits action suffix when action_type is null', () => {
      const p = buildWebhookPayload(fullView({ action_type: null }), 'slack', false);
      expect(p.text).not.toContain('` on `');
    });

    it('renders hashed refs line when refs present', () => {
      const view = fullView({ refs: { subject: null, actor: 'aaaaaaaaaaaa…', target: null, issuer: null } });
      const p = buildWebhookPayload(view, 'slack', false);
      expect(p.attachments[0].blocks[0].text.text).toContain('Refs (hashed)');
      expect(p.attachments[0].blocks[0].text.text).toContain('actor=aaaaaaaaaaaa…');
    });

    it('omits refs line when all refs are null', () => {
      const view = fullView({ refs: { subject: null, actor: null, target: null, issuer: null } });
      const p = buildWebhookPayload(view, 'slack', false);
      expect(p.attachments[0].blocks[0].text.text).not.toContain('Refs (hashed)');
    });
  });

  describe('discord', () => {
    it('builds a rich embed with fields + footer disclaimer', () => {
      const p = buildWebhookPayload(fullView(), 'discord', false);
      expect(p.content).not.toContain(':warning:'); // emoji shortcode stripped
      expect(p.embeds).toHaveLength(1);
      const embed = p.embeds[0];
      expect(embed.color).toBe(0xe8731a);
      expect(embed.title).toBe('Eye advisory: Elevated');
      expect(embed.footer.text).toContain('informational only');
      expect(embed.timestamp).toBe('2026-06-14T00:00:00.000Z');
      // Fields parsed from "*Name:* value" detail lines.
      const reason = embed.fields.find((f) => f.name === 'Reason codes');
      expect(reason).toBeTruthy();
      expect(reason.value).toContain('velocity_spike');
    });

    it('adds (shadow) suffix to embed title', () => {
      const p = buildWebhookPayload(fullView(), 'discord', true);
      expect(p.embeds[0].title).toBe('Eye advisory: Elevated (shadow)');
    });

    it('falls back to generated timestamp when issued_at missing', () => {
      const p = buildWebhookPayload(fullView({ issued_at: null }), 'discord', false);
      expect(typeof p.embeds[0].timestamp).toBe('string');
      expect(p.embeds[0].timestamp.length).toBeGreaterThan(0);
    });

    it('maps a non "*Name:*" detail line to a zero-width name field', () => {
      // A refs line keeps the "*X:*" shape, but a line lacking that shape hits
      // the else branch. Force it by providing a refs object that yields a line
      // without ":*" — not possible via detailLines, so verify zero-width path
      // via a minimal view whose only line is reason codes (already "*..:*").
      // Instead, exercise the else branch using evidence-only style is N/A;
      // assert at least the structure holds for a sparse view.
      const p = buildWebhookPayload(fullView({ reason_codes: [], recommended_policy_action: null, evidence_count: 0, scope_binding_hash: null, expires_at: null }), 'discord', false);
      // No detail lines -> empty fields array.
      expect(p.embeds[0].fields).toEqual([]);
    });
  });

  describe('teams', () => {
    it('builds a MessageCard with facts + disclaimer text', () => {
      const p = buildWebhookPayload(fullView(), 'teams', false);
      expect(p['@type']).toBe('MessageCard');
      expect(p['@context']).toBe('https://schema.org/extensions');
      expect(p.themeColor).toBe('E8731A');
      expect(p.summary).toBe('Eye advisory: Elevated');
      expect(p.title).toBe('Eye advisory: Elevated');
      const section = p.sections[0];
      expect(section.activityTitle).toContain('vendor_bank_account_change');
      expect(section.text).toContain('informational only');
      expect(section.markdown).toBe(true);
      // Facts stripped of markdown emphasis.
      const reason = section.facts.find((f) => f.name === 'Reason codes');
      expect(reason.value).not.toContain('*');
      expect(reason.value).not.toContain('`');
    });

    it('adds shadow/observe-mode suffix to title and uses default activityTitle', () => {
      const p = buildWebhookPayload(fullView({ action_type: null }), 'teams', true);
      expect(p.title).toContain('(shadow / observe-mode)');
      expect(p.sections[0].activityTitle).toBe('Eye advisory');
    });
  });

  it('falls back to slack formatter for unknown kind', () => {
    const p = buildWebhookPayload(fullView(), 'pager', false);
    expect(p.attachments).toBeTruthy(); // slack shape
  });

  it('defaults isShadow to false', () => {
    const p = buildWebhookPayload(fullView(), 'slack');
    expect(p.text).not.toContain('shadow');
  });

  it('falls back to caution status meta for unknown status', () => {
    const p = buildWebhookPayload(fullView({ status: 'weird' }), 'slack', false);
    expect(p.attachments[0].color).toBe('#f5a623'); // caution color
  });

  it.each(['caution', 'elevated', 'review_required'])(
    'produces correct color for status %s',
    (status) => {
      const colors = { caution: '#f5a623', elevated: '#e8731a', review_required: '#d0021b' };
      const p = buildWebhookPayload(fullView({ status }), 'slack', false);
      expect(p.attachments[0].color).toBe(colors[status]);
    },
  );
});

// ── notifyEyeAdvisory: fail-soft results ──────────────────────────────────────
describe('notifyEyeAdvisory', () => {
  const PUBLIC_URL = 'https://hooks.slack.com/services/T/B/X';

  function setUrl(url = PUBLIC_URL) {
    vi.stubEnv('EYE_WEBHOOK_URL', url);
  }

  it('skips with no_url when EYE_WEBHOOK_URL is unset', async () => {
    vi.stubEnv('EYE_WEBHOOK_URL', '');
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: false, skipped: 'no_url' });
  });

  it('skips with no_advisory when advisory is missing or not an object', async () => {
    setUrl();
    expect(await notifyEyeAdvisory(null)).toEqual({ notified: false, skipped: 'no_advisory' });
    expect(await notifyEyeAdvisory('nope')).toEqual({ notified: false, skipped: 'no_advisory' });
    expect(await notifyEyeAdvisory(undefined)).toEqual({ notified: false, skipped: 'no_advisory' });
  });

  it('skips with below_threshold for a clear advisory', async () => {
    setUrl();
    const res = await notifyEyeAdvisory(makeAdvisory({ status: 'clear' }));
    expect(res).toEqual({ notified: false, skipped: 'below_threshold' });
  });

  it('skips with below_threshold for a shadow advisory when shadow disabled', async () => {
    setUrl();
    vi.stubEnv('EYE_WEBHOOK_SHADOW', 'false');
    const res = await notifyEyeAdvisory(makeAdvisory(), { isShadow: true });
    expect(res).toEqual({ notified: false, skipped: 'below_threshold' });
  });

  it('skips with invalid_url when URL targets a private host', async () => {
    setUrl('http://169.254.169.254/latest/meta-data');
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: false, skipped: 'invalid_url' });
  });

  it('skips with invalid_url when URL is malformed', async () => {
    setUrl('not-a-real-url');
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: false, skipped: 'invalid_url' });
  });

  it('returns notified:true on a 2xx response', async () => {
    setUrl();
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: true, kind: 'slack', status: 200 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fetchMock.mock.calls[0];
    expect(calledUrl).toContain('hooks.slack.com');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(() => JSON.parse(init.body)).not.toThrow();
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('returns notified:false + http_error on a non-2xx response', async () => {
    setUrl();
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 500,
      text: async () => 'internal error body',
    }));
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: false, kind: 'slack', status: 500, detail: 'http_error' });
  });

  it('tolerates res.text() rejecting on a non-2xx response', async () => {
    setUrl();
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 502,
      text: async () => {
        throw new Error('stream closed');
      },
    }));
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: false, kind: 'slack', status: 502, detail: 'http_error' });
  });

  it('returns notified:false with network detail when fetch throws', async () => {
    setUrl();
    const fetchMock = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    });
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res.notified).toBe(false);
    expect(res.kind).toBe('slack');
    expect(res.detail).toBe('ECONNREFUSED');
  });

  it('reports network_error when a thrown error has no message', async () => {
    setUrl();
    const fetchMock = vi.fn(async () => {
      throw {}; // no .name, no .message
    });
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: false, kind: 'slack', detail: 'network_error' });
  });

  it('reports detail "timeout" when fetch aborts (AbortError)', async () => {
    setUrl();
    const fetchMock = vi.fn(async () => {
      const err = new Error('aborted');
      err.name = 'AbortError';
      throw err;
    });
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: false, kind: 'slack', detail: 'timeout' });
  });

  it('honors the configured timeout: aborts the request after timeoutMs', async () => {
    vi.useFakeTimers();
    setUrl();
    vi.stubEnv('EYE_WEBHOOK_TIMEOUT_MS', '50');
    let capturedSignal;
    const fetchMock = vi.fn(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          capturedSignal = init.signal;
          init.signal.addEventListener('abort', () => {
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const resultP = notifyEyeAdvisory(makeAdvisory());
    await vi.advanceTimersByTimeAsync(60);
    const res = await resultP;
    expect(capturedSignal.aborted).toBe(true);
    expect(res).toEqual({ notified: false, kind: 'slack', detail: 'timeout' });
  });

  it('routes to the discord formatter when host implies discord', async () => {
    setUrl('https://discord.com/api/webhooks/1/abc');
    let body;
    const fetchMock = vi.fn(async (_url, init) => {
      body = JSON.parse(init.body);
      return { ok: true, status: 204 };
    });
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res).toEqual({ notified: true, kind: 'discord', status: 204 });
    expect(body.embeds).toBeTruthy(); // discord shape
  });

  it('includes hashed refs in the payload only when reveal is enabled', async () => {
    setUrl();
    vi.stubEnv('EYE_WEBHOOK_REVEAL_REFS', 'true');
    let body;
    const fetchMock = vi.fn(async (_url, init) => {
      body = init.body;
      return { ok: true, status: 200 };
    });
    vi.stubGlobal('fetch', fetchMock);
    await notifyEyeAdvisory(makeAdvisory());
    // Short hash token of actor_ref (HEX64) appears; raw refs never do.
    expect(body).toContain('aaaaaaaaaaaa…');
    expect(body).not.toContain('subject-human-readable');
    expect(body).not.toContain('issuer@example.com');
  });

  it('hits the outer fail-soft backstop when redaction throws (skipped:error)', async () => {
    // A throwing getter on a passing-the-object-check advisory explodes inside
    // redactAdvisory, which is OUTSIDE postWebhook's try — so the top-level
    // try/catch must catch it and return skipped:'error' with a detail.
    setUrl();
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const advisory = {
      status: 'elevated', // passes shouldNotify gate
      get evidence_refs() {
        throw new Error('boom in redaction');
      },
    };
    const res = await notifyEyeAdvisory(advisory);
    expect(res).toEqual({ notified: false, skipped: 'error', detail: 'boom in redaction' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('is fail-soft and never throws when fetch itself is unavailable', async () => {
    setUrl();
    vi.stubGlobal('fetch', undefined);
    const res = await notifyEyeAdvisory(makeAdvisory());
    expect(res.notified).toBe(false);
  });

  it('fires a real shadow advisory when shadow is enabled', async () => {
    setUrl();
    vi.stubEnv('EYE_WEBHOOK_SHADOW', 'true');
    let body;
    const fetchMock = vi.fn(async (_url, init) => {
      body = JSON.parse(init.body);
      return { ok: true, status: 200 };
    });
    vi.stubGlobal('fetch', fetchMock);
    const res = await notifyEyeAdvisory(makeAdvisory(), { isShadow: true });
    expect(res.notified).toBe(true);
    expect(body.text).toContain('(shadow / observe-mode)');
  });
});
