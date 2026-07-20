/**
 * EP Eye — Real-time webhook notifier (Slack / Discord / Teams).
 *
 * @license Apache-2.0
 *
 * Formats a non-`clear` Eye advisory (a caution / elevated / review_required
 * posture, including shadow / observe-mode advisories) into a chat-platform
 * webhook payload and POSTs it to a single operator-configured URL.
 *
 * ## The Law (non-negotiable)
 *
 * This notifier INFORMS humans and MAY motivate a human to tighten posture.
 * It is NEVER a gate and NEVER authorizes anything. An Eye advisory does not
 * approve, reject, or block an action — the Guard (Enforcement Point) and a
 * named human via signoff do that. See docs/positioning/EYE_VS_EP.md and
 * docs/EMILIA-EYE-ADVISORY-SPEC.md. The notification therefore carries no
 * decision, no allow/deny verdict, and no reputation score.
 *
 * ## What this is NOT
 *
 *  - NOT a trust score / reputation index / 0-100 / ranking. Eye does not score
 *    entities and this payload never invents one. It carries the advisory's own
 *    status enum (`caution`/`elevated`/`review_required`), reason codes, and a
 *    re-derivable `scope_binding_hash` — facts a recipient can verify, not an
 *    EMILIA-vouched opinion.
 *  - NOT the per-tenant signed webhook system in lib/cloud/webhooks.js. That
 *    delivers EP-RECEIPT-v1 style signed events to subscriber endpoints with
 *    retry + auto-disable. THIS module is a fire-and-forget operator ping to a
 *    chat tool (Slack/Discord/Teams incoming webhook), configured by env.
 *  - NOT a notification to the *target* entity. Eye never tells an entity it was
 *    flagged; advisory data flows to the OPERATOR's surfaces only. The URL here
 *    is the operator's own channel.
 *
 * ## Fail-soft contract
 *
 * A webhook failure MUST NOT break the advisory path. Every public function
 * resolves to a structured result and never throws. Network/timeout/HTTP errors
 * are caught and logged. The caller (the advisory-emit hook) ignores the return
 * value; this module exists to inform, not to gate.
 *
 * ## Privacy / redaction (default on)
 *
 * Sensitive scope identifiers and action parameters are NOT sent by default.
 * Raw `subject_ref` / `actor_ref` / `target_ref` / `issuer_ref`, raw context,
 * evidence contents, and per-entity transaction volumes are redacted. Only the
 * deterministic `scope_binding_hash`, the status enum, reason codes, the
 * recommended posture action, evidence *count*, and timestamps are sent. Set
 * `EYE_WEBHOOK_REVEAL_REFS=true` to opt into including short hashed ref tokens
 * (still hashes, never raw identifiers).
 *
 * ## Configuration (env)
 *
 *   EYE_WEBHOOK_URL          Incoming-webhook URL. If unset, notifier is a no-op.
 *   EYE_WEBHOOK_KIND         'slack' | 'discord' | 'teams' (default: inferred
 *                            from the URL host, else 'slack').
 *   EYE_WEBHOOK_MIN_STATUS   Lowest status that fires: 'caution' | 'elevated' |
 *                            'review_required' (default: 'caution').
 *   EYE_WEBHOOK_SHADOW       'true' to also notify on shadow/observe-mode
 *                            advisories (default: 'false').
 *   EYE_WEBHOOK_REVEAL_REFS  'true' to include short hashed ref tokens
 *                            (default: 'false' — refs fully omitted).
 *   EYE_WEBHOOK_TIMEOUT_MS   Delivery timeout in ms (default: 8000).
 */

import { logger } from '../logger.js';

// ── Status ordering ───────────────────────────────────────────────────────────
// Mirrors EYE_STATUSES severity order. 'clear' is index 0 and never fires.
const STATUS_RANK = Object.freeze({
  clear: 0,
  caution: 1,
  elevated: 2,
  review_required: 3,
});

const DEFAULT_TIMEOUT_MS = 8000;

// ── SSRF protection ───────────────────────────────────────────────────────────
// Operator-configured URL is server-trusted, but we still refuse private /
// internal targets so a misconfiguration (or a poisoned env) can't be used to
// probe internal infrastructure.
const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^fc/i,
  /^fd/i,
  /^fe80/i,
];

function isPrivateHost(hostname) {
  if (['localhost', '0.0.0.0'].includes(hostname)) return true;
  if (hostname.endsWith('.internal') || hostname.endsWith('.local')) return true;
  // URL.hostname returns IPv6 literals BRACKETED (e.g. "[::1]") and may carry a
  // "%zone" suffix. Strip both and lowercase before range-testing — otherwise
  // loopback (::1), ULA (fc00::/7) and link-local (fe80::/10) IPv6 webhook
  // targets would slip past the guard, since the regexes never match "[…]".
  const host = hostname.replace(/^\[|\]$/g, '').replace(/%.*$/, '').toLowerCase();
  // IPv4-mapped/compat IPv6 (e.g. ::ffff:127.0.0.1) must be judged on the
  // embedded IPv4 address as well.
  const mapped = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  const candidates = mapped ? [host, mapped[1]] : [host];
  return candidates.some((h) => PRIVATE_RANGES.some((r) => r.test(h)));
}

/**
 * Parse + validate the configured URL. Returns the URL object or null (never
 * throws) so a bad URL fails soft.
 * @param {string} urlString
 * @returns {URL|null}
 */
function safeParseUrl(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return null;
  }
  if (isPrivateHost(parsed.hostname)) return null;
  if (parsed.protocol !== 'https:') return null;
  return parsed;
}

// ── Config ────────────────────────────────────────────────────────────────────

/**
 * Read notifier config from env. Centralized here so the rest of the module is
 * pure. (Mirrors the env-direct idiom of lib/trust-desk/notify.js; can be moved
 * behind lib/env.js later without changing callsites.)
 * @returns {{url:string|null, kind:'slack'|'discord'|'teams', minRank:number, shadow:boolean, revealRefs:boolean, timeoutMs:number}}
 */
function readConfig() {
  const url = process.env.EYE_WEBHOOK_URL || null;
  const minStatus = process.env.EYE_WEBHOOK_MIN_STATUS || 'caution';
  const minRank = STATUS_RANK[minStatus] ?? STATUS_RANK.caution;
  const timeoutMs = Number(process.env.EYE_WEBHOOK_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
  return {
    url,
    kind: inferKind(process.env.EYE_WEBHOOK_KIND, url),
    minRank: minRank === 0 ? STATUS_RANK.caution : minRank, // never let 'clear' fire
    shadow: process.env.EYE_WEBHOOK_SHADOW === 'true',
    revealRefs: process.env.EYE_WEBHOOK_REVEAL_REFS === 'true',
    timeoutMs,
  };
}

/**
 * Resolve the webhook flavor. Explicit env wins; else infer from URL host.
 * @param {string|undefined} explicit
 * @param {string|null} url
 * @returns {'slack'|'discord'|'teams'}
 */
function inferKind(explicit, url) {
  const e = (explicit || '').toLowerCase();
  if (e === 'slack' || e === 'discord' || e === 'teams') return e;
  const host = (url ? (safeParseUrl(url)?.hostname || '') : '').toLowerCase();
  // Match on hostname suffix, not substring — `includes('discord')` would also
  // match discord.evil.com / evil-discord.net. Exact domain or true subdomain only.
  const hostIs = (domain) => host === domain || host.endsWith(`.${domain}`);
  if (hostIs('discord.com') || hostIs('discordapp.com')) return 'discord';
  // office.com covers outlook.office.com + *.webhook.office.com; plus teams.microsoft.com.
  if (hostIs('office.com') || hostIs('teams.microsoft.com')) return 'teams';
  return 'slack';
}

// ── Redaction ─────────────────────────────────────────────────────────────────

/**
 * Build the privacy-safe view of an advisory. Raw scope identifiers and action
 * parameters never appear. Only re-derivable / non-attributable facts survive.
 *
 * @param {object} advisory
 * @param {{revealRefs:boolean}} opts
 * @returns {object} redacted advisory view
 */
function redactAdvisory(advisory, opts) {
  const evidenceRefs = Array.isArray(advisory.evidence_refs) ? advisory.evidence_refs : [];
  const reasonCodes = Array.isArray(advisory.reason_codes) ? advisory.reason_codes : [];

  const view = {
    advisory_id: advisory.advisory_id ?? null,
    status: advisory.status ?? null,
    reason_codes: reasonCodes,
    recommended_policy_action: advisory.recommended_policy_action ?? null,
    // scope_binding_hash is a deterministic SHA-256 over scope fields — safe to
    // share: a recipient who knows the scope can re-derive it; it leaks nothing
    // on its own. This is the "fact, not opinion" the recipient can verify.
    scope_binding_hash: advisory.scope_binding_hash ?? null,
    advisory_hash: advisory.advisory_hash ?? null,
    evidence_count: evidenceRefs.length,
    issued_at: advisory.issued_at ?? null,
    expires_at: advisory.expires_at ?? null,
    version: advisory.version ?? null,
    // action_type is a workflow label (e.g. "vendor_bank_account_change"), not
    // an entity identifier — it gives operators context without leaking who.
    action_type: advisory.action_type ?? null,
  };

  // Opt-in: short hashed ref tokens. NEVER the raw subject/actor/target/issuer.
  // We only ever expose the first 12 hex chars of an already-hashed value if the
  // ref already looks like a hash; otherwise the ref is omitted entirely.
  if (opts.revealRefs) {
    view.refs = {
      subject: shortHashToken(advisory.subject_ref),
      actor: shortHashToken(advisory.actor_ref),
      target: shortHashToken(advisory.target_ref),
      issuer: shortHashToken(advisory.issuer_ref),
    };
  }

  return view;
}

/**
 * Emit a short, non-reversible token for a ref ONLY when it already appears to be
 * a hash. Raw human/entity identifiers are dropped (return null) so we never leak
 * an attributable id even in reveal mode.
 * @param {*} ref
 * @returns {string|null}
 */
function shortHashToken(ref) {
  if (typeof ref !== 'string' || ref.length === 0) return null;
  // Heuristic: looks like a hex hash (>=32 hex chars) → expose a short prefix.
  if (/^[0-9a-f]{32,}$/i.test(ref)) return `${ref.slice(0, 12)}…`;
  // Anything that could be a human-readable identifier is redacted.
  return null;
}

// ── Human-facing copy ─────────────────────────────────────────────────────────

const STATUS_META = Object.freeze({
  caution: { label: 'Caution', emoji: ':eyes:', color: 0xf5a623, slackColor: '#f5a623', teams: 'F5A623' },
  elevated: { label: 'Elevated', emoji: ':warning:', color: 0xe8731a, slackColor: '#e8731a', teams: 'E8731A' },
  review_required: { label: 'Review required', emoji: ':rotating_light:', color: 0xd0021b, slackColor: '#d0021b', teams: 'D0021B' },
});

function statusMeta(status) {
  return STATUS_META[status] || STATUS_META.caution;
}

/** One-line disclaimer carried on every notification so it is never read as a gate. */
const ADVISORY_DISCLAIMER =
  'Eye advisory — informational only. This does not block or authorize the action; ' +
  'the Enforcement Point and signoff decide. Not a trust score.';

function headline(view, isShadow) {
  const meta = statusMeta(view.status);
  const mode = isShadow ? ' (shadow / observe-mode)' : '';
  const action = view.action_type ? ` on \`${view.action_type}\`` : '';
  return `${meta.emoji} Eye advisory: *${meta.label}*${mode}${action}`;
}

function detailLines(view) {
  const lines = [];
  if (view.reason_codes.length) lines.push(`*Reason codes:* ${view.reason_codes.join(', ')}`);
  if (view.recommended_policy_action) {
    lines.push(`*Recommended posture:* ${view.recommended_policy_action} (tighten-only; never a gate)`);
  }
  if (view.evidence_count) lines.push(`*Contributing observations:* ${view.evidence_count}`);
  if (view.scope_binding_hash) lines.push(`*Scope binding:* \`${view.scope_binding_hash.slice(0, 16)}…\``);
  if (view.expires_at) lines.push(`*Advisory expires:* ${view.expires_at}`);
  if (view.refs) {
    const refLine = Object.entries(view.refs)
      .filter(([, v]) => v)
      .map(([k, v]) => `${k}=${v}`)
      .join(' ');
    if (refLine) lines.push(`*Refs (hashed):* ${refLine}`);
  }
  return lines;
}

// ── Payload formatters (per platform) ─────────────────────────────────────────

/**
 * Slack incoming-webhook payload (Block Kit + attachment color rail).
 * @param {object} view  redacted advisory view
 * @param {boolean} isShadow
 */
function formatSlack(view, isShadow) {
  const meta = statusMeta(view.status);
  const body = detailLines(view).join('\n');
  return {
    text: headline(view, isShadow), // fallback / notification text
    attachments: [
      {
        color: meta.slackColor,
        blocks: [
          {
            type: 'section',
            text: { type: 'mrkdwn', text: `${headline(view, isShadow)}\n${body}` },
          },
          {
            type: 'context',
            elements: [{ type: 'mrkdwn', text: ADVISORY_DISCLAIMER }],
          },
        ],
      },
    ],
  };
}

/**
 * Discord webhook payload (rich embed). Discord mrkdwn differs slightly; we send
 * plain markdown which renders acceptably.
 * @param {object} view
 * @param {boolean} isShadow
 */
function formatDiscord(view, isShadow) {
  const meta = statusMeta(view.status);
  const fields = detailLines(view).map((line) => {
    const idx = line.indexOf(':*');
    if (line.startsWith('*') && idx !== -1) {
      return {
        name: line.slice(1, idx).trim(),
        value: line.slice(idx + 2).trim() || '—',
        inline: false,
      };
    }
    return { name: '​', value: line, inline: false };
  });
  return {
    content: discordPlain(headline(view, isShadow)),
    embeds: [
      {
        title: `Eye advisory: ${meta.label}${isShadow ? ' (shadow)' : ''}`,
        color: meta.color,
        fields,
        footer: { text: ADVISORY_DISCLAIMER },
        timestamp: view.issued_at || new Date().toISOString(),
      },
    ],
  };
}

/** Strip Slack-style emoji shortcodes for Discord content fallback. */
function discordPlain(text) {
  return text.replace(/:[a-z_]+:\s?/g, '').replace(/\*/g, '**');
}

/**
 * Microsoft Teams payload (MessageCard / connector card — broadly compatible
 * with both classic Office 365 connectors and Workflows incoming webhooks).
 * @param {object} view
 * @param {boolean} isShadow
 */
function formatTeams(view, isShadow) {
  const meta = statusMeta(view.status);
  const facts = detailLines(view).map((line) => {
    const idx = line.indexOf(':*');
    if (line.startsWith('*') && idx !== -1) {
      return { name: line.slice(1, idx).trim(), value: stripMd(line.slice(idx + 2).trim()) };
    }
    return { name: 'Detail', value: stripMd(line) };
  });
  return {
    '@type': 'MessageCard',
    '@context': 'https://schema.org/extensions',
    themeColor: meta.teams,
    summary: `Eye advisory: ${meta.label}`,
    title: `Eye advisory: ${meta.label}${isShadow ? ' (shadow / observe-mode)' : ''}`,
    sections: [
      {
        activityTitle: view.action_type ? `Action: ${view.action_type}` : 'Eye advisory',
        facts,
        text: ADVISORY_DISCLAIMER,
        markdown: true,
      },
    ],
  };
}

/** Strip Slack/Discord markdown emphasis for Teams fact values. */
function stripMd(text) {
  return text.replace(/[*`]/g, '');
}

const FORMATTERS = Object.freeze({
  slack: formatSlack,
  discord: formatDiscord,
  teams: formatTeams,
});

/**
 * Build the platform-specific webhook payload for a redacted advisory view.
 * Exported for testing and for callers that want to deliver via their own
 * transport.
 *
 * @param {object} view  redacted advisory view (from redactAdvisory)
 * @param {'slack'|'discord'|'teams'} kind
 * @param {boolean} isShadow
 * @returns {object} platform payload
 */
export function buildWebhookPayload(view, kind, isShadow = false) {
  const fmt = FORMATTERS[kind] || formatSlack;
  return fmt(view, isShadow);
}

// ── Gating (which advisories fire) ────────────────────────────────────────────

/**
 * Decide whether an advisory should produce a notification under the given
 * config. Never fires on 'clear'. Shadow advisories fire only when opted in.
 * @param {object} advisory
 * @param {{minRank:number, shadow:boolean}} cfg
 * @param {{isShadow?:boolean}} meta
 * @returns {boolean}
 */
function shouldNotify(advisory, cfg, meta) {
  const rank = STATUS_RANK[advisory?.status] ?? 0;
  if (rank <= 0) return false; // 'clear' or unknown — never notify
  if (rank < cfg.minRank) return false;
  if (meta?.isShadow && !cfg.shadow) return false;
  return true;
}

// ── Public entrypoint ─────────────────────────────────────────────────────────

/**
 * Notify the operator's chat channel about a non-`clear` Eye advisory.
 *
 * FAIL-SOFT: never throws. Returns a structured result describing whether a
 * delivery was attempted and its outcome. The caller (advisory-emit hook) should
 * NOT await-block the advisory path on this; fire-and-forget is fine.
 *
 * @param {object} advisory  The issued advisory (eye-advisory-v1 shape).
 * @param {object} [meta]    Optional metadata.
 * @param {boolean} [meta.isShadow=false]  Whether this is a shadow/observe-mode advisory.
 * @returns {Promise<{notified:boolean, skipped?:string, kind?:string, status?:number, detail?:string}>}
 */
export async function notifyEyeAdvisory(advisory, meta = {}) {
  try {
    const cfg = readConfig();

    if (!cfg.url) {
      return { notified: false, skipped: 'no_url' };
    }
    if (!advisory || typeof advisory !== 'object') {
      return { notified: false, skipped: 'no_advisory' };
    }
    if (!shouldNotify(advisory, cfg, meta)) {
      return { notified: false, skipped: 'below_threshold' };
    }

    const parsed = safeParseUrl(cfg.url);
    if (!parsed) {
      logger.warn('[eye/webhook] EYE_WEBHOOK_URL invalid or targets a private host — skipping', {
        advisory_id: advisory.advisory_id,
      });
      return { notified: false, skipped: 'invalid_url' };
    }

    const view = redactAdvisory(advisory, { revealRefs: cfg.revealRefs });
    const payload = buildWebhookPayload(view, cfg.kind, Boolean(meta.isShadow));

    return await postWebhook(parsed.toString(), payload, cfg);
  } catch (err) {
    // Absolute fail-soft backstop: a notifier bug must never break the
    // advisory path.
    logger.warn('[eye/webhook] notifyEyeAdvisory failed (suppressed)', {
      error: err?.message,
    });
    return { notified: false, skipped: 'error', detail: err?.message };
  }
}

/**
 * POST a prebuilt payload to the webhook URL with a timeout. Fail-soft.
 * @param {string} url
 * @param {object} payload
 * @param {{kind:string, timeoutMs:number}} cfg
 * @returns {Promise<{notified:boolean, kind:string, status?:number, detail?:string}>}
 */
async function postWebhook(url, payload, cfg) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
      // Do not follow redirects. A public webhook URL that redirects to an
      // internal/metadata endpoint would bypass the preflight host check.
      redirect: 'manual',
    });
    clearTimeout(timer);

    if (res.ok) {
      logger.info('[eye/webhook] advisory notification delivered', { kind: cfg.kind, status: res.status });
      return { notified: true, kind: cfg.kind, status: res.status };
    }

    const body = await res.text().catch(() => '');
    logger.warn('[eye/webhook] non-2xx from webhook (suppressed)', {
      kind: cfg.kind,
      status: res.status,
      detail: body.slice(0, 256),
    });
    return { notified: false, kind: cfg.kind, status: res.status, detail: 'http_error' };
  } catch (err) {
    clearTimeout(timer);
    const detail = err?.name === 'AbortError' ? 'timeout' : err?.message || 'network_error';
    logger.warn('[eye/webhook] delivery failed (suppressed)', { kind: cfg.kind, detail });
    return { notified: false, kind: cfg.kind, detail };
  }
}

// Internal helpers exported for unit tests only.
export const __test__ = Object.freeze({
  redactAdvisory,
  shouldNotify,
  inferKind,
  safeParseUrl,
  shortHashToken,
  readConfig,
  STATUS_RANK,
});
