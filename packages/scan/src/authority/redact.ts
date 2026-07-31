// SPDX-License-Identifier: Apache-2.0
//
// Discovery must parse local configuration in memory, but every value that
// crosses the report boundary passes through this module. It returns a
// descriptor or conservative redaction, never an intentionally emitted
// credential value.

import type { SecretDescriptor } from './types.js';

const SECRET_KEY_PATTERNS: ReadonlyArray<{ re: RegExp; class: string }> = Object.freeze([
  { re: /\bAPI ?KEY\b/, class: 'api_key' },
  { re: /\bSECRET\b/, class: 'secret' },
  { re: /\bTOKEN\b/, class: 'token' },
  { re: /\bPASSWORD\b/, class: 'password' },
  { re: /\bPASSWD\b/, class: 'password' },
  { re: /\bCREDENTIAL/, class: 'credential' },
  { re: /\bPRIVATE ?KEY\b/, class: 'private_key' },
  { re: /\bACCESS ?KEY\b/, class: 'access_key' },
  { re: /\bKEY\b/, class: 'key' },
  { re: /\bSERVICE ?ROLE\b/, class: 'service_role' },
  { re: /\bAUTH(ORIZATION)?\b/, class: 'authorization' },
  { re: /\bBEARER\b/, class: 'bearer' },
  { re: /\bSESSION\b/, class: 'session' },
  { re: /\bSIGNING\b/, class: 'signing_key' },
  { re: /\bDSN\b/, class: 'dsn' },
]);

const VALUE_SHAPES: ReadonlyArray<{ re: RegExp; class: string; take: number }> = Object.freeze([
  { re: /^AIza[0-9A-Za-z_-]{20,}$/, class: 'google_api_key', take: 4 },
  { re: /^sk-[A-Za-z0-9_-]{20,}$/, class: 'openai_secret_key', take: 3 },
  { re: /^sk_live_[A-Za-z0-9]{16,}$/, class: 'stripe_live_secret', take: 8 },
  { re: /^sk_test_[A-Za-z0-9]{16,}$/, class: 'stripe_test_secret', take: 8 },
  { re: /^rk_live_[A-Za-z0-9]{16,}$/, class: 'stripe_live_restricted', take: 8 },
  { re: /^whsec_[A-Za-z0-9]{16,}$/, class: 'stripe_webhook_secret', take: 6 },
  { re: /^gh[pousr]_[A-Za-z0-9]{20,}$/, class: 'github_token', take: 4 },
  { re: /^github_pat_[A-Za-z0-9_]{20,}$/, class: 'github_fine_grained_pat', take: 11 },
  { re: /^xox[baprs]-[A-Za-z0-9-]{10,}$/, class: 'slack_token', take: 5 },
  { re: /^(?:AKIA|ASIA)[0-9A-Z]{16}$/, class: 'aws_access_key_id', take: 4 },
  { re: /^ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, class: 'jwt', take: 2 },
  { re: /^npm_[A-Za-z0-9]{30,}$/, class: 'npm_token', take: 4 },
  { re: /^sbp_[a-f0-9]{40,}$/, class: 'supabase_token', take: 4 },
  { re: /^glpat-[A-Za-z0-9_-]{16,}$/, class: 'gitlab_pat', take: 6 },
  { re: /^-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}/, class: 'pem_private_key', take: 0 },
]);

const CONNECTION_SCHEMES = new Set([
  'postgres', 'postgresql', 'mysql', 'mongodb', 'mongodb+srv',
  'redis', 'rediss', 'amqp', 'amqps',
]);

function looksHighEntropy(value: unknown): boolean {
  if (typeof value !== 'string' || value.length < 24 || /\s/.test(value)) return false;
  const distinct = new Set(value).size;
  return distinct / value.length > 0.35 && /[0-9]/.test(value) && /[A-Za-z]/.test(value);
}

export function describeSecret(key: unknown, value: unknown): SecretDescriptor {
  const keyName = String(key ?? '');
  const upper = keyName.toUpperCase().replace(/[_\-.:/]+/g, ' ');
  const str = typeof value === 'string' ? value : '';
  const out: SecretDescriptor = {
    secret: false,
    class: null,
    key: keyName,
    length: str.length,
    prefix_class: null,
    evidence: null,
    scheme: null,
  };

  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(str);
  if (schemeMatch && CONNECTION_SCHEMES.has(schemeMatch[1].toLowerCase())) {
    return {
      ...out,
      secret: true,
      class: 'connection_string',
      scheme: schemeMatch[1].toLowerCase(),
      evidence: 'value_shape',
    };
  }

  for (const shape of VALUE_SHAPES) {
    if (shape.re.test(str)) {
      return {
        ...out,
        secret: true,
        class: shape.class,
        evidence: 'value_shape',
        prefix_class: shape.take > 0 ? `${str.slice(0, shape.take)}...` : null,
      };
    }
  }

  for (const pattern of SECRET_KEY_PATTERNS) {
    if (pattern.re.test(upper)) {
      return { ...out, secret: true, class: pattern.class, evidence: 'key_name' };
    }
  }

  if (looksHighEntropy(str)) {
    return {
      ...out,
      secret: true,
      class: 'unclassified_high_entropy',
      evidence: 'entropy',
    };
  }
  return out;
}

export function safeValue(key: unknown, value: unknown): string {
  const descriptor = describeSecret(key, value);
  if (descriptor.secret) {
    const parts = [descriptor.class];
    if (descriptor.scheme) parts.push(`scheme=${descriptor.scheme}`);
    if (descriptor.prefix_class) parts.push(`prefix=${descriptor.prefix_class}`);
    if (descriptor.length) parts.push(`len=${descriptor.length}`);
    return `<redacted ${parts.join(' ')}>`;
  }
  const str = typeof value === 'string' ? value : JSON.stringify(value ?? null);
  return str.length > 120 ? `${str.slice(0, 117)}...` : str;
}

export function describeEnv(env: unknown): SecretDescriptor[] {
  if (!env || typeof env !== 'object' || Array.isArray(env)) return [];
  return Object.entries(env).map(([key, value]) => describeSecret(key, value));
}

export function redactText(text: unknown): string {
  if (typeof text !== 'string' || !text) return typeof text === 'string' ? text : String(text ?? '');
  let out = text;

  out = out.replace(
    /-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[\s\S]*?-{5}END [A-Z ]*PRIVATE KEY-{5}/g,
    '<redacted pem_private_key>',
  );
  out = out.replace(
    /\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^\s"'<>]+/gi,
    (_match, scheme: string) => `<redacted connection_string scheme=${scheme.toLowerCase()}>`,
  );
  out = out.replace(
    /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]{8,}={0,2}/gi,
    (_match, kind: string) => `<redacted ${kind.toLowerCase()} credential>`,
  );
  out = out.replace(
    /(--?(?:key|api[-_]?key|secret|token|password|passwd|credential|authorization|private[-_]?key|access[-_]?key|service[-_]?role|session|signing[-_]?key|dsn))(\s*=\s*|\s+)(?:"[^"]*"|'[^']*'|[^\s)"']+)/gi,
    (_match, key: string, separator: string) => `${key}${separator.includes('=') ? '=' : ' '}<redacted credential>`,
  );
  out = out.replace(
    /\b((?:[A-Za-z0-9]+[_-])*(?:key|api[_-]?key|secret|token|password|passwd|credential|authorization|private[_-]?key|access[_-]?key|service[_-]?role|session|signing[_-]?key|dsn))(\s*(?:=|:)\s*)(?:"[^"]*"|'[^']*'|[^\s)"']+)/gi,
    (_match, key: string, separator: string) => `${key}${separator}<redacted credential>`,
  );
  for (const shape of VALUE_SHAPES) {
    const global = new RegExp(shape.re.source.replace(/^\^/, '').replace(/\$$/, ''), 'g');
    out = out.replace(global, `<redacted ${shape.class}>`);
  }
  out = out.replace(
    /\b([a-z][a-z0-9+.-]*):\/\/[^\s"']*:[^\s"'@]*@[^\s"']+/gi,
    (_match, scheme: string) => `<redacted connection_string scheme=${scheme.toLowerCase()}>`,
  );
  out = out.replace(/[A-Za-z0-9._~+/-]{24,}={0,2}/g, (token) => (
    looksHighEntropy(token) ? '<redacted high_entropy_token>' : token
  ));
  return out;
}

export function sanitizeForReport(
  value: unknown,
  key = 'value',
  seen: WeakSet<object> = new WeakSet<object>(),
): unknown {
  if (typeof value === 'string') {
    const redacted = redactText(value);
    return redacted === value ? safeValue(key, value) : redacted;
  }
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return '<redacted circular_reference>';
  seen.add(value);
  if (Array.isArray(value)) {
    if (key === 'args' || key === 'arguments') {
      seen.delete(value);
      return sanitizeArgs(value);
    }
    const sanitized = value.map((item) => sanitizeForReport(item, key, seen));
    seen.delete(value);
    return sanitized;
  }
  const out: Record<string, unknown> = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    out[childKey] = sanitizeForReport(childValue, childKey, seen);
  }
  seen.delete(value);
  return out;
}

export function sanitizeArgs(args: unknown): string[] {
  if (!Array.isArray(args)) return [];
  const out: string[] = [];
  let redactNext = false;
  for (const raw of args) {
    const arg = String(raw);
    if (redactNext) {
      out.push('<redacted credential argument>');
      redactNext = false;
      continue;
    }
    if (arg.startsWith('-')) {
      const key = arg.replace(/^-+/, '').split('=', 1)[0];
      if (describeSecret(key, 'placeholder').secret) {
        const equals = arg.indexOf('=');
        if (equals >= 0) out.push(`${arg.slice(0, equals + 1)}<redacted credential>`);
        else {
          out.push(arg);
          redactNext = true;
        }
        continue;
      }
    }
    out.push(String(sanitizeForReport(arg, 'argument')));
  }
  return out;
}
