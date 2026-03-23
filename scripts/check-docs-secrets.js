#!/usr/bin/env node
/**
 * check-docs-secrets.js
 *
 * Scans docs/ and content/ directories for patterns that look like
 * leaked secrets, internal email addresses, or real hostnames.
 * Exits with code 1 if any violations are found.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");

// Directories to scan
const SCAN_DIRS = ["docs", "content"];

// File extensions to check
const EXTENSIONS = new Set([
  ".md",
  ".mdx",
  ".txt",
  ".html",
  ".htm",
  ".yaml",
  ".yml",
  ".json",
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
]);

// ── Patterns ────────────────────────────────────────────────────

const PATTERNS = [
  {
    name: "OpenAI API key",
    regex: /sk-[A-Za-z0-9]{20,}/g,
    allowlist: [
      /sk-your-/,
      /sk-xxx/,
      /sk-\.\.\./,
      /sk-<[^>]+>/,
      /sk-\{/,
      /placeholder/i,
      /example/i,
    ],
  },
  {
    name: "Stripe live key",
    regex: /sk_live_[A-Za-z0-9]{20,}/g,
    allowlist: [/placeholder/i, /example/i],
  },
  {
    name: "Anthropic API key",
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/g,
    allowlist: [/placeholder/i, /example/i, /your-/],
  },
  {
    name: "JWT / Supabase token",
    regex: /eyJhbGciO[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
    allowlist: [/example/i, /placeholder/i, /test/i, /mock/i, /dummy/i],
  },
  {
    name: "Internal email address",
    regex: /[a-zA-Z0-9._%+-]+@emiliaprotocol\.ai/g,
    allowlist: [
      /contact@emiliaprotocol\.ai/,
      /hello@emiliaprotocol\.ai/,
      /support@emiliaprotocol\.ai/,
      /info@emiliaprotocol\.ai/,
      /team@emiliaprotocol\.ai/,
      /press@emiliaprotocol\.ai/,
      /security@emiliaprotocol\.ai/,
    ],
  },
  {
    name: "Suspicious Base64 credential (50+ chars)",
    regex: /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{50,}={0,2}(?![A-Za-z0-9+/=])/g,
    allowlist: [/example/i, /placeholder/i, /test/i, /mock/i],
    // Extra validation: check that it decodes to something credential-like
    validate: (match, line) => {
      // Skip if on a line that looks like a hash, checksum, or data blob
      if (/sha256|sha512|hash|checksum|integrity/i.test(line)) return false;
      // Skip if it looks like a base64 image or data URI
      if (/data:image|data:application/i.test(line)) return false;
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        // Flag if decoded contains key-like patterns
        return (
          /password|secret|token|key|auth|credential/i.test(decoded) ||
          // Or if the raw base64 string is very long and not on an allowlisted line
          match.length > 80
        );
      } catch {
        return false;
      }
    },
  },
];

// Real-looking hostnames (not localhost or example domains)
const HOSTNAME_PATTERN =
  /(?:https?:\/\/)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:[a-z]{2,})(?:\.[a-z]{2,})?)/gi;

const SAFE_HOSTS = new Set([
  "localhost",
  "example.com",
  "example.org",
  "example.net",
  "test.com",
  "test.org",
  "foo.com",
  "bar.com",
  "placeholder.com",
  "yourdomain.com",
  "your-domain.com",
  "my-app.com",
  "myapp.com",
  // Common legitimate public references
  "github.com",
  "npmjs.com",
  "npmjs.org",
  "nodejs.org",
  "vercel.com",
  "vercel.app",
  "nextjs.org",
  "supabase.co",
  "supabase.com",
  "supabase.io",
  "stripe.com",
  "twilio.com",
  "openai.com",
  "anthropic.com",
  "emiliaprotocol.ai",
  "wikipedia.org",
  "mozilla.org",
  "w3.org",
  "json-schema.org",
  "yaml.org",
  "markdownguide.org",
  "creativecommons.org",
  "schema.org",
  "googleapis.com",
  "cloudflare.com",
  "amazonaws.com",
  "heroku.com",
  "docker.com",
  "docker.io",
  "python.org",
  "pypi.org",
  "typescriptlang.org",
  "reactjs.org",
  "svelte.dev",
  "tailwindcss.com",
  "x.com",
  "twitter.com",
  "linkedin.com",
  "youtube.com",
  "reddit.com",
  "stackoverflow.com",
  "dev.to",
  "medium.com",
  "fonts.google.com",
  "cdn.jsdelivr.net",
  "unpkg.com",
  "shields.io",
  "img.shields.io",
  "badge.fury.io",
  "coveralls.io",
  "codecov.io",
  "travis-ci.org",
  "circleci.com",
  "sentry.io",
  "datadog.com",
  "grafana.com",
  "elastic.co",
  "mermaid.js.org",
  "swagger.io",
  "redocly.com",
  "postman.com",
]);

// ── File discovery ──────────────────────────────────────────────

function collectFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      results.push(...collectFiles(full));
    } else if (EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      results.push(full);
    }
  }
  return results;
}

// ── Main scan ───────────────────────────────────────────────────

let violations = 0;

function report(filePath, lineNum, patternName, match) {
  const rel = path.relative(ROOT, filePath);
  const preview = match.length > 40 ? match.slice(0, 37) + "..." : match;
  console.error(`  ${rel}:${lineNum}  [${patternName}]  ${preview}`);
  violations++;
}

for (const dir of SCAN_DIRS) {
  const absDir = path.join(ROOT, dir);
  const files = collectFiles(absDir);

  for (const filePath of files) {
    const content = fs.readFileSync(filePath, "utf8");
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check each secret pattern
      for (const pattern of PATTERNS) {
        // Reset regex lastIndex
        pattern.regex.lastIndex = 0;
        let m;
        while ((m = pattern.regex.exec(line)) !== null) {
          const matchStr = m[0];

          // Check allowlist
          const allowed = (pattern.allowlist || []).some((al) => al.test(line));
          if (allowed) continue;

          // Run custom validator if present
          if (pattern.validate && !pattern.validate(matchStr, line)) continue;

          report(filePath, lineNum, pattern.name, matchStr);
        }
      }

      // Check for real-looking hostnames
      HOSTNAME_PATTERN.lastIndex = 0;
      let hm;
      while ((hm = HOSTNAME_PATTERN.exec(line)) !== null) {
        const host = hm[1].toLowerCase();
        // Strip trailing dots
        const cleanHost = host.replace(/\.$/, "");

        // Check if it is a safe/known host
        if (SAFE_HOSTS.has(cleanHost)) continue;
        // Check if any safe host is a suffix (e.g. *.github.com)
        const isSafeSuffix = [...SAFE_HOSTS].some(
          (safe) =>
            cleanHost.endsWith("." + safe) || cleanHost === safe
        );
        if (isSafeSuffix) continue;

        // Skip common documentation TLDs used as examples
        if (
          cleanHost.endsWith(".example") ||
          cleanHost.endsWith(".test") ||
          cleanHost.endsWith(".invalid") ||
          cleanHost.endsWith(".localhost") ||
          cleanHost.endsWith(".local")
        )
          continue;

        report(filePath, lineNum, "Real-looking hostname", hm[0]);
      }
    }
  }
}

// ── Result ──────────────────────────────────────────────────────

if (violations > 0) {
  console.error(`\n${violations} potential secret(s) or violation(s) found.`);
  process.exit(1);
} else {
  console.log("No secrets or violations found in docs/content.");
  process.exit(0);
}
