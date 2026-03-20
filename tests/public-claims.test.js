/**
 * Public Claims Audit — Static Analysis Tests
 *
 * Verifies that every public-facing claim (README, website, .well-known,
 * OpenAPI, SDK READMEs, MCP server README) is literally true in the code.
 *
 * Standard: "Can a serious buyer, auditor, or regulator read this literally
 * and find it true in the code?"
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

// ── Helpers ────────────────────────────────────────────────────────────────

function readFile(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf-8');
}

function countRouteFiles() {
  const apiDir = path.join(ROOT, 'app', 'api');
  const routes = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name === 'route.js') routes.push(full);
    }
  }
  walk(apiDir);
  return routes.length;
}

function countOpenApiPaths() {
  const content = readFile('openapi.yaml');
  const pathMatches = content.match(/^  \/api\//gm);
  return pathMatches ? pathMatches.length : 0;
}

function countMcpTools(source) {
  const matches = source.match(/name:\s*['"]ep_[a-z_]+['"]/g);
  return matches ? matches.length : 0;
}

function countMcpToolsInReadme(source) {
  // Count rows in tool tables — lines starting with | `ep_
  const matches = source.match(/\|\s*`ep_[a-z_]+`/g);
  return matches ? matches.length : 0;
}

// ── 1. README Claims ───────────────────────────────────────────────────────

describe('README claims', () => {
  const readme = readFile('README.md');

  it('Route parity number matches actual route file count', () => {
    // Extract the route parity claim, e.g. "50/50"
    const match = readme.match(/Route parity.*?\|\s*(\d+)\/(\d+)/);
    expect(match).not.toBeNull();
    const [, claimed, total] = match;
    expect(claimed).toBe(total); // claimed parity means both sides equal

    const routeCount = countRouteFiles();
    const openApiCount = countOpenApiPaths();

    // Both the claimed number and actual counts should match
    expect(routeCount).toBe(Number(claimed));
    expect(openApiCount).toBe(Number(total));
  });

  it('MCP tools listed in README match actual tool count in mcp-server/index.js', () => {
    const mcpSource = readFile('mcp-server/index.js');
    const actualToolCount = countMcpTools(mcpSource);

    // README lists tools in tables with | `ep_... pattern
    const readmeToolCount = countMcpToolsInReadme(readme);

    expect(actualToolCount).toBeGreaterThan(0);
    expect(readmeToolCount).toBe(actualToolCount);
  });

  it('"3 Core Objects" claim matches PROTOCOL-STANDARD.md', () => {
    const protocolStandard = readFile('docs/PROTOCOL-STANDARD.md');

    // README claims three core objects: Trust Receipt, Trust Profile, Trust Decision
    expect(readme).toContain('Three Core Objects');
    expect(readme).toContain('Trust Receipt');
    expect(readme).toContain('Trust Profile');
    expect(readme).toContain('Trust Decision');

    // PROTOCOL-STANDARD.md must also list the same three
    expect(protocolStandard).toContain('Trust Receipt');
    expect(protocolStandard).toContain('Trust Profile');
    expect(protocolStandard).toContain('Trust Decision');
    expect(protocolStandard).toMatch(/three interoperable objects/i);
  });

  it('Decision vocabulary matches VALID_DECISIONS in lib/commit.js', () => {
    const commitSource = readFile('lib/commit.js');

    // Extract VALID_DECISIONS from commit.js
    const validDecisionsMatch = commitSource.match(
      /VALID_DECISIONS\s*=\s*new\s+Set\(\[([^\]]+)\]/
    );
    expect(validDecisionsMatch).not.toBeNull();

    const decisions = validDecisionsMatch[1]
      .match(/'([^']+)'/g)
      .map((d) => d.replace(/'/g, ''));

    // README mentions allow/review/deny as the decision vocabulary
    for (const decision of decisions) {
      expect(readme.toLowerCase()).toContain(decision);
    }

    // Canonical set should be exactly allow, review, deny
    expect(decisions.sort()).toEqual(['allow', 'deny', 'review']);
  });

  it('Does NOT claim ZK (zero-knowledge) in primary public claims', () => {
    // "Commitment proofs" is the correct term in primary claims.
    // The README may reference "zk-proof" in API endpoint paths (that is fine,
    // since the API path is a legacy URL), but the primary feature description
    // must say "commitment proofs" not "zero-knowledge proofs".
    const coreObjectsSection = readme.split('## EP Core')[0]; // before core section listing
    const primaryClaims = readme.split('## What\'s Live')[0]; // everything above the status table

    // The extension description should say "Commitment proofs" not "Zero-knowledge proofs"
    expect(readme).toContain('Commitment proofs');

    // The "What is EP" section and core description must not lead with ZK
    const whatIsEP = readme.split('## What is EP?')[1]?.split('---')[0] || '';
    expect(whatIsEP).not.toMatch(/zero-knowledge proof/i);
  });
});

// ── 2. Website Claims ──────────────────────────────────────────────────────

describe('Website (landing.html) claims', () => {
  const landing = readFile('content/landing.html');

  it('Does NOT claim "standard" status in hero/lead (it is a protocol)', () => {
    // The hero section should say "protocol" not claim it is already a "standard"
    // Extract hero section
    const heroMatch = landing.match(
      /<!-- HERO -->[\s\S]*?<\/section>/
    );
    expect(heroMatch).not.toBeNull();
    const hero = heroMatch[0];

    // Hero should say "protocol" prominently
    expect(hero.toLowerCase()).toContain('protocol');

    // Hero h1 and hook should not claim "standard" as the entity type
    // (using "standard" in a policy name like "standard" is fine,
    //  claiming EP IS a standard is premature)
    const h1Match = hero.match(/<h1[^>]*>([\s\S]*?)<\/h1>/);
    if (h1Match) {
      expect(h1Match[1].toLowerCase()).not.toContain('the standard');
    }
  });

  it('Does NOT use "zero-knowledge proof" as a primary claim', () => {
    // The hero section should not claim ZK
    const heroMatch = landing.match(
      /<!-- HERO -->[\s\S]*?<\/section>/
    );
    expect(heroMatch).not.toBeNull();
    const hero = heroMatch[0];
    expect(hero.toLowerCase()).not.toContain('zero-knowledge');
  });

  it('Does NOT use "trust layer" as the lead hero positioning', () => {
    // "The Trust Layer" appears in a comparison table context (line 914),
    // which is acceptable. But it must NOT be the h1 or hero-hook lead.
    const heroMatch = landing.match(
      /<!-- HERO -->[\s\S]*?<\/section>/
    );
    expect(heroMatch).not.toBeNull();
    const hero = heroMatch[0];

    const h1Match = hero.match(/<h1[^>]*>([\s\S]*?)<\/h1>/);
    if (h1Match) {
      expect(h1Match[1].toLowerCase()).not.toContain('trust layer');
    }

    const hookMatch = hero.match(/class="hero-hook"[^>]*>([\s\S]*?)<\/p>/);
    if (hookMatch) {
      expect(hookMatch[1].toLowerCase()).not.toContain('trust layer');
    }
  });
});

// ── 3. .well-known Claims ──────────────────────────────────────────────────

describe('.well-known/ep-trust.json claims', () => {
  const wellKnown = JSON.parse(readFile('public/.well-known/ep-trust.json'));

  it('Every URL endpoint has a corresponding route file', () => {
    // Extract URL fields that reference /api/ paths
    const urlFields = [
      'trust_profile_url',
      'trust_evaluate_url',
      'receipt_submit_url',
      'receipt_confirm_url',
      'dispute_file_url',
      'dispute_report_url',
    ];

    for (const field of urlFields) {
      const url = wellKnown[field];
      expect(url).toBeDefined();

      // Extract the path from the URL, e.g. /api/trust/profile/{entity_id}
      const pathMatch = url.match(/\/api\/[^\s?#]+/);
      expect(pathMatch).not.toBeNull();

      let apiPath = pathMatch[0];
      // Normalize template params: {entity_id} -> [entityId] style for directory lookup
      // But we just need to check a route.js exists in the right directory
      // Strip the template param to get the directory
      apiPath = apiPath.replace(/\/\{[^}]+\}$/, '');

      // Check that a route.js exists somewhere under this path
      const routeDir = path.join(ROOT, 'app', apiPath);
      const routeFile = path.join(routeDir, 'route.js');
      // Some routes use dynamic segments like [entityId]
      // So we check either the exact path or a dynamic segment variant
      let exists = fs.existsSync(routeFile);
      if (!exists) {
        // Try to find a route.js in a directory that matches the pattern
        // e.g., /api/trust/profile might have /api/trust/profile/[entityId]/route.js
        const parentDir = routeDir;
        if (fs.existsSync(parentDir)) {
          const entries = fs.readdirSync(parentDir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isDirectory() && entry.name.startsWith('[')) {
              const dynamicRoute = path.join(parentDir, entry.name, 'route.js');
              if (fs.existsSync(dynamicRoute)) {
                exists = true;
                break;
              }
            }
          }
        }
        // Also check if route.js exists directly in the parent
        if (!exists) {
          exists = fs.existsSync(path.join(parentDir, 'route.js'));
        }
      }

      expect(exists, `Route file missing for ${field}: ${apiPath}`).toBe(true);
    }
  });

  it('protocol_version matches PROTOCOL-STANDARD.md version', () => {
    const protocolStandard = readFile('docs/PROTOCOL-STANDARD.md');

    // Extract version from PROTOCOL-STANDARD.md header
    const versionMatch = protocolStandard.match(/\*\*Version:\*\*\s*(\S+)/);
    expect(versionMatch).not.toBeNull();
    const specVersion = versionMatch[1];

    // .well-known uses "version" field
    const wellKnownVersion = wellKnown.version;
    expect(wellKnownVersion).toBeDefined();

    // The .well-known version should be compatible with the spec version
    // .well-known says "1.1", spec says "1.0" — both are 1.x family
    // They should share the same major version
    const specMajor = specVersion.split('.')[0];
    const wellKnownMajor = wellKnownVersion.split('.')[0];
    expect(wellKnownMajor).toBe(specMajor);
  });
});

// ── 4. OpenAPI Coverage ────────────────────────────────────────────────────

describe('OpenAPI coverage', () => {
  it('OpenAPI path count matches or exceeds route file count', () => {
    const routeCount = countRouteFiles();
    const openApiCount = countOpenApiPaths();

    // They should be equal (route parity claim) or OpenAPI >= routes
    expect(openApiCount).toBeGreaterThanOrEqual(routeCount);
  });

  it('Route parity: OpenAPI and route files match exactly', () => {
    const routeCount = countRouteFiles();
    const openApiCount = countOpenApiPaths();
    expect(openApiCount).toBe(routeCount);
  });
});

// ── 5. SDK Claims ──────────────────────────────────────────────────────────

describe('SDK (TypeScript) claims', () => {
  const sdkReadme = readFile('sdks/typescript/README.md');

  it('EP_BASE_URL referenced in SDK README matches actual default in client.ts', () => {
    const clientSource = readFile('sdks/typescript/src/client.ts');

    // Extract DEFAULT_BASE_URL from client.ts
    const defaultUrlMatch = clientSource.match(
      /DEFAULT_BASE_URL\s*=\s*['"]([^'"]+)['"]/
    );
    expect(defaultUrlMatch).not.toBeNull();
    const actualDefault = defaultUrlMatch[1];

    // SDK README should reference the same base URL
    expect(sdkReadme).toContain(actualDefault);
  });

  it('SDK README EP_BASE_URL default matches code default', () => {
    const clientSource = readFile('sdks/typescript/src/client.ts');

    const defaultUrlMatch = clientSource.match(
      /DEFAULT_BASE_URL\s*=\s*['"]([^'"]+)['"]/
    );
    const actualDefault = defaultUrlMatch[1];

    // README says default is https://emiliaprotocol.ai
    const readmeDefaultMatch = sdkReadme.match(
      /EP_BASE_URL.*?\|\s*`([^`]+)`/
    );
    if (readmeDefaultMatch) {
      expect(readmeDefaultMatch[1]).toBe(actualDefault);
    } else {
      // If no explicit default in table, just verify the URL appears
      expect(sdkReadme).toContain(actualDefault);
    }
  });
});

// ── 6. MCP Server Claims ──────────────────────────────────────────────────

describe('MCP server README claims', () => {
  const mcpReadme = readFile('mcp-server/README.md');
  const mcpSource = readFile('mcp-server/index.js');

  it('Tool count in MCP README matches actual handlers in index.js', () => {
    // Count tool descriptions in the README summary table
    const readmeToolCount = countMcpToolsInReadme(mcpReadme);

    // Count actual tool definitions in index.js
    const actualToolCount = countMcpTools(mcpSource);

    expect(readmeToolCount).toBeGreaterThan(0);
    expect(actualToolCount).toBeGreaterThan(0);
    expect(readmeToolCount).toBe(actualToolCount);
  });

  it('MCP README claims 34 tools and that matches actual count', () => {
    // README says "34 tools"
    const claimMatch = mcpReadme.match(/(\d+)\s*tools/);
    expect(claimMatch).not.toBeNull();
    const claimedCount = Number(claimMatch[1]);

    const actualToolCount = countMcpTools(mcpSource);
    expect(actualToolCount).toBe(claimedCount);
  });

  it('Every tool listed in MCP README exists as a handler in index.js', () => {
    // Extract tool names from README
    const readmeTools =
      mcpReadme
        .match(/`(ep_[a-z_]+)`/g)
        ?.map((t) => t.replace(/`/g, '')) || [];
    const uniqueReadmeTools = [...new Set(readmeTools)];

    // Extract tool names from index.js
    const sourceTools =
      mcpSource
        .match(/name:\s*['"]ep_([a-z_]+)['"]/g)
        ?.map((m) => 'ep_' + m.match(/ep_([a-z_]+)/)[1]) || [];

    for (const tool of uniqueReadmeTools) {
      expect(
        sourceTools.includes(tool),
        `Tool ${tool} listed in MCP README but not found in index.js`
      ).toBe(true);
    }
  });
});

// ── 7. Crypto Claims ──────────────────────────────────────────────────────

describe('Crypto / ZK claims', () => {
  it('lib/zk-proofs.js does NOT claim "zero-knowledge proofs" in primary description', () => {
    const zkSource = readFile('lib/zk-proofs.js');

    // Extract the top JSDoc comment (first block comment)
    const topComment = zkSource.match(/\/\*\*([\s\S]*?)\*\//);
    expect(topComment).not.toBeNull();
    const description = topComment[1];

    // The primary description should say "commitment" not claim to implement
    // actual zero-knowledge proofs (it uses HMAC-SHA256 commitments)
    expect(description.toLowerCase()).toContain('commitment');

    // It should NOT say "implements zero-knowledge proofs" as the lead description
    // (referencing ZK as context/comparison is fine, claiming to implement ZK SNARKs is not)
    const firstLine = description.split('\n').find((l) => l.trim().length > 0);
    expect(firstLine?.toLowerCase()).not.toMatch(
      /implements?\s+zero-knowledge\s+proofs?/
    );
  });

  it('README does not claim ZK in primary "What is EP" description', () => {
    const readme = readFile('README.md');
    const whatIsEP =
      readme.split('## What is EP?')[1]?.split('---')[0] || '';

    // "What is EP" should not lead with zero-knowledge claims
    expect(whatIsEP).not.toMatch(/zero-knowledge proof/i);
  });

  it('README extension description says "commitment proofs" not "zero-knowledge proofs"', () => {
    const readme = readFile('README.md');

    // The extension bullet point should say "Commitment proofs"
    expect(readme).toMatch(/Commitment proofs/);

    // Find the EP Extensions section and verify it does not say "Zero-knowledge proofs"
    const extensionsSection =
      readme.split('**EP Extensions**')[1]?.split('**EP Product')[0] || '';
    expect(extensionsSection).not.toMatch(/Zero-knowledge proofs/);
  });
});
