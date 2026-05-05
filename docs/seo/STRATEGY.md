# SEO Strategy — EMILIA Protocol

Working strategy doc covering keyword targeting, page mapping, and
content gaps. Update as rankings, search-console data, and ICP feedback
evolve.

## ICPs (in priority order)

1. **AI agent platform engineering leaders** — Cognition, Sierra, Adept,
   Lindy, Browser, Multi On, custom agent frameworks. Buyer: Head of
   Eng, Head of Trust/Safety, CTO. Volume: ~150 named US companies. Cycle:
   4–8 weeks. Deal: $20K–$80K ARR.
2. **Financial-fraud-defense buyers** — community banks, credit unions,
   regional banks, fintechs. Buyer: Head of Fraud, AI Risk lead, CISO.
   Volume: ~5,000 US institutions. Cycle: 3–6 months. Deal: $50K–$500K.
3. **Federal/state benefit-integrity teams** — SNAP, Medicaid, UI fraud
   working groups, state AI sandboxes. Buyer: Director of Innovation,
   IG/GAO-adjacent. Volume: smaller, slower (~50 named entities). Cycle:
   12–18 months. Deal: $100K–$2M.

## Keyword strategy

### Tier 1 — primary keywords (high intent, sized)

| Keyword | Target page | Intent | ICP | Estimated Difficulty |
|---|---|---|---|---|
| AI agent authorization | `/use-cases/ai-agent` | What/How | AI agent | Medium |
| pre-action authorization | `/protocol` | What | All | Low |
| verifiable AI authorization | `/protocol` | What | AI agent + Gov | Low |
| AI agent governance platform | `/use-cases/ai-agent` | Comparison | AI agent | High |
| MCP authorization | `/protocol`, blog | How | AI agent | Low (rising) |
| AI agent trust gate | `/use-cases/ai-agent` | What/How | AI agent | Low |
| wire transfer fraud prevention AI | `/finguard`, `/use-cases/financial` | How | Fin | Medium |
| vendor bank change fraud | `/use-cases/financial` | How/Defense | Fin | Low |
| AI voice fraud defense | `/use-cases/financial` | What/Defense | Fin | Low |
| benefit redirection fraud | `/use-cases/government`, `/govguard` | What/Defense | Gov | Low |
| SNAP fraud prevention | `/use-cases/government` | How | Gov | Medium |
| caseworker override control | `/govguard` | What | Gov | Very Low |
| NIST AI RMF compliance tool | `/protocol`, blog | Solution | All | Medium |
| EU AI Act high-risk system controls | blog, `/spec` | Solution | All | Medium |
| formal verification AI authorization | `/spec`, blog | Educational | All | Very Low |

### Tier 2 — long-tail and educational

| Keyword | Target | Notes |
|---|---|---|
| how to authorize AI agent actions | blog post | Educational, top-of-funnel |
| how to prevent prompt injection action exploits | blog | Adjacent — frames EP as defense |
| difference between OAuth and AI agent authorization | comparison page | Bottom of funnel — buyers search this |
| trust receipt vs audit log | blog post | Educational |
| MCP authorization best practices | blog post | Hot topic, low competition |
| autonomous agent safety standards | blog, `/spec` | Aligns with NIST/AISI vocab |
| federation architecture for AI agents | blog | Surface for the federation work |
| compliance mapping NIST AI RMF | blog, `/spec` | Procurement-team query |

### Tier 3 — branded / direct

`emilia protocol`, `ep govguard`, `ep finguard`, `@emilia-protocol/sdk`,
`@emilia-protocol/verify`. These should rank #1 immediately given the
domain authority of `emiliaprotocol.ai`. Track them in Search Console.

## Page-to-keyword mapping (existing pages)

| Page | Primary keyword | Secondary keywords |
|---|---|---|
| `/` (home) | EMILIA Protocol, AI agent authorization | trust before AI action, formal verification |
| `/protocol` | pre-action authorization, verifiable AI authorization | EP four layers, eye handshake signoff commit |
| `/spec` | EP protocol specification, formal verification AI | TLA+ theorems, Alloy assertions, EP-RECEIPT-v1 |
| `/govguard` | benefit redirection fraud, government AI controls | caseworker override, SNAP/Medicaid integrity |
| `/finguard` | wire transfer fraud prevention, vendor bank change fraud | AI voice fraud, beneficiary swap, BEC prevention |
| `/use-cases/ai-agent` | AI agent authorization, AI agent governance | MCP authorization, agent action binding |
| `/use-cases/government` | benefit redirection fraud, NIST AI RMF compliance | federal AI controls, IG/GAO evidence |
| `/use-cases/financial` | wire transfer fraud, AI voice fraud defense | community bank fraud, treasury authorization |
| `/use-cases/enterprise` | privileged action authorization, PAM AI | zero trust action, production deployment authorization |
| `/playground` | EMILIA Protocol playground | live trust ceremony demo, EP demo |
| `/explorer` | trust receipt explorer, verify EP receipt | etherscan for trust |

## Content gaps to fill (highest leverage)

### Comparison / Alternatives pages
*Procurement teams search "EP vs X". Owning these pages is high-conversion.*

1. `/compare/oauth` — "How EP differs from OAuth and why action-binding matters"
2. `/compare/mcp-auth-alone` — "MCP authorization is necessary but insufficient"
3. `/compare/audit-logs` — "Why audit logs aren't enough for AI agent action governance"
4. `/compare/fraud-detection` — "Pre-action authorization vs post-action fraud detection"

### Educational / blog posts (top-of-funnel)
*Each one gets 200–2K monthly searches; collectively grow domain authority.*

1. **What is pre-action authorization?** — define-the-category post; target
   "pre-action authorization" + "what is action binding"
2. **How formal verification works for protocols** — explain TLA+ + Alloy
   accessibly; target "formal verification protocol" + "TLA+ tutorial"
3. **A walkthrough of the EP handshake ceremony** — technical deep-dive;
   target "AI agent handshake protocol" + "OAuth for AI agents"
4. **Federation architecture for AI trust** — surface the federation work
5. **The four layers of AI action governance: Eye, Handshake, Signoff, Commit**
   — frame EP's mental model
6. **MCP authorization best practices in 2026** — ride the MCP wave; lots
   of search volume for "MCP server authorization"
7. **AI voice cloning fraud: defense by action binding** — connect
   topical news to EP's solution
8. **Vendor-bank-change fraud explained (and how to prevent it)** — 
   community bank/CU search query
9. **Compliance walkthrough: mapping EP to NIST AI RMF** — procurement
   team comfort document
10. **Compliance walkthrough: mapping EP to EU AI Act Chapter 2** — same
    for European regulated industries

### Documentation gaps
*Each is a real SEO surface in addition to being good docs.*

1. `/docs/quickstart-typescript` — for the @emilia-protocol/sdk landing
2. `/docs/quickstart-python` — for the python SDK landing
3. `/docs/quickstart-mcp` — connecting an EP MCP server to Claude / OpenAI
4. `/docs/policy-authoring-guide` — long-tail "how to write an EP policy"
5. `/docs/handshake-modes` — `basic | mutual | selective | delegated`

### Glossary page (`/glossary`)
*Each term becomes its own anchor and an internal-linking surface.*

handshake, signoff, trust receipt, action binding, policy hash pinning,
Merkle anchoring, commit ceremony, federation operator, EP-RECEIPT-v1,
binding hash, accountable signoff, observe mode, shadow mode, enforce mode.

## Technical SEO foundation status (after this PR)

| Area | Status |
|---|---|
| `metadataBase` set | ✅ |
| `title.template` for site-wide branding | ✅ |
| Open Graph defaults | ✅ |
| Twitter card defaults | ✅ |
| Per-page `alternates.canonical` | ✅ for top 12 pages, partial for the rest |
| Per-page `openGraph` | ✅ for top 12 pages |
| `app/sitemap.js` (auto /sitemap.xml) | ✅ |
| `app/robots.js` (auto /robots.txt) | ✅ |
| JSON-LD Organization | ✅ (root layout) |
| JSON-LD WebSite (with SearchAction) | ✅ (root layout) |
| JSON-LD SoftwareApplication | ✅ (root layout) |
| Indexable pages: noindex on intentional ones | ✅ (`/investors` is noindex) |
| AI search bots allowed in robots | ✅ (Googlebot, GPTBot, ClaudeBot, PerplexityBot) |
| `og-default.png` social preview image | ⚠️ **NEEDS CREATION** — referenced in metadata but file doesn't exist yet |
| Logo at `/logo.png` | ⚠️ **NEEDS VERIFICATION** — referenced in Organization JSON-LD |

## Pending implementation work

Tracked on TODO.md; the high-leverage SEO follow-ups are:

1. Create `public/og-default.png` (1200×630, EP logo + "Trust before
   high-risk AI action") — without this, social shares look broken.
2. Verify `public/logo.png` exists at the size the Organization
   schema expects (≥112×112 minimum for Google Knowledge Panel).
3. Submit `https://www.emiliaprotocol.ai/sitemap.xml` to Google
   Search Console + Bing Webmaster Tools (one-time, takes 5 min each).
4. Write the first three comparison pages (vs OAuth, vs MCP auth alone,
   vs audit logs) — biggest near-term ranking gains.
5. Write three top-of-funnel blog posts (pick from the list above) —
   start with the MCP authorization piece since it's lowest-difficulty
   highest-trend.
