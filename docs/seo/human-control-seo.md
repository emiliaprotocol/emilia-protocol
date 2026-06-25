# SEO Strategy — Human Control / Autonomy Vertical

**Goal:** own the search term for the open niche — *the verifiable evidence artifact for
meaningful human control*. Be the canonical answer when a program officer, prime engineer,
policy analyst, or journalist searches "how do we prove a human was in control."

Pillar page: **`/human-control`** (shipped). This doc defines the cluster around it.

## Target keywords

**Primary (own these):**
- meaningful human control (evidence / proof / verifiable)
- verifiable human oversight
- human-on-the-loop vs human-in-the-loop
- proof a human authorized an AI / autonomous action

**Compliance intent (high commercial value):**
- DoD Directive 3000.09 human judgment / compliance evidence
- EU AI Act Article 14 human oversight (how to demonstrate / prove)
- NIST AI RMF human oversight documentation
- autonomous weapon systems accountability / auditability

**Long-tail (the open niche — low competition, high fit):**
- how to prove meaningful human control
- audit trail for human approval of autonomous action
- offline-verifiable human authorization receipt
- two-person rule cryptographic evidence
- rules of engagement authorization audit

## Content cluster (supporting pages/posts → link up to /human-control)

1. **"Meaningful Human Control: doctrine vs. evidence"** — explainer; the gap thesis. (blog)
2. **"How to demonstrate EU AI Act Article 14 human oversight"** — interlink with existing `/eu-ai-act`. (blog/guide)
3. **"DoD 3000.09 in practice: from 'appropriate human judgment' to a verifiable artifact."** (brief → gated PDF / lead magnet)
4. **"Human-in-the-loop vs. human-on-the-loop, and why the authorization boundary is what you audit."** (blog)
5. **The crosswalk** (`docs/compliance/HUMAN_CONTROL_CROSSWALK.md`) → render as a public `/human-control/crosswalk` table page (high-intent, linkable).
6. **PIP-013** → linked from `/docs` and the pillar.

## On-page / technical

- Title + meta + canonical + OG + keywords: shipped in `app/human-control/layout.js`.
- **Schema markup (add next):** `TechArticle` or `WebPage` + `FAQPage` for the "what it proves / does not" and the doctrine Q&A. Use the `schema-markup` skill. Candidate FAQ entries: "What is meaningful human control?", "How do you prove a human authorized an autonomous action?", "Does this satisfy EU AI Act Article 14?", "Human-in-the-loop vs human-on-the-loop?"
- Internal links: pillar ↔ `/eu-ai-act`, `/government`, `/govguard`, `/quorum`, `/demo`, `/docs`. Add `/human-control` to `SiteNav` (or a "Solutions" submenu) and the footer.
- Breadcrumbs + a single H1 (present), descriptive H2s (present).

## Off-page / authority

- The Microsoft `ai-agents-for-beginners` lesson (PR #616) and the IETF I-Ds are the
  credibility backlinks — cite them from the cluster, and cite the cluster from the brief/deck.
- The AIPF §8.5 thread and dispatch positioning reinforce topical authority around
  "accountability for autonomous action."

## Honesty guardrail (also protects SEO trust)

Never rank for "stop autonomous weapons" / "prevent AI takeover" — wrong audience, kills
credibility, invites takedown. Rank for the *evidence* terms. Keep "necessary, not
sufficient" on the page (it's already there) — it's both honest and a differentiator.

## Next actions

- [ ] Add `FAQPage` + `TechArticle` JSON-LD to the pillar (schema-markup skill).
- [ ] Add `/human-control` to `SiteNav` + footer.
- [ ] Publish cluster posts 1–4 (copywriting skill; one per week).
- [ ] Render the crosswalk as `/human-control/crosswalk`.
- [ ] Submit pillar URL in the next sitemap; request indexing.
