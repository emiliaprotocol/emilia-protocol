import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font } from '@/lib/tokens';

export const metadata = {
  title: 'Changelog — EMILIA Protocol',
  description:
    'Release history for EMILIA Protocol — protocol spec, reference runtime, SDKs, and MCP server. '
    + 'Versioned, formally verified, shipped on a steady cadence.',
  alternates: { canonical: '/changelog' },
  openGraph: {
    title: 'EMILIA Protocol — Changelog',
    description: 'What shipped, when. Protocol hardening, formal verification, SDKs, MCP server.',
    url: 'https://www.emiliaprotocol.ai/changelog',
    type: 'website',
  },
  keywords: ['EMILIA Protocol changelog', 'release notes', 'version history'],
};

const GH = 'https://github.com/emiliaprotocol/emilia-protocol';

const RELEASES = [
  {
    version: 'Unreleased',
    date: 'In progress',
    tag: 'Experimental profiles',
    points: [
      'EP-QUORUM-v1 — multi-party signoff (the two-person rule): M-of-N / ordered approval, each named human bound to the exact action, fail-closed. Three reference verifiers (JS / Python / Go) agree on it in cross-language conformance; live in-browser demo at /try/multi-party; server-side enforcement merged into the authorization path, pending production end-to-end validation.',
      'EP-AEC-v1 — Authorization Evidence Chain: composes heterogeneous agent-authorization receipts (delegation, policy/permit, and EP human-authorization) all bound to one canonical action into a single offline, fail-closed ALLOW/DENY. Filed as draft-schrock-ep-authorization-evidence-chain (IETF individual submission); tri-language reference verifier (JS / Python / Go) with portable conformance vectors.',
      'EP-PROVENANCE-CHAIN-v1 — chained provenance receipt. EXPERIMENTAL, additive over the frozen EP-RECEIPT-v1; governed by a Draft PIP (PIP-009).',
      'EP-DISPLAY-ATTESTATION-v1 — display attestation for WYSIWYS rendering. EXPERIMENTAL, additive over frozen EP-RECEIPT-v1; governed by a Draft PIP (PIP-010).',
      'EP-EXECUTION-INTEGRITY-v1 — execution binding between approved bytes and executed action. EXPERIMENTAL, additive over frozen EP-RECEIPT-v1; governed by a Draft PIP (PIP-010).',
      'EP-REVOCATION-v1 — portable, offline-verifiable revocation statement. EXPERIMENTAL, additive over frozen EP-RECEIPT-v1; governed by a Draft PIP (PIP-011).',
      'EP-EYE-SET-v1 — Eye continuous-eval advisory as a signed Security Event Token. EXPERIMENTAL, additive over frozen EP-RECEIPT-v1; governed by a Draft PIP (PIP-011).',
    ],
  },
  {
    version: '1.1.0',
    date: '2026-04-04',
    tag: 'Protocol hardening',
    points: [
      'EP-IX Identity Continuity — full state machine (pending → under-challenge → frozen → terminal) with rate-limit and self-contest guards.',
      'Protocol Hardening v2 — 9 Supabase migrations (065–073) closing every L99/L90/L75 finding: binding FOR UPDATE, policy-version pin, DB-clock expiry, tenant isolation, issuer-authority TOCTOU.',
      'Formal verification extended to 26 TLA+ properties (20 verified by TLC 2.19, 6 EP-IX specified).',
      '3,277 tests across 125 files — passed full internal adversarial audit.',
      'New docs: audit methodology, 1.x API compatibility policy, migration runbook.',
    ],
  },
  {
    version: '1.0.0',
    date: '2026-03-18',
    tag: 'Standard v1.0',
    points: [
      'Protocol Standard v1.0 — 17-section complete specification.',
      '29 MCP tools, 4 resources, 3 prompts; RFC 7807 errors on every surface.',
      'TypeScript SDK (25 methods) + Python SDK (21 methods) — published to npm / PyPI.',
      'EP Commit — signed pre-action authorization tokens proving policy evaluation before proceeding.',
      'OpenAPI 50/50 route coverage; 6-job CI pipeline (tests, build, lint, SDK builds, conformance, integration).',
    ],
  },
  {
    version: '0.9.0',
    date: '2026-03-15',
    tag: 'Pre-release',
    points: [
      'Canonical evaluator — single read brain across all trust surfaces.',
      'Canonical writer — single write brain for all trust-changing operations.',
      'Four-factor receipt weighting (submitter × time × graph × provenance) with Sybil quality gate.',
      'Trust profile materialization — snapshot on write, freshness on read.',
    ],
  },
];

const C = ({ children, style }) => (
  <div style={{ maxWidth: 820, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

export default function ChangelogPage() {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="" />

      <section style={{ paddingTop: 110, paddingBottom: 40 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 20 }}>
            Changelog
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(34px, 4.5vw, 56px)', letterSpacing: -2, lineHeight: 1.02, color: color.t1, margin: '0 0 20px' }}>
            What shipped, and when.
          </h1>
          <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.7, maxWidth: 560, margin: 0 }}>
            Protocol spec and reference runtime share the root version; SDKs and the MCP server version
            independently. Full history and signed releases live on{' '}
            <a href={`${GH}/releases`} target="_blank" rel="noopener noreferrer" style={{ color: color.gold }}>GitHub</a>.
          </p>
        </C>
      </section>

      <section style={{ paddingBottom: 80 }}>
        <C>
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {RELEASES.map((r) => (
              <div key={r.version} style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: 40, alignItems: 'start', padding: '40px 0', borderBottom: `1px solid ${color.border}` }}>
                <div style={{ position: 'sticky', top: 96 }}>
                  <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 22, letterSpacing: -0.5, color: color.t1 }}>v{r.version}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginTop: 4 }}>{r.date}</div>
                  <div style={{ display: 'inline-block', marginTop: 10, fontFamily: font.mono, fontSize: 9, letterSpacing: 1, textTransform: 'uppercase', color: color.gold, border: `1px solid ${color.border}`, borderRadius: 2, padding: '3px 8px' }}>{r.tag}</div>
                </div>
                <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {r.points.map((p, i) => (
                    <li key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                      <span style={{ color: color.gold, fontSize: 14, marginTop: 2, flexShrink: 0 }}>—</span>
                      <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{p}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 36 }}>
            <a href={`${GH}/blob/main/CHANGELOG.md`} target="_blank" rel="noopener noreferrer" className="ep-cta" style={cta.primary}>Full changelog on GitHub →</a>
            <Link href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the spec</Link>
          </div>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
