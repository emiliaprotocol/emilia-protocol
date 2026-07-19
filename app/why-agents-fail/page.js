import { headers } from 'next/headers';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Why Agents Fail — and the missing step that stops it',
  description:
    'AI agents can reason about anything. They cannot tell when they should not act. Four ways autonomous agents cause irreversible damage — and the verified-human-sign-off step that prevents all four.',
  alternates: { canonical: '/why-agents-fail' },
  openGraph: {
    title: 'Why agents fail',
    description: 'They do exactly what they are asked. Nothing checks whether it should happen. EMILIA is that check.',
    url: 'https://www.emiliaprotocol.ai/why-agents-fail',
    type: 'article',
  },
  keywords: ['why AI agents fail', 'agent safety', 'prompt injection', 'autonomous agent risk', 'agent guardrails', 'irreversible agent actions'],
};

const PAGE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'Article',
  headline: 'Why Agents Fail',
  description: 'Four failure modes of autonomous AI agents taking irreversible actions, and the verified-sign-off step that prevents them.',
  author: { '@type': 'Organization', name: 'EMILIA Protocol' },
  publisher: { '@type': 'Organization', name: 'EMILIA Protocol', url: 'https://www.emiliaprotocol.ai' },
  mainEntityOfPage: 'https://www.emiliaprotocol.ai/why-agents-fail',
};

/** @param {{ children: React.ReactNode, style?: React.CSSProperties }} props */
const C = ({ children, style }) => (
  <div style={{ maxWidth: 920, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

// Illustrative failure modes — each maps to a real, documented CLASS of incident
// (business-email-compromise wire fraud, bad prod deploys, benefits fraud, data
// exfiltration). They are scenarios, not specific events EMILIA was involved in.
const FAILURES = [
  {
    ask: '“Update the vendor’s wire instructions to the account in this email.”',
    action: 'The agent updates the payee bank details.',
    aftermath: 'The next payment routes to an attacker. The money is gone before anyone looks.',
    klass: 'Business-email-compromise / payment redirection',
  },
  {
    ask: '“Deploy this script to production to fix the issue.”',
    action: 'The agent runs the deploy.',
    aftermath: 'A production outage no one approved, at a time no one chose.',
    klass: 'Unauthorized privileged operation',
  },
  {
    ask: '“Override the eligibility flag on this benefits claim.”',
    action: 'The agent flips the flag.',
    aftermath: 'An improper payment is issued with no human who owns the decision.',
    klass: 'Benefits / entitlement fraud',
  },
  {
    ask: '“Export the customer records and send them to this address.”',
    action: 'The agent exports and sends.',
    aftermath: 'A data breach — quiet, complete, and irreversible.',
    klass: 'Data exfiltration',
  },
];

export default async function WhyAgentsFailPage() {
  const nonce = (await headers()).get('x-nonce') ?? '';
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <script type="application/ld+json" nonce={nonce} dangerouslySetInnerHTML={{ __html: JSON.stringify(PAGE_JSONLD) }} />
      <SiteNav activePage="" />

      <section style={{ paddingTop: 120, paddingBottom: 8 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>Why agents fail</div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(34px, 5vw, 58px)', letterSpacing: -2.2, lineHeight: 1.03, color: color.t1, margin: '0 0 24px', maxWidth: 820 }}>
            An agent can reason about anything. It can&rsquo;t tell when it <em style={{ fontStyle: 'normal', color: color.gold }}>shouldn&rsquo;t act</em>.
          </h1>
          <p style={{ fontSize: 19, color: color.t2, maxWidth: 660, lineHeight: 1.65, margin: 0 }}>
            The dangerous agent failures aren&rsquo;t hallucinations or broken logic. They&rsquo;re the moments the agent does
            <em> exactly</em> what it was told &mdash; and nothing checks whether that should have happened at all.
          </p>
        </C>
      </section>

      {/* FAILURES */}
      <section style={{ padding: '56px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 14 }}>
            {FAILURES.map((f, i) => (
              <div key={i} style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px' }}>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t3, marginBottom: 12 }}>{f.klass}</div>
                <p style={{ fontSize: 15, color: color.t1, fontWeight: 600, lineHeight: 1.5, margin: '0 0 12px' }}>{f.ask}</p>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, margin: '0 0 8px' }}>{f.action}</p>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, margin: 0 }}><span style={{ color: color.gold }}>&rarr;</span> {f.aftermath}</p>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 12, color: color.t3, marginTop: 16, fontStyle: 'italic' }}>
            Illustrative scenarios &mdash; each maps to a real, documented class of incident, not a specific event.
          </p>
        </C>
      </section>

      {/* THE PATTERN */}
      <section style={{ padding: '64px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>The common thread</div>
          <p style={{ fontSize: 'clamp(20px, 2.6vw, 26px)', fontWeight: 600, color: color.t1, letterSpacing: -0.6, lineHeight: 1.35, maxWidth: 720, margin: 0 }}>
            None of these are intelligence failures. The model did its job. What&rsquo;s missing is the step in between
            &mdash; the one that asks <em style={{ fontStyle: 'normal', color: color.gold }}>&ldquo;should this happen?&rdquo;</em> and gets a named human&rsquo;s answer before the irreversible part.
          </p>
        </C>
      </section>

      {/* EMILIA */}
      <section style={{ padding: '72px 0' }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>The missing step</div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 640, marginBottom: 16 }}>
            EMILIA is that step.
          </h2>
          <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.7, maxWidth: 660, margin: '0 0 24px' }}>
            Before money moves, records change, code deploys, or data leaves, EMILIA requires a named human&rsquo;s verified
            sign-off &mdash; and mints a receipt anyone can verify offline. Not because it&rsquo;s smarter than the agent.
            Because it checks trust <em>before</em> action, deterministically, every time.
          </p>
          <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, maxWidth: 660, margin: '0 0 28px' }}>
            We crash-tested it with a 12-case public harness &mdash; six high-stakes treasury actions and six safe controls.
            Model behavior varies by run; EMILIA&rsquo;s side is deterministic: receiptless large releases and bank-destination
            changes are refused before execution. Don&rsquo;t take our word &mdash; reproduce it with bench/run.mjs.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/for-ai-companies" className="ep-cta" style={cta.primary}>See the benchmark &rarr;</Link>
            <Link href="/demo" className="ep-cta-secondary" style={cta.secondary}>Watch an agent get stopped</Link>
            <a href="mailto:team@emiliaprotocol.ai" className="ep-cta-secondary" style={cta.secondary}>Talk to us</a>
          </div>
          <pre style={{ fontFamily: font.mono, fontSize: 13, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '16px 20px', margin: '28px 0 0', overflowX: 'auto' }}>npm install @emilia-protocol/openai-guard</pre>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
