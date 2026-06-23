// SPDX-License-Identifier: Apache-2.0
// Developer guide: require a receipt in one endpoint (the 402 demand loop).

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const codeBox = {
  fontFamily: font.mono,
  fontSize: 12.5,
  lineHeight: 1.7,
  color: '#D6D3D1',
  background: '#1C1917',
  border: `1px solid ${color.border}`,
  borderRadius: radius.base,
  padding: '20px 22px',
  margin: '14px 0 0',
  overflowX: 'auto',
  whiteSpace: 'pre',
};

const MIDDLEWARE = `import { requireEmiliaReceipt } from '@emilia-protocol/require-receipt';

app.post(
  '/release-payment',
  requireEmiliaReceipt({
    trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY], // base64url SPKI you trust
    action: 'payment.release',
    maxAgeSec: 900,
  }),
  (req, res) => {
    // Only reached if a fresh, untampered, action-bound receipt from a
    // trusted issuer was presented. req.emiliaReceipt holds the verified claim.
    res.json({ released: true, receipt: req.emiliaReceipt.receipt_id });
  },
);`;

const LOOP = `→ POST /release-payment            (no receipt)
← 402 EMILIA Receipt Required
  WWW-Authenticate: EMILIA realm="agent-actions", action="payment.release"
  { required: { action: "payment.release",
                header: "X-EMILIA-Receipt: base64(...)" } }

→ POST /release-payment            X-EMILIA-Receipt: base64(<receipt>)
← 200 { released: true }`;

const FAQ = [
  ['Why would a service add 402 friction?',
    'Because it converts "trust me, a human approved this" into portable, offline-checkable evidence — and it lets well-behaved agents self-serve authorization with no human in the support loop. 402 deliberately rides the same "challenge-to-transact" rail as agent-commerce conventions (x402 / AP2).'],
  ['Do I need an EMILIA backend to verify?',
    'No. Verification is offline and asymmetric: you hold the issuer public keys you trust and check the receipt locally. Nothing calls home. The middleware fails closed — no valid receipt, no irreversible action.'],
  ['What about MCP tool calls?',
    'Use @emilia-protocol/mcp-guard: it wraps an MCP tool-call handler so irreversible tool calls route through signoff and emit a receipt while everything else passes through — the same demand hook, returning a 402-style refusal.'],
];

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map(([q, a]) => ({
    '@type': 'Question', name: q, acceptedAnswer: { '@type': 'Answer', text: a },
  })),
};

export default function RequireReceiptGuide() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <SiteNav activePage="Agent Guard" />
      <main style={styles.page}>
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>DEVELOPER GUIDE · THE DEMAND SIDE</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 880 }}>Require a receipt in one endpoint.</h1>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 18, fontSize: 18 }}>
            <strong>No receipt, no irreversible action.</strong> Make your service refuse an
            irreversible call unless a valid authorization receipt rides with it. The caller gets a
            402 that says exactly what to bring; a well-behaved agent obtains a receipt and retries;
            you verify it offline — no EMILIA backend, fail-closed.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
            <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/402-loop.mjs" target="_blank" rel="noopener noreferrer" style={cta.primary}>See the runnable loop</a>
            <a href="/agent-guard" style={cta.secondary}>Agent Guard (the gate)</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STEP 1 · THE ONE MIDDLEWARE</div>
          <h2 style={{ ...styles.h2, maxWidth: 720 }}>Wrap the irreversible endpoint.</h2>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            Framework-agnostic Express-style middleware. Install{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>npm i @emilia-protocol/require-receipt</span>,
            then gate the one route that does something it can&rsquo;t take back:
          </p>
          <pre style={codeBox}>{MIDDLEWARE}</pre>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STEP 2 · THE 402 LOOP</div>
          <h2 style={{ ...styles.h2, maxWidth: 720 }}>The agent self-serves the proof.</h2>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            No receipt? The service answers <strong>402</strong> and tells the agent exactly what to
            bring — like a browser handling 401. A well-behaved agent obtains a receipt and retries,
            no human in the support loop:
          </p>
          <pre style={codeBox}>{LOOP}</pre>
          <p style={{ ...styles.body, maxWidth: 720, marginTop: 16, fontSize: 15, color: color.t2 }}>
            Run the whole loop end to end from a clean checkout:{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>node examples/402-loop.mjs</span>
            {'  '}· or see a receipt issued + verified offline in 30s:{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>npx @emilia-protocol/crash-test</span>
          </p>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STEP 3 · VERIFY OFFLINE</div>
          <h2 style={{ ...styles.h2, maxWidth: 720 }}>Check it yourself — no one&rsquo;s word for it.</h2>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            The same package exports <span style={{ fontFamily: font.mono, color: color.t1 }}>verifyEmiliaReceipt(doc, opts)</span> for
            programmatic checks, and any receipt verifies from the terminal with{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>npx @emilia-protocol/verify receipt.json</span> —
            asymmetric, offline, open-source (Apache-2.0). For MCP servers,{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>@emilia-protocol/mcp-guard</span> applies the same
            demand hook to a tool-call handler.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
            <a href="/mcp" style={cta.secondary}>MCP tool guarding</a>
            <a href="/auditors" style={cta.secondary}>How auditors verify</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>FREQUENTLY ASKED</div>
          {FAQ.map(([q, a]) => (
            <div key={q} style={{ padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
              <div style={{ ...styles.h3, fontSize: 18, marginBottom: 6 }}>{q}</div>
              <p style={{ ...styles.body, margin: 0, fontSize: 15, maxWidth: 760 }}>{a}</p>
            </div>
          ))}
        </section>

        <section style={styles.section}>
          <p style={{ fontSize: 13, color: color.t3, maxWidth: 760, lineHeight: 1.6 }}>
            The middleware fails closed: an absent, expired, tampered, or untrusted-issuer receipt is
            refused. Offline verification proves the receipt is authentic, intact, and bound to the
            exact action; it does not assert the decision was correct or identity beyond the
            enrollment layer. Open standard (Apache-2.0), IETF Internet-Drafts.
          </p>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
