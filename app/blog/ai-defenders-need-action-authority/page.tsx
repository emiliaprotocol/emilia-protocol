import Link from 'next/link';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { color, cta, font } from '@/lib/tokens';

const article: React.CSSProperties = {
  maxWidth: 760,
  margin: '0 auto',
  padding: '0 32px 72px',
};

const paragraph: React.CSSProperties = {
  margin: '0 0 22px',
  color: color.t2,
  fontSize: 17,
  lineHeight: 1.82,
};

const heading: React.CSSProperties = {
  margin: '44px 0 22px',
  color: color.t1,
  fontSize: 'clamp(28px, 4vw, 42px)',
  lineHeight: 1.08,
  letterSpacing: -1.3,
};

const sourceLink: React.CSSProperties = {
  color: color.t1,
  textDecoration: 'underline',
  textUnderlineOffset: 3,
};

export default function AIDefenderAuthorityPost(): React.ReactElement {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav />

      <article>
        <header style={{ maxWidth: 940, margin: '0 auto', padding: '112px 32px 66px' }}>
          <div style={{ marginBottom: 24, color: color.gold, fontFamily: font.mono, fontSize: 11, letterSpacing: 2.2, textTransform: 'uppercase' }}>
            Field note · Agent security · August 29, 2026
          </div>
          <h1 style={{ maxWidth: 900, margin: '0 0 28px', fontSize: 'clamp(44px, 7vw, 78px)', lineHeight: 0.98, letterSpacing: -3 }}>
            AI defenders need action authority, not just credentials.
          </h1>
          <p style={{ maxWidth: 770, margin: 0, color: color.t2, fontSize: 20, lineHeight: 1.65 }}>
            Cyber-capable AI can investigate and respond at machine speed. Before it disables an
            identity, isolates a host, or changes a network rule, the customer still needs one answer:
            is this exact action inside the authority we gave it?
          </p>
        </header>

        <div style={article}>
          <p style={paragraph}>
            OpenAI&apos;s collective cyber-defense letter calls for more capable AI in defenders&apos;
            hands, stronger least privilege, accountable agent identities, authorized testing, and
            verified fixes. That direction is important. It also creates a control problem after the
            model recommends a response and before a real system changes.
          </p>
          <p style={paragraph}>
            A security product may correctly detect a compromised service identity. Its automation may
            hold a valid identity-provider credential. Neither fact establishes that the automation may
            disable this identity, in this tenant, under this incident, at this time.
          </p>

          <h2 style={heading}>Detection and authority answer different questions</h2>
          <p style={paragraph}>
            Detection asks what is happening and what response might help. Authority asks whether this
            exact response may enter the customer&apos;s system of record. A log answers what the operator
            says happened afterward. These are three different claims.
          </p>
          <p style={paragraph}>
            The authority boundary should sit beside the credential-owning adapter. The AI defender
            proposes the action without receiving the provider credential. The customer pins the
            operation, target, limits, evidence, expiry, and exception path. Gate freezes the exact
            request and permits one provider attempt only when that request fits the mandate.
          </p>

          <div style={{ margin: '34px 0', padding: 26, border: `1px solid ${color.borderHover}`, borderLeft: `3px solid ${color.gold}`, borderRadius: 8, background: '#F5F5F4' }}>
            <div style={{ color: color.t3, fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase' }}>
              The crossing
            </div>
            <div style={{ marginTop: 15, color: color.t1, fontFamily: font.mono, fontSize: 14, lineHeight: 1.8 }}>
              Security product proposes → EMILIA checks exact authority → provider adapter attempts once → action-bound record
            </div>
          </div>

          <h2 style={heading}>The refusal is the product</h2>
          <p style={paragraph}>
            A credible deployment must demonstrate more than the happy path. If an agent changes the
            target from one service identity to an entire tenant, the request is wider and provider
            entry stays closed. If it replays evidence already consumed, it does not receive a second
            attempt. If a provider times out after entry, the result remains indeterminate and blind
            retry stays closed until authenticated reconciliation.
          </p>
          <p style={paragraph}>
            Those outcomes are useful to a security vendor because they let the vendor automate a
            bounded response without asking the customer to treat a standing credential as unlimited
            permission.
          </p>

          <h2 style={heading}>Start with administrative actions, not safety-critical control</h2>
          <p style={paragraph}>
            In a hospital, the first action should be a privileged IT session or administrative
            identity, not a clinical decision. In public power, start with remote IT access rather than
            grid switching. In water, start with a bounded defensive network rule rather than chemical
            dosing. Independent safety systems and emergency procedures remain independent.
          </p>
          <p style={paragraph}>
            The first buyer should usually be the security vendor, MSSP, SOC platform, or integrator
            already delivering automated remediation into those environments. EMILIA supplies an
            authority component inside that deployment. It does not become another EDR, SIEM, SOAR, or
            critical-infrastructure security suite.
          </p>

          <h2 style={heading}>What this does not claim</h2>
          <ul style={{ ...paragraph, paddingLeft: 24 }}>
            <li style={{ marginBottom: 12 }}>EMILIA does not detect threats, attribute incidents, patch vulnerabilities, or stop exploitation.</li>
            <li style={{ marginBottom: 12 }}>Gate prevents only on completely mediated covered paths. Alternate credentials and direct provider calls remain outside coverage.</li>
            <li style={{ marginBottom: 12 }}>Admission does not establish that a response was wise, safe, lawful, or clinically correct.</li>
            <li>An action receipt does not prove a provider or physical effect without authenticated outcome evidence.</li>
          </ul>

          <h2 style={heading}>Pressure-test one action</h2>
          <p style={paragraph}>
            Our opening offer is deliberately small: bring one consequential administrative action,
            one credential-owning executor, and the current approval path. We will map the boundary,
            name the bypasses, and demonstrate admission, substitution refusal, replay refusal, and
            indeterminate handling before anyone relies on it in production.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, margin: '30px 0 58px' }}>
            <Link href="/cyber-authority#authority-drill" style={cta.primary}>Run the browser drill</Link>
            <Link href="/pilot?v=other" style={cta.secondary}>Scope one protected action</Link>
          </div>

          <div style={{ paddingTop: 28, borderTop: `1px solid ${color.border}` }}>
            <div style={{ marginBottom: 14, color: color.gold, fontFamily: font.mono, fontSize: 10, letterSpacing: 1.8, textTransform: 'uppercase' }}>
              Primary sources
            </div>
            <ul style={{ ...paragraph, paddingLeft: 20, fontSize: 14 }}>
              <li style={{ marginBottom: 10 }}>
                <a href="https://openai.com/collective-cyberdefense/" target="_blank" rel="noopener noreferrer" style={sourceLink}>
                  OpenAI — Collective Cyber Defense
                </a>
              </li>
              <li style={{ marginBottom: 10 }}>
                <a href="https://www.ncsc.gov.uk/news/the-ai-shift-in-cyber-risk-why-leaders-must-act-now" target="_blank" rel="noopener noreferrer" style={sourceLink}>
                  UK NCSC and Five Eyes partners — The AI shift in cyber risk
                </a>
              </li>
              <li>
                <a href="https://openai.com/index/hugging-face-incident-and-the-road-ahead/" target="_blank" rel="noopener noreferrer" style={sourceLink}>
                  OpenAI — Hugging Face incident and the road ahead
                </a>
              </li>
            </ul>
          </div>
        </div>
      </article>

      <SiteFooter />
    </div>
  );
}
