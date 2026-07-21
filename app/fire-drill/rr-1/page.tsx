// SPDX-License-Identifier: Apache-2.0
// /fire-drill/rr-1 — the RR-1 maintainer program. Social proof ("we are testing
// the MCP ecosystem for receipt-required dangerous actions; maintainers can earn
// RR-1") + the make-you-look-good badge ("safer than the default ecosystem"),
// NOT a shame badge. Drives maintainers to the 10-minute Receipt Required PR kit.

import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import registryIndex from '../../../packages/fire-drill/registry-index.json';
import reports from '../../../packages/fire-drill/reports.json';

export const metadata: Metadata = {
  title: 'RR-1 — the Receipt Required badge for MCP maintainers | EMILIA',
  description:
    'We are testing the MCP ecosystem for receipt-required dangerous actions. RR-1 means your most dangerous action is safer than the ecosystem default: missing receipt blocked, valid receipt runs once, replay refused, forged refused.',
};

const BADGE = 'https://www.emiliaprotocol.ai/badges/rr-1.svg';
const BADGE_MD = `[![Receipt Required: RR-1](${BADGE})](https://www.emiliaprotocol.ai/fire-drill/rr-1)`;

export default function RR1Page() {
  const { rr1 } = reports as any;
  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 24 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>RR-1 · RECEIPT REQUIRED, LEVEL 1</div>
            <h1 style={{ ...styles.h1, marginTop: 14 }}>
              We&rsquo;re testing the MCP ecosystem for receipt-required dangerous actions.
            </h1>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16 }}>
              We scanned the full public MCP registry: <b>{registryIndex.servers_scanned.toLocaleString()}</b> servers,
              and <b>{registryIndex.pct_advertise_high_risk}%</b> advertise a capability that can move money, destroy or
              export data, deploy infrastructure, or change permissions. Almost none require a verifiable human
              authorization before that action runs. <b>RR-1 is how a maintainer fixes that — and gets credit for it.</b>
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
              <a href="https://www.npmjs.com/package/@emilia-protocol/require-receipt" target="_blank" rel="noopener noreferrer" style={cta.primary}>Earn RR-1 in 10 minutes</a>
              <Link href="/fire-drill/registry" style={cta.secondary}>The ecosystem index</Link>
            </div>
          </div>
        </section>

        {/* The badge is a credential, not a warning */}
        <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
          <div style={styles.container}>
            <div style={{
              display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap',
              border: `1px solid ${color.border}`, borderRadius: 12, padding: '22px 24px', background: '#0b0e14',
            }}>
              {/* eslint-disable-next-line @next/next/no-img-element -- static SVG badge, next/image is overkill */}
              <img src="/badges/rr-1.svg" alt="Receipt Required: RR-1" width={178} height={20} />
              <p style={{ ...styles.body, fontSize: 14, color: color.t2, margin: 0, flex: 1, minWidth: 280 }}>
                {rr1.framing}
              </p>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>What RR-1 does.</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16 }}>
              RR-1 means one thing: your documented dangerous tool structurally declares a required <code>receipt</code> input, and a reference implementation proves it refuses calls without one.
            </p>
            <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              {[
                { title: 'Missing receipt', body: 'The call is rejected with a 428 challenge.' },
                { title: 'Valid receipt', body: 'The call proceeds exactly once.' },
                { title: 'Replay of the same receipt', body: 'Refused. One-time consumption is enforced.' },
                { title: 'Forged or tampered receipt', body: 'Signature check fails. The call is refused.' },
              ].map(({ title, body }) => (
                <div key={title} style={{ borderTop: `1px solid ${color.border}`, paddingTop: 14 }}>
                  <div style={{ ...styles.h3, fontSize: 16 }}>{title}</div>
                  <div style={{ ...styles.body, fontSize: 13, color: color.t2, marginTop: 6 }}>{body}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={styles.h2}>RR-1 is not.</h2>
            <p style={{ ...styles.body, maxWidth: 760 }}>
              RR-1 is not a vulnerability report, a conformance badge for a full protocol, a claim about runtime enforcement, or a legal compliance statement. It is simply: we tested this tool's documented interface and it structurally requires a receipt.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={styles.h2}>How to earn RR-1.</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 10 }}>
              Wrap your dangerous tool call with the Receipt Required middleware, point the test harness at your schema, and confirm the result. The whole integration takes about 10 minutes.
            </p>
            <div style={{ marginTop: 28 }}>
              <a href="https://www.npmjs.com/package/@emilia-protocol/require-receipt" style={cta.primary}>Read the 10-minute kit</a>
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 760, marginTop: 24 }}>
              Once you pass the harness, link to <code style={{ fontFamily: font.mono }}>rr-1.json</code> in your repo root (template at <code style={{ fontFamily: font.mono }}>@emilia-protocol/require-receipt/rr-1.json.example</code>) and add the badge to your README.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={styles.h2}>Recent RR-1 earners.</h2>
            <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
              {rr1.maintainers.map((m: any) => (
                <div key={m.name} style={{ ...styles.card, padding: 20 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase' }}>{m.type}</div>
                  <div style={{ ...styles.h3, fontSize: 16, marginTop: 8 }}>{m.name}</div>
                  <div style={{ ...styles.body, fontSize: 13, color: color.t2, marginTop: 8 }}>{m.dangerous_tool}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
