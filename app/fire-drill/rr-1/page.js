// SPDX-License-Identifier: Apache-2.0
// /fire-drill/rr-1 — the RR-1 maintainer program. Social proof ("we are testing
// the MCP ecosystem for receipt-required dangerous actions; maintainers can earn
// RR-1") + the make-you-look-good badge ("safer than the default ecosystem"),
// NOT a shame badge. Drives maintainers to the 10-minute Receipt Required PR kit.

import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import registryIndex from '../../../packages/fire-drill/registry-index.json';
import reports from '../../../packages/fire-drill/reports.json';

export const metadata = {
  title: 'RR-1 — the Receipt Required badge for MCP maintainers | EMILIA',
  description:
    'We are testing the MCP ecosystem for receipt-required dangerous actions. RR-1 means your most dangerous action is safer than the ecosystem default: missing receipt blocked, valid receipt runs once, replay refused, forged refused.',
};

const BADGE = 'https://www.emiliaprotocol.ai/badges/rr-1.svg';
const BADGE_MD = `[![Receipt Required: RR-1](${BADGE})](https://www.emiliaprotocol.ai/fire-drill/rr-1)`;

export default function RR1Page() {
  const { rr1 } = reports;
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
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 12 }}>
              Earn it, then add the badge to your README:
            </p>
            <pre style={{
              fontFamily: font.mono, fontSize: 12.5, color: color.t1, background: '#0b0e14',
              border: `1px solid ${color.border}`, borderRadius: 8, padding: '12px 14px', overflowX: 'auto', marginTop: 6,
            }}>{BADGE_MD}</pre>
          </div>
        </section>

        {/* The four checks */}
        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={{ ...styles.h2 }}>What RR-1 certifies</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 12 }}>
              Four behaviors on your most dangerous action — re-proven on every push by{' '}
              <code style={{ fontFamily: font.mono }}>receipt-required.test.js</code>:
            </p>
            <div style={{ marginTop: 14 }}>
              {rr1.checks.map((c, i) => (
                <div key={c.id} style={{ display: 'flex', gap: 14, alignItems: 'baseline', padding: '11px 0', borderTop: `1px solid ${color.border}` }}>
                  <span style={{ fontFamily: font.mono, fontSize: 13, color: color.gold, minWidth: 22 }}>{i + 1}</span>
                  <span style={{ ...styles.body, fontSize: 15, color: color.t1, fontWeight: 600, minWidth: 300 }}>{c.claim}</span>
                  <span style={{ fontFamily: font.mono, fontSize: 12.5, color: color.t2 }}>{c.expect}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 720 }}>
              RR-1 is a reference-implementation conformance level, <b>not</b> a vulnerability rating and <b>not</b> auth or
              permissions. It is portable accountability evidence — proof a named human authorized an irreversible action —
              a <i>necessary, not sufficient</i> condition: it does not prove the decision was wise or lawful. Built on the
              offline verifier in <code style={{ fontFamily: font.mono }}>@emilia-protocol/require-receipt</code> (Apache-2.0);
              spec: IETF <code style={{ fontFamily: font.mono }}>draft-schrock-ep-authorization-receipts</code>.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
