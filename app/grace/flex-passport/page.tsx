// SPDX-License-Identifier: Apache-2.0
// GRACE Flex Passport — verifiable flexible-load evidence for AI datacenters.
// The productized Proof-of-Curtailment package: prove a facility can give
// power back to the grid on command, with evidence anyone can verify offline.

import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'GRACE Flex Passport — verifiable flexible-load evidence for AI datacenters | EMILIA',
  description:
    'Prove your AI facility can curtail on command. Signed curtailment orders, named-human authorization, attested meter telemetry, and an offline-verifiable settlement packet — the evidence layer that turns AI compute into a bankable flexible grid resource.',
};

const PASSPORT_CONTENTS = [
  { item: 'Signed curtailment order', body: 'A bounded, reversible grid.curtailment order — target ΔkW, window, hard expiry — signed by the market-authorized party.' },
  { item: 'Named-human / quorum authorization', body: 'The accountable decision captured as a device-bound signoff; multi-party quorum for hard cuts. Who said yes, to exactly what, before anything shed.' },
  { item: 'Scheduler acknowledgment', body: 'The facility’s signed acknowledgment that it entered curtailment posture against the verified order — not against a spoofed or stale one.' },
  { item: 'Attested meter / PDU telemetry', body: 'Power samples signed at source by the meter’s own key, anchored so they cannot be backfilled or cherry-picked after the fact.' },
  { item: 'Pinned baseline method', body: 'The hash of the program’s prescribed baseline methodology, bound into the order — method swaps and input manipulation become tamper-evident.' },
  { item: 'Delivered-kWh calculation', body: 'Delivered = baseline − actual, recomputable by any verifier from the signed samples. The number the settlement is paid against.' },
  { item: 'Replay & tamper refusal record', body: 'The negative evidence: forged orders refused, tampered telemetry invalid, replayed authorizations rejected — each refusal itself a signed event.' },
  { item: 'Offline verifier', body: 'Open-source cross-language reference verifiers (JavaScript, Python, Go). Anyone — utility, auditor, counterparty — verifies the packet with math, not trust.' },
  { item: 'Settlement packet', body: 'One Proof-of-Curtailment Bundle: order + authorization + acknowledgment + telemetry + delivered kWh, portable and verifiable offline forever.' },
  { item: 'Recurring fire-drill evidence', body: 'Scheduled curtailment drills produce fresh bundles on a cadence — the passport stays current instead of decaying into a one-time certificate.' },
];

const STAKEHOLDERS = [
  { who: 'Datacenter / neocloud operator', ask: '“Help me get connected faster.”', get: 'Interconnection-grade evidence that the load is genuinely curtailable — the flexibility story regulators and utilities can verify instead of discount.' },
  { who: 'Utility / ISO', ask: '“Prove this load will actually curtail when dispatched.”', get: 'Dispatch confirmation against cryptographic proof, not the operator’s self-reported logs.' },
  { who: 'Regulator', ask: '“Show me this AI facility will not wreck ratepayers.”', get: 'A standing, third-party-verifiable record that curtailment commitments are real and exercised.' },
  { who: 'DR aggregator', ask: '“Give me settlement-grade evidence I can bid.”', get: 'A portable M&V artifact for large, fast flexible loads — higher-value products, fewer settlement disputes.' },
  { who: 'Public / policymaker', ask: '“Can AI give power back during grid stress?”', get: 'A verifiable yes — receipts, not press releases.' },
];

const PILOT_STEPS = [
  { n: '1', t: 'Integrate', b: 'One facility or GPU cluster. Smart-PDU / meter integration and the facility controller wired to verify orders offline, fail-closed.' },
  { n: '2', t: 'Drill', b: 'Three simulated curtailment drills — plus one live curtailment where the program and facility allow — each emitting a full Proof-of-Curtailment Bundle.' },
  { n: '3', t: 'Verify & report', b: 'Every bundle verified under the open verifier; adversarial paths exercised (forged order, tampered telemetry, replay — all refused). A utility/aggregator-facing report packages the result.' },
  { n: '4', t: 'Keep it current', b: 'Ongoing managed evidence: recurring fire drills, key registry, audit exports, and the settlement archive. The passport is a practice, not a plaque.' },
];

export default function FlexPassportPage() {
  return (
    <>
      <SiteNav activePage="GRACE" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>GRACE FLEX PASSPORT</div>
            <h1 style={{ ...styles.h1, marginTop: 16, maxWidth: 820 }}>
              Prove your facility can give power back to the grid on command.
            </h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              Prove your facility can curtail. Get connected faster. Get paid for flexibility.
              Survive audit. The Flex Passport is a portable evidence packet — verifiable by anyone,
              offline — that an AI datacenter is a real flexible grid resource, not a dumb peak load.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14, fontSize: 17, color: color.t1 }}>
              <span style={{ color: color.gold }}>EMILIA turns AI compute from an untrusted load into a verifiable flexible grid resource.</span>
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="/pilot?v=grace-passport" style={cta.primary}>Request a Flex Passport pilot</a>
              <a href="/grace" style={cta.secondary}>How Proof-of-Curtailment works</a>
            </div>
          </div>
        </section>

        {/* Why now */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHY NOW</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 820 }}>
              Flexibility is proven. Verification is the missing piece.
            </h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              The IEA projects global data-centre electricity demand more than doubles by 2030 to
              roughly <b style={{ color: color.t1 }}>945&nbsp;TWh</b>, with AI-optimized capacity more
              than quadrupling. And grid-responsive AI compute is no longer theoretical: 2026 research
              demonstrates a real <b style={{ color: color.t1 }}>130&nbsp;kW GPU cluster</b> delivering
              rapid load reduction and sustained curtailment in deployment while preserving priority
              jobs. Schedulers can shed. Meters can measure. What no one produces is the
              <b style={{ color: color.t1 }}> bankable proof</b> — the artifact a utility, aggregator,
              regulator, or auditor can verify without trusting the operator’s own logs. That artifact
              is the Flex Passport.
            </p>
          </div>
        </section>

        {/* What's inside */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHAT A PASSPORT CONTAINS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Ten artifacts. One verifiable packet.</h2>
            <div style={{ marginTop: 32 }}>
              {PASSPORT_CONTENTS.map((c, i) => (
                <div key={c.item} style={{ display: 'flex', gap: 24, padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 28 }}>{String(i + 1).padStart(2, '0')}</div>
                  <div>
                    <div style={{ ...styles.h3, fontSize: 17 }}>{c.item}</div>
                    <div style={{ ...styles.body, fontSize: 15, marginTop: 6, maxWidth: 700 }}>{c.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Five problems */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>ONE ARTIFACT, FIVE PROBLEMS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Everyone at the table needs the same proof.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {STAKEHOLDERS.map((s) => (
                <div key={s.who} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ ...styles.h3, fontSize: 16 }}>{s.who}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 13, marginTop: 8, color: color.gold }}>{s.ask}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 10, color: color.t2 }}>{s.get}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* How a facility gets one */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HOW A FACILITY GETS ONE</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>A 90-day pilot, then a living evidence practice.</h2>
            <div style={{ marginTop: 32 }}>
              {PILOT_STEPS.map((s) => (
                <div key={s.n} style={{ display: 'flex', gap: 24, padding: '20px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{s.n}</div>
                  <div>
                    <div style={{ ...styles.h3, fontSize: 18 }}>{s.t}</div>
                    <div style={{ ...styles.body, fontSize: 15, marginTop: 6, maxWidth: 700 }}>{s.b}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Honest boundary */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HONEST POSTURE</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>
              Verified means verifiable — by you, not just by us.
            </h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              The Flex Passport is evidence-based, not authority-based: every claim in the packet is
              checkable offline with the open-source verifier, so its value does not depend on
              trusting EMILIA as a certifier. The baseline methodology belongs to the applicable
              program or tariff — GRACE pins it and makes its application tamper-evident; it does not
              invent it. EMILIA proves authorization, execution acknowledgment, and evidence
              integrity — a necessary, not sufficient, condition for trustworthy demand response.
              The shed side is scheduler-agnostic: COSA is the first supported actuator, and any
              scheduler that can acknowledge a verified order can hold a passport.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="/pilot?v=grace-passport" style={cta.primary}>Request a pilot</a>
              <a href="/grace" style={cta.secondary}>GRACE overview</a>
              <a href="/verify" style={cta.secondary}>Verify a receipt</a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
