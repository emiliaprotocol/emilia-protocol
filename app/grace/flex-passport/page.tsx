// SPDX-License-Identifier: Apache-2.0
// GRACE Flex Passport: verifiable flexible-load evidence for AI datacenters.
// The productized Proof-of-Curtailment package. The public reference circuit runs
// in software with simulated actuator and meter adapters; this page must not claim
// more than lib/grace implements.

import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'GRACE Flex Passport: verifiable flexible-load evidence for AI datacenters | EMILIA',
  description:
    'Bounded curtailment orders, named-human authorization, separately keyed meter statements, and a signed Proof-of-Curtailment Bundle that verifies offline. The public reference uses simulated actuator and meter adapters; no physical measurement has been run.',
  alternates: { canonical: '/grace/flex-passport' },
};

const PASSPORT_CONTENTS = [
  { item: 'Bounded curtailment order', body: 'A bounded, reversible grid.curtailment order (target ΔkW, window, hard expiry), digest-bound and checked fail-closed against the season’s human-authorized flex envelope before anything is dispatched.' },
  { item: 'Named-human / quorum authorization', body: 'The accountable decision captured as a device-bound signoff; multi-party quorum for hard cuts. Who said yes, to exactly what, before anything shed.' },
  { item: 'Scheduler acknowledgment', body: 'The facility’s signed acknowledgment that it entered curtailment posture against the verified order, not against a spoofed or stale one. In the reference it comes from a simulated COSA adapter, and the shipped verifier accepts only simulated acknowledgments.' },
  { item: 'Separately keyed meter statement', body: 'Power samples signed under the meter’s own pinned key, separate from the actuator’s key, and bound to the exact event and window. In the reference the meter is simulated and derives its readings from the order. The samples are not anchored: the Action State record is a signed statement that is not registered in any transparency log.' },
  { item: 'Pinned baseline method', body: 'The hash of the program’s prescribed baseline methodology, bound into the order and the bundle, so a method swap is evident. GRACE does not execute the method: the baseline value arrives as a number in the meter statement and is not derived from the pinned method.' },
  { item: 'Delivered-load calculation', body: 'Delivered = baseline − average interval load, in average MW, with compliance at 95% of the ordered reduction by default. Deterministic from the signed meter statement, which the bundle carries by digest. The reference admits settlement only when the result is compliant and in bounds.' },
  { item: 'Replay & tamper refusals', body: 'The negative evidence: forged orders, tampered telemetry, and replayed authorizations are refused with a stated reason, and the reference tests exercise each path. Refusals are returned as unsigned verdicts today; they are not signed events.' },
  { item: 'Offline bundle check', body: 'The bundle carries an Ed25519 signature that verifies offline with the open-source reference library (JavaScript). The JavaScript, Python, and Go EMILIA verifiers cover EMILIA receipts; none of them verifies the GRACE bundle yet.' },
  { item: 'Proof-of-Curtailment Bundle', body: 'One signed bundle binding the order, authorization, acknowledgment, meter statement digest, and computed result, portable and verifiable offline for as long as the pinned keys are trusted. The reference keys expire on 2027-01-01.' },
];

const STAKEHOLDERS = [
  { who: 'Datacenter / neocloud operator', ask: '“Help me get connected faster.”', get: 'Portable evidence of who authorized each curtailment, what was ordered, and what the supplied meter statement shows, in a form a utility can check instead of discount.' },
  { who: 'Utility / ISO', ask: '“Prove this load will actually curtail when dispatched.”', get: 'Signed, digest-bound records of the authorized dispatch and the supplied meter statement, checkable offline instead of relying only on the operator’s application logs. Meter truth still depends on the meter.' },
  { who: 'Regulator', ask: '“Show me this AI facility will not wreck ratepayers.”', get: 'A third-party-checkable record of which curtailments were authorized, ordered, and reported under the program’s pinned method.' },
  { who: 'DR aggregator', ask: '“Give me evidence I can take into settlement review.”', get: 'A portable, tamper-evident M&V artifact for large, fast flexible loads, carried into the program’s existing review and settlement process.' },
  { who: 'Public / policymaker', ask: '“Can AI give power back during grid stress?”', get: 'Receipts for each authorized curtailment, not press releases. Proving physical delivery still needs a metered facility pilot.' },
];

const PILOT_STEPS = [
  { n: '1', t: 'Integrate', b: 'One facility or GPU cluster, with the facility controller wired to verify orders offline, fail-closed. A real smart-PDU or meter needs its own adapter and verifier, which GRACE does not ship yet: today’s verifiers accept only simulated meter and actuator statements.' },
  { n: '2', t: 'Drill', b: 'Three simulated curtailment drills, each emitting a Proof-of-Curtailment Bundle. A live curtailment, where the program and facility allow, needs real meter and actuator adapters and verifiers, which do not exist yet.' },
  { n: '3', t: 'Verify & report', b: 'Every bundle signature checked offline; adversarial paths exercised (forged order, tampered telemetry, replay: all refused). A utility/aggregator-facing report packages the result.' },
  { n: '4', t: 'Keep it current', b: 'Ongoing managed evidence: repeat drills on an agreed schedule, key registry, audit exports, and the settlement archive. Drill scheduling is a service step run with the facility; it is not shipped code.' },
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
              Portable, offline-verifiable evidence for flexible AI load.
            </h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              The Flex Passport is a portable evidence packet, verifiable offline, that binds who
              authorized each curtailment, what was ordered, and what the meter statement reported.
              Interconnection, payment, and audit decisions stay with the utility, the program, and
              the auditor.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14, fontSize: 17, color: color.t1 }}>
              <span style={{ color: color.gold }}>EMILIA makes the authorization and evidence behind AI compute flexibility verifiable.</span>
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14, fontSize: 15, color: color.t2 }}>
              Where it stands: the reference circuit runs end to end in software. Its actuator and
              meter adapters are reference simulations, and no physical measurement has been run.
              Physical evidence starts with a facility pilot.
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
              Grid-responsive AI compute is no longer theoretical: 2026 research
              demonstrates a real <b style={{ color: color.t1 }}>130&nbsp;kW GPU cluster</b> delivering
              rapid load reduction and sustained curtailment in deployment while preserving priority
              jobs. Schedulers can shed. Meters can measure. What is missing is
              <b style={{ color: color.t1 }}> evidence a utility, aggregator, regulator, or auditor can
              check offline</b> instead of relying only on the operator’s application logs. The Flex
              Passport is built to be that evidence.
            </p>
          </div>
        </section>

        {/* What's inside */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHAT A PASSPORT CONTAINS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Nine artifacts. One verifiable packet.</h2>
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
              Verified means verifiable: by you, not just by us.
            </h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              The Flex Passport is evidence-based, not authority-based: the bundle signature verifies
              offline with the open-source reference library, so its value does not depend on
              trusting EMILIA as a certifier. The baseline methodology belongs to the applicable
              program or tariff. GRACE pins its hash so a method swap is evident; it does not invent
              the method, execute it, or derive the baseline. EMILIA proves authorization, execution
              acknowledgment, and integrity of the supplied evidence: a necessary, not sufficient,
              condition for trustworthy demand response. It does not prove that meter readings are
              physically true. The shed side is scheduler-agnostic: COSA is the first actuator
              profile, through a simulated reference adapter today, and any scheduler that can
              acknowledge a verified order can hold a passport.
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
