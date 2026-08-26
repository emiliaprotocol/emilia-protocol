// SPDX-License-Identifier: Apache-2.0
// EMILIA GRACE — Proof-of-Curtailment: a verifiable demand-response rail for AI
// compute. Energy vertical landing page (COSA × EMILIA).

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const LOOP = [
  { n: '1', title: 'Authorize', body: 'A market-authorized party (ISO, utility, aggregator, or facility under the applicable tariff) signs a bounded grid.curtailment order — named human, or quorum for hard cuts.' },
  { n: '2', title: 'Verify & gate', body: 'The facility controller verifies the order offline, fail-closed: posture changes only against a valid, in-scope, unexpired order. Spoofed or stale orders are refused.' },
  { n: '3', title: 'Shed', body: 'The scheduler reduces compute — cache-first inference, deferred batch, capped GPU clocks — preserving life-safety lanes. Power falls. (COSA moves the megawatts.)' },
  { n: '4', title: 'Measure', body: 'A separately keyed meter or smart PDU signs the supplied telemetry. The public reference simulates this source; its signature authenticates the supplied records but does not prove physical truth or a complete source population.' },
  { n: '5', title: 'Compute', body: 'The reference computes the delivered-load result from accepted inputs under the program’s prescribed baseline method, pinned by hash. This proves deterministic computation from supplied inputs, not physical delivery.' },
  { n: '6', title: 'Package', body: 'A Proof-of-Curtailment Bundle records the accepted order, acknowledgment, meter evidence, and computed result for offline verification. The program separately decides eligibility and settlement under its own rules.' },
];

const BUYERS = [
  { who: 'AI / HPC datacenters & neoclouds', val: 'Present portable evidence of the authorized event, supplied observations, and result computed under the program’s pinned method.' },
  { who: 'Grid operators / ISOs / utilities', val: 'Evaluate supplied curtailment evidence without relying only on the operator’s application logs. Program rules still determine eligibility and settlement.' },
  { who: 'Demand-response aggregators', val: 'Carry a portable, tamper-evident M&V artifact for large, fast flexible loads into the program’s existing review and settlement process.' },
];

export default function GracePage() {
  return (
    <>
      <SiteNav activePage="GRACE" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA Gate solution profile &middot; GRACE energy controls</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>A verifiable demand-response rail for AI compute.</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              When the grid asks an AI datacenter to reduce load, GRACE binds who authorized the
              exact event, what was allowed, which supplied actuator and meter claims were accepted,
              and the result computed under a pinned method. The bundle verifies offline without
              trusting the operator’s application logs. It does not prove physical meter truth or
              decide settlement.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14, fontSize: 17, color: color.t1 }}>
              COSA moves the megawatts. <span style={{ color: color.gold }}>EMILIA binds the authorization, supplied observations, and deterministic result.</span>
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="/grace/live" style={cta.primary}>Run the live control room</a>
              <a href="/grace/flex-passport" style={cta.primary}>Get the Flex Passport</a>
              <a href="#loop" style={cta.secondary}>How it works</a>
              <a href="/pilot?v=grace" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>

        {/* Why now / bankable */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHY NOW</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 820 }}>
              Flexible compute is growing, but grid programs still need evidence they can evaluate.
            </h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              Duke University’s Nicholas Institute finds the 22 largest U.S. balancing areas could
              absorb <b style={{ color: color.t1 }}>76–126 GW of new load</b> if it can be curtailed
              under ~1% of hours — ERCOT alone ≈ 10 GW at 0.5%. But that headroom is only bankable if
              the curtailment evidence is <em>verifiable</em> enough for a grid operator to evaluate.
              Today, operators may have to rely heavily on self-reported logs and supplied
              measurements. <span style={{ color: color.t1 }}>GRACE addresses one part of that gap:
              authorization and tamper-evident evidence over supplied inputs under a pinned method.</span>
            </p>
          </div>
        </section>

        {/* The loop */}
        <section id="loop" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HOW IT WORKS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Authorize → verify → shed → measure → compute → package.</h2>
            <div style={{ marginTop: 32 }}>
              {LOOP.map((s) => (
                <div key={s.n} style={{ display: 'flex', gap: 24, padding: '20px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{s.n}</div>
                  <div>
                    <div style={{ ...styles.h3, fontSize: 18 }}>{s.title}</div>
                    <div style={{ ...styles.body, fontSize: 15, marginTop: 6, maxWidth: 700 }}>{s.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Buyers */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHO IT'S FOR</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>One evidence bundle, evaluated under each program’s rules.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {BUYERS.map((b) => (
                <div key={b.who} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ ...styles.h3, fontSize: 17 }}>{b.who}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 10, color: color.t2 }}>{b.val}</div>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 24, fontSize: 14, color: color.t2 }}>
              First mover: an AI/HPC datacenter or neocloud operator with a DR aggregator or utility
              sponsor — the party that holds the interconnection/payment incentive and a grid
              counterpart that can evaluate the bundle under its program rules.
            </p>
          </div>
        </section>

        {/* Demonstration */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>DEMONSTRATION</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>Available now: the full reference circuit, visible end to end.</h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              A runnable reference circuit is published and verifies under the current EMILIA
              verifier. It issues a grid.curtailment order, simulates a shed, signs separately keyed
              simulated meter evidence, computes the reference result, and emits the
              Proof-of-Curtailment Bundle. The adversarial paths refuse tampered telemetry, forged
              orders, and replay. The control-room view makes each transition inspectable without
              implying a physical deployment or complete source population. A hardware
              demonstration with a host-approved compute node and independent meter still requires
              a facility partner.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 24, flexWrap: 'wrap' }}>
              <a href="/grace/live" style={cta.primary}>Open the reference control room</a>
              <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples/grace" style={cta.secondary}>Run from source</a>
            </div>
          </div>
        </section>

        {/* Honest boundary */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HONEST POSTURE</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>GRACE does not invent the baseline. It makes application of the pinned method tamper-evident.</h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              The baseline methodology belongs to the ISO/program (CAISO ELAP, PJM CBL, ERCOT). GRACE
              pins its digest and binds the accepted authorization, supplied meter observations,
              and deterministic computation. The result is tamper-evident under the pinned method
              and supplied inputs. It does not establish that the readings are physically true or
              complete, that an event qualifies under a tariff, or what should be paid. Settlement
              remains a separate program decision.
            </p>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              A deployment may preserve an authenticated OT transport event digest as a distinct
              evidence leg. That digest does not grant authority or prove the physical outcome.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="/gate" style={cta.primary}>EMILIA Gate</a>
              <a href="/verify" style={cta.secondary}>Verify a receipt</a>
              <a href="/pilot?v=grace" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
