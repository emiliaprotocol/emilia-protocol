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
  { n: '4', title: 'Measure', body: 'An attested meter / smart PDU signs the power telemetry at source, Merkle-anchored so it cannot be backfilled or cherry-picked.' },
  { n: '5', title: 'Prove', body: 'Delivered = baseline − actual, computed from the signed telemetry against the program’s prescribed baseline method (pinned by hash).' },
  { n: '6', title: 'Settle', body: 'A Proof-of-Curtailment Bundle is emitted — order + acknowledgment + attested telemetry + computed kW·h — verifiable offline. The program pays against proof, not self-report.' },
];

const BUYERS = [
  { who: 'AI / HPC datacenters & neoclouds', val: 'Connect faster (prove flexible load for interconnection), get paid for verifiable curtailment, survive audit without exposing operational logs.' },
  { who: 'Grid operators / ISOs / utilities', val: 'Dispatch flexible compute and confirm delivery without trusting the operator’s self-reported logs. Settlement against cryptographic proof.' },
  { who: 'Demand-response aggregators', val: 'A portable, tamper-evident M&V artifact for large, fast flexible loads — higher-value DR products, fewer settlement disputes.' },
];

export default function GracePage() {
  return (
    <>
      <SiteNav activePage="GRACE" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA GRACE · PROOF-OF-CURTAILMENT</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>A verifiable demand-response rail for AI compute.</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              When the grid asks an AI datacenter to reduce load, GRACE proves who authorized it,
              what was allowed, whether the facility complied, and what should be paid — verifiable
              by anyone, offline, without trusting the operator’s own logs.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14, fontSize: 17, color: color.t1 }}>
              COSA moves the megawatts. <span style={{ color: color.gold }}>EMILIA proves the move was authorized and delivered.</span>
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
              ~100 GW of flexibility is sitting unused — because no one can verify it.
            </h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              Duke University’s Nicholas Institute finds the 22 largest U.S. balancing areas could
              absorb <b style={{ color: color.t1 }}>76–126 GW of new load</b> if it can be curtailed
              under ~1% of hours — ERCOT alone ≈ 10 GW at 0.5%. But that headroom is only bankable if
              the curtailment is <em>verifiable</em> enough for a grid operator to count it as
              capacity. Today curtailment is self-reported and trust-based — baselines gamed,
              telemetry backfilled, sheds over-claimed. <span style={{ color: color.t1 }}>That
              measurement-and-verification gap is what GRACE removes.</span>
            </p>
          </div>
        </section>

        {/* The loop */}
        <section id="loop" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HOW IT WORKS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Authorize → verify → shed → measure → prove → settle.</h2>
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
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Bankable on every side of the meter.</h2>
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
              counterpart to settle against.
            </p>
          </div>
        </section>

        {/* Demonstration */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>DEMONSTRATION</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>Available now: the full reference circuit, visible end to end.</h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              A runnable reference of the full loop is published and verifies under the production
              EMILIA verifier — issue a grid.curtailment order, shed, sign attested telemetry,
              compute delivered kW·h, emit the Proof-of-Curtailment bundle — with the adversarial
              paths refusing (tampered telemetry → invalid; forged order → refused; replay →
              refused). The control-room view makes each transition inspectable without implying a
              physical deployment. A hardware demonstration adds a host-approved compute node and
              independently keyed meter; that step requires a facility partner.
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
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>GRACE does not invent the baseline. It makes the program’s method un-fudgeable.</h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16 }}>
              The baseline methodology belongs to the ISO/program (CAISO ELAP, PJM CBL, ERCOT). GRACE
              pins its hash and makes its application tamper-evident against method swaps, telemetry
              backfill, and input manipulation. EMILIA proves authorization and evidence integrity —
              a necessary, not sufficient, condition for trustworthy demand response. This is a
              critical-infrastructure vertical, not the NETL generation prize.
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
