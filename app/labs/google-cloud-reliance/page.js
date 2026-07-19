// SPDX-License-Identifier: Apache-2.0
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import labStyles from './page.module.css';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';
const DEMO = `${REPO}/tree/main/examples/google-cloud-reliance`;

const CASES = [
  ['REFUSE', 'No customer evidence', 'IAM and content controls allow. The customer-pinned evidence requirement is still unsatisfied. The GCP client is never called.'],
  ['REFUSE', 'One signer for a two-person rule', 'A real device-bound human signoff is valid, but insufficient for a roles/owner mutation requiring quorum.'],
  ['REFUSE', 'Viewer evidence presented for Owner', 'The signed evidence binds roles/viewer. The observed system-of-record call requests roles/owner. Exact-field binding refuses the drift.'],
  ['REFUSE', 'Receipt altered after issuance', 'Changing a signed field breaks the receipt. A structurally plausible object is not accepted evidence.'],
  ['RELY', 'Exact two-person evidence', 'Two distinct human ceremonies bind the exact project, member, role, and action. The mutation executes once and emits a reliance packet.'],
  ['REFUSE', 'Accepted evidence replayed', 'The same receipt is presented again. One-time consumption refuses the second mutation.'],
];

const CONTROL_ROWS = [
  ['Google-side controls', 'Authenticate the caller, apply IAM, govern MCP tools, and inspect calls or responses for security threats.'],
  ['Customer reliance boundary', 'Require the exact action to carry sufficient, fresh, unused evidence under a profile the customer controls.'],
  ['Portable result', 'Bind the execution to the authorization decision and emit a reliance packet that an auditor can inspect outside the agent runtime.'],
];

export default function GoogleCloudReliancePage() {
  return (
    <>
      <SiteNav activePage="Labs" />
      <main style={styles.page}>
        <section style={{ background: color.t1, color: '#F8F5EF', borderBottom: `1px solid ${color.border}` }}>
          <div style={{ ...styles.sectionWide, paddingTop: 78, paddingBottom: 72 }}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>OPEN COMPATIBILITY LAB · GOOGLE CLOUD-SHAPED MUTATION</div>
            <h1 className={labStyles.heroTitle}>
              IAM says the agent may act. Can the customer prove why it did?
            </h1>
            <p style={{ ...styles.body, color: '#D6D3D1', maxWidth: 800, marginTop: 20, fontSize: 18 }}>
              This runnable lab composes with Google Cloud controls instead of replacing them.
              IAM and a Model Armor-shaped content check both return allow. A separate,
              customer-controlled boundary still refuses a high-blast-radius roles/owner grant
              until exact, two-person, single-use evidence arrives.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
              <a href={DEMO} style={cta.primary}>Run the lab</a>
              <a href="https://docs.cloud.google.com/mcp/overview" style={{ ...cta.secondary, color: '#F8F5EF', borderColor: '#57534E' }}>Google Cloud MCP controls</a>
            </div>
            <p style={{ color: '#A8A29E', fontSize: 12.5, lineHeight: 1.65, maxWidth: 820, marginTop: 18 }}>
              Independent Apache-2.0 demonstration. No Google service is called. Not affiliated
              with, endorsed by, or deployed at Google. Google Cloud, Gemini, and Model Armor are
              referenced nominatively to describe the composition boundary.
            </p>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 46, paddingBottom: 50 }}>
          <div style={styles.eyebrow}>THE ONE-COMMAND RESULT</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Five refusals. One mutation. No second chance.</h2>
          <div style={{ marginTop: 24, background: '#171412', color: '#E7E5E4', borderRadius: radius.base, padding: '24px 26px', fontFamily: font.mono, overflowX: 'auto' }}>
            <div style={{ color: color.gold, fontSize: 11, letterSpacing: 1.2, marginBottom: 14 }}>EXTERNAL RELIANCE LAB</div>
            <div style={{ fontSize: 13, lineHeight: 1.85, whiteSpace: 'pre', minWidth: 650 }}>{`$ node examples/google-cloud-reliance/demo.mjs

IAM                         ALLOW
MODEL ARMOR-SHAPED CHECK    ALLOW
NO CUSTOMER EVIDENCE        REFUSE
ONE SIGNER / QUORUM RULE    REFUSE
VIEWER -> OWNER DRIFT       REFUSE
TAMPERED RECEIPT            REFUSE
EXACT TWO-PERSON EVIDENCE   RELY · EXECUTE ONCE
REPLAY                      REFUSE

REAL MUTATION COUNT         1`}</div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, ...styles.sectionAlt }}>
          <div style={styles.eyebrow}>THE DISTINCTION</div>
          <h2 style={{ ...styles.h2, maxWidth: 840 }}>Local authorization and external reliance are different decisions.</h2>
          <p style={{ ...styles.body, maxWidth: 780 }}>
            The lab does not claim Google Cloud lacks security controls. It demonstrates the
            complementary artifact a regulated customer needs when the consequence must remain
            independently explainable after the agent session, vendor log, or cloud account is gone.
          </p>
          <div style={{ marginTop: 26, borderTop: `1px solid ${color.border}` }}>
            {CONTROL_ROWS.map(([label, detail], index) => (
              <div key={label} className={labStyles.controlRow}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: index === 1 ? color.gold : color.t1, fontWeight: 700 }}>{label}</div>
                <div style={{ ...styles.body, margin: 0, fontSize: 15 }}>{detail}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>ATTACK THE BOUNDARY</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>The refuse cases are the product claim.</h2>
          <div className={labStyles.caseGrid}>
            {CASES.map(([verdict, title, detail]) => (
              <div key={title} style={{ ...styles.card, padding: 24, borderTop: `3px solid ${verdict === 'RELY' ? color.green : color.red}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1, color: verdict === 'RELY' ? color.green : color.red, fontWeight: 700 }}>{verdict}</div>
                <h3 style={{ ...styles.h3, fontSize: 17, marginTop: 10 }}>{title}</h3>
                <p style={{ ...styles.cardBody, marginTop: 9 }}>{detail}</p>
              </div>
            ))}
          </div>
        </section>

        <section style={{ ...styles.sectionWide, ...styles.sectionAlt }}>
          <div style={styles.eyebrow}>WHAT ACTUALLY RUNS</div>
          <h2 style={{ ...styles.h2, maxWidth: 820 }}>The production enforcement path, not a policy stub.</h2>
          <p style={{ ...styles.body, maxWidth: 780 }}>
            The example invokes EMILIA&apos;s MCP tool wrapper with the existing Google Cloud
            action pack and Gate. The valid path uses Ed25519 receipt signing plus WebAuthn-shaped P-256
            per-signer evidence. The Gate binds action type, project, member, and role; consumes
            the receipt once; calls the injected GCP client; and returns an execution-bound
            reliance packet.
          </p>
          <div style={{ marginTop: 26, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 14 }}>
            {[
              ['GCP action pack', 'MCP tool mapping and exact system-of-record material-field binding.'],
              ['Quorum verifier', 'Two distinct human/device ceremonies; a single signer is insufficient.'],
              ['Consumption store', 'The accepted receipt can authorize at most one mutation.'],
              ['Reliance packet', 'The execution record names the authorization decision it consumed.'],
            ].map(([title, detail]) => (
              <div key={title} style={{ padding: '18px 0', borderTop: `2px solid ${color.gold}` }}>
                <div style={{ ...styles.h3, fontSize: 16 }}>{title}</div>
                <div style={{ ...styles.cardBody, marginTop: 7 }}>{detail}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>HONEST BOUNDARY</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Evidence that the rule ran is not proof the rule was wise.</h2>
          <p style={{ ...styles.body, maxWidth: 780 }}>
            The lab proves the customer-pinned evidence and execution-binding checks passed for
            this mutation. It does not prove that granting roles/owner was a good decision, that
            Google&apos;s own control decisions were correct, or that an unmediated write path did not
            exist. Production deployments must pin real issuer and approver keys, use durable
            atomic consumption, and mediate every protected mutation path.
          </p>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 30, paddingBottom: 88 }}>
          <div style={{ borderTop: `1px solid ${color.border}`, paddingTop: 34, textAlign: 'center' }}>
            <h2 style={{ ...styles.h2, maxWidth: 700, margin: '0 auto 12px' }}>Give the lab to the people shipping Google Cloud agents.</h2>
            <p style={{ ...styles.body, maxWidth: 680, margin: '0 auto 24px', fontSize: 15 }}>
              The question is intentionally narrow: should a regulated customer be able to pin
              an evidence requirement that remains independently verifiable after Google-side
              controls have allowed the call?
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: 12, flexWrap: 'wrap' }}>
              <a href={DEMO} style={cta.primary}>Inspect the six cases</a>
              <a href="mailto:team@emiliaprotocol.ai?subject=Google%20Cloud%20external%20reliance%20lab" style={cta.secondary}>Reproduce it with us</a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
