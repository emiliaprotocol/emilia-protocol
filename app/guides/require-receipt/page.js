// SPDX-License-Identifier: Apache-2.0
// Developer guide: add Receipt Required to one dangerous MCP tool.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

/** @type {React.CSSProperties} */
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

const MANIFEST = `{
  "@version": "EP-ACTION-RISK-MANIFEST-v0.1",
  "service": {
    "name": "Acme MCP",
    "manifest_url": "https://mcp.acme.com/.well-known/agent-actions.json"
  },
  "receipt_required": {
    "status": 428,
    "challenge_header": "Receipt-Required",
    "proof_header": "X-EMILIA-Receipt",
    "receipt_profile": "EP-RECEIPT-v1"
  },
  "defaults": {
    "read_only": "allow",
    "missing_receipt": "refuse",
    "invalid_receipt": "refuse",
    "stale_receipt": "refuse"
  },
  "actions": [
    {
      "id": "mcp.release_payment",
      "match": { "protocol": "mcp", "tool": "release_payment" },
      "action_type": "payment.release",
      "risk": "high",
      "receipt_required": true,
      "assurance_class": "class_a",
      "max_age_sec": 900,
      "quorum": { "required": false }
    }
  ]
}`;

const MCP_GATE = `import {
  findActionRequirement,
  makeReceiptGate,
} from '@emilia-protocol/require-receipt';

const manifest = await fetch('https://mcp.acme.com/.well-known/agent-actions.json')
  .then((r) => r.json());
const gates = new Map();
const approverKeys = JSON.parse(process.env.EMILIA_APPROVER_KEYS_JSON);
const allowedOrigins = process.env.EMILIA_ALLOWED_ORIGINS.split(',');

// Inject a fleet-wide ownership-fenced implementation. reserve() must be an
// atomic insert-if-absent; an uncertain reservation remains closed.
const store = productionReceiptStore; // { reserve, commit, release }

function gateFor(req) {
  if (!gates.has(req.action_type)) {
    gates.set(req.action_type, makeReceiptGate({
      action: req.action_type,
      trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY].filter(Boolean),
      approverKeys,
      rpId: process.env.EMILIA_RP_ID,
      allowedOrigins,
      assuranceClass: req.assurance_class,
      quorum: req.quorum,
      quorumPolicy: req.quorum?.required ? PINNED_QUORUM_POLICIES[req.id] : undefined,
      maxAgeSec: req.max_age_sec,
      manifestUrl: '/.well-known/agent-actions.json',
      store,
    }));
  }
  return gates.get(req.action_type);
}

function stripEpControlArgs(args = {}) {
  const { __ep, emilia_receipt, ...clean } = args;
  return clean;
}

export async function guardedCallTool(name, args, extra = {}) {
  const req = findActionRequirement(manifest, { protocol: 'mcp', tool: name });
  if (!req?.receipt_required) return handleTool(name, args, extra);

  const receipt = args.__ep?.receipt || args.emilia_receipt || extra._meta?.emilia_receipt;
  const clean = stripEpControlArgs(args);
  const result = await gateFor(req).run(
    receipt,
    { target: clean.payment_id },
    () => handleTool(name, clean, extra),
  );
  return result.ok ? result.result : result.body;
}`;

const LIVE_GUARD = `import { EPClient } from '@emilia-protocol/sdk';
import { withMcpReceiptGuard } from '@emilia-protocol/mcp-guard';

const ep = new EPClient({ apiKey });   // EP_API_KEY from your env

const guardedHandleTool = withMcpReceiptGuard(handleTool, {
  client: ep,
  executingSystem: 'acme-mcp-server',
  annotations: {
    release_payment: {
      irreversible: true,
      actionType: 'payment.release',
      targetResourceId: (args) => args.payment_id,
      amount: (args) => args.amount,
      currency: (args) => args.currency,
      approverId: 'ap_controller_jane',
      onSignoffRequired: async ({ signoff }) => waitForApprovedSignoff(signoff.signoff_id),
    },
  },
});

// dispatch through guardedHandleTool instead of handleTool`;

const RITUAL = `FAST=1 node examples/mcp/payment-server.mjs
FAST=1 node examples/mcp/github-admin.mjs
FAST=1 node examples/mcp/prod-deploy.mjs

# Each demo proves:
# 1. no receipt -> 428 Receipt Required
# 2. exact signed receipt -> tool runs
# 3. same receipt again -> replay_refused
# 4. tampered receipt -> refused`;

const HTTP = `import { requireEmiliaReceipt } from '@emilia-protocol/require-receipt';

app.post(
  '/release-payment',
  requireEmiliaReceipt({
    trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY],
    action: 'payment.release',
    statusCode: 428,
    manifestUrl: '/.well-known/agent-actions.json',
    maxAgeSec: 900,
  }),
  (req, res) => res.json({ released: true, receipt: req.emiliaReceipt.receipt_id }),
);`;

const FAQ = [
  [
    'Why 428 instead of 402?',
    '428 is the clean precondition rail: bring an authorization receipt before mutation. 402 remains available for x402/AP2-compatible flows, but new Receipt Required integrations should advertise 428.',
  ],
  [
    'Does the manifest grant permission?',
    'No. The manifest is a refusal contract. It tells agents which action needs proof; the receipt verifier, authority checks, quorum rules, and consume-before-write gate decide whether the action may run.',
  ],
  [
    'Do I need an EMILIA backend?',
    'No for the offline demand demo: pin issuer keys and verify locally. For production issuance, signoff, one-time consumption, and execution attestation, use the SDK or your EMILIA host.',
  ],
  [
    'What should I show a maintainer?',
    'One dangerous MCP tool that returns 428 without proof, runs with an exact signed receipt, refuses replay, and refuses a forged receipt. That four-step ritual is the adoption wedge.',
  ],
];

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map(([q, a]) => ({
    '@type': 'Question',
    name: q,
    acceptedAnswer: { '@type': 'Answer', text: a },
  })),
};

export default function RequireReceiptGuide() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <SiteNav activePage="Agent Guard" />
      <main style={styles.page}>
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>DEVELOPER GUIDE · RECEIPT REQUIRED</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 920 }}>Add Receipt Required to an MCP server in 10 minutes.</h1>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 18, fontSize: 18 }}>
            <strong>No receipt, no irreversible action.</strong> Publish an Action Risk Manifest,
            wrap one dangerous tool, and return <strong>428 Receipt Required</strong> until the
            agent brings an <span style={{ fontFamily: font.mono, color: color.t1 }}>EP-RECEIPT-v1</span>
            bound to the exact action. Valid receipt runs. Same receipt again is replay-refused.
            Forged receipt never reaches the mutation.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
            <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples/mcp" target="_blank" rel="noopener noreferrer" style={cta.primary}>Run the MCP ritual</a>
            <a href="/mcp" style={cta.secondary}>See the MCP page</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STEP 1 · DECLARE THE DANGER</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Publish <span style={{ fontFamily: font.mono }}>/.well-known/agent-actions.json</span>.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            Start with one irreversible MCP tool. The manifest is deliberately boring: it names the
            tool, the canonical action bound into the receipt, the assurance class, and the freshness
            window an agent must satisfy.
          </p>
          <pre style={codeBox}>{MANIFEST}</pre>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STEP 2 · REFUSE BEFORE MUTATION</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Wrap the tool dispatcher.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            Install <span style={{ fontFamily: font.mono, color: color.t1 }}>@emilia-protocol/require-receipt</span>.
            Resolve the tool requirement from the manifest, verify the receipt offline, consume it
            before the write, then call the real tool handler.
          </p>
          <pre style={codeBox}>{MCP_GATE}</pre>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STEP 3 · PROVE THE RITUAL</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Run it cold, no account, no API key.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            The repo ships three manifest-driven MCP examples: payment release, repo deletion, and
            production deploy. They exercise the real verifier and the replay check.
          </p>
          <pre style={codeBox}>{RITUAL}</pre>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STEP 4 · GO LIVE</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Use the system-of-record guard when the write is real.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            For production, <span style={{ fontFamily: font.mono, color: color.t1 }}>withMcpReceiptGuard</span>
            drives the v1 flow: require receipt, request signoff if needed, consume before mutation,
            run the tool, then emit execution evidence. If consume fails, your handler is never called.
          </p>
          <pre style={codeBox}>{LIVE_GUARD}</pre>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>HTTP SERVICES</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Same rail for ordinary APIs.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            If the dangerous action is an HTTP route instead of an MCP tool, opt into the same 428
            rail with one middleware. Omit <span style={{ fontFamily: font.mono, color: color.t1 }}>statusCode</span>
            only when you deliberately need legacy 402/x402 compatibility.
          </p>
          <pre style={codeBox}>{HTTP}</pre>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>FREQUENTLY ASKED</div>
          {FAQ.map(([q, a]) => (
            <div key={q} style={{ padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
              <div style={{ ...styles.h3, fontSize: 18, marginBottom: 6 }}>{q}</div>
              <p style={{ ...styles.body, margin: 0, fontSize: 15, maxWidth: 780 }}>{a}</p>
            </div>
          ))}
        </section>

        <section style={styles.section}>
          <p style={{ fontSize: 13, color: color.t3, maxWidth: 780, lineHeight: 1.6 }}>
            Receipt Required is not identity, permissions, or a correctness oracle. It is a
            fail-closed refusal rail: if an agent changes money, code, permissions, records, or
            regulated state, the system can demand portable proof of exactly who authorized exactly
            what under exactly which policy.
          </p>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
