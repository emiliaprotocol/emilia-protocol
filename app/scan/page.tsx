// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';
import mcpGuardPackage from '../../packages/mcp-guard/package.json';
import scanPackage from '../../packages/scan/package.json';

export const metadata: Metadata = {
  title: 'EMILIA Gate Starter — Map and Prepare One Agent Boundary',
  description:
    'Map the actions declared to an MCP agent, choose one consequential tool, generate a local Gate scaffold, and run bounded refusal checks without an account, upload, or telemetry.',
  alternates: { canonical: '/scan' },
  openGraph: {
    images: ['/opengraph-image'],
    title: 'See every declared action. Prepare one boundary.',
    description:
      'One local command maps a declared MCP surface, prepares one reviewable boundary, and runs bounded refusal checks. Production activation remains separate.',
    url: 'https://www.emiliaprotocol.ai/scan',
    type: 'website',
  },
  keywords: [
    'AI agent Gate starter',
    'MCP security scanner',
    'MCP tool guard',
    'AI agent authority map',
    'AI agent consequence firewall',
    'agent action authorization',
  ],
};

const shell: React.CSSProperties = {
  maxWidth: 1120,
  margin: '0 auto',
  padding: '0 32px',
};

const codeBox: React.CSSProperties = {
  fontFamily: font.mono,
  fontSize: 13,
  lineHeight: 1.75,
  color: '#ECFEFF',
  background: '#17212A',
  border: '1px solid #30414E',
  borderRadius: radius.base,
  padding: '22px 24px',
  overflowX: 'auto',
  whiteSpace: 'pre',
};

const SCAN_INSTALL_SPEC = `@emilia-protocol/scan@${scanPackage.version}`;
const PROTECT_COMMAND = `npx ${SCAN_INSTALL_SPEC} protect ./tools.json --action sendWire --apply --verify`;
const SAMPLE_COMMAND = `npx ${SCAN_INSTALL_SPEC} protect --sample --action sendWire --apply --verify`;
const REVIEW_COMMAND = `npx ${SCAN_INSTALL_SPEC} protect ./tools.json --action sendWire --reviewed \\
  --crossing-profile ccs-wang-draft08-v13`;
const INSTALL_COMMAND = `npm install --save-exact @emilia-protocol/mcp-guard@${mcpGuardPackage.version}`;

const LADDER = [
  {
    n: '01',
    title: 'Map',
    body: 'Read the actions declared in your MCP tool list and preserve the scanner\'s blind spots.',
    state: 'LOCAL',
  },
  {
    n: '02',
    title: 'Choose',
    body: 'Name one consequential tool. Classification is a proposal until the owner reviews it.',
    state: 'OWNER',
  },
  {
    n: '03',
    title: 'Prepare',
    body: 'Write a manifest, guard scaffold, integration guide, and bounded local refusal check.',
    state: 'SCAFFOLD',
  },
  {
    n: '04',
    title: 'Activate',
    body: 'Connect Gate to the real credential-owning path under a customer mandate and verify refusal.',
    state: 'PRODUCTION',
  },
];

const LOCAL_OUTPUTS = [
  ['Action map', 'The declared MCP surface, proposed consequence classes, and explicit blind spots.'],
  ['Selected boundary', 'A generated wrapper for the exact tool name you selected, not a blanket security claim.'],
  ['Integration files', 'A manifest, guard module, setup verifier, and instructions written to a local directory.'],
  ['RR-1 check', 'Synthetic missing, exact-match, mutation, and replay cases exercised without calling the real tool.'],
];

const ACTIVATION_REQUIREMENTS = [
  ['Customer mandate', 'Mission, limits, evidence rules, expiry, trust roots, and exception path are owned by the customer.'],
  ['Owning connector', 'Every covered call reaches Gate beside the credential-owning executor. Alternate paths remain exclusions until mediated.'],
  ['Durable state', 'Pinned keys and policy, shared one-use consumption, provenance, and failure handling survive process restarts.'],
  ['Verified refusal', 'Missing, stale, exhausted, invalid, or mismatched authority is shown to refuse provider entry on the covered path.'],
];

const STARTER_EXIT_CODES = [
  ['0', 'Requested preview, generation, local check, or reviewed handoff completed'],
  ['1', 'Input, runtime, filesystem, safety, or local verification was refused'],
  ['2', 'A required value is missing, or OpenAPI protection is not available'],
  ['64', 'An option or selected-action contract is invalid'],
];

export default function AuthorityScanPage(): React.ReactElement {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="" />

      <main>
        <section id="run-local" style={{ padding: '112px 0 80px', borderBottom: `1px solid ${color.border}` }}>
          <div style={shell}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2.4, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>
              Free local Gate Starter · MCP alpha
            </div>
            <h1 style={{ fontFamily: font.sans, fontSize: 'clamp(42px, 7vw, 80px)', lineHeight: 0.98, letterSpacing: -3, margin: '0 0 28px', maxWidth: 980 }}>
              See every declared action. Prepare one boundary before it becomes real.
            </h1>
            <p style={{ fontSize: 19, lineHeight: 1.7, color: color.t2, maxWidth: 780, margin: '0 0 36px' }}>
              Point EMILIA Scan at the MCP tools your agent is configured to call. After one exact runtime
              install, the Gate Starter command maps that declared surface, prepares a reviewable guard for
              one tool, and runs bounded refusal checks. No account, upload, or telemetry.
            </p>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.6, color: color.t3, marginBottom: 8 }}>
              STEP 0 · INSTALL THE EXACT LOCAL RUNTIME
            </div>
            <pre aria-label="Gate Starter runtime install command" style={{ ...codeBox, maxWidth: 900, margin: '0 0 18px' }}>{INSTALL_COMMAND}</pre>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.6, color: color.t3, marginBottom: 8 }}>
              CREATE THE STARTER AND RUN ITS LOCAL CHECK
            </div>
            <pre aria-label="Gate Starter command" style={{ ...codeBox, maxWidth: 900 }}>{PROTECT_COMMAND}</pre>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
              <a
                href="https://www.npmjs.com/package/@emilia-protocol/scan"
                target="_blank"
                rel="noopener noreferrer"
                style={cta.primary}
              >
                Inspect the package and run it
              </a>
              <a href="#sample" style={cta.secondary}>Try the built-in sample</a>
            </div>
            <p style={{ fontFamily: font.mono, fontSize: 11, lineHeight: 1.65, color: color.t3, maxWidth: 820, margin: '18px 0 0' }}>
              Replace sendWire with one exact name from your declared MCP surface. The command does not
              launch the configured server or call the selected tool. Package installation may contact npm;
              Scan and the generated verifier make no remote request.
            </p>
          </div>
        </section>

        <section aria-labelledby="protection-ladder" style={{ padding: '82px 0', borderBottom: `1px solid ${color.border}` }}>
          <div style={shell}>
            <div style={{ maxWidth: 720, marginBottom: 38 }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>
                One useful path
              </div>
              <h2 id="protection-ladder" style={{ fontSize: 'clamp(30px, 4vw, 48px)', lineHeight: 1.06, letterSpacing: -1.6, margin: '0 0 16px' }}>
                Map → Choose → Prepare → Activate
              </h2>
              <p style={{ fontSize: 16, lineHeight: 1.75, color: color.t2, margin: 0 }}>
                The first three steps happen on your machine. Production activation is a separate engineering
                step because generated files cannot prove that every real execution path is controlled.
              </p>
            </div>

            <ol style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(220px, 100%), 1fr))', gap: 12, listStyle: 'none', padding: 0, margin: 0 }}>
              {LADDER.map((step) => (
                <li key={step.n} style={{ position: 'relative', minHeight: 220, border: `1px solid ${step.n === '04' ? color.gold : color.border}`, borderRadius: radius.base, padding: 26, background: step.n === '04' ? '#FFFBEB' : color.card }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, alignItems: 'baseline', marginBottom: 38 }}>
                    <span style={{ fontFamily: font.mono, color: color.gold, fontSize: 12 }}>{step.n}</span>
                    <span style={{ fontFamily: font.mono, color: color.t3, fontSize: 9, letterSpacing: 1.5 }}>{step.state}</span>
                  </div>
                  <h3 style={{ fontSize: 25, letterSpacing: -0.6, margin: '0 0 10px' }}>{step.title}</h3>
                  <p style={{ fontSize: 14, lineHeight: 1.68, color: color.t2, margin: 0 }}>{step.body}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section id="sample" aria-labelledby="run-it" style={{ padding: '82px 0', borderBottom: `1px solid ${color.border}` }}>
          <div style={shell}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(360px, 100%), 1fr))', gap: 64, alignItems: 'start' }}>
              <div>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>
                  No tools file required
                </div>
                <h2 id="run-it" style={{ fontSize: 'clamp(30px, 4vw, 46px)', lineHeight: 1.06, letterSpacing: -1.5, margin: '0 0 18px' }}>
                  Try the whole local path on a built-in sample.
                </h2>
                <p style={{ fontSize: 16, lineHeight: 1.75, color: color.t2, margin: '0 0 24px' }}>
                  After the same exact runtime install, this uses a synthetic tool list and writes only local
                  scaffold files. It is a fast way to inspect the shape before pointing the command at your own declaration.
                </p>
                <pre aria-label="Gate Starter sample command" style={codeBox}>{SAMPLE_COMMAND}</pre>
              </div>

              <div>
                <h3 style={{ fontSize: 20, letterSpacing: -0.4, margin: '0 0 10px' }}>What you get</h3>
                {LOCAL_OUTPUTS.map(([title, body]) => (
                  <div key={title} style={{ padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
                    <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 5 }}>{title}</div>
                    <div style={{ fontSize: 14, lineHeight: 1.65, color: color.t2 }}>{body}</div>
                  </div>
                ))}
                <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, padding: 20, marginTop: 22, background: color.card }}>
                  <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.6, color: color.gold, marginBottom: 9 }}>
                    AFTER YOU INSPECT THE BYTES
                  </div>
                  <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 7 }}>Record review as a second, explicit action.</div>
                  <p style={{ fontSize: 13.5, lineHeight: 1.65, color: color.t2, margin: '0 0 14px' }}>
                    Read the generated Authority Map and manifest first. Then this separate command
                    revalidates the existing pack and creates an owner-only handoff. It does not activate Gate.
                  </p>
                  <pre aria-label="Reviewed Gate Starter handoff command" style={{ ...codeBox, padding: '15px 16px', fontSize: 11.5 }}>{REVIEW_COMMAND}</pre>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section aria-labelledby="proof-boundary" style={{ padding: '82px 0', background: '#F5F5F4', borderBottom: `1px solid ${color.border}` }}>
          <div style={shell}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(340px, 100%), 1fr))', gap: 72, alignItems: 'start' }}>
              <div>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>
                  The honest boundary
                </div>
                <h2 id="proof-boundary" style={{ fontSize: 'clamp(30px, 4vw, 46px)', lineHeight: 1.06, letterSpacing: -1.5, margin: '0 0 18px' }}>
                  A passing local check is not production protection.
                </h2>
                <p style={{ fontSize: 16, lineHeight: 1.75, color: color.t2, margin: 0 }}>
                  RR-1 exercises the generated wrapper against synthetic evidence. It does not prove a production
                  authority source, complete mediation, correct policy, durable replay defense, or a protected deployment.
                </p>
              </div>
              <div>
                {ACTIVATION_REQUIREMENTS.map(([title, body], index) => (
                  <div key={title} style={{ display: 'grid', gridTemplateColumns: '42px 1fr', gap: 16, padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
                    <span aria-hidden="true" style={{ width: 30, height: 30, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', borderRadius: 999, background: color.t1, color: '#fff', fontFamily: font.mono, fontSize: 11 }}>{index + 1}</span>
                    <div>
                      <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 5 }}>{title}</div>
                      <div style={{ fontSize: 14, lineHeight: 1.65, color: color.t2 }}>{body}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section aria-labelledby="activate-boundary" style={{ padding: '88px 0 96px' }}>
          <div style={shell}>
            <div style={{ border: `1px solid ${color.gold}`, borderRadius: radius.base, padding: 'clamp(28px, 5vw, 52px)', background: '#FFFBEB', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(320px, 100%), 1fr))', gap: 48, alignItems: 'end' }}>
              <div>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>
                  Fixed protected-workflow pilot
                </div>
                <h2 id="activate-boundary" style={{ fontSize: 'clamp(30px, 4vw, 48px)', lineHeight: 1.04, letterSpacing: -1.6, margin: '0 0 18px' }}>
                  Make this one boundary real.
                </h2>
                <p style={{ fontSize: 16, lineHeight: 1.75, color: color.t2, margin: 0 }}>
                  In the 90-day, $25K pilot, we scope one consequential workflow, connect Gate beside its
                  owning executor, install the customer mandate, and verify refusal before production entry.
                </p>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'stretch' }}>
                <Link href="/pilot" style={{ ...cta.primary, textAlign: 'center' }}>Activate this boundary in production</Link>
                <Link href="/mcp" style={{ ...cta.secondary, textAlign: 'center' }}>Inspect the MCP integration</Link>
              </div>
            </div>

            <details style={{ marginTop: 28, borderTop: `1px solid ${color.border}`, paddingTop: 20 }}>
              <summary style={{ cursor: 'pointer', fontFamily: font.mono, fontSize: 12, color: color.t2 }}>
                Gate Starter exit codes and limits
              </summary>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(220px, 100%), 1fr))', gap: 10, marginTop: 18 }}>
                {STARTER_EXIT_CODES.map(([code, meaning]) => (
                  <div key={code} style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '14px 16px', background: color.card }}>
                    <span style={{ fontFamily: font.mono, color: color.gold, marginRight: 10 }}>{code}</span>
                    <span style={{ fontSize: 13, color: color.t2 }}>{meaning}</span>
                  </div>
                ))}
              </div>
              <p style={{ fontSize: 13, lineHeight: 1.7, color: color.t3, maxWidth: 780, margin: '16px 0 0' }}>
                Exit 0 means only that the requested local CLI operation completed. It is never a clean bill
                of health: Scan cannot see runtime-registered tools or value-dependent risk, and no local
                command proves complete operation coverage or production mediation.
              </p>
            </details>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
