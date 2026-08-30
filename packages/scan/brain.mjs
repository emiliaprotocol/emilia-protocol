// SPDX-License-Identifier: Apache-2.0
//
// Self-contained local Authority Brain dashboard generation. This module
// renders only a whitelisted projection of a real scanActions report and
// writes the complete HTML as one owner-only, direct-child artifact.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export const DEFAULT_BRAIN_OUTPUT = 'emilia-authority-brain.html';
export const SCAN_PACKAGE_VERSION = JSON.parse(
  fs.readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
).version;
if (typeof SCAN_PACKAGE_VERSION !== 'string' || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(SCAN_PACKAGE_VERSION)) {
  throw new TypeError('Authority Brain requires a canonical Scan package version.');
}
export const SCAN_INSTALL_SPEC = `@emilia-protocol/scan@${SCAN_PACKAGE_VERSION}`;

const STANDARD_BLIND_SPOTS = Object.freeze([
  'Whether every execution path reaches a credential-owning Gate. Complete mediation must be verified after integration.',
  'Whether your organization will fail closed on denial. That is an owner decision, not a scanner setting.',
]);

const MAX_ACTIONS = 10_000;
const MAX_DESCRIPTION_LENGTH = 16_384;
const MAX_BLIND_SPOTS = 100;
const MAX_DISPLAY_TEXT_LENGTH = 4_096;
const MAX_INPUT_REFERENCE_LENGTH = 4_096;
const SOURCE_CONFUSING_TEXT = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const SOURCE_CONFUSING_COMMAND = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const DECISIONS = new Set(['gate', 'review_fail_closed', 'pass_through', 'review']);
const CONFIDENCES = new Set(['high', 'medium', 'low']);
const HTTP_METHODS = new Set(['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE']);
const RESERVED_OBJECT_NAMES = new Set(['__proto__', 'prototype', 'constructor']);

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function assertText(value, label, {
  maxLength = MAX_DISPLAY_TEXT_LENGTH,
  allowEmpty = false,
  commandSafe = false,
} = {}) {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || value.length > maxLength) {
    throw new TypeError(`Authority Brain requires a bounded ${label}.`);
  }
  const unsafe = commandSafe ? SOURCE_CONFUSING_COMMAND : SOURCE_CONFUSING_TEXT;
  if (unsafe.test(value)) {
    throw new TypeError(`Authority Brain refuses source-confusing characters in ${label}.`);
  }
  return value;
}

function assertOptionalText(value, label, options) {
  if (value === undefined || value === null) return;
  assertText(value, label, { ...options, allowEmpty: true });
}

function posixQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function assertReport(report) {
  if (!isRecord(report) || !Array.isArray(report.results) || !isRecord(report.counts)
      || typeof report.source !== 'string') {
    throw new TypeError('Authority Brain requires a scanActions report.');
  }
  if (!['mcp', 'openapi', 'list'].includes(report.source)) {
    throw new TypeError('Authority Brain does not support the supplied source type.');
  }
  if (report.results.length > MAX_ACTIONS) {
    throw new TypeError(`Authority Brain supports at most ${MAX_ACTIONS} visible actions.`);
  }

  const actualCounts = {
    total: report.results.length,
    gate: 0,
    review_fail_closed: 0,
    pass_through: 0,
    review: 0,
  };
  const exactNames = new Set();
  const normalizedNames = new Set();
  for (const result of report.results) {
    if (!isRecord(result) || !isRecord(result.action) || !isRecord(result.classification)) {
      throw new TypeError('Authority Brain requires bounded action and classification records.');
    }
    const { action, classification } = result;
    assertText(action.name, 'action name', { maxLength: 256, commandSafe: true });
    const normalizedName = action.name.toLowerCase().replace(/[^a-z0-9]+/g, '_');
    if (RESERVED_OBJECT_NAMES.has(action.name) || exactNames.has(action.name)
        || !normalizedName || normalizedNames.has(normalizedName)) {
      throw new TypeError('Authority Brain refuses duplicate or source-confusing action names.');
    }
    exactNames.add(action.name);
    normalizedNames.add(normalizedName);
    assertOptionalText(action.description, 'action description', { maxLength: MAX_DESCRIPTION_LENGTH });
    if (!DECISIONS.has(classification.decision)
        || typeof classification.receipt_required !== 'boolean'
        || !CONFIDENCES.has(classification.confidence)) {
      throw new TypeError('Authority Brain refuses an unknown classification state.');
    }
    if ((classification.decision === 'pass_through' && classification.receipt_required)
        || (['gate', 'review_fail_closed'].includes(classification.decision)
          && !classification.receipt_required)) {
      throw new TypeError('Authority Brain refuses an inconsistent receipt disposition.');
    }
    assertText(classification.reason, 'classification reason');
    assertOptionalText(classification.category, 'classification category', { maxLength: 256 });
    assertOptionalText(classification.assurance_class, 'assurance class', { maxLength: 128 });
    if (classification.required_fields !== undefined) {
      if (!Array.isArray(classification.required_fields) || classification.required_fields.length > 256) {
        throw new TypeError('Authority Brain requires a bounded material-field list.');
      }
      for (const field of classification.required_fields) {
        assertText(field, 'material field', { maxLength: 256, commandSafe: true });
      }
    }
    if (report.source === 'openapi') {
      assertText(action.http_method, 'HTTP method', { maxLength: 16, commandSafe: true });
      assertText(action.route_path, 'route path', { maxLength: 2_048, commandSafe: true });
      if (!HTTP_METHODS.has(action.http_method.toUpperCase()) || !action.route_path.startsWith('/')) {
        throw new TypeError('Authority Brain refuses a malformed OpenAPI action.');
      }
    }
    actualCounts[classification.decision] += 1;
  }

  for (const [key, expected] of Object.entries(actualCounts)) {
    if (!Number.isSafeInteger(report.counts[key]) || report.counts[key] < 0
        || report.counts[key] !== expected) {
      throw new TypeError('Authority Brain refuses inconsistent scan counts.');
    }
  }

  if (report.blindSpots !== undefined) {
    if (!Array.isArray(report.blindSpots) || report.blindSpots.length > MAX_BLIND_SPOTS) {
      throw new TypeError('Authority Brain requires a bounded blind-spot list.');
    }
    for (const blindSpot of report.blindSpots) assertText(blindSpot, 'blind spot');
  }
}

function buildModel(report, {
  inputReference,
  outputDirectory = 'emilia',
  starterSelectedTool = null,
}) {
  assertReport(report);
  assertText(inputReference, 'scanner input reference', {
    maxLength: MAX_INPUT_REFERENCE_LENGTH,
    commandSafe: true,
  });
  assertText(outputDirectory, 'protection output directory', {
    maxLength: MAX_INPUT_REFERENCE_LENGTH,
    commandSafe: true,
  });
  if (starterSelectedTool !== null) {
    assertText(starterSelectedTool, 'Gate Starter selected tool', {
      maxLength: 256,
      commandSafe: true,
    });
    const selectedMatches = report.results.filter(({ action, classification }) => (
      action.name === starterSelectedTool && classification.receipt_required === true
    ));
    if (report.source !== 'mcp' || selectedMatches.length !== 1) {
      throw new TypeError('Authority Brain requires one visible consequential MCP action for a selected Gate Starter.');
    }
  }

  const sample = inputReference === '--sample';
  const commandInputReference = !sample && inputReference.startsWith('-')
    ? `./${inputReference}`
    : inputReference;
  const protectTarget = sample ? '--sample' : posixQuote(commandInputReference);
  const outputOption = outputDirectory === 'emilia' ? '' : ` --out ${posixQuote(outputDirectory)}`;
  const actions = report.results.map(({ action, classification }, index) => {
    const isMcp = report.source === 'mcp';
    const receiptRequired = classification.receipt_required === true;
    const selectedInStarter = starterSelectedTool !== null
      && action.name === starterSelectedTool;
    const reviewPendingInStarter = starterSelectedTool !== null
      && receiptRequired
      && !selectedInStarter;
    const baseCommandEligible = isMcp
      && receiptRequired
      && !action.name.startsWith('-');
    const generationEligible = baseCommandEligible && starterSelectedTool === null;
    const handoffEligible = baseCommandEligible
      && (starterSelectedTool === null || selectedInStarter);
    const sourceDetail = report.source === 'openapi'
      ? `${String(action.http_method || '').toUpperCase()} ${String(action.route_path || '')}`
      : report.source === 'mcp' ? 'MCP tool' : 'declared action';
    return {
      id: `visible-action-${index + 1}`,
      name: String(action.name),
      description: typeof action.description === 'string' ? action.description : '',
      sourceDetail,
      decision: String(classification.decision),
      receiptRequired,
      confidence: String(classification.confidence),
      reason: String(classification.reason),
      authoritySource: 'not established by static scan',
      provenance: report.source === 'openapi'
        ? 'declared OpenAPI operation · deterministic local classification'
        : report.source === 'mcp'
          ? 'declared MCP metadata · deterministic local classification'
          : 'declared action metadata · deterministic local classification',
      category: classification.category ? String(classification.category) : null,
      assuranceClass: classification.assurance_class ? String(classification.assurance_class) : null,
      materialFields: Array.isArray(classification.required_fields)
        ? classification.required_fields.map(String)
        : receiptRequired ? ['action_type'] : [],
      lifecycleState: 'proposal',
      protectCommand: generationEligible
        ? `npx ${SCAN_INSTALL_SPEC} protect ${protectTarget}${outputOption} --action ${posixQuote(action.name)} --apply --verify`
        : null,
      verifyCommand: null,
      handoffCommand: handoffEligible
        ? `npx ${SCAN_INSTALL_SPEC} protect ${protectTarget}${outputOption} --action ${posixQuote(action.name)} --reviewed`
        : null,
      handoffLimitation: isMcp && receiptRequired && !reviewPendingInStarter && action.name.startsWith('-')
        ? 'The selected-action Gate Starter cannot safely select a leading-dash tool name. Rename that declared tool before generating the starter.'
        : null,
      starterReviewPending: reviewPendingInStarter,
      starterSelectedAction: selectedInStarter,
    };
  });

  return {
    product: 'EMILIA Authority Brain',
    source: report.source,
    inputMode: sample ? 'sample' : 'file',
    counts: {
      total: Number(report.counts.total || 0),
      gate: Number(report.counts.gate || 0),
      review_fail_closed: Number(report.counts.review_fail_closed || 0),
      pass_through: Number(report.counts.pass_through || 0),
      review: Number(report.counts.review || 0),
    },
    actions,
    blindSpots: [
      ...(Array.isArray(report.blindSpots) ? report.blindSpots.map(String) : []),
      ...STANDARD_BLIND_SPOTS,
    ],
    claimBoundary: {
      scanner: 'proposal',
      ownerReview: 'not recorded by this dashboard',
      protection: 'not installed by this dashboard',
      enforcement: 'requires a completely mediated Gate with durable state, pinned roots, and credential custody',
      evidence: 'available only after the corresponding local or production procedure completes',
    },
  };
}

function inertJson(value) {
  return JSON.stringify(value)
    .replaceAll('&', '\\u0026')
    .replaceAll('<', '\\u003c')
    .replaceAll('>', '\\u003e')
    .replaceAll('\u2028', '\\u2028')
    .replaceAll('\u2029', '\\u2029');
}

const EMILIA_WORDMARK_DATA_URI = 'data:image/png;base64,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Smo/3Le0tPTigRh/OvrEzYcx/bnvf8PNuouvEHeG5T8n5xdlEvrwiehIdiws+Is90+9/t79aOdvtsWW2CkSRxdqq9b+5yG76tZ0ObnbssjqbaHESY+wyit9HMzNfsf3+2X7mH8d8rp+7j7ViZmZ+hF4PE9BQ+p8/W+v97Wqn9nDQa0qsiQy63e4Tw4+7ieL3mUR/iMFgS+bX5X9PKlKpFOF9ezT+tc32ek+u1mpnBz/K5L23x0bFXG+sbWz285hayXslUv1F8p1pfa/EAwET3YzBoBXeJ0xlW+Of55rIs5G1Yf3h0HtBo+ifGfqa7dp3Op3v1Ov1syqafyI+NPPj4JaIiIiIiKbPpMX7yK5d28PiuxYAbHd/LmCH+ztlpVO0snI0ozjklcaJTopRHVwbTGhYTqgivW836j0wae/tSXxfUbE+X6N4P0zrtWC7sbmiET7WpPXfRERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERESEHP4/YFwjJlyy61UAAAAASUVORK5CYII=';

export function renderAuthorityBrain(report, options) {
  const model = buildModel(report, options);
  const data = inertJson(model);
  const scriptNonce = randomUUID().replaceAll('-', '');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${scriptNonce}'; img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'">
  <meta name="color-scheme" content="light">
  <title>EMILIA Authority Brain — Local Authority Map</title>
  <style>
    :root{--ink:#0c0a09;--muted:#57534e;--dim:#8a817a;--canvas:#f4f3ef;--paper:#fff;--panel:#fafaf9;--panel-2:#f0eee8;--line:#e7e5e4;--line-strong:#d6d3d1;--gold:#b08d35;--gold-soft:#f4eedc;--blue:#315f77;--amber:#8a5a00;--red:#a63c35;--green:#2f6b48;--radius:8px;font-family:"IBM Plex Sans","Helvetica Neue",Arial,sans-serif;color:var(--ink);background:var(--canvas)}
    *{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-width:320px;min-height:100vh;background:var(--canvas);line-height:1.5}
    button{font:inherit}button:focus-visible,a:focus-visible{outline:2px solid var(--gold);outline-offset:3px}.skip{position:fixed;z-index:50;top:12px;left:12px;padding:10px 14px;color:var(--paper);background:var(--ink);border-radius:4px;transform:translateY(-180%)}.skip:focus{transform:none}
    .shell{width:min(1360px,100%);margin:auto;padding:0 clamp(18px,4vw,52px) 48px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:24px;min-height:72px;border-bottom:1px solid var(--line-strong)}
    .brand{display:flex;align-items:center;gap:16px;min-width:0}.wordmark{display:block;width:126px;height:auto}.product-name{padding-left:16px;border-left:1px solid var(--line-strong);color:var(--muted);font:600 .78rem/1.2 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.04em}
    .local-pill{display:flex;align-items:center;gap:8px;color:var(--muted);font:600 .65rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.05em;text-transform:uppercase}.local-pill:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--green)}
    .hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(240px,310px);gap:64px;align-items:end;padding:54px 0 34px}.eyebrow{color:var(--gold);font:600 .68rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.12em;text-transform:uppercase}h1{margin:14px 0 13px;font-size:clamp(2.8rem,5vw,5.1rem);font-weight:650;letter-spacing:-.055em;line-height:.96}.lede{max-width:720px;margin:0;color:var(--muted);font-size:clamp(1rem,1.35vw,1.16rem)}.canonical{margin:18px 0 0;color:var(--ink);font-size:.86rem}.hero-note{display:grid;grid-template-columns:1fr auto;gap:7px 20px;padding:4px 0 5px 21px;border-left:3px solid var(--gold)}.hero-note>span{color:var(--dim);font:600 .62rem/1.3 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase}.hero-note>strong{grid-row:1/3;grid-column:2;font:650 2.1rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}.hero-note p{margin:0;color:var(--muted);font-size:.75rem}
    .summary{display:grid;grid-template-columns:repeat(4,1fr);margin-bottom:18px;border:1px solid var(--line-strong);border-radius:var(--radius);overflow:hidden;background:var(--paper)}.metric{padding:18px 20px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric-label{color:var(--muted);font-size:.72rem}.metric-value{display:block;margin-top:5px;font:650 1.8rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:-.04em}.metric:first-child .metric-value{color:var(--gold)}
    .flow{display:grid;grid-template-columns:repeat(4,1fr);margin:0 0 18px;border:1px solid var(--line-strong);border-radius:var(--radius);overflow:hidden;background:var(--paper)}.phase{position:relative;min-height:105px;padding:17px 19px 18px;border-right:1px solid var(--line)}.phase:last-child{border:0}.phase-no{display:block;margin-bottom:15px;color:var(--dim);font:600 .6rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em}.phase strong{display:block;margin-bottom:3px;font-size:.9rem}.phase p{margin:0;color:var(--muted);font-size:.72rem}.phase-state{position:absolute;top:17px;right:18px;width:18px;height:2px;background:var(--line-strong)}.phase.done .phase-state{background:var(--gold)}.phase.current{box-shadow:inset 0 -3px var(--ink)}.phase.current .phase-state{background:var(--ink)}
    .workspace{display:grid;grid-template-columns:minmax(300px,.68fr) minmax(0,1.32fr);min-height:650px;border:1px solid var(--line-strong);border-radius:var(--radius);overflow:hidden;background:var(--paper)}.map-panel{border-right:1px solid var(--line-strong);background:var(--panel)}.panel-head{padding:22px;border-bottom:1px solid var(--line)}.kicker{color:var(--gold);font:600 .62rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.1em;text-transform:uppercase}.panel-head h2,.detail h2{margin:8px 0 4px;font-size:1.32rem;letter-spacing:-.025em}.panel-head p{margin:0;color:var(--muted);font-size:.78rem}.filters{display:flex;gap:6px;margin-top:16px;flex-wrap:wrap}.filter{padding:7px 10px;border:1px solid var(--line-strong);border-radius:4px;color:var(--muted);background:var(--paper);font-size:.67rem;cursor:pointer}.filter:hover,.filter[aria-pressed="true"]{color:var(--paper);border-color:var(--ink);background:var(--ink)}
    .action-list{display:grid;max-height:610px;overflow:auto}.action{width:100%;padding:16px 20px;border:0;border-bottom:1px solid var(--line);color:inherit;background:transparent;text-align:left;cursor:pointer;transition:background .12s ease}.action:hover{background:var(--panel-2)}.action[aria-current="true"]{background:var(--paper);box-shadow:inset 3px 0 var(--gold)}.action-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.action-name{min-width:0;font:600 .8rem/1.35 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.badge{flex:none;padding:4px 6px;border:1px solid var(--line-strong);border-radius:4px;color:var(--muted);background:var(--paper);font:600 .54rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:uppercase}.badge.gate{color:var(--red);border-color:#d9aaa6;background:#fff8f7}.badge.review_fail_closed,.badge.review{color:var(--amber);border-color:#d8c39b;background:#fffaf0}.badge.pass_through{color:var(--green);border-color:#aec8b8;background:#f5faf7}.action-reason{display:-webkit-box;margin-top:7px;color:var(--muted);font-size:.69rem;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
    .detail{padding:clamp(24px,4vw,42px);overflow:hidden}.detail-top{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}.source-chip{padding:6px 8px;border:1px solid var(--line-strong);border-radius:4px;color:var(--muted);background:var(--panel);font:600 .6rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:uppercase}.description{max-width:760px;margin:14px 0 25px;color:var(--muted)}.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));border:1px solid var(--line-strong);border-radius:var(--radius);overflow:hidden}.fact{min-height:92px;padding:15px;background:var(--paper);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.fact:nth-child(even){border-right:0}.fact:nth-last-child(-n+2){border-bottom:0}.fact:last-child{border-right:0}.fact dt{margin-bottom:8px;color:var(--dim);font:600 .59rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase}.fact dd{margin:0;color:var(--ink);font-size:.82rem;overflow-wrap:anywhere}.tokens{display:flex;flex-wrap:wrap;gap:6px}.token{padding:5px 7px;border:1px solid var(--line-strong);border-radius:4px;color:var(--muted);background:var(--panel);font:600 .62rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
    .claim{margin-top:22px;padding:14px 16px;border-left:3px solid var(--gold);background:var(--gold-soft);color:var(--muted);font-size:.77rem}.claim strong{display:block;margin-bottom:3px;color:var(--ink)}.commands{margin-top:22px;padding:20px;border-radius:var(--radius);background:#1c1917;color:#fafaf9}.commands h3{margin:0 0 5px;font-size:.9rem}.commands>p{margin:0 0 17px;color:#a8a29e;font-size:.72rem}.command-block{margin-top:12px}.command-label{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:7px;color:#a8a29e;font:600 .57rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.09em;text-transform:uppercase}.copy{padding:5px 8px;border:1px solid #57534e;border-radius:4px;color:#fafaf9;background:transparent;font-size:.62rem;cursor:pointer}.copy:hover{border-color:#d6d3d1}code{display:block;padding:12px 14px;border:1px solid #44403c;border-radius:4px;color:#e7e5e4;background:#0c0a09;font:500 .7rem/1.55 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;overflow-wrap:anywhere}.passive{margin-top:22px;padding:17px;border:1px solid #b6cbd6;border-radius:var(--radius);background:#f5f9fb}.passive strong{color:var(--blue)}.passive p{margin:6px 0 0;color:var(--muted);font-size:.78rem}
    .lower{display:grid;grid-template-columns:1.15fr .85fr;gap:14px;margin-top:14px}.lower-card{padding:23px;border:1px solid var(--line-strong);border-radius:var(--radius);background:var(--paper)}.lower-card h2{margin:7px 0 15px;font-size:1.05rem}.blind-list{display:grid;gap:10px;margin:0;padding:0;list-style:none}.blind-list li{position:relative;padding-left:18px;color:var(--muted);font-size:.77rem}.blind-list li:before{content:"";position:absolute;top:.55em;left:0;width:6px;height:6px;background:var(--gold)}.state-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.state{padding:11px;border:1px solid var(--line);border-radius:4px;background:var(--panel)}.state strong{display:block;font:600 .63rem/1 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:uppercase}.state p{margin:7px 0 0;color:var(--muted);font-size:.67rem}.state.active{border-color:#cfbd89;background:var(--gold-soft)}.state.active strong{color:var(--ink)}
    footer{display:flex;justify-content:space-between;gap:24px;margin-top:28px;padding-top:20px;border-top:1px solid var(--line-strong);color:var(--dim);font-size:.67rem}footer strong{color:var(--ink)}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
    @media(max-width:900px){.hero{grid-template-columns:1fr;gap:28px}.hero-note{max-width:360px}.flow,.summary{grid-template-columns:repeat(2,1fr)}.metric:nth-child(2),.phase:nth-child(2){border-right:0}.metric:nth-child(-n+2),.phase:nth-child(-n+2){border-bottom:1px solid var(--line)}.workspace{grid-template-columns:1fr}.map-panel{border-right:0;border-bottom:1px solid var(--line-strong)}.action-list{max-height:350px}.lower{grid-template-columns:1fr}}
    @media(max-width:560px){.shell{padding-inline:14px}.topbar{align-items:flex-start;padding:15px 0}.wordmark{width:110px}.product-name{font-size:.68rem;padding-left:10px}.local-pill{max-width:130px;justify-content:flex-end;text-align:right;font-size:.54rem;line-height:1.35}.hero{padding-top:40px}h1{font-size:2.8rem}.flow,.summary,.facts,.state-grid{grid-template-columns:1fr}.metric,.phase{border-right:0;border-bottom:1px solid var(--line)}.metric:last-child,.phase:last-child{border-bottom:0}.detail{padding:22px 17px}.detail-top,footer{flex-direction:column}.hero-note{grid-template-columns:1fr auto}.fact{border-right:0}.fact:nth-last-child(-n+2){border-bottom:1px solid var(--line)}.fact:last-child{border-bottom:0}}
    @media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to Authority Map</a>
  <div class="shell">
    <header class="topbar">
      <div class="brand"><img class="wordmark" src="${EMILIA_WORDMARK_DATA_URI}" alt="EMILIA"><span class="product-name">Authority Brain</span></div>
      <div class="local-pill">Local report · stays on this device</div>
    </header>
    <main id="main">
      <section class="hero" aria-labelledby="page-title">
        <div>
          <div class="eyebrow">Local Authority Map / declared surfaces</div>
          <h1 id="page-title">Authority Map</h1>
          <p class="lede">See the consequential actions this scanner can identify, review the proposed authority boundary, and name what the scan cannot establish.</p>
          <p class="canonical"><strong>The scanner proposes. The owner reviews. Gate enforces.</strong></p>
        </div>
        <aside class="hero-note" aria-label="Current dashboard state">
          <span>Current state</span><strong id="core-count">0</strong>
          <p>visible actions · scanner proposal only</p>
        </aside>
      </section>

      <section class="summary" aria-label="Scan summary">
        <div class="metric"><span class="metric-label">Visible actions</span><strong class="metric-value" id="metric-total">0</strong></div>
        <div class="metric"><span class="metric-label">Consequential candidates</span><strong class="metric-value" id="metric-candidates">0</strong></div>
        <div class="metric"><span class="metric-label">Review required</span><strong class="metric-value" id="metric-review">0</strong></div>
        <div class="metric"><span class="metric-label">Pass-through proposals</span><strong class="metric-value" id="metric-pass">0</strong></div>
      </section>

      <section class="flow" aria-label="Authority Brain operating loop">
        <div class="phase done"><span class="phase-state"></span><span class="phase-no">01 / VISIBLE</span><strong>Discover</strong><p>Enumerate declared action surfaces the scanner can actually see.</p></div>
        <div class="phase current"><span class="phase-state"></span><span class="phase-no">02 / PROPOSAL</span><strong>Map</strong><p>Review the Authority Map's dispositions, material fields, confidence, and blind spots.</p></div>
        <div class="phase"><span class="phase-state"></span><span class="phase-no">03 / OWNER ACTION</span><strong>Protect</strong><p>Generate, review, and install Gate for one action at the credential-owning boundary.</p></div>
        <div class="phase"><span class="phase-state"></span><span class="phase-no">04 / AFTER TEST</span><strong>Prove</strong><p>Preserve factual evidence after the corresponding procedure completes.</p></div>
      </section>

      <section class="workspace" aria-label="Authority Map workspace">
        <aside class="map-panel" aria-labelledby="map-title">
          <div class="panel-head">
            <span class="kicker" id="source-type">Declared source</span>
            <h2 id="map-title">Authority Map</h2>
            <p>Select an action to inspect the scanner's proposal.</p>
            <div class="filters" aria-label="Filter visible actions">
              <button class="filter" type="button" data-filter="all" aria-pressed="true">All</button>
              <button class="filter" type="button" data-filter="requires" aria-pressed="false">Receipt proposed</button>
              <button class="filter" type="button" data-filter="pass" aria-pressed="false">Pass-through</button>
            </div>
          </div>
          <div class="action-list" id="action-list" aria-label="Visible actions"></div>
        </aside>
        <article class="detail" aria-labelledby="detail-title">
          <div class="detail-top"><div><span class="kicker">Selected action</span><h2 id="detail-title">—</h2></div><span class="source-chip" id="detail-source">—</span></div>
          <p class="description" id="detail-description">Select a visible action.</p>
          <dl class="facts">
            <div class="fact"><dt>Disposition</dt><dd id="detail-decision">—</dd></div>
            <div class="fact"><dt>Confidence</dt><dd id="detail-confidence">—</dd></div>
            <div class="fact"><dt>Reason</dt><dd id="detail-reason">—</dd></div>
            <div class="fact"><dt>Category / assurance</dt><dd id="detail-category">—</dd></div>
            <div class="fact"><dt>Authority source</dt><dd id="detail-authority">—</dd></div>
            <div class="fact"><dt>Provenance</dt><dd id="detail-provenance">—</dd></div>
            <div class="fact" style="grid-column:1/-1"><dt>Material fields proposed for binding</dt><dd class="tokens" id="detail-fields"></dd></div>
          </dl>
          <div class="claim"><strong>Scan proposes. It does not protect.</strong> Nothing is enforced by this dashboard. The owner must review the proposal and install Gate on a completely mediated path.</div>
          <div id="action-path"></div>
          <p class="sr-only" id="copy-status" aria-live="polite"></p>
        </article>
      </section>

      <section class="lower">
        <article class="lower-card"><span class="kicker">Coverage boundary</span><h2>What this scan could not see</h2><ul class="blind-list" id="blind-list"></ul></article>
        <article class="lower-card"><span class="kicker">State discipline</span><h2>Do not collapse the states</h2><div class="state-grid">
          <div class="state active"><strong>Proposal</strong><p>Scanner output awaiting owner review.</p></div>
          <div class="state"><strong>Owner-reviewed</strong><p>Classification confirmed outside this dashboard.</p></div>
          <div class="state"><strong>Protected candidate</strong><p>Generated scaffold reviewed; mediation still must be verified.</p></div>
          <div class="state"><strong>Enforced</strong><p>Only a completely mediated Gate with required runtime controls.</p></div>
        </div></article>
      </section>
    </main>
    <footer><span><strong>Protocol proves. Gate prevents.</strong></span><span>Customer-controlled authority, credentials, trust roots, policy, and evidence.</span></footer>
  </div>
  <script id="authority-brain-data" type="application/json" nonce="${scriptNonce}">${data}</script>
  <script nonce="${scriptNonce}">
    (() => {
      'use strict';
      const model = JSON.parse(document.getElementById('authority-brain-data').textContent);
      const byId = (id) => document.getElementById(id);
      const decisionLabel = {
        gate: 'require receipt',
        review_fail_closed: 'review · fail-closed proposal',
        pass_through: 'pass-through proposal',
        review: 'owner review required'
      };
      const sourceLabel = { mcp: 'MCP declared surface', openapi: 'OpenAPI declared surface', list: 'Declared action list' };
      let selectedIndex = 0;
      let activeFilter = 'all';

      byId('core-count').textContent = String(model.counts.total);
      byId('metric-total').textContent = String(model.counts.total);
      byId('metric-candidates').textContent = String(model.counts.gate + model.counts.review_fail_closed);
      byId('metric-review').textContent = String(model.counts.review_fail_closed + model.counts.review);
      byId('metric-pass').textContent = String(model.counts.pass_through);
      byId('source-type').textContent = sourceLabel[model.source] || model.source;

      function element(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
      }

      function visible(action) {
        if (activeFilter === 'requires') return action.receiptRequired;
        if (activeFilter === 'pass') return !action.receiptRequired;
        return true;
      }

      function renderList() {
        const list = byId('action-list');
        list.replaceChildren();
        model.actions.forEach((action, index) => {
          if (!visible(action)) return;
          const button = element('button', 'action');
          button.type = 'button';
          button.setAttribute('aria-current', String(index === selectedIndex));
          button.addEventListener('click', () => { selectedIndex = index; renderList(); renderDetail(); });
          const row = element('span', 'action-row');
          row.append(element('span', 'action-name', action.name));
          row.append(element('span', 'badge ' + action.decision, decisionLabel[action.decision] || action.decision));
          button.append(row, element('span', 'action-reason', action.reason));
          list.append(button);
        });
      }

      function selectCommand(codeNode) {
        try {
          const selection = window.getSelection();
          const range = document.createRange();
          range.selectNodeContents(codeNode);
          selection.removeAllRanges();
          selection.addRange(range);
          codeNode.focus();
          return true;
        } catch (_) {
          return false;
        }
      }

      async function copy(text, button, codeNode) {
        let copied = false;
        try {
          if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            await navigator.clipboard.writeText(text);
            copied = true;
          }
        } catch (_) {}
        if (!copied) {
          let area;
          try {
            area = document.createElement('textarea');
            area.value = text;
            area.setAttribute('readonly', '');
            area.style.position = 'fixed';
            area.style.opacity = '0';
            document.body.append(area);
            area.select();
            copied = typeof document.execCommand === 'function' && document.execCommand('copy');
          } catch (_) {
          } finally {
            if (area) area.remove();
          }
        }
        const selected = !copied && selectCommand(codeNode);
        button.textContent = copied ? 'Copied' : selected ? 'Selected' : 'Copy unavailable';
        byId('copy-status').textContent = copied
          ? 'Command copied.'
          : selected ? 'Copy was unavailable; the command is selected.' : 'Copy and selection were unavailable.';
        setTimeout(() => { button.textContent = 'Copy'; }, 1600);
      }

      function commandBlock(label, command) {
        const block = element('div', 'command-block');
        const head = element('div', 'command-label');
        head.append(element('span', '', label));
        const button = element('button', 'copy', 'Copy');
        button.type = 'button';
        const codeNode = element('code', '', command);
        codeNode.tabIndex = 0;
        button.addEventListener('click', () => copy(command, button, codeNode));
        head.append(button);
        block.append(head, codeNode);
        return block;
      }

      function renderDetail() {
        const action = model.actions[selectedIndex];
        if (!action) return;
        byId('detail-title').textContent = action.name;
        byId('detail-source').textContent = action.sourceDetail;
        byId('detail-description').textContent = action.description || 'No description was declared.';
        byId('detail-decision').textContent = decisionLabel[action.decision] || action.decision;
        byId('detail-confidence').textContent = action.confidence;
        byId('detail-reason').textContent = action.reason;
        byId('detail-category').textContent = [action.category || 'unclassified', action.assuranceClass || 'no assurance class proposed'].join(' · ');
        byId('detail-authority').textContent = action.authoritySource;
        byId('detail-provenance').textContent = action.provenance;
        const fields = byId('detail-fields');
        fields.replaceChildren();
        (action.materialFields.length ? action.materialFields : ['none proposed']).forEach((field) => fields.append(element('span', 'token', field)));
        const path = byId('action-path');
        path.replaceChildren();
        if (model.source === 'openapi') {
          const passive = element('div', 'passive');
          passive.append(element('strong', '', 'OpenAPI is passive-only until the durable admission edge is wired.'));
          passive.append(element('p', '', 'This map can inform review, but it does not generate a verification-only HTTP middleware or claim one-use enforcement.'));
          path.append(passive);
        } else if (action.starterReviewPending) {
          const pending = element('div', 'passive');
          pending.append(element('strong', '', 'Review-pending in this Gate Starter.'));
          pending.append(element('p', '', 'This action is refused by the generated wrapper. Return to a fresh scan and choose a different direct-child --out directory before creating a separately reviewed Gate Starter for it. Do not overwrite this starter with --force.'));
          path.append(pending);
        } else if (action.protectCommand || action.handoffCommand || action.handoffLimitation) {
          const commands = element('div', 'commands');
          commands.append(element('h3', '', action.starterSelectedAction ? 'Finish the reviewed handoff' : 'Protect this action'));
          if (action.protectCommand) {
            commands.append(element('p', '', 'The first command creates one selected-action Gate Starter and runs its synthetic local check. It emits no reviewed handoff. Read the generated map and manifest before running the second command. Neither command installs production enforcement.'));
            commands.append(commandBlock('1 · Create Gate Starter + run RR-1', action.protectCommand));
          }
          if (action.handoffCommand) {
            if (action.starterSelectedAction) {
              commands.append(element('p', '', 'This starter is already generated for this action. After reading this map and the manifest, the command below revalidates the unchanged bytes, reruns RR-1, and emits the reviewed handoff without overwriting the starter.'));
            }
            commands.append(commandBlock(action.starterSelectedAction
              ? 'After review · Bind current bytes into the handoff'
              : '2 · After review, bind current bytes into the handoff', action.handoffCommand));
          } else if (action.handoffLimitation) {
            const limitation = element('div', 'passive');
            limitation.append(element('strong', '', 'Reviewed handoff unavailable for this declared name.'));
            limitation.append(element('p', '', action.handoffLimitation));
            commands.append(limitation);
          }
          path.append(commands);
        } else {
          const passive = element('div', 'passive');
          passive.append(element('strong', '', 'No receipt requirement is proposed for this action.'));
          passive.append(element('p', '', 'Confirm the handler is actually read-only. A presenter-supplied hint is not policy.'));
          path.append(passive);
        }
      }

      document.querySelectorAll('.filter').forEach((button) => {
        button.addEventListener('click', () => {
          activeFilter = button.dataset.filter;
          document.querySelectorAll('.filter').forEach((candidate) => candidate.setAttribute('aria-pressed', String(candidate === button)));
          const next = model.actions.findIndex(visible);
          if (next >= 0 && !visible(model.actions[selectedIndex])) selectedIndex = next;
          renderList();
          renderDetail();
        });
      });

      const blindList = byId('blind-list');
      model.blindSpots.forEach((blindSpot) => blindList.append(element('li', '', blindSpot)));
      renderList();
      renderDetail();
    })();
  </script>
</body>
</html>
`;
}

function lstatIfPresent(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function fsyncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EBADF'].includes(error.code)) throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function directChildTarget(cwd, outPath) {
  if (typeof outPath !== 'string' || !outPath || outPath.includes('\0')) {
    throw new TypeError('Authority Brain output must be a non-empty direct-child output file.');
  }
  if (SOURCE_CONFUSING_COMMAND.test(outPath)) {
    throw new TypeError('Authority Brain output refuses source-confusing characters.');
  }
  const directory = path.resolve(cwd);
  const target = path.resolve(directory, outPath);
  const relative = path.relative(directory, target);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)
      || relative.split(path.sep).filter(Boolean).length !== 1) {
    throw new Error('Refusing Authority Brain output outside one direct-child output file.');
  }
  if (path.extname(relative) !== '.html') {
    throw new Error('Authority Brain output must use the .html extension.');
  }
  return { directory, target, relative };
}

function validateExistingOutput(stat, target, force) {
  if (!stat) return;
  if (stat.isSymbolicLink()) throw new Error(`Refusing symlinked output file: ${target}`);
  if (!stat.isFile()) throw new Error(`Refusing non-regular output file: ${target}`);
  if (stat.nlink > 1) throw new Error(`Refusing hard-linked output file: ${target}`);
  if (!force) throw new Error(`Refusing to overwrite existing Authority Brain dashboard: ${target}`);
}

export function writeAuthorityBrain(html, {
  cwd = process.cwd(),
  outPath = DEFAULT_BRAIN_OUTPUT,
  force = false,
} = {}) {
  if (typeof html !== 'string') throw new TypeError('Authority Brain HTML must be a string.');
  if (typeof force !== 'boolean') throw new TypeError('Authority Brain force must be a boolean.');
  const { directory, target, relative } = directChildTarget(cwd, outPath);
  const directoryStat = fs.lstatSync(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error(`Refusing non-directory Authority Brain working directory: ${directory}`);
  }
  const existing = lstatIfPresent(target);
  validateExistingOutput(existing, target, force);

  const stage = path.join(directory, `.${path.basename(relative)}.stage-${process.pid}-${randomUUID()}`);
  const backup = path.join(directory, `.${path.basename(relative)}.backup-${process.pid}-${randomUUID()}`);
  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;
  let fd;
  let backupInstalled = false;
  let targetInstalled = false;
  try {
    fd = fs.openSync(stage, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow, 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, html, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;

    if (existing) {
      const current = fs.lstatSync(target);
      validateExistingOutput(current, target, true);
      if (!sameIdentity(existing, current)) {
        throw new Error(`Refusing output changed during Authority Brain replacement: ${target}`);
      }
      fs.renameSync(target, backup);
      backupInstalled = true;
      const moved = fs.lstatSync(backup);
      if (!sameIdentity(existing, moved)) {
        throw new Error(`Refusing output changed during Authority Brain replacement: ${target}`);
      }
      fsyncDirectory(directory);
      try {
        fs.linkSync(stage, target);
      } catch (error) {
        if (error.code === 'EEXIST') {
          throw new Error(`Refusing output created during Authority Brain replacement. Original preserved at: ${backup}`);
        }
        throw error;
      }
      targetInstalled = true;
      fs.unlinkSync(stage);
      fsyncDirectory(directory);
      fs.unlinkSync(backup);
      backupInstalled = false;
    } else {
      fs.linkSync(stage, target);
      targetInstalled = true;
      fs.unlinkSync(stage);
      fsyncDirectory(directory);
    }
    return target;
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    if (backupInstalled && !lstatIfPresent(target)) {
      try {
        fs.linkSync(backup, target);
        fs.unlinkSync(backup);
        backupInstalled = false;
        fsyncDirectory(directory);
      } catch (restoreError) {
        if (restoreError.code !== 'EEXIST') throw restoreError;
      }
    }
    throw error;
  } finally {
    try { fs.unlinkSync(stage); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (backupInstalled && targetInstalled) {
      try { fs.unlinkSync(backup); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
}
