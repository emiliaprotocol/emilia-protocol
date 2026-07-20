/**
 * @emilia-protocol/fire-drill — the Agent Action Firewall Test.
 *
 * The vortex. People don't wake up wanting authorization receipts; they wake up
 * afraid of being the screenshot: "our agent deleted prod and nobody can prove
 * who approved it." This is the test they're scared to fail.
 *
 * Point it at an MCP manifest, an OpenAPI spec, or a tool list. It classifies
 * each operation into the high-risk families (money / data destruction /
 * production deploy / permission change / data export / regulated override) and
 * checks whether a dangerous one DECLARES a required receipt input. Output is a
 * static coverage score and a list of missing declarations. Static metadata
 * cannot prove runtime verification, trust anchoring, or consumption.
 *
 * This is a STATIC assessment from the manifest/spec — like SSL Labs or
 * `npm audit`. It reveals the gap; EG-1 conformance verifies the fix at runtime.
 * Zero dependencies so `npx` is instant.
 */
export declare const FIRE_DRILL_VERSION = "EP-FIRE-DRILL-v2";
type Obj = Record<string, any>;
/**
 * Classify one operation. Returns the strongest matching family (or {dangerous:false}).
 * @returns {{ dangerous: boolean, family?: string, label?: string, tier?: string, adapter?: string, why?: string }}
 */
export declare function classifyOperation({ name, description, method, path }?: Obj): Obj;
/**
 * Detect a structural declaration that receipt evidence is required.
 * This does NOT detect or certify runtime enforcement.
 * @param {object} [op]
 * @param {any} [raw] the original MCP tool / OpenAPI operation object, shape unknown until narrowed below
 */
export declare function detectReceiptGate(op?: Obj, raw?: any): boolean;
export declare function scanMcpManifest(manifest?: Obj): Obj;
export declare function scanOpenApi(spec?: Obj): Obj;
export declare function scanToolList(list?: Obj[]): Obj;
/** Auto-detect the input shape and scan. */
export declare function scan(input: Obj): Obj;
export declare function buildReport(operations: Obj[], targetType?: string): Obj;
export declare const TAGLINE = "Static declarations locate review targets; only runtime conformance can establish enforcement.";
/**
 * A shields-style badge for static declaration coverage. It is deliberately
 * never green and never says EG-1 Enforced; this scanner cannot prove runtime.
 * @param {object} o
 * @param {number} [o.score] 0..100
 * @param {string} [o.label='receipt declarations']
 */
export declare function badgeSvg({ score, label }?: Obj): string;
/**
 * Aggregate static declaration reports. The caller owns corpus selection and
 * this output makes no claim about runtime enforcement.
 * @param {object[]} reports  buildReport() results
 */
export declare function aggregate(reports?: Obj[]): Obj;
/**
 * Turn a report into a ready-to-open pull request (title + Markdown body) that
 * tells a maintainer which dangerous tools lack a required evidence declaration.
 * @param {object} report  a buildReport() result
 * @param {object} [o]
 * @param {string} [o.project] project/repo name for the title
 */
export declare function generatePullRequest(report: Obj, { project }?: Obj): Obj;
declare const _default: {
    FIRE_DRILL_VERSION: string;
    TAGLINE: string;
    classifyOperation: typeof classifyOperation;
    detectReceiptGate: typeof detectReceiptGate;
    buildReport: typeof buildReport;
    scan: typeof scan;
    scanMcpManifest: typeof scanMcpManifest;
    scanOpenApi: typeof scanOpenApi;
    scanToolList: typeof scanToolList;
    badgeSvg: typeof badgeSvg;
    generatePullRequest: typeof generatePullRequest;
    aggregate: typeof aggregate;
};
export default _default;
//# sourceMappingURL=index.d.ts.map