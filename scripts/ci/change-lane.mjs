#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * CI change-lane classifier.
 *
 * Decides whether a pull request may take the prose fast lane in
 * .github/workflows/ci.yml. The answer is `docs` only when every changed path
 * is prose (docs/, standards/ or papers/ prose files, or a root *.md) AND no
 * source that a docs-lane-skipped job executes or reads names a changed path
 * or one of its directories. Everything else, including any classifier
 * error, is `full`.
 *
 * The fast lane never skips a job that reads prose: `test` (dozens of suites
 * read docs/ and standards/), `build`, `e2e` and `docker-build` (the app
 * imports standards/STATUS.json and reads standards/posted/*.xml), and the
 * language, claim, proof-stat, preprint, observatory, docs-secrets and
 * docs-consistency checks all still run. It skips only the jobs whose `if:`
 * carries SKIP_CONDITION, and it derives that set from ci.yml at run time.
 * Pushes to main and merge groups always run the full lane.
 *
 * In CI this file is never taken from the pull request: the `changes` job in
 * ci.yml runs the copy (and self-test) from the base commit, and sends any
 * pull request that touches .github/ or scripts/ci/ to the full lane before
 * a classifier runs at all. A change to the classifier is therefore
 * classified by the previous classifier, which cannot be edited to pass
 * itself.
 *
 * Usage (CI, from a copy of the base commit's file):
 *   node "$RUNNER_TEMP/lane/change-lane.mjs" --event pull_request --github-output <file>
 * Usage (local):
 *   node scripts/ci/change-lane.mjs --event local --base origin/main --head HEAD
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const DOCS_LANE = 'docs';
export const FULL_LANE = 'full';

/**
 * The exact job-level condition that marks a ci.yml job as docs-lane-skipped.
 * It names the event as well as the lane, so a job is skipped only on a
 * pull_request run: pushes, merge groups and manual runs execute it whatever
 * the `changes` job reports.
 */
export const SKIP_CONDITION = "(github.event_name != 'pull_request' || needs.changes.outputs.lane != 'docs')";

/** Directories whose prose files are docs-lane candidates. */
export const DOCS_ROOTS = ['docs/', 'standards/', 'papers/'];

/**
 * Extensions treated as prose inside DOCS_ROOTS. JSON, YAML, scripts and
 * anything else stay in the full lane: standards/STATUS.json,
 * docs/ai/context-source.v1.json and docs/api/*.yaml are all read by code, and
 * standards/ ships executable .mjs/.ts self-tests.
 */
export const DOC_EXTENSIONS = new Set([
  'md', 'txt', 'xml', 'html', 'pdf', 'tex', 'bib',
  'png', 'svg', 'gif', 'jpg', 'jpeg', 'webp', 'docx',
]);

/** Extensionless prose files (Internet-Draft packet checksums). */
export const DOC_BASENAMES = new Set(['SHA256SUMS']);

/** Root-level markdown that is generated evidence, never hand-written prose. */
export const GENERATED_ROOT_PROSE = new Set(['AI_CONTEXT.md']);

/**
 * scripts/ checkers whose job is to read prose (standards packets, public
 * claims, conformance doc counts, artifact lifecycle tags, language, LLM
 * context, proof statistics, observatory, docs secrets). They run in jobs the docs lane keeps, so their references to
 * docs/ and standards/ are exercised on every docs-lane run and do not bind a
 * path to the full lane. `reachableKeptCheckers` re-proves on every run that
 * no docs-lane-skipped job reaches one of them; if one does, the lane is full.
 */
export const KEPT_CHECKER =
  /^scripts\/(?:check-(?:ae-challenge-\d+|authorization-receipts-\d+|bounded-capability-\d+|caid-\d+|model-to-matter-\d+|grace-[a-z0-9-]+|emergency-authority-freeze-drafts|standards-staged|artifact-lifecycle|authority-claims|conformance-doc-counts|docs-secrets|language-governance|preprint-sync|public-conformance-claims|repository-boundary)|build-standards-observatory|generate-llm-context|generate-proof-stats|gov-readiness-check)\.(?:mjs|mts|js|ts)$/;

/**
 * Tracked trees whose consumers are jobs the docs lane keeps: the vitest
 * suite and the node:test suites named in the `test` job, the Next.js app
 * (`build`, `e2e`, `docker-build`, `typecheck-app`, `lint`), the Playwright
 * specs, the gitleaks configuration (`secret-scan`), and this classifier and
 * the evidence autopilot tool (the `changes` job, `test`, and the autopilot
 * workflows, none of which the docs lane skips). Workflows other than
 * ci.yml are separate pipelines that this lane does not change. Postgres and
 * benchmark suites under tests/ run only in skipped jobs and stay audited.
 */
const KEPT_PREFIXES = [
  'app/', 'components/', 'e2e/', 'public/', 'content/', '.github/', 'scripts/ci/',
  'integrations/github-authority-map-action/tests/',
  'integrations/github-merge-gate-action/tests/',
];
const KEPT_FILES = new Set(['.gitleaks.toml']);
const TESTS_ONLY_IN_SKIPPED_JOBS = /(postgres|benchmark)/i;
const CI_WORKFLOW = '.github/workflows/ci.yml';

/** Source-like files whose text can name a path a job later opens. */
const AUDITED_EXTENSIONS = new Set([
  'js', 'mjs', 'cjs', 'ts', 'mts', 'cts', 'tsx', 'jsx',
  'py', 'go', 'rs', 'java', 'rb', 'sh', 'bash',
  'json', 'yml', 'yaml', 'toml', 'tla', 'cfg', 'sql',
]);
const AUDITED_BASENAME = /^(Dockerfile(\..+)?|Makefile|\.dockerignore)$/;
const CODE_EXTENSIONS = new Set(['js', 'mjs', 'cjs', 'ts', 'mts', 'cts', 'tsx', 'jsx', 'py', 'go', 'rs', 'java', 'rb']);
const SHELL_BASENAME = /^(Dockerfile(\..+)?|Makefile|.+\.(sh|bash))$/;

const TOP_LEVEL = '(docs|standards|papers)';
const SEGMENT = '[A-Za-z0-9_.@+-]+';

/**
 * Every segment of a docs-lane candidate must be made of these characters.
 * Reference extraction can only see paths spelled with them, and tree parsers
 * elsewhere in CI (verify-reproducible-package.mjs reads `git ls-tree` line
 * by line) reject line terminators, so a path with a newline, carriage
 * return, U+2028, a space or any non-ASCII character always runs the full
 * lane.
 */
export const PATH_SEGMENT = new RegExp(`^${SEGMENT}$`);

/**
 * @param {string} path
 * @returns {string}
 */
function extensionOf(path) {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

/**
 * @param {string} path
 * @returns {boolean}
 */
export function isDocsCandidate(path) {
  if (typeof path !== 'string' || path.length === 0) return false;
  const parts = path.split('/');
  if (parts.some((part) => part === '..' || part === '.' || !PATH_SEGMENT.test(part))) {
    return false;
  }
  if (!path.includes('/')) {
    return /^[A-Za-z0-9_.-]+\.md$/.test(path) && !GENERATED_ROOT_PROSE.has(path);
  }
  if (!DOCS_ROOTS.some((root) => path.startsWith(root))) return false;
  const base = path.slice(path.lastIndexOf('/') + 1);
  return DOC_BASENAMES.has(base) || DOC_EXTENSIONS.has(extensionOf(path));
}

/**
 * True when a tracked file is source that a docs-lane-skipped job may execute
 * or read, and therefore must not name a changed prose path. ci.yml and the
 * root package.json are audited separately, through the skipped-job closure.
 *
 * @param {string} path
 * @returns {boolean}
 */
export function isAuditedSource(path) {
  if (path === CI_WORKFLOW || path === 'package.json') return false;
  if (DOCS_ROOTS.some((root) => path.startsWith(root))) return false;
  if (KEPT_PREFIXES.some((root) => path.startsWith(root)) || KEPT_FILES.has(path)) return false;
  if (path.startsWith('tests/') && !TESTS_ONLY_IN_SKIPPED_JOBS.test(path)) return false;
  if (KEPT_CHECKER.test(path)) return false;
  if (path.startsWith('node_modules/') || path.includes('/node_modules/')) return false;
  const base = path.slice(path.lastIndexOf('/') + 1);
  return AUDITED_EXTENSIONS.has(extensionOf(path)) || AUDITED_BASENAME.test(base);
}

/**
 * Splits ci.yml into its top-level job blocks.
 *
 * @param {string} workflow
 * @returns {Map<string, string>}
 */
export function jobBlocks(workflow) {
  /** @type {Map<string, string>} */
  const blocks = new Map();
  const jobsAt = workflow.search(/^jobs:\s*$/m);
  if (jobsAt < 0) return blocks;
  const body = workflow.slice(jobsAt);
  const headers = [...body.matchAll(/^ {2}([A-Za-z0-9_-]+):\s*$/gm)];
  headers.forEach((header, index) => {
    const start = header.index ?? 0;
    const end = index + 1 < headers.length ? headers[index + 1].index ?? body.length : body.length;
    blocks.set(header[1], body.slice(start, end));
  });
  return blocks;
}

/**
 * The text a docs-lane-skipped job can execute: its ci.yml block, every root
 * npm script it reaches (transitively), and the scripts of every package
 * directory it enters with `working-directory:` or `npm --prefix`.
 *
 * @param {string} workflow ci.yml text
 * @param {(relativePath: string) => string | null} read repository reader
 * @returns {{ jobs: string[], text: string }}
 */
export function skippedJobClosure(workflow, read) {
  const skipped = [...jobBlocks(workflow)].filter(([, block]) => block.includes(SKIP_CONDITION));
  // The lane condition itself names 'docs'; it is not a path operand.
  const parts = skipped.map(([, block]) => block.split(SKIP_CONDITION).join(''));
  /** @type {Record<string, string>} */
  let rootScripts = {};
  try {
    rootScripts = JSON.parse(read('package.json') ?? '{}').scripts ?? {};
  } catch {
    rootScripts = {};
  }
  const seen = new Set();
  const queue = [...parts];
  while (queue.length > 0) {
    const text = queue.shift() ?? '';
    for (const match of text.matchAll(/npm run ([A-Za-z0-9:_.-]+)/g)) {
      const name = match[1];
      if (seen.has(name) || rootScripts[name] === undefined) continue;
      seen.add(name);
      parts.push(`${name}: ${rootScripts[name]}`);
      queue.push(rootScripts[name]);
    }
  }
  const directories = new Set();
  for (const block of skipped.map(([, b]) => b)) {
    for (const match of block.matchAll(/working-directory:\s*([A-Za-z0-9_./-]+)/g)) directories.add(match[1]);
    for (const match of block.matchAll(/npm --prefix\s+([A-Za-z0-9_./-]+)/g)) directories.add(match[1]);
  }
  for (const directory of directories) {
    const manifest = read(`${directory}/package.json`);
    if (manifest) parts.push(manifest);
  }
  return { jobs: skipped.map(([name]) => name), text: parts.join('\n') };
}

/**
 * KEPT_CHECKER files that a skipped job names directly, through an npm
 * script, or through a file it runs (one hop into that file's text).
 *
 * @param {string[]} tracked tracked repository paths
 * @param {string} closure skippedJobClosure(...).text
 * @param {(relativePath: string) => string | null} read
 * @returns {string[]}
 */
export function reachableKeptCheckers(tracked, closure, read) {
  const trackedSet = new Set(tracked);
  let reach = closure;
  const named = new Set();
  for (const match of closure.matchAll(/(?<![\w./-])((?:scripts|conformance|formal|examples|deploy|packages|lib|caid|fuzz|witness|interop|security|release)\/[\w./@+-]+\.(?:mjs|cjs|js|mts|cts|ts|sh|py))/g)) {
    named.add(match[1]);
  }
  for (const file of named) {
    if (!trackedSet.has(file)) continue;
    const text = read(file);
    if (text) reach += `\n${text}`;
  }
  return tracked.filter((path) => {
    if (!KEPT_CHECKER.test(path)) return false;
    const stem = path.slice('scripts/'.length).replace(/\.(mjs|mts|js|ts)$/, '');
    return new RegExp(`(?<![\\w-])${stem.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w-])`).test(reach);
  });
}

/**
 * Ancestor directories of `path`, nearest first, ending at the top-level
 * directory (empty for a root-level file).
 *
 * @param {string} path
 * @returns {string[]}
 */
export function ancestorsOf(path) {
  const parts = path.split('/');
  /** @type {string[]} */
  const directories = [];
  for (let i = parts.length - 1; i >= 1; i -= 1) {
    directories.push(parts.slice(0, i).join('/'));
  }
  return directories;
}

/**
 * Whether the text at `start` begins a filesystem-style reference rather than
 * a URL (https://host/docs), a bare route ("/docs") or the tail of a longer
 * path (apps/x/docs).
 *
 * @param {string} text
 * @param {number} start index of the first character, including any ./ or ../
 * @returns {boolean}
 */
function hasPathLeftBoundary(text, start) {
  if (start === 0) return true;
  const previous = text[start - 1];
  if (previous !== '/') return !/[A-Za-z0-9_.@$-]/.test(previous);
  const lineStart = text.lastIndexOf('\n', start - 1) + 1;
  const token = text.slice(lineStart, start).split(/[\s'"`(),[\]=]/).pop() ?? '';
  if (token.includes('://')) return false;
  // `${ROOT}/docs/x`, "$GITHUB_WORKSPACE/docs/x" and ROOT + '/docs/x' join a
  // variable root: treat them as repository paths.
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_.]*\}?\/$/.test(token)) return true;
  const beforeSlash = start >= 2 ? text[start - 2] : '';
  return beforeSlash === '}' || beforeSlash === '' || /[\s'"`(,[=+]/.test(beforeSlash);
}

/**
 * @param {string} text
 * @param {number} from
 * @param {1 | -1} step
 * @returns {string}
 */
function nonSpace(text, from, step) {
  for (let i = from; i >= 0 && i < text.length; i += step) {
    if (!/\s/.test(text[i])) return text[i];
  }
  return '';
}

/**
 * The index of the nearest unclosed '(', '[' or '{' before `index` (within
 * 400 characters), or -1. Tells join(ROOT, 'docs') apart from
 * ['docs', 'tests'] and []string{"docs"}.
 *
 * @param {string} text
 * @param {number} index
 * @returns {number}
 */
function enclosingOpenerIndex(text, index) {
  let parens = 0;
  let brackets = 0;
  let braces = 0;
  for (let i = index - 1; i >= 0 && i >= index - 400; i -= 1) {
    const c = text[i];
    if (c === ')') parens += 1;
    else if (c === ']') brackets += 1;
    else if (c === '}') braces += 1;
    else if (c === '(') {
      if (parens === 0) return i;
      parens -= 1;
    } else if (c === '[') {
      if (brackets === 0) return i;
      brackets -= 1;
    } else if (c === '{') {
      if (braces === 0) return i;
      braces -= 1;
    }
  }
  return -1;
}

/** Words after which '[' opens a list rather than indexing a value. */
const LIST_KEYWORDS = new Set(['in', 'of', 'return', 'yield', 'await', 'case', 'else', 'and', 'or', 'not', 'is', 'from', 'default']);

/**
 * Whether the '[' at `at` opens a list literal (['docs']) rather than a
 * subscript (v["docs"], rows[0]["docs"], call()["docs"]).
 *
 * @param {string} text
 * @param {number} at
 * @returns {boolean}
 */
function opensListLiteral(text, at) {
  let i = at - 1;
  while (i >= 0 && /\s/.test(text[i])) i -= 1;
  if (i < 0) return true;
  if (!/[A-Za-z0-9_$)\]]/.test(text[i])) return true;
  if (!/[A-Za-z0-9_$]/.test(text[i])) return false;
  let start = i;
  while (start > 0 && /[A-Za-z0-9_$]/.test(text[start - 1])) start -= 1;
  return LIST_KEYWORDS.has(text.slice(start, i + 1));
}

/**
 * Every prose path, directory or root *.md that `text` could make a job
 * open. A directory entry binds everything beneath it.
 *
 * @param {string} path repository path of the source (selects the rules)
 * @param {string} text
 * @param {Iterable<string>} [rootProse] root-level *.md names to look for
 * @returns {Set<string>}
 */
export function extractProseReferences(path, text, rootProse = []) {
  /** @type {Set<string>} */
  const refs = new Set();
  const base = path.slice(path.lastIndexOf('/') + 1);
  const isCode = CODE_EXTENSIONS.has(extensionOf(path));
  const isShell = SHELL_BASENAME.test(base) || path === CI_WORKFLOW;

  // 1. Slash paths: docs/x.md, 'standards/staged/', `${ROOT}/papers/${name}`,
  //    '../docs/*'. Deeper paths bind as written. A bare top-level directory
  //    binds only as a whole-directory operand ('docs/', `docs/${x}`,
  //    'docs/*'), not in prose such as "see docs/ for details".
  const slashPath = new RegExp(`((?:\\.{1,2}/)*)${TOP_LEVEL}((?:/${SEGMENT})*)(/?)`, 'g');
  for (const match of text.matchAll(slashPath)) {
    const start = match.index ?? 0;
    const [whole, , top, rest, trailing] = match;
    if (!rest && !trailing) continue;
    if (!hasPathLeftBoundary(text, start)) continue;
    if (!rest) {
      const next = text[start + whole.length] ?? '';
      if (next === '' || '$*{\'"`)'.includes(next)) refs.add(top);
      continue;
    }
    refs.add(`${top}${rest}`.replace(/[./]+$/, ''));
  }

  // 2. Code: a quoted top-level segment passed to a call, as in
  //    join(ROOT, 'docs'), join(ROOT, 'standards', 'staged', name) or
  //    os.path.join(root, "papers"). Literal trailing segments narrow the
  //    reference; the first non-literal argument leaves it directory-wide.
  //    An element of an array or list literal (['docs', 'standards'],
  //    []string{"papers"}) binds the whole directory: such lists are how
  //    walkers such as check-artifact-lifecycle.mjs enumerate their roots.
  if (isCode) {
    const quoted = new RegExp(`(['"\`])((?:\\.{1,2}/)*)${TOP_LEVEL}/?\\1`, 'g');
    for (const match of text.matchAll(quoted)) {
      const start = match.index ?? 0;
      const before = nonSpace(text, start - 1, -1);
      // ROOT + 'docs', ROOT / "docs" (pathlib), const DIR = 'docs' and
      // { dir: 'docs' } all hand the directory to later path code. A Go
      // struct tag (json:"docs") names a field, not a path.
      const tag = before === ':' && text[start - 1] === ':';
      if (before === '+' || before === '/' || before === '=' || (before === ':' && !tag)) {
        refs.add(match[3]);
        continue;
      }
      if (before !== '(' && before !== ',' && before !== '[' && before !== '{') continue;
      const openerAt = enclosingOpenerIndex(text, start);
      const opener = openerAt < 0 ? '' : text[openerAt];
      if (opener === '[' || opener === '{') {
        // A list element, unless it is a mapping key ({'docs': x}) or a
        // subscript (v["docs"]).
        const key = nonSpace(text, start + match[0].length, 1) === ':';
        if (!key && (opener === '{' || opensListLiteral(text, openerAt))) refs.add(match[3]);
        continue;
      }
      if (opener !== '(') continue;
      let cursor = start + match[0].length;
      let full = match[3];
      for (;;) {
        const segment = /^\s*,\s*(['"`])([A-Za-z0-9_.@+/-]+)\1/.exec(text.slice(cursor, cursor + 300));
        if (!segment) break;
        const clean = segment[2].replace(/^\/+|\/+$/g, '');
        if (!clean) break;
        full = `${full}/${clean}`;
        cursor += segment[0].length;
      }
      refs.add(full);
    }
  }

  // 3. Shell words: `find standards -name`, `COPY docs ./docs`, `ls papers/`.
  //    Comment lines are prose ("the docs lane"), not operands.
  if (isShell) {
    const commands = text.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');
    const word = new RegExp(`(^|[\\s'"=:(,])((?:\\.{1,2}/)*)${TOP_LEVEL}/?(?=$|[\\s'";)|&*])`, 'gm');
    for (const match of commands.matchAll(word)) refs.add(match[3]);
  }

  // 4. Root-level prose by name. A nested package.json's "files" and
  //    "readme" name the package's own README, not the repository's.
  const packageLocal = base === 'package.json' && path.includes('/');
  for (const name of packageLocal ? [] : rootProse) {
    let from = 0;
    for (;;) {
      const index = text.indexOf(name, from);
      if (index < 0) break;
      from = index + 1;
      const next = text[index + name.length] ?? '';
      if (/[A-Za-z0-9_-]/.test(next) || (next === '.' && /[A-Za-z0-9_]/.test(text[index + name.length + 1] ?? ''))) {
        continue;
      }
      let start = index;
      while (start >= 2 && text[start - 1] === '/' && text[start - 2] === '.') {
        start -= start >= 3 && text[start - 3] === '.' ? 3 : 2;
      }
      if (hasPathLeftBoundary(text, start)) refs.add(name);
    }
  }
  return refs;
}

/**
 * @param {string} path changed prose path
 * @param {Set<string>} refs output of extractProseReferences
 * @returns {string | null} the reference that binds `path`, if any
 */
export function bindingReference(path, refs) {
  if (refs.has(path)) return path;
  for (const directory of ancestorsOf(path)) {
    if (refs.has(directory)) return `${directory}/`;
  }
  return null;
}

/**
 * @typedef {{ status: string, path: string, oldMode: string, newMode: string }} Change
 * @typedef {{ path: string, text: string }} Source
 * @typedef {{ sources: Iterable<Source>, violations: string[] }} Audit
 * @typedef {{ lane: 'docs' | 'full', reasons: string[], changed: number }} Decision
 */

/**
 * Pure decision over parsed inputs. `loadAudit` is only called when every
 * change is a prose candidate.
 *
 * @param {Change[]} changes
 * @param {() => Audit} loadAudit
 * @returns {Decision}
 */
export function classify(changes, loadAudit) {
  /** @type {string[]} */
  const reasons = [];
  if (!Array.isArray(changes) || changes.length === 0) {
    return { lane: FULL_LANE, reasons: ['no changed paths were observed; running everything'], changed: 0 };
  }
  for (const change of changes) {
    if ([change.oldMode, change.newMode].some((mode) => mode === '120000' || mode === '160000')) {
      reasons.push(`${change.path}: symlink or submodule change`);
    } else if (!isDocsCandidate(change.path)) {
      reasons.push(`${change.path}: not a prose path`);
    }
  }
  if (reasons.length > 0) return { lane: FULL_LANE, reasons, changed: changes.length };

  const audit = loadAudit();
  for (const violation of audit.violations) reasons.push(violation);
  const rootProse = [...new Set(changes.map((change) => change.path).filter((p) => !p.includes('/')))];
  for (const source of audit.sources) {
    const refs = extractProseReferences(source.path, source.text, rootProse);
    if (refs.size === 0) continue;
    for (const change of changes) {
      const binding = bindingReference(change.path, refs);
      if (binding) reasons.push(`${change.path}: ${source.path} names ${binding}`);
    }
  }
  if (reasons.length > 0) return { lane: FULL_LANE, reasons, changed: changes.length };
  return {
    lane: DOCS_LANE,
    reasons: [`all ${changes.length} changed path(s) are prose that no docs-lane-skipped job reads`],
    changed: changes.length,
  };
}

/**
 * Parses `git diff --raw -z --no-renames` output.
 *
 * @param {string} raw
 * @returns {Change[]}
 */
export function parseRawDiff(raw) {
  const fields = raw.split('\0');
  /** @type {Change[]} */
  const changes = [];
  for (let i = 0; i + 1 < fields.length; i += 2) {
    const meta = fields[i];
    const path = fields[i + 1];
    if (!meta) break;
    const match = /^:(\d{6}) (\d{6}) [0-9a-f]+ [0-9a-f]+ ([A-Z])\d*$/.exec(meta);
    if (!match || !path) throw new Error(`unparseable diff entry: ${JSON.stringify(meta)}`);
    changes.push({ oldMode: match[1], newMode: match[2], status: match[3], path });
  }
  return changes;
}

/**
 * @param {string[]} args
 * @param {string} cwd
 * @returns {string}
 */
function git(args, cwd) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * Builds the audit for the checked-out tree at `cwd`.
 *
 * @param {string} cwd
 * @returns {Audit}
 */
export function repositoryAudit(cwd) {
  const tracked = git(['ls-files', '-z'], cwd).split('\0').filter(Boolean);
  /** @param {string} relativePath */
  const read = (relativePath) => {
    const absolute = join(cwd, relativePath);
    return existsSync(absolute) ? readFileSync(absolute, 'utf8') : null;
  };
  const workflow = read(CI_WORKFLOW) ?? '';
  const closure = skippedJobClosure(workflow, read);
  /** @type {string[]} */
  const violations = [];
  if (closure.jobs.length === 0) violations.push(`${CI_WORKFLOW} has no docs-lane-skipped jobs to audit`);
  for (const checker of reachableKeptCheckers(tracked, closure.text, read)) {
    violations.push(`${checker} reads prose and is reachable from a docs-lane-skipped job`);
  }
  function* sources() {
    yield { path: CI_WORKFLOW, text: closure.text };
    for (const path of tracked) {
      if (!isAuditedSource(path)) continue;
      let text;
      try {
        text = readFileSync(join(cwd, path), 'utf8');
      } catch {
        // A tracked source that cannot be read cannot be shown to be prose-free.
        text = "'docs/' 'standards/' 'papers/'";
      }
      yield { path, text };
    }
  }
  return { sources: sources(), violations };
}

/**
 * @param {string[]} argv
 * @returns {Record<string, string>}
 */
function parseArgs(argv) {
  /** @type {Record<string, string>} */
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`expected --option value pairs, got ${JSON.stringify(argv)}`);
    }
    options[key.slice(2)] = value;
  }
  return options;
}

/**
 * The base/head pair for the triggering event, or null when the event always
 * runs the full lane.
 *
 * @param {Record<string, string>} options
 * @param {string} cwd
 * @returns {{ base: string, head: string } | null}
 */
function resolveRange(options, cwd) {
  const event = options.event ?? '';
  if (event === 'pull_request') {
    // actions/checkout places the PR merge commit at HEAD; its first parent is
    // the exact base the checks run against, so the diff is the PR as merged.
    const parents = git(['rev-list', '--parents', '-n', '1', 'HEAD'], cwd).trim().split(' ');
    if (parents.length !== 3) throw new Error('pull_request HEAD is not a two-parent merge commit');
    return { base: parents[1], head: parents[0] };
  }
  if (event === 'local') {
    // Committed changes since the merge base, as a pull request would diff.
    if (!options.base) throw new Error('--event local requires --base <rev>');
    const head = options.head ?? 'HEAD';
    return { base: git(['merge-base', options.base, head], cwd).trim(), head };
  }
  return null;
}

/**
 * @param {string[]} argv
 * @param {string} [cwd]
 * @returns {Decision}
 */
export function run(argv, cwd = process.cwd()) {
  /** @type {Record<string, string>} */
  let options = {};
  /** @type {Decision} */
  let decision;
  try {
    options = parseArgs(argv);
    const range = resolveRange(options, cwd);
    if (range === null) {
      decision = {
        lane: FULL_LANE,
        reasons: [`event ${options.event ?? '(none)'} always runs the full lane`],
        changed: 0,
      };
    } else {
      const raw = git(['diff', '--raw', '-z', '--no-renames', '--no-ext-diff', '--no-textconv', range.base, range.head], cwd);
      decision = classify(parseRawDiff(raw), () => repositoryAudit(cwd));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    decision = { lane: FULL_LANE, reasons: [`classifier error, failing closed: ${message}`], changed: 0 };
  }

  const shown = decision.reasons.slice(0, 40);
  const summary = [
    `### CI lane: \`${decision.lane}\``,
    '',
    ...shown.map((reason) => `- ${reason}`),
    ...(decision.reasons.length > shown.length ? [`- and ${decision.reasons.length - shown.length} more`] : []),
    '',
  ].join('\n');
  process.stdout.write(`${summary}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
  // The lane is written last: if anything above throws, the output stays
  // empty and every gated job reads that as the full lane.
  if (options['github-output']) appendFileSync(options['github-output'], `lane=${decision.lane}\n`);
  return decision;
}

// import.meta.url names the resolved file, so compare against the resolved
// argv path: CI runs a copy from $RUNNER_TEMP, which may sit behind a symlink.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  run(process.argv.slice(2));
}
