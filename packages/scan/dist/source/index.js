// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { classifyAction } from '../index.js';
export const SOURCE_DISCOVERY_VERSION = 'EP-SOURCE-DISCOVERY-v1';
export const SOURCE_PARSER_VERSION = 'emilia-source-patterns-v1';
export const SOURCE_CLAIM_BOUNDARY = 'Pattern-based static discovery proposes review inputs. It does not prove runtime reachability, complete mediation, source truth, or authorization.';
const EXTENSIONS = new Map([
    ['.js', 'javascript'], ['.jsx', 'javascript'], ['.mjs', 'javascript'], ['.cjs', 'javascript'],
    ['.ts', 'typescript'], ['.tsx', 'typescript'], ['.mts', 'typescript'], ['.cts', 'typescript'],
    ['.py', 'python'], ['.java', 'java'],
]);
const SKIP_DIRECTORIES = new Set(['.git', '.next', 'node_modules', 'dist', 'build', 'coverage', 'vendor', '__pycache__']);
const SAFE_NAME = /^[A-Za-z_][A-Za-z0-9_.:-]{0,255}$/;
function sha(value) {
    return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}
function canonical(value) {
    if (value === null)
        return 'null';
    if (Array.isArray(value))
        return `[${value.map(canonical).join(',')}]`;
    if (typeof value === 'object') {
        return `{${Object.entries(value)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
    }
    return JSON.stringify(value);
}
function lineAt(text, index) {
    let line = 1;
    for (let cursor = 0; cursor < index; cursor += 1)
        if (text.charCodeAt(cursor) === 10)
            line += 1;
    return line;
}
function lineBytes(text, index, end = index) {
    const start = text.lastIndexOf('\n', index - 1) + 1;
    const lineEnd = text.indexOf('\n', Math.max(index, end));
    return text.slice(start, lineEnd === -1 ? text.length : lineEnd);
}
function literalAt(value) {
    const match = /^\s*(['"`])([^'"`$\r\n]{1,256})\1/.exec(value);
    return match ? { value: match[2], consumed: match[0].length } : null;
}
function propertyName(value) {
    const match = /\bname\s*[:=]\s*(['"`])([^'"`$\r\n]{1,256})\1/.exec(value.slice(0, 1_200));
    return match ? { value: match[2], offset: match.index, consumed: match[0].length } : null;
}
function pushCandidate(candidates, candidate) {
    if (candidate.name !== null && !SAFE_NAME.test(candidate.name))
        candidate.name = null;
    candidates.push(candidate);
}
function maskJsComments(text) {
    const chars = [...text];
    let state = 'code';
    let escaped = false;
    for (let index = 0; index < chars.length; index += 1) {
        const current = chars[index];
        const next = chars[index + 1];
        if (state === 'line') {
            if (current === '\n')
                state = 'code';
            else
                chars[index] = ' ';
            continue;
        }
        if (state === 'block') {
            if (current === '*' && next === '/') {
                chars[index] = ' ';
                chars[index + 1] = ' ';
                index += 1;
                state = 'code';
            }
            else if (current !== '\n')
                chars[index] = ' ';
            continue;
        }
        if (state !== 'code') {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (current === '\\') {
                escaped = true;
                continue;
            }
            if ((state === 'single' && current === "'")
                || (state === 'double' && current === '"')
                || (state === 'template' && current === '`'))
                state = 'code';
            continue;
        }
        if (current === '/' && next === '/') {
            chars[index] = ' ';
            chars[index + 1] = ' ';
            index += 1;
            state = 'line';
        }
        else if (current === '/' && next === '*') {
            chars[index] = ' ';
            chars[index + 1] = ' ';
            index += 1;
            state = 'block';
        }
        else if (current === "'")
            state = 'single';
        else if (current === '"')
            state = 'double';
        else if (current === '`')
            state = 'template';
    }
    return chars.join('');
}
function parseJsTs(text) {
    const searchable = maskJsComments(text);
    const candidates = [];
    const registration = /\b(?:server|mcp)\.(?:tool|registerTool)\s*\(/g;
    for (const match of searchable.matchAll(registration)) {
        const start = match.index;
        const tail = text.slice(start + match[0].length, start + match[0].length + 1_200);
        const literal = literalAt(tail);
        let description;
        if (literal) {
            const afterName = tail.slice(literal.consumed).replace(/^\s*,/, '');
            description = literalAt(afterName)?.value;
        }
        pushCandidate(candidates, {
            name: literal?.value ?? null,
            index: start,
            end: start + match[0].length + (literal?.consumed ?? 0),
            framework: 'mcp',
            confidence: 'high',
            description,
        });
    }
    const hasGenkit = /^\s*import\b[^\r\n]{0,500}\bfrom\s+['"][^'"]*genkit[^'"]*['"]/m.test(searchable);
    const genkit = /\b(?:[A-Za-z_$][\w$]*\.)?defineTool\s*\(/g;
    for (const match of searchable.matchAll(genkit)) {
        if (!hasGenkit && !/^ai\.defineTool/.test(match[0]))
            continue;
        const property = propertyName(text.slice(match.index + match[0].length));
        pushCandidate(candidates, {
            name: property?.value ?? null,
            index: match.index,
            end: match.index + match[0].length + (property?.offset ?? 0) + (property?.consumed ?? 0),
            framework: 'genkit',
            confidence: 'high',
        });
    }
    const hasLangChain = /^\s*import\b[^\r\n]{0,500}\bfrom\s+['"]@langchain\//m.test(searchable);
    const hasVercel = /^\s*import\b[^\r\n]{0,500}\bfrom\s+['"]ai['"]/m.test(searchable);
    const toolCall = /\btool\s*\(/g;
    if (!hasLangChain && !hasVercel)
        return candidates;
    for (const match of searchable.matchAll(toolCall)) {
        if (match.index > 0 && text[match.index - 1] === '.')
            continue;
        const property = propertyName(text.slice(match.index + match[0].length));
        pushCandidate(candidates, {
            name: property?.value ?? null,
            index: match.index,
            end: match.index + match[0].length + (property?.offset ?? 0) + (property?.consumed ?? 0),
            framework: hasLangChain ? 'langchain' : hasVercel ? 'vercel-ai' : 'tool-call',
            confidence: hasLangChain || hasVercel ? 'high' : 'medium',
        });
    }
    return candidates;
}
function parsePython(text) {
    const lines = text.split(/\r?\n/);
    const offsets = [];
    let offset = 0;
    for (const line of lines) {
        offsets.push(offset);
        offset += line.length + 1;
    }
    const candidates = [];
    for (let index = 0; index < lines.length; index += 1) {
        const decorator = /^\s*@(?:(?:mcp\.)?tool)\b(?:\((.*)\))?/.exec(lines[index]);
        if (!decorator)
            continue;
        const literal = decorator[1] ? literalAt(decorator[1]) : null;
        let functionName = null;
        for (let next = index + 1; next < Math.min(lines.length, index + 5); next += 1) {
            const definition = /^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(lines[next]);
            if (definition) {
                functionName = definition[1];
                break;
            }
            if (lines[next].trim() && !lines[next].trim().startsWith('@'))
                break;
        }
        pushCandidate(candidates, {
            name: literal?.value ?? functionName,
            index: offsets[index],
            end: offsets[index] + lines[index].length,
            framework: decorator[0].includes('mcp.') ? 'mcp' : 'python-tool',
            confidence: literal ? 'high' : 'medium',
        });
    }
    return candidates;
}
function parseJava(text) {
    const candidates = [];
    const annotation = /@Tool\s*\(([^)]*)\)/g;
    for (const match of text.matchAll(annotation)) {
        const named = /\bname\s*=\s*"([A-Za-z_][A-Za-z0-9_.:-]{0,255})"/.exec(match[1]);
        const positional = /^\s*"([A-Za-z_][A-Za-z0-9_.:-]{0,255})"/.exec(match[1]);
        pushCandidate(candidates, {
            name: named?.[1] ?? positional?.[1] ?? null,
            index: match.index,
            end: match.index + match[0].length,
            framework: 'java-tool',
            confidence: 'high',
        });
    }
    return candidates;
}
function capabilityNames(actions, expression) {
    return [...new Set(actions.filter((action) => expression.test(action.name)).map((action) => action.name))].sort();
}
function finding(id, severity, title, groups, reason) {
    if (groups.some((group) => group.length === 0))
        return null;
    return {
        id,
        severity,
        title,
        affected_actions: [...new Set(groups.flat())].sort(),
        only_tightens: true,
        reason,
        does_not_prove: 'Static co-presence does not prove data flow, reachability, exploitability, or deployment exposure.',
    };
}
function composition(actions) {
    const untrusted = capabilityNames(actions, /(email|message|prompt|webpage|url|inbox|external.*input|untrusted)/i);
    const money = capabilityNames(actions, /(pay|payment|wire|transfer|refund|payout|purchase|invoice)/i);
    const destination = capabilityNames(actions, /(beneficiary|bank.*detail|account.*detail|destination|routing|payee)/i);
    const shell = capabilityNames(actions, /(shell|exec|command|terminal|bash|powershell|spawn)/i);
    const credential = capabilityNames(actions, /(credential|secret|api.?key|token|password|keychain)/i);
    const external = capabilityNames(actions, /(send|post|upload|publish|webhook|transmit|export|email)/i);
    const duplicateNames = [...new Set(actions.map((action) => action.name)
            .filter((name, index, all) => all.indexOf(name) !== index))].sort();
    return [
        finding('untrusted_input_plus_money_movement', 'critical', 'Untrusted input and money movement coexist', [untrusted, money], 'Treat the money-moving actions as requiring owner review even if either tool appears harmless alone.'),
        finding('mutable_destination_plus_money_movement', 'critical', 'Mutable destination data and money movement coexist', [destination, money], 'A destination-changing action can redirect a later financial effect; classification can only tighten.'),
        finding('untrusted_reader_plus_shell_executor', 'critical', 'Untrusted reader and shell execution coexist', [untrusted, shell], 'Untrusted content may influence a general executor; require an explicit reviewed boundary.'),
        finding('credential_access_plus_external_transmission', 'high', 'Credential access and external transmission coexist', [credential, external], 'Sensitive access plus an outbound channel requires review even without a proven data flow.'),
        duplicateNames.length ? {
            id: 'duplicate_registration_name',
            severity: 'critical',
            title: 'One action name resolves to multiple source registrations',
            affected_actions: duplicateNames,
            only_tightens: true,
            reason: 'A reviewed manifest cannot identify one handler from a duplicate name without an additional binding.',
            does_not_prove: 'Duplicate names do not prove either handler is reachable at runtime.',
        } : null,
    ].filter((item) => item !== null).sort((a, b) => a.id.localeCompare(b.id));
}
function tighten(actions, findings) {
    const affected = new Set(findings.flatMap((item) => item.affected_actions));
    for (const action of actions) {
        action.classification_after = affected.has(action.name)
            && (action.classification_before === 'pass_through' || action.classification_before === 'review')
            ? 'review_fail_closed'
            : action.classification_before;
    }
}
function proposedBaseline(actions) {
    const counts = new Map();
    for (const action of actions)
        counts.set(action.name, (counts.get(action.name) ?? 0) + 1);
    const proposed = actions
        .filter((action) => counts.get(action.name) === 1)
        .map((action) => ({
        name: action.name,
        source_evidence: {
            file: action.file,
            line: action.line,
            framework: action.framework,
            parser_version: action.parser_version,
            file_sha256: action.file_sha256,
            registration_sha256: action.registration_sha256,
        },
        proposed_control: {
            decision: action.classification_after,
            receipt_required: action.classification_after !== 'pass_through',
            assurance_class: action.classification.assurance_class ?? null,
            category: action.classification.category ?? null,
        },
    }))
        .sort((a, b) => a.name.localeCompare(b.name));
    return {
        '@version': 'EP-SOURCE-DISCOVERY-BASELINE-v1',
        parser_version: SOURCE_PARSER_VERSION,
        claim_boundary: 'A reviewed source baseline records what was statically observed. It is not an action-control manifest and grants no authority.',
        actions: proposed,
    };
}
export function scanSourceDirectory(rootInput, options = {}) {
    function boundedLimit(value, fallback, label) {
        if (value === undefined)
            return fallback;
        if (!Number.isSafeInteger(value) || value <= 0 || value > fallback) {
            throw new Error(`${label} must be a positive safe integer no greater than ${fallback}`);
        }
        return value;
    }
    const limits = {
        maxFiles: boundedLimit(options.maxFiles, 5_000, 'maxFiles'),
        maxFileBytes: boundedLimit(options.maxFileBytes, 1024 * 1024, 'maxFileBytes'),
        maxTotalBytes: boundedLimit(options.maxTotalBytes, 64 * 1024 * 1024, 'maxTotalBytes'),
        maxDepth: boundedLimit(options.maxDepth, 12, 'maxDepth'),
    };
    const rootStat = fs.lstatSync(rootInput);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory())
        throw new Error('source root must be a non-symlink directory');
    const root = fs.realpathSync(rootInput);
    const files = [];
    const actions = [];
    const dynamic = [];
    const skipped = [];
    let totalBytes = 0;
    function walk(directory, depth) {
        if (depth > limits.maxDepth) {
            skipped.push({ file: path.relative(root, directory) || '.', reason: 'max_depth' });
            return;
        }
        const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            const absolute = path.join(directory, entry.name);
            const relative = path.relative(root, absolute).split(path.sep).join('/');
            const stat = fs.lstatSync(absolute);
            if (stat.isSymbolicLink()) {
                skipped.push({ file: relative, reason: 'symlink' });
                continue;
            }
            if (stat.isDirectory()) {
                if (!SKIP_DIRECTORIES.has(entry.name))
                    walk(absolute, depth + 1);
                continue;
            }
            const language = EXTENSIONS.get(path.extname(entry.name).toLowerCase());
            if (!language || !stat.isFile())
                continue;
            if (files.length >= limits.maxFiles) {
                skipped.push({ file: relative, reason: 'max_files' });
                continue;
            }
            if (stat.size > limits.maxFileBytes) {
                skipped.push({ file: relative, reason: 'file_too_large' });
                continue;
            }
            if (totalBytes + stat.size > limits.maxTotalBytes) {
                skipped.push({ file: relative, reason: 'total_bytes' });
                continue;
            }
            const before = fs.statSync(absolute);
            const bytes = fs.readFileSync(absolute);
            const after = fs.statSync(absolute);
            if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
                skipped.push({ file: relative, reason: 'changed_during_read' });
                continue;
            }
            totalBytes += bytes.length;
            const fileSha = sha(bytes);
            files.push({ file: relative, bytes: bytes.length, sha256: fileSha });
            if (bytes.includes(0)) {
                skipped.push({ file: relative, reason: 'binary' });
                continue;
            }
            let text;
            try {
                text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
            }
            catch {
                skipped.push({ file: relative, reason: 'invalid_utf8' });
                continue;
            }
            const candidates = language === 'python' ? parsePython(text) : language === 'java' ? parseJava(text) : parseJsTs(text);
            for (const candidate of candidates) {
                const line = lineAt(text, candidate.index);
                const registrationSha = sha(lineBytes(text, candidate.index, candidate.end));
                if (!candidate.name) {
                    dynamic.push({
                        file: relative, line, language, framework: candidate.framework,
                        parser_version: SOURCE_PARSER_VERSION, reason: 'non_literal_action_name',
                        file_sha256: fileSha, registration_sha256: registrationSha,
                    });
                    continue;
                }
                const classification = classifyAction({ name: candidate.name, description: candidate.description });
                actions.push({
                    name: candidate.name, file: relative, line, language, framework: candidate.framework,
                    parser_version: SOURCE_PARSER_VERSION, confidence: candidate.confidence,
                    file_sha256: fileSha, registration_sha256: registrationSha,
                    classification_before: classification.decision,
                    classification_after: classification.decision,
                    classification,
                });
            }
        }
    }
    walk(root, 0);
    actions.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.name.localeCompare(b.name));
    dynamic.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    skipped.sort((a, b) => a.file.localeCompare(b.file) || a.reason.localeCompare(b.reason));
    const findings = composition(actions);
    tighten(actions, findings);
    const manifest = proposedBaseline(actions);
    const digestMaterial = { files, actions, unresolved_dynamic_registrations: dynamic, composition_findings: findings, skipped, proposed_manifest: manifest };
    return {
        version: SOURCE_DISCOVERY_VERSION,
        parser_version: SOURCE_PARSER_VERSION,
        scan_digest: sha(canonical(digestMaterial)),
        files,
        actions,
        unresolved_dynamic_registrations: dynamic,
        composition_findings: findings,
        skipped,
        proposed_manifest: manifest,
        limitations: [
            'Discovery is pattern-based and can miss aliases, generated code, reflection, runtime registration, and framework versions not listed by this parser.',
            'Composition findings show static co-presence only; they do not establish data flow or runtime reachability.',
            'The scanner proposes review inputs and never installs a handler, creates authority, or changes source.',
        ],
        claim_boundary: SOURCE_CLAIM_BOUNDARY,
    };
}
function baselineActions(baseline) {
    if (!baseline || typeof baseline !== 'object' || !Array.isArray(baseline.actions)) {
        throw new Error('baseline must contain an actions array');
    }
    const out = new Map();
    for (const raw of baseline.actions) {
        const name = typeof raw?.name === 'string' ? raw.name : raw?.match?.tool;
        if (typeof name !== 'string' || !SAFE_NAME.test(name))
            continue;
        if (out.has(name))
            throw new Error(`baseline contains duplicate action name: ${name}`);
        out.set(name, {
            name,
            source_evidence: raw.source_evidence ?? null,
            proposed_control: raw.proposed_control ?? {
                decision: raw.receipt_required === false ? 'pass_through' : 'review_fail_closed',
                receipt_required: raw.receipt_required !== false,
                assurance_class: raw.assurance_class ?? null,
                category: null,
            },
        });
    }
    return out;
}
export function diffSourceDiscovery(current, baseline) {
    const previous = baselineActions(baseline);
    const counts = new Map();
    for (const action of current.actions)
        counts.set(action.name, (counts.get(action.name) ?? 0) + 1);
    const uniqueCurrent = new Map(current.actions.filter((action) => counts.get(action.name) === 1).map((action) => [action.name, action]));
    const newActions = [...uniqueCurrent.keys()].filter((name) => !previous.has(name)).sort();
    const removedActions = [...previous.keys()].filter((name) => !uniqueCurrent.has(name)).sort();
    const changed = [...uniqueCurrent.entries()].filter(([name, action]) => {
        const prior = previous.get(name)?.source_evidence;
        if (!prior)
            return false;
        return prior.file !== action.file || prior.line !== action.line || prior.framework !== action.framework
            || prior.parser_version !== action.parser_version || prior.file_sha256 !== action.file_sha256
            || prior.registration_sha256 !== action.registration_sha256;
    }).map(([name]) => name).sort();
    const duplicates = [...counts.entries()].filter(([, count]) => count > 1).map(([name]) => name).sort();
    const compositionIds = current.composition_findings.map((item) => item.id).sort();
    const requiresReview = Boolean(newActions.length || removedActions.length || changed.length
        || current.unresolved_dynamic_registrations.length || compositionIds.length || duplicates.length);
    return {
        version: 'EP-SOURCE-DISCOVERY-DIFF-v1',
        current_scan_digest: current.scan_digest,
        new_actions: newActions,
        removed_actions: removedActions,
        changed_source_actions: changed,
        unresolved_dynamic_registrations: current.unresolved_dynamic_registrations.length,
        composition_findings: compositionIds,
        duplicate_registration_names: duplicates,
        requires_review: requiresReview,
        claim_boundary: 'A diff identifies static source-surface change against supplied reviewed bytes. It does not approve, reject, or authorize an action.',
    };
}
export function sourceDiscoveryExitCode(value) {
    if ('requires_review' in value)
        return value.requires_review ? 1 : 0;
    return value.unresolved_dynamic_registrations.length > 0
        || value.composition_findings.length > 0
        || value.actions.some((action) => action.classification_after !== 'pass_through')
        ? 1 : 0;
}
export * from './types.js';
//# sourceMappingURL=index.js.map