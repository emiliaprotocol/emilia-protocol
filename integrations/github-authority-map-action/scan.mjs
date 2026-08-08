#!/usr/bin/env node

import { appendFile, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const TOOL_NAME = 'EMILIA Authority Map';
const PINNED_COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const OFFICIAL_ACTION_OWNERS = new Set(['actions', 'github']);
const EXPRESSION = /\$\{\{/;
const CONTRIBUTOR_CONTROLLED_TRIGGERS = new Set([
  'discussion',
  'discussion_comment',
  'issue_comment',
  'issues',
  'pull_request',
  'pull_request_review',
  'pull_request_review_comment',
  'pull_request_target',
]);
const CANDIDATE_CHECKOUT_CONTEXT =
  /\$\{\{[^}]*\b(?:github\.event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|github\.head_ref)\b[^}]*\}\}/i;
const UNTRUSTED_SHELL_CONTEXT =
  /\$\{\{[^}]*\b(?:github\.head_ref|github\.event\.(?:comment\.body|discussion\.(?:body|title)|issue\.(?:body|title)|pull_request\.(?:body|head\.(?:label|ref)|title)|review\.body))\b[^}]*\}\}/i;
/** @type {Array<[string, RegExp]>} */
const PRIVILEGED_COMMAND_PATTERNS = [
  ['package-publish', /(?:^|\n)\s*(?:npm|pnpm)\s+publish\b/im],
  ['package-publish', /(?:^|\n)\s*yarn\s+npm\s+publish\b/im],
  ['package-publish', /(?:^|\n)\s*(?:python(?:3)?\s+-m\s+)?twine\s+upload\b/im],
  ['package-publish', /(?:^|\n)\s*(?:cargo\s+publish|gem\s+push|dotnet\s+nuget\s+push)\b/im],
  ['release-mutation', /(?:^|\n)\s*gh\s+release\s+(?:create|delete|edit|upload)\b/im],
  ['repository-merge', /(?:^|\n)\s*gh\s+pr\s+merge\b/im],
  ['repository-push', /(?:^|\n)\s*git\s+push\b/im],
  ['container-push', /(?:^|\n)\s*(?:docker|podman)\s+push\b/im],
  ['infrastructure-deploy', /(?:^|\n)\s*kubectl\s+(?:apply|delete|patch|replace|set)\b/im],
  ['infrastructure-deploy', /(?:^|\n)\s*helm\s+(?:install|rollback|uninstall|upgrade)\b/im],
  ['infrastructure-deploy', /(?:^|\n)\s*terraform\s+(?:apply|destroy)\b/im],
  ['platform-deploy', /(?:^|\n)\s*(?:vercel|wrangler)\s+(?:deploy|--prod)\b/im],
];

export const STATIC_BOUNDARY = Object.freeze({
  blocksMutations: false,
  completeMediation: false,
  repositoryConfigurationIsAuthority: false,
  requiresApiPermissionsFor: Object.freeze([
    'GitHub environment protection settings',
    'GitHub rulesets',
    'GitHub bypass actors and settings',
  ]),
  statement:
    'This report is static discovery only. It does not block mutations, is not complete mediation, and does not use repository configuration as authority. Without suitable GitHub API permissions it cannot know environment protection, ruleset, or bypass settings.',
});

function stripInlineComment(value) {
  let quote = null;
  let escaped = false;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && character === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '#' && (index === 0 || /\s/.test(value[index - 1]))) {
      return value.slice(0, index).trimEnd();
    }
  }

  return value.trimEnd();
}

function unquote(value) {
  const trimmed = value.trim();
  if (trimmed.length < 2) return trimmed;
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replaceAll("''", "'");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function splitFlow(value) {
  const parts = [];
  let start = 0;
  let quote = null;
  let escaped = false;
  let squareDepth = 0;
  let curlyDepth = 0;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && character === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '[') squareDepth += 1;
    if (character === ']') squareDepth -= 1;
    if (character === '{') curlyDepth += 1;
    if (character === '}') curlyDepth -= 1;
    if (character === ',' && squareDepth === 0 && curlyDepth === 0) {
      parts.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(value.slice(start).trim());
  return parts.filter(Boolean);
}

function findMappingColon(value) {
  let quote = null;
  let escaped = false;
  let squareDepth = 0;
  let curlyDepth = 0;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && character === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '[') squareDepth += 1;
    if (character === ']') squareDepth -= 1;
    if (character === '{') curlyDepth += 1;
    if (character === '}') curlyDepth -= 1;
    if (character === ':' && squareDepth === 0 && curlyDepth === 0) return index;
  }
  return -1;
}

function parseKeyValue(content) {
  const colon = findMappingColon(content);
  if (colon < 0) return null;
  const rawKey = content.slice(0, colon).trim();
  if (!rawKey) return null;
  return {
    key: unquote(rawKey),
    value: stripInlineComment(content.slice(colon + 1)).trim(),
  };
}

function parseFlowSequence(value) {
  const trimmed = value.trim();
  if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) return null;
  return splitFlow(trimmed.slice(1, -1)).map(unquote);
}

function parseFlowMapping(value) {
  const trimmed = value.trim();
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return null;
  const entries = [];
  for (const part of splitFlow(trimmed.slice(1, -1))) {
    const parsed = parseKeyValue(part);
    if (!parsed) return null;
    entries.push(parsed);
  }
  return entries;
}

function sourceLines(source) {
  return source.split(/\r?\n/).map((raw, index) => {
    const indentation = raw.match(/^[ ]*/)?.[0].length ?? 0;
    const content = stripInlineComment(raw.slice(indentation));
    return {
      number: index + 1,
      raw,
      indent: indentation,
      content,
      trimmed: content.trim(),
    };
  });
}

function isSignificant(line) {
  return line.trimmed !== '' && line.trimmed !== '---' && line.trimmed !== '...';
}

function blockEnd(lines, start, parentIndent, maximum = lines.length) {
  for (let index = start + 1; index < maximum; index += 1) {
    if (isSignificant(lines[index]) && lines[index].indent <= parentIndent) return index;
  }
  return maximum;
}

function directEntries(lines, start, end, parentIndent) {
  let childIndent = Number.POSITIVE_INFINITY;
  for (let index = start + 1; index < end; index += 1) {
    const line = lines[index];
    if (isSignificant(line) && line.indent > parentIndent) {
      childIndent = Math.min(childIndent, line.indent);
    }
  }
  if (!Number.isFinite(childIndent)) return [];

  const entries = [];
  for (let index = start + 1; index < end; index += 1) {
    const line = lines[index];
    if (!isSignificant(line) || line.indent !== childIndent) continue;
    const parsed = parseKeyValue(line.trimmed);
    if (parsed) entries.push({ ...parsed, index, line: line.number, indent: line.indent });
  }
  return entries;
}

function addAmbiguity(ambiguities, kind, line, message) {
  const key = `${kind}:${line}:${message}`;
  if (ambiguities.some((item) => item._key === key)) return;
  ambiguities.push({ _key: key, kind, line, message });
}

function cleanAmbiguities(ambiguities) {
  return ambiguities
    .map(({ _key, ...item }) => item)
    .sort((left, right) => left.line - right.line || left.kind.localeCompare(right.kind));
}

function structuralAmbiguities(lines, ambiguities) {
  let documentCount = 0;
  for (const line of lines) {
    if (line.trimmed === '---') documentCount += 1;
    if (/^\t/.test(line.raw) || /^ +\t/.test(line.raw)) {
      addAmbiguity(
        ambiguities,
        'tab-indentation',
        line.number,
        'Tabs in indentation are unsupported by the conservative scanner.',
      );
    }
    if (line.trimmed.startsWith('%')) {
      addAmbiguity(
        ambiguities,
        'yaml-directive',
        line.number,
        'YAML directives are not interpreted.',
      );
    }
    if (line.trimmed.startsWith('? ')) {
      addAmbiguity(
        ambiguities,
        'complex-yaml-key',
        line.number,
        'Complex YAML keys are not interpreted.',
      );
    }
    const structural = line.trimmed.startsWith('- ')
      ? line.trimmed.slice(2).trimStart()
      : line.trimmed;
    const parsed = parseKeyValue(structural);
    if (!parsed) continue;
    if (parsed.key === '<<') {
      addAmbiguity(
        ambiguities,
        'yaml-merge-key',
        line.number,
        'YAML merge-key semantics are not resolved.',
      );
    }
    if (/(?:^|[\s[{,])&[A-Za-z0-9_-]+(?:$|[\s\]},])/.test(parsed.value)) {
      addAmbiguity(
        ambiguities,
        'yaml-anchor',
        line.number,
        'YAML anchors are noted but not resolved as authority facts.',
      );
    }
    if (/^\*[A-Za-z0-9_-]+$/.test(parsed.value)) {
      addAmbiguity(
        ambiguities,
        'yaml-alias',
        line.number,
        'YAML aliases are noted but not resolved as authority facts.',
      );
    }
    if (/^!/.test(parsed.value)) {
      addAmbiguity(
        ambiguities,
        'yaml-tag',
        line.number,
        'Tagged YAML values are not interpreted.',
      );
    }
  }
  if (documentCount > 1) {
    addAmbiguity(
      ambiguities,
      'multiple-yaml-documents',
      1,
      'Only a single workflow document is inventoried per file.',
    );
  }
}

function topLevelEntries(lines) {
  const entries = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!isSignificant(line) || line.indent !== 0) continue;
    const parsed = parseKeyValue(line.trimmed);
    if (parsed) entries.push({ ...parsed, index, line: line.number, indent: 0 });
  }
  return entries;
}

function duplicateKeyAmbiguities(entries, ambiguities, context) {
  const seen = new Map();
  for (const entry of entries) {
    if (seen.has(entry.key)) {
      addAmbiguity(
        ambiguities,
        'duplicate-key',
        entry.line,
        `Duplicate ${context} key "${entry.key}" is not resolved.`,
      );
    } else {
      seen.set(entry.key, entry.line);
    }
  }
}

function parseTriggers(lines, entry, end, ambiguities) {
  const value = entry.value;
  if (EXPRESSION.test(value)) {
    addAmbiguity(
      ambiguities,
      'dynamic-trigger',
      entry.line,
      'Expression-derived workflow triggers cannot be statically determined.',
    );
    return [];
  }

  const flowSequence = parseFlowSequence(value);
  if (flowSequence) return flowSequence;
  const flowMapping = parseFlowMapping(value);
  if (flowMapping) return flowMapping.map((item) => item.key);
  if (value && !['null', '~', '{}', '[]'].includes(value)) return [unquote(value)];
  if (value === '{}') return [];

  const children = directEntries(lines, entry.index, end, entry.indent);
  duplicateKeyAmbiguities(children, ambiguities, 'trigger');
  return children.map((item) => item.key);
}

function permissionRecord(form, line, entries = [], ambiguous = false) {
  const writeScopes = entries
    .filter((item) => unquote(item.value).toLowerCase() === 'write')
    .map((item) => item.key)
    .sort();
  return {
    form,
    line,
    writeAll: form === 'write-all',
    writeScopes,
    entries: Object.fromEntries(entries.map((item) => [item.key, unquote(item.value)])),
    ambiguous,
  };
}

function parsePermissions(lines, entry, end, ambiguities, context) {
  const rawValue = entry.value;
  const value = unquote(rawValue).toLowerCase();
  if (value === 'write-all' || value === 'read-all') {
    return permissionRecord(value, entry.line);
  }
  if (rawValue === '{}') return permissionRecord('empty', entry.line);
  if (EXPRESSION.test(rawValue) || /^\*/.test(rawValue)) {
    addAmbiguity(
      ambiguities,
      'dynamic-permission',
      entry.line,
      `${context} permissions cannot be statically determined.`,
    );
    return permissionRecord('ambiguous', entry.line, [], true);
  }

  const flow = parseFlowMapping(rawValue);
  if (flow) {
    let ambiguous = false;
    for (const item of flow) {
      if (EXPRESSION.test(item.value) || !['read', 'write', 'none'].includes(unquote(item.value))) {
        ambiguous = true;
        addAmbiguity(
          ambiguities,
          'dynamic-permission',
          entry.line,
          `${context} permission "${item.key}" has an unsupported or dynamic value.`,
        );
      }
    }
    return permissionRecord('map', entry.line, flow, ambiguous);
  }

  if (rawValue && !/^&[A-Za-z0-9_-]+$/.test(rawValue)) {
    addAmbiguity(
      ambiguities,
      'unsupported-permission-form',
      entry.line,
      `${context} permissions use an unsupported scalar form.`,
    );
    return permissionRecord('ambiguous', entry.line, [], true);
  }

  const children = directEntries(lines, entry.index, end, entry.indent);
  duplicateKeyAmbiguities(children, ambiguities, `${context} permission`);
  let ambiguous = Boolean(rawValue);
  for (const item of children) {
    const itemValue = unquote(item.value).toLowerCase();
    if (item.key === '<<') {
      ambiguous = true;
      continue;
    }
    if (EXPRESSION.test(item.value) || !['read', 'write', 'none'].includes(itemValue)) {
      ambiguous = true;
      addAmbiguity(
        ambiguities,
        'dynamic-permission',
        item.line,
        `${context} permission "${item.key}" has an unsupported or dynamic value.`,
      );
    }
  }
  return permissionRecord('map', entry.line, children, ambiguous);
}

function absentPermissions() {
  return permissionRecord('absent', null);
}

function parseEnvironment(lines, entry, end, ambiguities, job) {
  const rawValue = entry.value;
  if (EXPRESSION.test(rawValue) || /^\*/.test(rawValue)) {
    addAmbiguity(
      ambiguities,
      'dynamic-environment',
      entry.line,
      `Job "${job}" has an expression-derived environment.`,
    );
    return {
      job,
      value: unquote(rawValue),
      line: entry.line,
      production: /\bprod(?:uction)?\b/i.test(rawValue),
      ambiguous: true,
    };
  }

  const flow = parseFlowMapping(rawValue);
  if (flow) {
    const name = flow.find((item) => item.key === 'name');
    if (!name || EXPRESSION.test(name.value)) {
      addAmbiguity(
        ambiguities,
        'dynamic-environment',
        entry.line,
        `Job "${job}" has an environment mapping without a static name.`,
      );
      return {
        job,
        value: name ? unquote(name.value) : rawValue,
        line: entry.line,
        production: Boolean(name && /\bprod(?:uction)?\b/i.test(name.value)),
        ambiguous: true,
      };
    }
    const value = unquote(name.value);
    return {
      job,
      value,
      line: entry.line,
      production: /\bprod(?:uction)?\b/i.test(value),
      ambiguous: false,
    };
  }

  if (rawValue) {
    const value = unquote(rawValue);
    return {
      job,
      value,
      line: entry.line,
      production: /\bprod(?:uction)?\b/i.test(value),
      ambiguous: false,
    };
  }

  const children = directEntries(lines, entry.index, end, entry.indent);
  duplicateKeyAmbiguities(children, ambiguities, `job "${job}" environment`);
  const name = children.find((item) => item.key === 'name');
  if (!name || EXPRESSION.test(name.value) || /^\*/.test(name.value)) {
    addAmbiguity(
      ambiguities,
      'dynamic-environment',
      name?.line ?? entry.line,
      `Job "${job}" has an environment mapping without a static name.`,
    );
    return {
      job,
      value: name ? unquote(name.value) : '',
      line: name?.line ?? entry.line,
      production: Boolean(name && /\bprod(?:uction)?\b/i.test(name.value)),
      ambiguous: true,
    };
  }
  const value = unquote(name.value);
  return {
    job,
    value,
    line: name.line,
    production: /\bprod(?:uction)?\b/i.test(value),
    ambiguous: false,
  };
}

function runnerValue(lines, entry, end) {
  if (entry.value) return entry.value;
  const values = [];
  for (let index = entry.index + 1; index < end; index += 1) {
    const line = lines[index];
    if (!isSignificant(line) || line.indent <= entry.indent) continue;
    values.push(line.trimmed.replace(/^-\s*/, ''));
  }
  return values.join(', ');
}

function hasSelfHosted(value) {
  return /(?:^|[\s,[{])['"]?self-hosted['"]?(?:$|[\s,\]}])/i.test(value);
}

function parseActionReference(value) {
  const uses = unquote(value);
  if (uses.startsWith('./') || uses.startsWith('docker://')) return { kind: 'local' };
  if (EXPRESSION.test(uses)) return { kind: 'dynamic', uses };
  const at = uses.lastIndexOf('@');
  if (at <= 0) return { kind: 'unsupported', uses };
  const target = uses.slice(0, at);
  const ref = uses.slice(at + 1);
  const owner = target.split('/')[0]?.toLowerCase();
  if (!owner || target.split('/').length < 2) return { kind: 'unsupported', uses };
  return {
    kind: 'remote',
    uses,
    target,
    owner,
    ref,
    thirdParty: !OFFICIAL_ACTION_OWNERS.has(owner),
    pinned: PINNED_COMMIT.test(ref),
  };
}

function parsedStructuralLine(line) {
  const content = line.trimmed.startsWith('- ')
    ? line.trimmed.slice(2).trimStart()
    : line.trimmed;
  return parseKeyValue(content);
}

function nestedStepField(lines, start, end, key) {
  for (let index = start + 1; index < end; index += 1) {
    if (!isSignificant(lines[index])) continue;
    const parsed = parsedStructuralLine(lines[index]);
    if (parsed?.key === key) {
      return { ...parsed, index, line: lines[index].number };
    }
  }
  return null;
}

function runSource(lines, index, end, value) {
  if (!/^[>|][+-]?$/.test(value)) return unquote(value);
  const source = [];
  for (let cursor = index + 1; cursor < end; cursor += 1) {
    if (lines[cursor].indent <= lines[index].indent && isSignificant(lines[cursor])) break;
    source.push(lines[cursor].raw.trim());
  }
  return source.join('\n');
}

function privilegedCommandSink(source) {
  for (const [kind, pattern] of PRIVILEGED_COMMAND_PATTERNS) {
    if (pattern.test(source)) return { kind, evidence: source.trim().split(/\r?\n/)[0] };
  }
  return null;
}

function privilegedActionSink(reference) {
  if (reference.kind !== 'remote') return null;
  const target = reference.target.toLowerCase();
  if (
    /(?:^|[/_-])(?:deploy|publish)(?:$|[/_-])/.test(target) ||
    target.includes('gh-action-pypi-publish') ||
    target === 'actions/deploy-pages'
  ) {
    return { kind: 'publish-or-deploy-action', evidence: reference.uses };
  }
  return null;
}

function isDefaultCheckoutPath(value) {
  if (!value) return true;
  const normalized = unquote(value).trim();
  return normalized === '.' || normalized === '${{ github.workspace }}';
}

function productionReferences(lines, environmentReferences) {
  const references = environmentReferences
    .filter((item) => item.production)
    .map((item) => ({
      kind: 'environment',
      job: item.job,
      value: item.value,
      line: item.line,
      ambiguous: item.ambiguous,
    }));
  const occupied = new Set(references.map((item) => item.line));
  for (const line of lines) {
    if (occupied.has(line.number)) continue;
    const match = line.trimmed.match(/\bprod(?:uction)?\b/i);
    if (!match) continue;
    references.push({
      kind: 'text',
      job: null,
      value: match[0],
      line: line.number,
      ambiguous: true,
    });
  }
  return references.sort((left, right) => left.line - right.line);
}

function analyzeWorkflow(source, relativeFile) {
  const lines = sourceLines(source);
  const ambiguities = [];
  structuralAmbiguities(lines, ambiguities);
  const topEntries = topLevelEntries(lines);
  duplicateKeyAmbiguities(topEntries, ambiguities, 'top-level');

  const nameEntry = topEntries.find((item) => item.key === 'name');
  const onEntry = topEntries.find((item) => item.key === 'on');
  const permissionsEntry = topEntries.find((item) => item.key === 'permissions');
  const jobsEntry = topEntries.find((item) => item.key === 'jobs');

  if (!onEntry) {
    addAmbiguity(
      ambiguities,
      'missing-trigger',
      1,
      'No statically recognizable top-level "on" key was found.',
    );
  }
  if (!jobsEntry) {
    addAmbiguity(
      ambiguities,
      'missing-jobs',
      1,
      'No statically recognizable top-level "jobs" key was found.',
    );
  }

  const triggerEnd = onEntry ? blockEnd(lines, onEntry.index, onEntry.indent) : 0;
  const triggers = onEntry ? parseTriggers(lines, onEntry, triggerEnd, ambiguities) : [];
  const topPermissionEnd = permissionsEntry
    ? blockEnd(lines, permissionsEntry.index, permissionsEntry.indent)
    : 0;
  const topPermissions = permissionsEntry
    ? parsePermissions(lines, permissionsEntry, topPermissionEnd, ambiguities, 'Top-level')
    : absentPermissions();

  const jobs = [];
  const jobPermissions = {};
  const environmentReferences = [];
  const selfHostedRunners = [];
  const unpinnedThirdPartyActions = [];
  const candidateCheckouts = [];
  const dangerousPullRequestTargetCompositions = [];
  const obviousPrivilegedSinks = [];

  if (jobsEntry) {
    const jobsEnd = blockEnd(lines, jobsEntry.index, jobsEntry.indent);
    const jobEntries = directEntries(lines, jobsEntry.index, jobsEnd, jobsEntry.indent);
    duplicateKeyAmbiguities(jobEntries, ambiguities, 'job');

    for (let position = 0; position < jobEntries.length; position += 1) {
      const jobEntry = jobEntries[position];
      const job = jobEntry.key;
      const jobEnd = position + 1 < jobEntries.length ? jobEntries[position + 1].index : jobsEnd;
      const fields = directEntries(lines, jobEntry.index, jobEnd, jobEntry.indent);
      duplicateKeyAmbiguities(fields, ambiguities, `job "${job}"`);
      const permissionEntry = fields.find((item) => item.key === 'permissions');
      const environmentEntry = fields.find((item) => item.key === 'environment');
      const runsOnEntry = fields.find((item) => item.key === 'runs-on');
      const permissionEnd = permissionEntry
        ? blockEnd(lines, permissionEntry.index, permissionEntry.indent, jobEnd)
        : 0;
      const permissions = permissionEntry
        ? parsePermissions(
            lines,
            permissionEntry,
            permissionEnd,
            ambiguities,
            `Job "${job}"`,
          )
        : null;
      if (permissions) jobPermissions[job] = permissions;

      let environment = null;
      if (environmentEntry) {
        const environmentEnd = blockEnd(
          lines,
          environmentEntry.index,
          environmentEntry.indent,
          jobEnd,
        );
        environment = parseEnvironment(
          lines,
          environmentEntry,
          environmentEnd,
          ambiguities,
          job,
        );
        environmentReferences.push(environment);
      }

      if (runsOnEntry) {
        const runsOnEnd = blockEnd(lines, runsOnEntry.index, runsOnEntry.indent, jobEnd);
        const value = runnerValue(lines, runsOnEntry, runsOnEnd);
        if (EXPRESSION.test(value)) {
          addAmbiguity(
            ambiguities,
            'dynamic-runner',
            runsOnEntry.line,
            `Job "${job}" has an expression-derived runner selection.`,
          );
        }
        if (hasSelfHosted(value)) {
          selfHostedRunners.push({ job, value, line: runsOnEntry.line });
        }
      } else if (!fields.some((item) => item.key === 'uses')) {
        addAmbiguity(
          ambiguities,
          'missing-runner',
          jobEntry.line,
          `Job "${job}" has neither a static runs-on field nor a reusable-workflow uses field.`,
        );
      }

      const jobCandidateCheckouts = [];
      const jobLocalActions = [];
      const jobRuns = [];
      for (let index = jobEntry.index + 1; index < jobEnd; index += 1) {
        const line = lines[index];
        if (!isSignificant(line)) continue;
        const parsed = parsedStructuralLine(line);
        if (!parsed || parsed.key !== 'uses') continue;
        const reference = parseActionReference(parsed.value);
        const stepEnd = blockEnd(lines, index, line.indent, jobEnd);
        if (reference.kind === 'dynamic') {
          addAmbiguity(
            ambiguities,
            'dynamic-action-reference',
            line.number,
            `Job "${job}" has an expression-derived action or reusable-workflow reference.`,
          );
        } else if (reference.kind === 'unsupported') {
          addAmbiguity(
            ambiguities,
            'unsupported-action-reference',
            line.number,
            `Job "${job}" has an unsupported action reference form.`,
          );
        } else if (reference.kind === 'remote' && reference.thirdParty && !reference.pinned) {
          unpinnedThirdPartyActions.push({
            job,
            uses: reference.uses,
            ref: reference.ref,
            line: line.number,
            reason: 'Third-party reference is not a full commit SHA.',
          });
        }

        if (reference.kind === 'local') {
          jobLocalActions.push({ job, line: line.number, index, uses: unquote(parsed.value) });
        }
        if (
          reference.kind === 'remote' &&
          reference.target.toLowerCase() === 'actions/checkout'
        ) {
          const ref = nestedStepField(lines, index, stepEnd, 'ref');
          const repository = nestedStepField(lines, index, stepEnd, 'repository');
          const checkoutPath = nestedStepField(lines, index, stepEnd, 'path');
          const sourceValues = [ref?.value, repository?.value].filter(Boolean);
          if (sourceValues.some((value) => CANDIDATE_CHECKOUT_CONTEXT.test(value))) {
            const checkout = {
              job,
              line: line.number,
              index,
              ref: ref ? unquote(ref.value) : null,
              repository: repository ? unquote(repository.value) : null,
              path: checkoutPath ? unquote(checkoutPath.value) : null,
              defaultWorkspace: isDefaultCheckoutPath(checkoutPath?.value),
            };
            jobCandidateCheckouts.push(checkout);
            candidateCheckouts.push(checkout);
          }
        }
        const actionSink = privilegedActionSink(reference);
        if (actionSink) {
          obviousPrivilegedSinks.push({
            job,
            line: line.number,
            source: 'uses',
            ...actionSink,
            environment: environment?.value ?? null,
            environmentAmbiguous: environment?.ambiguous ?? false,
          });
        }
      }

      for (let index = jobEntry.index + 1; index < jobEnd; index += 1) {
        const line = lines[index];
        if (!isSignificant(line)) continue;
        const parsed = parsedStructuralLine(line);
        if (!parsed || parsed.key !== 'run') continue;
        const runEnd = blockEnd(lines, index, line.indent, jobEnd);
        const source = runSource(lines, index, runEnd, parsed.value);
        const run = { job, line: line.number, index, source };
        jobRuns.push(run);
        const commandSink = privilegedCommandSink(source);
        if (commandSink) {
          obviousPrivilegedSinks.push({
            job,
            line: line.number,
            source: 'run',
            ...commandSink,
            environment: environment?.value ?? null,
            environmentAmbiguous: environment?.ambiguous ?? false,
          });
        }
      }

      if (triggers.includes('pull_request_target')) {
        for (const run of jobRuns) {
          if (!UNTRUSTED_SHELL_CONTEXT.test(run.source)) continue;
          dangerousPullRequestTargetCompositions.push({
            job,
            line: run.line,
            kind: 'untrusted-shell-expression',
            evidence: 'A contributor-controlled GitHub context is interpolated directly into run.',
          });
        }
        for (const checkout of jobCandidateCheckouts) {
          const localExecution = jobLocalActions.find((item) => item.index > checkout.index);
          const shellExecution = jobRuns.find((item) => item.index > checkout.index);
          if (!checkout.defaultWorkspace || (!localExecution && !shellExecution)) continue;
          const execution = /** @type {{ line: number }} */ (localExecution ?? shellExecution);
          dangerousPullRequestTargetCompositions.push({
            job,
            line: checkout.line,
            kind: 'candidate-code-execution',
            evidence: localExecution
              ? `Candidate checkout is followed by local action ${localExecution.uses}.`
              : `Candidate checkout is followed by a run step at line ${execution.line}.`,
          });
        }
      }

      jobs.push({
        id: job,
        line: jobEntry.line,
        permissions,
        environment,
      });
    }
  }

  const mutationSignals = [];
  if (topPermissions.writeAll || topPermissions.writeScopes.length > 0) {
    mutationSignals.push({
      source: 'top-level-permissions',
      job: null,
      line: topPermissions.line,
      writeAll: topPermissions.writeAll,
      writeScopes: topPermissions.writeScopes,
    });
  }
  const mutatingJobs = [];
  const ambiguousMutationJobs = [];
  for (const job of jobs) {
    const effective = job.permissions ?? topPermissions;
    const writes = effective.writeAll || effective.writeScopes.length > 0;
    if (writes) {
      mutatingJobs.push(job);
      mutationSignals.push({
        source: job.permissions ? 'job-permissions' : 'inherited-top-level-permissions',
        job: job.id,
        line: effective.line,
        writeAll: effective.writeAll,
        writeScopes: effective.writeScopes,
      });
    }
    if (effective.ambiguous) ambiguousMutationJobs.push(job);
  }
  const jobsWithoutEnvironment = mutatingJobs.filter((job) => !job.environment);
  const jobsWithAmbiguousEnvironment = mutatingJobs.filter(
    (job) => job.environment?.ambiguous,
  );
  let environmentAssessment = 'not-applicable';
  if (jobsWithoutEnvironment.length > 0) environmentAssessment = 'absent';
  else if (
    jobsWithAmbiguousEnvironment.length > 0 ||
    ambiguousMutationJobs.some((job) => !job.environment || job.environment.ambiguous)
  ) {
    environmentAssessment = 'ambiguous';
  } else if (mutatingJobs.length > 0) environmentAssessment = 'present';

  const cleanedAmbiguities = cleanAmbiguities(ambiguities);
  return {
    file: relativeFile,
    name: nameEntry ? unquote(nameEntry.value) : path.basename(relativeFile),
    triggers,
    environmentReferences,
    productionReferences: productionReferences(lines, environmentReferences),
    permissions: {
      topLevel: topPermissions,
      jobs: jobPermissions,
    },
    hazards: {
      pullRequestTarget: {
        present: triggers.includes('pull_request_target'),
        line: onEntry?.line ?? null,
      },
      contributorControlledTriggers: triggers.filter((trigger) =>
        CONTRIBUTOR_CONTROLLED_TRIGGERS.has(trigger),
      ),
      selfHostedRunners,
      unpinnedThirdPartyActions,
      candidateCheckouts: candidateCheckouts.map(({ index, ...item }) => item),
      dangerousPullRequestTargetCompositions,
    },
    mutation: {
      hasDeclaredWriteCapability: mutatingJobs.length > 0,
      hasAmbiguousWriteCapability: ambiguousMutationJobs.length > 0,
      signals: mutationSignals,
      mutatingJobs: mutatingJobs.map((job) => job.id),
      jobsWithoutEnvironment: jobsWithoutEnvironment.map((job) => job.id),
      withoutEnvironment: jobsWithoutEnvironment.length > 0,
      environmentAssessment,
      obviousPrivilegedSinks,
      staticBasis:
        'Mutation capability is inferred only from declared effective GitHub token write permissions. Steps may mutate through other credentials or systems that static discovery cannot establish.',
    },
    ambiguities: cleanedAmbiguities,
  };
}

/**
 * @param {{
 *   code: string,
 *   severity: string,
 *   workflow: string,
 *   line: number | null | undefined,
 *   job?: string | null,
 *   message: string,
 *   composition?: string | null,
 *   evidence?: string | null,
 * }} input
 */
function finding({
  code,
  severity,
  workflow,
  line,
  job = null,
  message,
  composition = null,
  evidence = null,
}) {
  return {
    id: `${workflow}:${line ?? 0}:${job ?? '-'}:${code}`,
    code,
    severity,
    file: workflow,
    workflow,
    job,
    line,
    composition,
    evidence,
    message,
  };
}

function workflowFindings(workflow) {
  const findings = [];
  if (workflow.permissions.topLevel.writeAll) {
    findings.push(
      finding({
        code: 'TOP_LEVEL_WRITE_ALL',
        severity: 'critical',
        workflow: workflow.file,
        line: workflow.permissions.topLevel.line,
        message: 'Top-level permissions grant write-all.',
      }),
    );
  } else {
    for (const scope of workflow.permissions.topLevel.writeScopes) {
      findings.push(
        finding({
          code: 'TOP_LEVEL_WRITE_PERMISSION',
          severity: 'warning',
          workflow: workflow.file,
          line: workflow.permissions.topLevel.line,
          message: `Top-level permissions grant ${scope}: write.`,
        }),
      );
    }
  }
  for (const [job, permissions] of Object.entries(workflow.permissions.jobs)) {
    if (permissions.writeAll) {
      findings.push(
        finding({
          code: 'JOB_WRITE_ALL',
          severity: 'critical',
          workflow: workflow.file,
          job,
          line: permissions.line,
          message: `Job "${job}" grants write-all.`,
        }),
      );
    } else {
      for (const scope of permissions.writeScopes) {
        findings.push(
          finding({
            code: 'JOB_WRITE_PERMISSION',
            severity: 'warning',
            workflow: workflow.file,
            job,
            line: permissions.line,
            message: `Job "${job}" grants ${scope}: write.`,
          }),
        );
      }
    }
  }
  if (workflow.hazards.pullRequestTarget.present) {
    findings.push(
      finding({
        code: 'PULL_REQUEST_TARGET',
        severity: 'warning',
        workflow: workflow.file,
        line: workflow.hazards.pullRequestTarget.line,
        message:
          'Workflow is triggered by pull_request_target; review for candidate-code or untrusted-input composition.',
      }),
    );
  }
  for (const runner of workflow.hazards.selfHostedRunners) {
    const contributorTrigger = workflow.hazards.contributorControlledTriggers.length > 0;
    findings.push(
      finding({
        code: 'SELF_HOSTED_RUNNER',
        severity: contributorTrigger ? 'critical' : 'warning',
        workflow: workflow.file,
        job: runner.job,
        line: runner.line,
        composition: contributorTrigger ? 'contributor-trigger' : null,
        evidence: contributorTrigger
          ? workflow.hazards.contributorControlledTriggers.join(', ')
          : null,
        message: contributorTrigger
          ? `Job "${runner.job}" can select a self-hosted runner from a contributor-controlled trigger.`
          : `Job "${runner.job}" can select a self-hosted runner; no contributor-controlled trigger was statically discovered.`,
      }),
    );
  }
  for (const action of workflow.hazards.unpinnedThirdPartyActions) {
    findings.push(
      finding({
        code: 'UNPINNED_THIRD_PARTY_ACTION',
        severity: 'critical',
        workflow: workflow.file,
        job: action.job,
        line: action.line,
        message: `${action.uses} is a third-party reference not pinned to a full commit SHA.`,
      }),
    );
  }
  for (const composition of workflow.hazards.dangerousPullRequestTargetCompositions) {
    findings.push(
      finding({
        code: 'DANGEROUS_PULL_REQUEST_TARGET_COMPOSITION',
        severity: 'critical',
        workflow: workflow.file,
        job: composition.job,
        line: composition.line,
        composition: composition.kind,
        evidence: composition.evidence,
        message: `pull_request_target is composed with ${composition.kind}.`,
      }),
    );
  }
  for (const checkout of workflow.hazards.candidateCheckouts) {
    const composed = workflow.hazards.dangerousPullRequestTargetCompositions.some(
      (item) => item.job === checkout.job && item.line === checkout.line,
    );
    if (composed) continue;
    findings.push(
      finding({
        code: 'CANDIDATE_CHECKOUT_REVIEW',
        severity: 'warning',
        workflow: workflow.file,
        job: checkout.job,
        line: checkout.line,
        message:
          'Candidate pull-request content is checked out, but direct execution was not statically established.',
      }),
    );
  }
  if (workflow.mutation.withoutEnvironment) {
    findings.push(
      finding({
        code: 'MUTATION_WITHOUT_ENVIRONMENT',
        severity: 'warning',
        workflow: workflow.file,
        line: workflow.mutation.signals[0]?.line ?? null,
        message: `Review path: declared write-capable jobs without an environment: ${workflow.mutation.jobsWithoutEnvironment.join(', ')}. No publish/deploy sink is implied by permissions alone.`,
      }),
    );
  }
  const sinksByJob = new Map();
  for (const sink of workflow.mutation.obviousPrivilegedSinks) {
    if (!sinksByJob.has(sink.job)) sinksByJob.set(sink.job, []);
    sinksByJob.get(sink.job).push(sink);
  }
  for (const [job, sinks] of sinksByJob) {
    const first = sinks[0];
    if (first.environment && !first.environmentAmbiguous) continue;
    const ambiguousEnvironment = first.environmentAmbiguous;
    findings.push(
      finding({
        code: ambiguousEnvironment
          ? 'PRIVILEGED_SINK_ENVIRONMENT_AMBIGUOUS'
          : 'PRIVILEGED_SINK_WITHOUT_ENVIRONMENT',
        severity: ambiguousEnvironment ? 'warning' : 'critical',
        workflow: workflow.file,
        job,
        line: first.line,
        composition: 'privileged-sink-without-static-environment',
        evidence: sinks.map((sink) => sink.evidence).join('; '),
        message: ambiguousEnvironment
          ? `Job "${job}" has an obvious privileged sink and an expression-derived environment.`
          : `Job "${job}" has an obvious publish, deploy, release, push, or merge sink without an environment.`,
      }),
    );
  }
  for (const ambiguity of workflow.ambiguities) {
    findings.push(
      finding({
        code: 'STATIC_ANALYSIS_AMBIGUITY',
        severity: 'notice',
        workflow: workflow.file,
        line: ambiguity.line,
        message: `${ambiguity.kind}: ${ambiguity.message}`,
      }),
    );
  }
  return findings;
}

export async function scanWorkspace(workspace, options = {}) {
  const root = path.resolve(workspace);
  const workflowDirectory = path.join(root, '.github', 'workflows');
  let directoryEntries = [];
  try {
    directoryEntries = await readdir(workflowDirectory, { withFileTypes: true });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  const fileNames = directoryEntries
    .filter((entry) => entry.isFile() && /\.ya?ml$/i.test(entry.name))
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right));
  const workflows = [];
  for (const fileName of fileNames) {
    const relativeFile = path.posix.join('.github', 'workflows', fileName);
    const source = await readFile(path.join(workflowDirectory, fileName), 'utf8');
    workflows.push(analyzeWorkflow(source, relativeFile));
  }

  const findings = workflows.flatMap(workflowFindings);
  const ambiguityCount = workflows.reduce(
    (total, workflow) => total + workflow.ambiguities.length,
    0,
  );
  return {
    schemaVersion: '1.0',
    tool: {
      name: TOOL_NAME,
      mode: 'static-discovery-only',
      runtime: 'Node.js 20+',
    },
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    scanRoot: root,
    boundary: {
      ...STATIC_BOUNDARY,
      requiresApiPermissionsFor: [...STATIC_BOUNDARY.requiresApiPermissionsFor],
    },
    summary: {
      workflowCount: workflows.length,
      findingCount: findings.length,
      criticalFindingCount: findings.filter((item) => item.severity === 'critical').length,
      warningFindingCount: findings.filter((item) => item.severity === 'warning').length,
      ambiguityCount,
      mutationWithoutEnvironmentCount: workflows.filter(
        (workflow) => workflow.mutation.withoutEnvironment,
      ).length,
      reviewPathWithoutEnvironmentCount: workflows.filter(
        (workflow) => workflow.mutation.withoutEnvironment,
      ).length,
    },
    workflows,
    findings,
  };
}

function markdownCell(value) {
  return String(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function permissionSummary(workflow) {
  const parts = [];
  const top = workflow.permissions.topLevel;
  if (top.writeAll) parts.push('top: write-all');
  else if (top.writeScopes.length > 0) parts.push(`top: ${top.writeScopes.join(', ')}`);
  for (const [job, permission] of Object.entries(workflow.permissions.jobs)) {
    if (permission.writeAll) parts.push(`${job}: write-all`);
    else if (permission.writeScopes.length > 0) {
      parts.push(`${job}: ${permission.writeScopes.join(', ')}`);
    }
  }
  return parts.length > 0 ? parts.join('; ') : 'none discovered';
}

function hazardSummary(workflow) {
  const hazards = [];
  if (workflow.hazards.pullRequestTarget.present) hazards.push('pull_request_target');
  if (workflow.hazards.selfHostedRunners.length > 0) hazards.push('self-hosted runner');
  if (workflow.hazards.unpinnedThirdPartyActions.length > 0) {
    hazards.push('unpinned third-party action');
  }
  if (workflow.hazards.dangerousPullRequestTargetCompositions.length > 0) {
    hazards.push('dangerous pull_request_target composition');
  }
  if (
    workflow.mutation.obviousPrivilegedSinks.some(
      (item) => !item.environment && !item.environmentAmbiguous,
    )
  ) {
    hazards.push('privileged sink without environment');
  }
  return hazards.length > 0 ? hazards.join(', ') : 'none discovered';
}

export function renderMarkdown(report) {
  const lines = [
    `# ${TOOL_NAME}`,
    '',
    '> Static discovery only. EMILIA Authority Map does not block mutations, is not complete mediation, and does not use repository configuration as authority.',
    '',
    'Without suitable GitHub API permissions, this scan cannot know GitHub environment protection settings, GitHub rulesets, or GitHub bypass actors and settings.',
    '',
    '## Summary',
    '',
    `- Workflows: ${report.summary.workflowCount}`,
    `- Critical findings: ${report.summary.criticalFindingCount}`,
    `- Warning findings: ${report.summary.warningFindingCount}`,
    `- Ambiguities and unsupported constructs: ${report.summary.ambiguityCount}`,
    `- Scoped write review paths without an environment: ${report.summary.reviewPathWithoutEnvironmentCount}`,
    '',
    '## Workflow inventory',
    '',
    '| Workflow | Triggers | Environments | Write permissions | Hazards | Ambiguities |',
    '| --- | --- | --- | --- | --- | ---: |',
  ];

  for (const workflow of report.workflows) {
    const environments = workflow.environmentReferences.length
      ? workflow.environmentReferences.map((item) => `${item.job}: ${item.value || '?'}`).join('; ')
      : 'none discovered';
    lines.push(
      `| ${markdownCell(workflow.file)} | ${markdownCell(workflow.triggers.join(', ') || 'none discovered')} | ${markdownCell(environments)} | ${markdownCell(permissionSummary(workflow))} | ${markdownCell(hazardSummary(workflow))} | ${workflow.ambiguities.length} |`,
    );
  }

  lines.push('', '## Critical findings', '');
  lines.push(
    'Critical severity requires a concrete composition or a deliberately high-risk static fact; scoped writes and bare triggers remain warnings.',
    '',
  );
  const critical = report.findings.filter((item) => item.severity === 'critical');
  if (critical.length === 0) lines.push('No critical findings were statically discovered.');
  for (const item of critical) {
    const location = `${item.file}:${item.line ?? '?'}${item.job ? ` (${item.job})` : ''}`;
    lines.push(`- **${item.code}** — ${item.message} \`${location}\``);
  }

  lines.push('', '## Scoped write review paths without an environment', '');
  const withoutEnvironment = report.workflows.filter(
    (workflow) => workflow.mutation.withoutEnvironment,
  );
  if (withoutEnvironment.length === 0) {
    lines.push('None were discovered from declared effective GitHub token write permissions.');
  } else {
    lines.push(
      'These are warning-level review paths. A scoped write permission without an environment does not by itself establish a production mutation.',
      '',
    );
    for (const workflow of withoutEnvironment) {
      lines.push(
        `- \`${workflow.file}\`: ${workflow.mutation.jobsWithoutEnvironment.join(', ')}`,
      );
    }
  }

  lines.push('', '## Ambiguity and unsupported constructs', '');
  if (report.summary.ambiguityCount === 0) {
    lines.push('No parser ambiguities were recorded.');
  } else {
    for (const workflow of report.workflows) {
      for (const ambiguity of workflow.ambiguities) {
        lines.push(
          `- \`${workflow.file}:${ambiguity.line}\` **${ambiguity.kind}** — ${ambiguity.message}`,
        );
      }
    }
  }

  lines.push(
    '',
    '## Boundary',
    '',
    report.boundary.statement,
    '',
    'A clean report is not proof that mutations are impossible or mediated. Repository workflow files are discovery inputs, not authority. Runtime credentials, called workflows, action internals, external systems, environment protections, rulesets, and bypass paths require separate verification.',
    '',
  );
  return lines.join('\n');
}

function usage() {
  return [
    `${TOOL_NAME}`,
    '',
    'Usage: node scan.mjs [options]',
    '',
    '  --workspace <path>  Repository workspace (default: GITHUB_WORKSPACE or cwd)',
    '  --json <path>       JSON output path',
    '  --markdown <path>   Markdown output path',
    '  --fail-on <policy>  never|critical (default: never)',
    '  --help              Show this help',
  ].join('\n');
}

function argumentValue(arguments_, index, option) {
  const value = arguments_[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${option} requires a value.`);
  return value;
}

function parseArguments(arguments_, environment) {
  const options = {
    workspace: environment.GITHUB_WORKSPACE || process.cwd(),
    json: environment['INPUT_JSON-OUTPUT'] || null,
    markdown: environment['INPUT_MARKDOWN-OUTPUT'] || null,
    failOn: environment['INPUT_FAIL-ON'] || 'never',
    help: false,
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--help') {
      options.help = true;
    } else if (argument === '--workspace') {
      options.workspace = argumentValue(arguments_, index, argument);
      index += 1;
    } else if (argument === '--json') {
      options.json = argumentValue(arguments_, index, argument);
      index += 1;
    } else if (argument === '--markdown') {
      options.markdown = argumentValue(arguments_, index, argument);
      index += 1;
    } else if (argument === '--fail-on') {
      options.failOn = argumentValue(arguments_, index, argument);
      index += 1;
    } else {
      throw new Error(`Unknown option: ${argument}`);
    }
  }
  options.failOn = options.failOn.toLowerCase();
  if (!['never', 'critical'].includes(options.failOn)) {
    throw new Error('fail-on must be never|critical.');
  }
  return options;
}

function resolveOutputPath(value, fallbackDirectory, fallbackName, workspace) {
  const selected = value || path.join(fallbackDirectory, fallbackName);
  return path.resolve(path.isAbsolute(selected) ? selected : path.join(workspace, selected));
}

async function writeActionOutputs(environment, values) {
  if (!environment.GITHUB_OUTPUT) return;
  const content = Object.entries(values)
    .map(([key, value]) => `${key}=${String(value).replaceAll('\n', '%0A').replaceAll('\r', '%0D')}`)
    .join('\n');
  await appendFile(environment.GITHUB_OUTPUT, `${content}\n`, 'utf8');
}

export async function main(arguments_ = process.argv.slice(2), environment = process.env) {
  let options;
  try {
    options = parseArguments(arguments_, environment);
  } catch (error) {
    console.error(`${TOOL_NAME}: ${error.message}`);
    console.error(usage());
    return 2;
  }
  if (options.help) {
    console.log(usage());
    return 0;
  }

  try {
    const workspace = path.resolve(options.workspace);
    const outputDirectory = environment.RUNNER_TEMP || workspace;
    const jsonPath = resolveOutputPath(
      options.json,
      outputDirectory,
      'emilia-authority-map.json',
      workspace,
    );
    const markdownPath = resolveOutputPath(
      options.markdown,
      outputDirectory,
      'emilia-authority-map.md',
      workspace,
    );
    const report = await scanWorkspace(workspace);
    const markdown = renderMarkdown(report);
    await Promise.all([
      mkdir(path.dirname(jsonPath), { recursive: true }),
      mkdir(path.dirname(markdownPath), { recursive: true }),
    ]);
    await Promise.all([
      writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8'),
      writeFile(markdownPath, markdown, 'utf8'),
      environment.GITHUB_STEP_SUMMARY
        ? appendFile(environment.GITHUB_STEP_SUMMARY, markdown, 'utf8')
        : Promise.resolve(),
    ]);
    await writeActionOutputs(environment, {
      'json-path': jsonPath,
      'markdown-path': markdownPath,
      'critical-findings': report.summary.criticalFindingCount,
      'ambiguity-count': report.summary.ambiguityCount,
    });

    const noun = report.summary.criticalFindingCount === 1 ? 'finding' : 'findings';
    console.log(
      `${TOOL_NAME}: ${report.summary.workflowCount} workflows, ${report.summary.criticalFindingCount} critical ${noun}. JSON: ${jsonPath}. Markdown: ${markdownPath}.`,
    );
    if (options.failOn === 'critical' && report.summary.criticalFindingCount > 0) return 1;
    return 0;
  } catch (error) {
    console.error(`${TOOL_NAME}: ${error.stack || error.message}`);
    return 2;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  process.exitCode = await main();
}
