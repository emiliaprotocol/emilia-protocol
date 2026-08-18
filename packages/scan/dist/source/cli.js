// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import { strictJsonGate } from '@emilia-protocol/verify/strict-json';
import { diffSourceDiscovery, scanSourceDirectory, sourceDiscoveryExitCode } from './index.js';
import { writePrivateReport } from '../authority/report.js';
const MAX_BASELINE_BYTES = 8 * 1024 * 1024;
const USAGE = `emilia-scan source discovery

  emilia-scan source <directory> [--json] [--out <new-file>]
  emilia-scan diff --baseline <reviewed-baseline.json> <directory> [--json] [--out <new-file>]

Passive, bounded static discovery. It never edits source or creates authority.
Exit 1 means review is required; 64 means usage or filesystem failure.
`;
function parse(argv) {
    const command = argv[0];
    if (command !== 'source' && command !== 'diff')
        throw new Error('expected source or diff command');
    let directory = null;
    let baseline = null;
    let json = false;
    let out = null;
    let help = false;
    for (let index = 1; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === '--help' || argument === '-h')
            help = true;
        else if (argument === '--json')
            json = true;
        else if (argument === '--baseline' || argument === '--out') {
            const value = argv[index + 1];
            if (!value || value.startsWith('-'))
                throw new Error(`${argument} requires a value`);
            if (argument === '--baseline') {
                if (baseline !== null)
                    throw new Error('duplicate option: --baseline');
                baseline = value;
            }
            else {
                if (out !== null)
                    throw new Error('duplicate option: --out');
                out = value;
            }
            index += 1;
        }
        else if (argument.startsWith('-'))
            throw new Error(`unknown option: ${argument}`);
        else if (directory === null)
            directory = argument;
        else
            throw new Error('provide exactly one source directory');
    }
    if (!help && directory === null)
        throw new Error('source directory is required');
    if (command === 'diff' && !help && baseline === null)
        throw new Error('diff requires --baseline');
    if (command === 'source' && baseline !== null)
        throw new Error('--baseline is valid only with diff');
    return { command, directory: directory ?? '.', baseline, json, out, help };
}
function readBaseline(file) {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink() || !stat.isFile())
        throw new Error('baseline must be a non-symlink regular file');
    if (stat.size > MAX_BASELINE_BYTES)
        throw new Error('baseline exceeds 8 MiB');
    const raw = fs.readFileSync(file, 'utf8');
    const gate = strictJsonGate(raw);
    if (!gate.ok)
        throw new Error(`baseline refused: ${gate.reason}`);
    return JSON.parse(raw);
}
function renderText(value) {
    if ('requires_review' in value) {
        return [
            `EMILIA source diff — ${value.requires_review ? 'REVIEW REQUIRED' : 'no observed change'}`,
            `New actions: ${value.new_actions.join(', ') || 'none'}`,
            `Removed actions: ${value.removed_actions.join(', ') || 'none'}`,
            `Changed source evidence: ${value.changed_source_actions.join(', ') || 'none'}`,
            `Dynamic registrations unresolved: ${value.unresolved_dynamic_registrations}`,
            `Composition findings: ${value.composition_findings.join(', ') || 'none'}`,
            '', value.claim_boundary,
        ].join('\n');
    }
    return [
        `EMILIA source discovery — ${value.actions.length} literal registrations in ${value.files.length} files`,
        `Dynamic registrations unresolved: ${value.unresolved_dynamic_registrations.length}`,
        `Composition findings: ${value.composition_findings.length}`,
        ...value.actions.map((action) => `  ${action.classification_after.padEnd(18)} ${action.name}  ${action.file}:${action.line}  ${action.framework}`),
        '', value.claim_boundary,
    ].join('\n');
}
export function sourceMain(argv, io = {
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
}) {
    try {
        const options = parse(argv);
        if (options.help) {
            io.stdout(USAGE);
            return 0;
        }
        const report = scanSourceDirectory(options.directory);
        const result = options.command === 'diff' ? diffSourceDiscovery(report, readBaseline(options.baseline)) : report;
        const output = options.json ? `${JSON.stringify(result, null, 2)}\n` : `${renderText(result)}\n`;
        if (options.out) {
            writePrivateReport(options.out, output);
            io.stdout(`report written to ${options.out}\n`);
        }
        else
            io.stdout(output);
        return sourceDiscoveryExitCode(result);
    }
    catch (error) {
        io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
        return 64;
    }
}
//# sourceMappingURL=cli.js.map