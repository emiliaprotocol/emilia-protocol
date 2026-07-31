// SPDX-License-Identifier: Apache-2.0
import { AUTHORITY_SCAN_VERSION, authorityExitCode, renderAuthorityJson, renderAuthorityText, runAuthorityScan, writePrivateReport, } from './index.js';
const USAGE = `emilia-scan authority ${AUTHORITY_SCAN_VERSION}

  emilia-scan authority [--json] [--out <new-file>] [--cwd <dir>]

  Passive local inventory of configured agent authority.
  Reads bounded configuration files. Launches nothing. Makes no network request.
  Credential values are not intentionally emitted.

  Alpha diagnostic. Not a security product. No authorization guarantee.

  Exit codes
    0  complete visible surface and no signals (not currently reachable in config-only mode)
    1  signals present
    2  malformed configuration source
    3  operation surface not visible or not classifiable
`;
function parseArgs(argv) {
    const options = { json: false, out: null, cwd: process.cwd() };
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === '--json')
            options.json = true;
        else if (argument === '--out' || argument === '--cwd') {
            const value = argv[index + 1];
            if (!value || value.startsWith('--'))
                throw new Error(`${argument} requires a value`);
            if (argument === '--out')
                options.out = value;
            else
                options.cwd = value;
            index += 1;
        }
        else {
            throw new Error(`unknown authority option: ${argument}`);
        }
    }
    return options;
}
export function authorityMain(argv, io = {
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
}) {
    if (argv.includes('--help') || argv.includes('-h')) {
        io.stdout(USAGE);
        return 0;
    }
    try {
        const options = parseArgs(argv);
        const result = runAuthorityScan({ cwd: options.cwd });
        const output = options.json ? renderAuthorityJson(result) : renderAuthorityText(result);
        if (options.out) {
            writePrivateReport(options.out, output);
            io.stdout(`report written to ${options.out}\n`);
        }
        else {
            io.stdout(`${output}\n`);
        }
        return authorityExitCode(result);
    }
    catch (error) {
        io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
        return 64;
    }
}
//# sourceMappingURL=cli.js.map