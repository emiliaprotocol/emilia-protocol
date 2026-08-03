// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import {
  AUTHORITY_SCAN_VERSION,
  authorityExitCode,
  renderAuthorityJson,
  renderAuthorityText,
  runAuthorityScan,
  writePrivateReport,
} from './index.js';

const USAGE = `emilia-scan authority ${AUTHORITY_SCAN_VERSION}

  emilia-scan authority [--json] [--out <new-file>] [--cwd <dir>]

  Passive local inventory of configured agent authority.
  Reads bounded configuration files. After startup, scanner code launches no
  configured server or child process and performs no network I/O.
  npx may download the package before scanner startup.
  Credential values are not intentionally emitted.

  Alpha diagnostic. Not a security product. No authorization guarantee.

  Exit codes
    0  complete visible surface and no signals (not currently reachable in config-only mode)
    1  signals present
    2  malformed configuration source
    3  operation surface not visible or not classifiable
    64 usage, argument, or filesystem error
`;

interface ParsedArgs {
  help: boolean;
  json: boolean;
  out: string | null;
  cwd: string;
}

export interface AuthorityIo {
  stdout: (value: string) => void;
  stderr: (value: string) => void;
}

function parseArgs(argv: string[]): ParsedArgs {
  const options: ParsedArgs = { help: false, json: false, out: null, cwd: process.cwd() };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument === '--json') options.json = true;
    else if (argument === '--out' || argument === '--cwd') {
      const value = argv[index + 1];
      if (!value || value.startsWith('-')) throw new Error(`${argument} requires a value`);
      if (argument === '--out') options.out = value;
      else options.cwd = value;
      index += 1;
    } else {
      throw new Error(`unknown authority option: ${argument}`);
    }
  }
  return options;
}

export function authorityMain(
  argv: string[],
  io: AuthorityIo = {
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
  },
): number {
  try {
    const options = parseArgs(argv);
    if (options.help) {
      io.stdout(USAGE);
      return 0;
    }
    if (!fs.statSync(options.cwd).isDirectory()) {
      throw new Error(`--cwd must name an existing directory: ${options.cwd}`);
    }
    const result = runAuthorityScan({ cwd: options.cwd });
    const output = options.json ? renderAuthorityJson(result) : renderAuthorityText(result);
    if (options.out) {
      writePrivateReport(options.out, output);
      io.stdout(`report written to ${options.out}\n`);
    } else {
      io.stdout(`${output}\n`);
    }
    return authorityExitCode(result);
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
    return 64;
  }
}
