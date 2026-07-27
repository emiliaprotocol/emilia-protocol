#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from run-referee-conformance.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// @ts-nocheck
//
// Language-neutral AEB-1 Referee self-test harness. It runs a bounded external
// argv command over strict JSON stdin/stdout, verifies deterministic results,
// and writes a non-certifying report. This is not a production sandbox.
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { access, lstat, mkdir, readFile, realpath, rename, writeFile, } from 'node:fs/promises';
import { constants as fsConstants, createReadStream } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const HARD_LIMITS = Object.freeze({
    manifestBytes: 4_194_304,
    schemaBytes: 1_048_576,
    commandBytes: 16_384,
    commandArguments: 33,
    argumentBytes: 4_096,
});
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
class RefereeError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'RefereeError';
        this.code = code;
    }
}
function byteLength(value) {
    return Buffer.byteLength(value, 'utf8');
}
function validUnicode(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff) {
            return false;
        }
    }
    return true;
}
function inspectJsonValue(value, label, maxDepth, depth, ancestors) {
    if (depth > maxDepth) {
        throw new RefereeError('INVALID_JSON', label + ': JSON depth exceeds ' + maxDepth);
    }
    if (value === null || typeof value === 'boolean')
        return;
    if (typeof value === 'string') {
        if (!validUnicode(value)) {
            throw new RefereeError('INVALID_JSON', label + ': invalid Unicode scalar value');
        }
        return;
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            throw new RefereeError('INVALID_JSON', label + ': non-finite number');
        }
        return;
    }
    if (typeof value !== 'object') {
        throw new RefereeError('INVALID_JSON', label + ': non-JSON value');
    }
    if (ancestors.has(value)) {
        throw new RefereeError('INVALID_JSON', label + ': cyclic value');
    }
    ancestors.add(value);
    if (Array.isArray(value)) {
        for (const child of value) {
            inspectJsonValue(child, label, maxDepth, depth + 1, ancestors);
        }
    }
    else {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
            throw new RefereeError('INVALID_JSON', label + ': non-plain object');
        }
        for (const [key, child] of Object.entries(value)) {
            if (!validUnicode(key)) {
                throw new RefereeError('INVALID_JSON', label + ': invalid Unicode member name');
            }
            inspectJsonValue(child, label, maxDepth, depth + 1, ancestors);
        }
    }
    ancestors.delete(value);
}
function scanDuplicateNamesAndDepth(raw, label, maxDepth) {
    let index = 0;
    const stack = [];
    while (index < raw.length) {
        const character = raw[index];
        if (character === '{') {
            stack.push({ object: true, keys: new Set(), expectKey: true });
            if (stack.length > maxDepth) {
                throw new RefereeError('INVALID_JSON', label + ': JSON depth exceeds ' + maxDepth);
            }
            index += 1;
        }
        else if (character === '[') {
            stack.push({ object: false });
            if (stack.length > maxDepth) {
                throw new RefereeError('INVALID_JSON', label + ': JSON depth exceeds ' + maxDepth);
            }
            index += 1;
        }
        else if (character === '}' || character === ']') {
            stack.pop();
            index += 1;
        }
        else if (character === ',') {
            const top = stack[stack.length - 1];
            if (top && top.object)
                top.expectKey = true;
            index += 1;
        }
        else if (character === '"') {
            const start = index;
            index += 1;
            while (index < raw.length) {
                if (raw[index] === '\\') {
                    index += 2;
                }
                else if (raw[index] === '"') {
                    index += 1;
                    break;
                }
                else {
                    index += 1;
                }
            }
            const top = stack[stack.length - 1];
            if (top && top.object && top.expectKey) {
                const key = JSON.parse(raw.slice(start, index));
                if (top.keys.has(key)) {
                    throw new RefereeError('INVALID_JSON', label + ': duplicate object member name');
                }
                top.keys.add(key);
                top.expectKey = false;
            }
        }
        else {
            index += 1;
        }
    }
}
export function parseStrictJson(input, options) {
    const label = options.label;
    const maxBytes = options.maxBytes;
    const maxDepth = options.maxDepth;
    let raw;
    if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
        if (input.byteLength > maxBytes) {
            throw new RefereeError('BYTE_LIMIT', label + ': byte limit exceeds ' + maxBytes);
        }
        try {
            raw = new TextDecoder('utf-8', { fatal: true }).decode(input);
        }
        catch {
            throw new RefereeError('INVALID_UTF8', label + ': invalid UTF-8');
        }
    }
    else if (typeof input === 'string') {
        if (byteLength(input) > maxBytes) {
            throw new RefereeError('BYTE_LIMIT', label + ': byte limit exceeds ' + maxBytes);
        }
        raw = input;
    }
    else {
        throw new RefereeError('INVALID_JSON', label + ': input must be bytes or text');
    }
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch {
        throw new RefereeError('INVALID_JSON', label + ': invalid JSON');
    }
    scanDuplicateNamesAndDepth(raw, label, maxDepth);
    inspectJsonValue(value, label, maxDepth, 0, new WeakSet());
    return value;
}
function canonicalValue(value) {
    if (Array.isArray(value))
        return value.map(canonicalValue);
    if (value !== null && typeof value === 'object') {
        const sorted = {};
        for (const key of Object.keys(value).sort())
            sorted[key] = canonicalValue(value[key]);
        return sorted;
    }
    return value;
}
export function canonicalJson(value) {
    inspectJsonValue(value, 'canonical JSON', 64, 0, new WeakSet());
    return JSON.stringify(canonicalValue(value)) + '\n';
}
function digestJson(value) {
    return 'sha256:' + crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}
function valuesEqual(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}
class SchemaError extends RefereeError {
    constructor(message) {
        super('SCHEMA', message);
        this.name = 'SchemaError';
    }
}
function schemaTypeMatches(value, expected) {
    if (expected === 'null')
        return value === null;
    if (expected === 'array')
        return Array.isArray(value);
    if (expected === 'object')
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    if (expected === 'integer')
        return Number.isSafeInteger(value);
    if (expected === 'number')
        return typeof value === 'number' && Number.isFinite(value);
    return typeof value === expected;
}
function pointerValue(root, fragment) {
    if (fragment === '' || fragment === '#')
        return root;
    if (!fragment.startsWith('#/'))
        throw new SchemaError('unsupported schema fragment: ' + fragment);
    let value = root;
    for (const token of fragment.slice(2).split('/')) {
        const key = token.replace(/~1/g, '/').replace(/~0/g, '~');
        if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) {
            throw new SchemaError('unresolved schema pointer: ' + fragment);
        }
        value = value[key];
    }
    return value;
}
function resolveSchemaReference(reference, context) {
    const hashAt = reference.indexOf('#');
    const file = hashAt === -1 ? reference : reference.slice(0, hashAt);
    const fragment = hashAt === -1 ? '' : reference.slice(hashAt);
    const root = file === '' ? context.root : context.store.get(file);
    if (!root)
        throw new SchemaError('unresolved schema reference: ' + reference);
    return { schema: pointerValue(root, fragment), root };
}
function validateAgainstSchema(value, schema, context, valuePath) {
    if (schema.$ref) {
        const resolved = resolveSchemaReference(schema.$ref, context);
        validateAgainstSchema(value, resolved.schema, {
            root: resolved.root,
            store: context.store,
        }, valuePath);
        return;
    }
    if (schema.oneOf) {
        let matches = 0;
        for (const candidate of schema.oneOf) {
            try {
                validateAgainstSchema(value, candidate, context, valuePath);
                matches += 1;
            }
            catch (error) {
                if (!(error instanceof SchemaError))
                    throw error;
            }
        }
        if (matches !== 1) {
            throw new SchemaError(valuePath + ': expected exactly one schema match');
        }
    }
    if (Object.hasOwn(schema, 'const') && !valuesEqual(value, schema.const)) {
        throw new SchemaError(valuePath + ': value does not match const');
    }
    if (schema.enum && !schema.enum.some((candidate) => valuesEqual(value, candidate))) {
        throw new SchemaError(valuePath + ': value is outside enum');
    }
    if (schema.type && !schemaTypeMatches(value, schema.type)) {
        throw new SchemaError(valuePath + ': expected type ' + schema.type);
    }
    if (schema.type === 'object') {
        const properties = schema.properties || {};
        for (const required of schema.required || []) {
            if (!Object.hasOwn(value, required)) {
                throw new SchemaError(valuePath + ': missing required property ' + required);
            }
        }
        for (const [key, child] of Object.entries(value)) {
            if (!Object.hasOwn(properties, key)) {
                if (schema.additionalProperties === false) {
                    throw new SchemaError(valuePath + ': unknown additional property ' + key);
                }
            }
            else {
                validateAgainstSchema(child, properties[key], context, valuePath + '.' + key);
            }
        }
    }
    if (schema.type === 'array') {
        if (schema.minItems !== undefined && value.length < schema.minItems) {
            throw new SchemaError(valuePath + ': too few array items');
        }
        if (schema.maxItems !== undefined && value.length > schema.maxItems) {
            throw new SchemaError(valuePath + ': too many array items');
        }
        if (schema.uniqueItems) {
            const seen = new Set();
            for (const child of value) {
                const key = canonicalJson(child);
                if (seen.has(key))
                    throw new SchemaError(valuePath + ': duplicate array item');
                seen.add(key);
            }
        }
        if (schema.items) {
            value.forEach((child, index) => {
                validateAgainstSchema(child, schema.items, context, valuePath + '[' + index + ']');
            });
        }
    }
    if (schema.type === 'string') {
        const length = Array.from(value).length;
        if (schema.minLength !== undefined && length < schema.minLength) {
            throw new SchemaError(valuePath + ': string is too short');
        }
        if (schema.maxLength !== undefined && length > schema.maxLength) {
            throw new SchemaError(valuePath + ': string is too long');
        }
        if (schema.pattern && !(new RegExp(schema.pattern, 'u')).test(value)) {
            throw new SchemaError(valuePath + ': string does not match pattern');
        }
    }
    if (schema.type === 'integer' || schema.type === 'number') {
        if (schema.minimum !== undefined && value < schema.minimum) {
            throw new SchemaError(valuePath + ': number is below minimum');
        }
        if (schema.maximum !== undefined && value > schema.maximum) {
            throw new SchemaError(valuePath + ': number exceeds maximum');
        }
    }
}
function validateDocument(value, schema, store) {
    validateAgainstSchema(value, schema, { root: schema, store }, '$');
    return value;
}
function assertClosedSchema(schema, label, seen) {
    if (schema === null || typeof schema !== 'object' || seen.has(schema))
        return;
    seen.add(schema);
    if (schema.type === 'object' && schema.additionalProperties !== false) {
        throw new RefereeError('SCHEMA', label + ': object schema is not closed');
    }
    for (const key of ['$defs', 'properties']) {
        if (schema[key]) {
            for (const [name, child] of Object.entries(schema[key])) {
                assertClosedSchema(child, label + '.' + key + '.' + name, seen);
            }
        }
    }
    for (const key of ['oneOf', 'allOf', 'anyOf']) {
        if (schema[key]) {
            schema[key].forEach((child, index) => {
                assertClosedSchema(child, label + '.' + key + '[' + index + ']', seen);
            });
        }
    }
    if (schema.items && typeof schema.items === 'object') {
        assertClosedSchema(schema.items, label + '.items', seen);
    }
}
async function readStrictJsonFile(file, options) {
    const bytes = await readFile(file);
    return parseStrictJson(bytes, options);
}
function sortedUniqueStrings(values) {
    for (let index = 1; index < values.length; index += 1) {
        if (Buffer.compare(Buffer.from(values[index - 1], 'utf8'), Buffer.from(values[index], 'utf8')) >= 0) {
            return false;
        }
    }
    return true;
}
export async function loadRefereePack(manifestPath) {
    const schemaDirectory = path.resolve(path.dirname(manifestPath), '../schemas');
    const names = [
        'case.schema.json',
        'runner-result.schema.json',
        'report.schema.json',
        'manifest.schema.json',
    ];
    const loaded = {};
    for (const name of names) {
        loaded[name] = await readStrictJsonFile(path.join(schemaDirectory, name), {
            label: name,
            maxBytes: HARD_LIMITS.schemaBytes,
            maxDepth: 64,
        });
        assertClosedSchema(loaded[name], name, new WeakSet());
    }
    const store = new Map();
    for (const [name, schema] of Object.entries(loaded)) {
        store.set(name, schema);
        if (schema.$id)
            store.set(schema.$id, schema);
    }
    const manifest = await readStrictJsonFile(manifestPath, {
        label: 'referee manifest',
        maxBytes: HARD_LIMITS.manifestBytes,
        maxDepth: 32,
    });
    validateDocument(manifest, loaded['manifest.schema.json'], store);
    if (manifest.fixtures.length > manifest.limits.max_cases) {
        throw new RefereeError('MANIFEST', 'manifest fixture count exceeds max_cases');
    }
    const caseIds = new Set();
    for (const fixture of manifest.fixtures) {
        validateDocument(fixture.case, loaded['case.schema.json'], store);
        validateDocument(fixture.expected, loaded['runner-result.schema.json'], store);
        if (fixture.case.case_id !== fixture.expected.case_id) {
            throw new RefereeError('MANIFEST', 'fixture case/result identifier mismatch');
        }
        if (caseIds.has(fixture.case.case_id)) {
            throw new RefereeError('MANIFEST', 'duplicate fixture case identifier');
        }
        caseIds.add(fixture.case.case_id);
        if (!sortedUniqueStrings(fixture.expected.reason_codes)) {
            throw new RefereeError('MANIFEST', fixture.case.case_id + ': reason_codes must be sorted and unique');
        }
        if (byteLength(canonicalJson(fixture.case)) > manifest.limits.max_case_bytes) {
            throw new RefereeError('MANIFEST', fixture.case.case_id + ': case exceeds max_case_bytes');
        }
    }
    return {
        manifest,
        schemas: {
            case: loaded['case.schema.json'],
            runnerResult: loaded['runner-result.schema.json'],
            report: loaded['report.schema.json'],
            manifest: loaded['manifest.schema.json'],
            store,
        },
        validateCase(value) {
            return validateDocument(value, loaded['case.schema.json'], store);
        },
        validateResult(value) {
            return validateDocument(value, loaded['runner-result.schema.json'], store);
        },
        validateReport(value) {
            return validateDocument(value, loaded['report.schema.json'], store);
        },
        validateManifest(value) {
            return validateDocument(value, loaded['manifest.schema.json'], store);
        },
    };
}
export function sanitizedChildEnvironment(source = process.env) {
    const result = {
        CI: '1',
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        NO_COLOR: '1',
        PATH: source.PATH || '/usr/local/bin:/usr/bin:/bin',
        TZ: 'UTC',
    };
    if (source.SystemRoot)
        result.SystemRoot = source.SystemRoot;
    return result;
}
function validateCommandArgv(commandArgv) {
    if (!Array.isArray(commandArgv) || commandArgv.length < 1
        || commandArgv.length > HARD_LIMITS.commandArguments) {
        throw new RefereeError('COMMAND', 'command argv must contain 1-' + HARD_LIMITS.commandArguments + ' strings');
    }
    for (const argument of commandArgv) {
        if (typeof argument !== 'string' || argument.length === 0
            || /[\u0000-\u001f\u007f]/u.test(argument)
            || byteLength(argument) > HARD_LIMITS.argumentBytes) {
            throw new RefereeError('COMMAND', 'invalid command argument');
        }
    }
}
function isContained(root, candidate) {
    const relative = path.relative(root, candidate);
    return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}
async function resolveExecutable(command, workspace, childEnvironment) {
    const candidates = [];
    if (path.isAbsolute(command)) {
        candidates.push(command);
    }
    else if (command.includes('/') || command.includes('\\')) {
        candidates.push(path.resolve(workspace, command));
    }
    else {
        for (const directory of (childEnvironment.PATH || '').split(path.delimiter)) {
            if (directory)
                candidates.push(path.join(directory, command));
        }
    }
    for (const candidate of candidates) {
        try {
            await access(candidate, fsConstants.X_OK);
            const resolved = await realpath(candidate);
            const stat = await lstat(resolved);
            if (stat.isFile())
                return resolved;
        }
        catch {
            // Continue searching PATH.
        }
    }
    throw new RefereeError('COMMAND_FAILED', 'command executable is unavailable');
}
export async function digestExecutable(executable) {
    const resolved = await realpath(executable);
    const stat = await lstat(resolved);
    if (!stat.isFile())
        throw new RefereeError('COMMAND_FAILED', 'executable is not a regular file');
    const hash = crypto.createHash('sha256');
    await new Promise((resolve, reject) => {
        const stream = createReadStream(resolved);
        stream.on('data', (chunk) => hash.update(chunk));
        stream.once('error', reject);
        stream.once('end', resolve);
    });
    return 'sha256:' + hash.digest('hex');
}
function pinsEqual(left, right) {
    if (!DIGEST_RE.test(left) || !DIGEST_RE.test(right))
        return false;
    return crypto.timingSafeEqual(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function terminateChild(child, detached) {
    try {
        if (detached && child.pid) {
            process.kill(-child.pid, 'SIGKILL');
        }
        else {
            child.kill('SIGKILL');
        }
    }
    catch {
        // The process may already have exited.
    }
}
async function invokeExternal(options) {
    const input = Buffer.from(canonicalJson(options.caseDocument), 'utf8');
    if (input.byteLength > options.limits.max_case_bytes) {
        return { error: 'COMMAND_FAILED', stdout: null };
    }
    const childEnvironment = sanitizedChildEnvironment();
    let executable;
    try {
        executable = await resolveExecutable(options.commandArgv[0], options.workspace, childEnvironment);
        const actualPin = await digestExecutable(executable);
        if (!pinsEqual(actualPin, options.runnerPin.executable_sha256)) {
            return { error: 'EXECUTABLE_PIN_MISMATCH', stdout: null };
        }
    }
    catch (error) {
        return {
            error: error instanceof RefereeError ? error.code : 'COMMAND_FAILED',
            stdout: null,
        };
    }
    return new Promise((resolve) => {
        const detached = process.platform !== 'win32';
        let child;
        try {
            child = spawn(executable, options.commandArgv.slice(1), {
                cwd: options.workspace,
                detached,
                env: childEnvironment,
                shell: false,
                stdio: ['pipe', 'pipe', 'pipe'],
                windowsHide: true,
            });
        }
        catch {
            resolve({ error: 'COMMAND_FAILED', stdout: null });
            return;
        }
        const stdoutChunks = [];
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let errorCode = null;
        let settled = false;
        let timer = null;
        const finish = (code) => {
            if (settled)
                return;
            settled = true;
            if (timer)
                clearTimeout(timer);
            if (!errorCode && code !== 0)
                errorCode = 'COMMAND_FAILED';
            resolve({
                error: errorCode,
                stdout: errorCode ? null : Buffer.concat(stdoutChunks),
            });
        };
        const failAndKill = (code) => {
            if (!errorCode)
                errorCode = code;
            terminateChild(child, detached);
        };
        child.stdout.on('data', (chunk) => {
            stdoutBytes += chunk.length;
            if (stdoutBytes > options.limits.max_result_bytes) {
                failAndKill('STDOUT_LIMIT');
            }
            else {
                stdoutChunks.push(chunk);
            }
        });
        child.stderr.on('data', (chunk) => {
            stderrBytes += chunk.length;
            if (stderrBytes > options.limits.max_stderr_bytes)
                failAndKill('STDERR_LIMIT');
        });
        child.once('error', () => {
            errorCode = errorCode || 'COMMAND_FAILED';
            terminateChild(child, detached);
        });
        child.once('close', finish);
        child.stdin.on('error', () => {
            // EPIPE is reflected by the child exit and never relaxes the result.
        });
        child.stdin.end(input);
        timer = setTimeout(() => {
            failAndKill('TIMEOUT');
        }, options.limits.timeout_ms);
        timer.unref();
    });
}
function emptyRow(fixture, error) {
    return {
        case_id: fixture.case.case_id,
        case_digest: digestJson(fixture.case),
        expected_digest: digestJson(fixture.expected),
        actual: null,
        actual_digest: null,
        matched: false,
        error,
    };
}
export async function runExternalCase(options) {
    validateCommandArgv(options.commandArgv);
    if (!options.runnerPin || !DIGEST_RE.test(options.runnerPin.executable_sha256 || '')) {
        throw new RefereeError('COMMAND', 'runner_pin.executable_sha256 is required');
    }
    const observed = [];
    for (let run = 0; run < options.limits.deterministic_runs; run += 1) {
        const invocation = await invokeExternal({
            caseDocument: options.fixture.case,
            commandArgv: options.commandArgv,
            workspace: options.workspace,
            limits: options.limits,
            runnerPin: options.runnerPin,
        });
        if (invocation.error)
            return emptyRow(options.fixture, invocation.error);
        let result;
        try {
            result = parseStrictJson(invocation.stdout, {
                label: options.fixture.case.case_id + ' stdout',
                maxBytes: options.limits.max_result_bytes,
                maxDepth: options.limits.max_json_depth,
            });
        }
        catch (error) {
            if (error instanceof RefereeError && error.code === 'INVALID_UTF8') {
                return emptyRow(options.fixture, 'INVALID_UTF8');
            }
            return emptyRow(options.fixture, 'INVALID_JSON');
        }
        try {
            validateDocument(result, options.resultSchema, options.schemaStore);
        }
        catch {
            return emptyRow(options.fixture, 'RESULT_SCHEMA');
        }
        if (result.case_id !== options.fixture.case.case_id) {
            return emptyRow(options.fixture, 'CASE_ID_MISMATCH');
        }
        if (!sortedUniqueStrings(result.reason_codes)) {
            return emptyRow(options.fixture, 'RESULT_SCHEMA');
        }
        observed.push(result);
    }
    const firstCanonical = canonicalJson(observed[0]);
    if (observed.some((result) => canonicalJson(result) !== firstCanonical)) {
        const row = emptyRow(options.fixture, 'NONDETERMINISTIC');
        row.actual = observed[0];
        row.actual_digest = digestJson(observed[0]);
        return row;
    }
    const matched = valuesEqual(observed[0], options.fixture.expected);
    return {
        case_id: options.fixture.case.case_id,
        case_digest: digestJson(options.fixture.case),
        expected_digest: digestJson(options.fixture.expected),
        actual: observed[0],
        actual_digest: digestJson(observed[0]),
        matched,
        error: matched ? null : 'RESULT_MISMATCH',
    };
}
async function verifyCheckedInEntrypoint(entrypoint, commandArgv, workspace) {
    if (typeof entrypoint !== 'string' || entrypoint.length === 0 || path.isAbsolute(entrypoint)
        || /[\u0000-\u001f\u007f]/u.test(entrypoint)) {
        throw new RefereeError('COMMAND', 'checked-in entrypoint must be a relative path');
    }
    const absolute = path.resolve(workspace, entrypoint);
    if (!isContained(workspace, absolute)) {
        throw new RefereeError('COMMAND', 'checked-in entrypoint escapes workspace');
    }
    const directStat = await lstat(absolute);
    if (!directStat.isFile() || directStat.isSymbolicLink()) {
        throw new RefereeError('COMMAND', 'checked-in entrypoint must be a non-symlink regular file');
    }
    const resolved = await realpath(absolute);
    if (!isContained(await realpath(workspace), resolved)) {
        throw new RefereeError('COMMAND', 'checked-in entrypoint resolves outside workspace');
    }
    const present = commandArgv.slice(0, 2).some((argument) => {
        if (path.isAbsolute(argument))
            return path.resolve(argument) === absolute;
        if (argument.includes('/') || argument.includes('\\')) {
            return path.resolve(workspace, argument) === absolute;
        }
        return argument === entrypoint;
    });
    if (!present) {
        throw new RefereeError('COMMAND', 'checked-in entrypoint must be argv[0] or argv[1]');
    }
    const tracked = spawnSync('git', [
        '-C', workspace, 'ls-files', '--error-unmatch', '--', entrypoint,
    ], {
        encoding: 'utf8',
        env: sanitizedChildEnvironment(),
        shell: false,
        stdio: 'ignore',
    });
    if (tracked.status !== 0) {
        throw new RefereeError('COMMAND', 'entrypoint is not checked in');
    }
}
async function writeReport(reportPath, report, options) {
    const absolute = path.resolve(reportPath);
    if (options.mustBeInWorkspace && !isContained(path.resolve(options.workspace), absolute)) {
        throw new RefereeError('REPORT', 'report path escapes workspace');
    }
    await mkdir(path.dirname(absolute), { recursive: true });
    try {
        const existing = await lstat(absolute);
        if (existing.isSymbolicLink() || !existing.isFile()) {
            throw new RefereeError('REPORT', 'report target must be a regular file');
        }
    }
    catch (error) {
        if (error instanceof RefereeError)
            throw error;
        if (error && error.code !== 'ENOENT')
            throw error;
    }
    const temporary = absolute + '.tmp-' + process.pid + '-' + crypto.randomBytes(6).toString('hex');
    await writeFile(temporary, canonicalJson(report), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await rename(temporary, absolute);
}
export async function runReferee(options) {
    const pack = await loadRefereePack(options.manifestPath);
    validateCommandArgv(options.commandArgv);
    if (!options.runnerPin || !DIGEST_RE.test(options.runnerPin.executable_sha256 || '')) {
        throw new RefereeError('COMMAND', 'runner_pin.executable_sha256 is required');
    }
    if (options.requireCheckedInCommand) {
        await verifyCheckedInEntrypoint(options.checkedInEntrypoint, options.commandArgv, options.workspace);
    }
    const rows = [];
    for (const fixture of pack.manifest.fixtures) {
        rows.push(await runExternalCase({
            fixture,
            commandArgv: options.commandArgv,
            resultSchema: pack.schemas.runnerResult,
            schemaStore: pack.schemas.store,
            limits: pack.manifest.limits,
            workspace: options.workspace,
            runnerPin: options.runnerPin,
        }));
    }
    const passed = rows.filter((row) => row.matched).length;
    const failed = rows.length - passed;
    const report = {
        '@version': 'AEB-1-REFEREE-REPORT-v1',
        assessment: 'SELF_TEST',
        suite_id: pack.manifest.suite_id,
        profile: pack.manifest.profile,
        manifest_digest: digestJson(pack.manifest),
        implementation: {
            command: options.commandArgv[0],
            entrypoint: options.checkedInEntrypoint || null,
            arguments: options.commandArgv.slice(1),
            runner_pin: {
                executable_sha256: options.runnerPin.executable_sha256,
                verification: 'BEFORE_EACH_SPAWN',
            },
        },
        deterministic_runs: pack.manifest.limits.deterministic_runs,
        rows,
        summary: {
            total: rows.length,
            passed,
            failed,
            outcome: failed === 0 ? 'PASS' : 'FAIL',
        },
        claim_boundary: {
            certification: false,
            authorization: false,
            production_deployment: false,
            production_sandbox: false,
        },
    };
    pack.validateReport(report);
    const reportBytes = byteLength(canonicalJson(report));
    if (reportBytes > pack.manifest.limits.max_report_bytes) {
        throw new RefereeError('REPORT', 'report exceeds max_report_bytes');
    }
    if (report.summary.total !== report.summary.passed + report.summary.failed) {
        throw new RefereeError('REPORT', 'report summary is inconsistent');
    }
    await writeReport(options.reportPath, report, {
        workspace: options.workspace,
        mustBeInWorkspace: Boolean(options.reportMustBeInWorkspace),
    });
    return report;
}
function takeOption(argv, index, name) {
    if (index + 1 >= argv.length)
        throw new RefereeError('USAGE', name + ' requires a value');
    return argv[index + 1];
}
function parseCli(argv) {
    const options = {
        requireCheckedInCommand: false,
        reportMustBeInWorkspace: false,
    };
    for (let index = 0; index < argv.length; index += 1) {
        const name = argv[index];
        if (name === '--require-checked-in-command') {
            options.requireCheckedInCommand = true;
        }
        else if (name === '--report-must-be-in-workspace') {
            options.reportMustBeInWorkspace = true;
        }
        else if ([
            '--manifest',
            '--report',
            '--report-env',
            '--workspace',
            '--command-json',
            '--command-env',
            '--entrypoint',
            '--entrypoint-env',
            '--executable-sha256',
            '--executable-sha256-env',
        ].includes(name)) {
            const value = takeOption(argv, index, name);
            index += 1;
            options[name.slice(2).replace(/-/g, '_')] = value;
        }
        else {
            throw new RefereeError('USAGE', 'unknown argument: ' + name);
        }
    }
    return options;
}
function oneSource(direct, environmentName, label) {
    if (direct && environmentName) {
        throw new RefereeError('USAGE', label + ' may use a direct value or environment source, not both');
    }
    const value = environmentName ? process.env[environmentName] : direct;
    if (!value)
        throw new RefereeError('USAGE', label + ' is required');
    return value;
}
export async function cliMain(argv = process.argv.slice(2)) {
    const cli = parseCli(argv);
    const manifestPath = oneSource(cli.manifest, null, '--manifest');
    const reportPath = oneSource(cli.report, cli.report_env, '--report');
    if (byteLength(reportPath) > 1024 || /[\u0000-\u001f\u007f]/u.test(reportPath)) {
        throw new RefereeError('USAGE', '--report contains invalid path characters');
    }
    const workspace = path.resolve(cli.workspace || process.cwd());
    const commandText = oneSource(cli.command_json, cli.command_env, '--command-json');
    const executableSha256 = oneSource(cli.executable_sha256, cli.executable_sha256_env, '--executable-sha256');
    const checkedInEntrypoint = cli.entrypoint_env
        ? process.env[cli.entrypoint_env]
        : (cli.entrypoint || null);
    if (cli.requireCheckedInCommand && !checkedInEntrypoint) {
        throw new RefereeError('USAGE', '--entrypoint is required with --require-checked-in-command');
    }
    const commandArgv = parseStrictJson(commandText, {
        label: 'command argv',
        maxBytes: HARD_LIMITS.commandBytes,
        maxDepth: 4,
    });
    const report = await runReferee({
        manifestPath: path.resolve(manifestPath),
        reportPath: path.isAbsolute(reportPath) ? reportPath : path.resolve(workspace, reportPath),
        commandArgv,
        workspace,
        runnerPin: { executable_sha256: executableSha256 },
        checkedInEntrypoint,
        requireCheckedInCommand: cli.requireCheckedInCommand,
        reportMustBeInWorkspace: cli.reportMustBeInWorkspace,
    });
    process.stdout.write('SELF_TEST\n');
    if (report.summary.outcome !== 'PASS')
        process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    cliMain().catch((error) => {
        const message = error instanceof Error ? error.message : 'unknown error';
        process.stderr.write('referee self-test error: ' + message + '\n');
        process.exitCode = 2;
    });
}
