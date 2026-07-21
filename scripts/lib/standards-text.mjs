// SPDX-License-Identifier: Apache-2.0
// Generated from standards-text.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
function parseTag(value, offset) {
    if (value[offset] !== '<')
        return null;
    if (value.startsWith('<!--', offset)) {
        const commentEnd = value.indexOf('-->', offset + 4);
        return {
            end: commentEnd === -1 ? value.length - 1 : commentEnd + 2,
            name: null,
            closing: false,
            selfClosing: false,
        };
    }
    let cursor = offset + 1;
    let closing = false;
    if (value[cursor] === '/') {
        closing = true;
        cursor += 1;
    }
    const nameStart = cursor;
    while (cursor < value.length) {
        const code = value.charCodeAt(cursor);
        const isNameCharacter = (code >= 48 && code <= 57)
            || (code >= 65 && code <= 90)
            || (code >= 97 && code <= 122)
            || value[cursor] === ':'
            || value[cursor] === '-';
        if (!isNameCharacter)
            break;
        cursor += 1;
    }
    if (cursor === nameStart)
        return null;
    const name = value.slice(nameStart, cursor).toLowerCase();
    let quote = null;
    let lastNonSpace = cursor - 1;
    for (; cursor < value.length; cursor += 1) {
        const character = value[cursor];
        if (quote !== null) {
            if (character === quote)
                quote = null;
            continue;
        }
        if (character === '"' || character === "'") {
            quote = character;
            continue;
        }
        if (character === '>') {
            return {
                end: cursor,
                name,
                closing,
                selfClosing: value[lastNonSpace] === '/',
            };
        }
        if (!/\s/.test(character))
            lastNonSpace = cursor;
    }
    return null;
}
/**
 * Extract visible text without using regular expressions as an HTML parser.
 *
 * This is intentionally a small, deterministic scanner rather than a sanitizer:
 * the observatory only needs stable text for quote matching. Script and style
 * bodies are suppressed, quoted attribute delimiters are respected, and malformed
 * markup is retained as text instead of being treated as trusted structure.
 */
export function stripMarkup(value) {
    let output = '';
    let suppressedElement = null;
    for (let cursor = 0; cursor < value.length; cursor += 1) {
        if (value[cursor] !== '<') {
            if (suppressedElement === null)
                output += value[cursor];
            continue;
        }
        const tag = parseTag(value, cursor);
        if (!tag) {
            if (suppressedElement === null)
                output += '<';
            continue;
        }
        if (suppressedElement !== null) {
            if (tag.closing && tag.name === suppressedElement) {
                suppressedElement = null;
                output += ' ';
            }
            cursor = tag.end;
            continue;
        }
        if (!tag.closing && !tag.selfClosing && (tag.name === 'script' || tag.name === 'style')) {
            suppressedElement = tag.name;
        }
        output += ' ';
        cursor = tag.end;
    }
    return output;
}
function decodeEntity(entity, original) {
    const named = new Map([
        ['amp', '&'], ['lt', '<'], ['gt', '>'], ['quot', '"'], ['apos', "'"], ['nbsp', ' '],
        ['ndash', '-'], ['mdash', '-'], ['lsquo', "'"], ['rsquo', "'"], ['ldquo', '"'], ['rdquo', '"'],
    ]);
    let codePoint;
    if (entity.startsWith('#x'))
        codePoint = Number.parseInt(entity.slice(2), 16);
    else if (entity.startsWith('#'))
        codePoint = Number.parseInt(entity.slice(1), 10);
    else
        return named.get(entity.toLowerCase()) ?? original;
    if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff
        || (codePoint >= 0xd800 && codePoint <= 0xdfff))
        return original;
    return String.fromCodePoint(codePoint);
}
function decodeEntities(value) {
    return value.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, entity) => (decodeEntity(entity, match)));
}
export function normalizeStandardsText(value) {
    return stripMarkup(decodeEntities(value))
        .replace(/-\s*\r?\n\s*(?=[a-z])/g, '-')
        .replace(/[\u2018\u2019]/g, "'")
        .replace(/[\u201c\u201d]/g, '"')
        .replace(/[\u2013\u2014]/g, '-')
        .replace(/\s+/g, ' ')
        .trim();
}
