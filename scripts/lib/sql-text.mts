// SPDX-License-Identifier: Apache-2.0

/**
 * Replace SQL comments and literal bodies with spaces while preserving line
 * breaks and executable SQL tokens. PostgreSQL permits nested block comments
 * and dollar-quoted function bodies; both must be masked so documentation or
 * procedural text cannot be mistaken for top-level DDL.
 */
export function maskSqlNonCode(sql: string): string {
  const output: string[] = [...sql];
  let cursor = 0;

  const mask = (start: number, end: number): void => {
    for (let index = start; index < end; index += 1) {
      if (output[index] !== '\n' && output[index] !== '\r') output[index] = ' ';
    }
  };

  while (cursor < sql.length) {
    if (sql.startsWith('--', cursor)) {
      const end = sql.indexOf('\n', cursor + 2);
      const commentEnd = end === -1 ? sql.length : end;
      mask(cursor, commentEnd);
      cursor = commentEnd;
      continue;
    }

    if (sql.startsWith('/*', cursor)) {
      const start = cursor;
      let depth = 1;
      cursor += 2;
      while (cursor < sql.length && depth > 0) {
        if (sql.startsWith('/*', cursor)) {
          depth += 1;
          cursor += 2;
        } else if (sql.startsWith('*/', cursor)) {
          depth -= 1;
          cursor += 2;
        } else {
          cursor += 1;
        }
      }
      mask(start, cursor);
      continue;
    }

    if (sql[cursor] === "'") {
      const start = cursor;
      cursor += 1;
      while (cursor < sql.length) {
        if (sql[cursor] !== "'") {
          cursor += 1;
          continue;
        }
        if (sql[cursor + 1] === "'") {
          cursor += 2;
          continue;
        }
        cursor += 1;
        break;
      }
      mask(start, cursor);
      continue;
    }

    if (sql[cursor] === '$') {
      const delimiter = sql.slice(cursor).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/)?.[0];
      if (delimiter) {
        const start = cursor;
        const closing = sql.indexOf(delimiter, cursor + delimiter.length);
        cursor = closing === -1 ? sql.length : closing + delimiter.length;
        mask(start, cursor);
        continue;
      }
    }

    // Double-quoted identifiers are executable tokens, not string literals.
    // Preserve them, including doubled quote escapes.
    if (sql[cursor] === '"') {
      cursor += 1;
      while (cursor < sql.length) {
        if (sql[cursor] !== '"') {
          cursor += 1;
          continue;
        }
        if (sql[cursor + 1] === '"') {
          cursor += 2;
          continue;
        }
        cursor += 1;
        break;
      }
      continue;
    }

    cursor += 1;
  }

  return output.join('');
}
