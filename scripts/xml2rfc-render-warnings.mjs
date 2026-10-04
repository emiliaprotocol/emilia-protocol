// SPDX-License-Identifier: Apache-2.0

const INDIVIDUAL_DRAFT_WARNINGS = [/Expected a valid submissionType/, /Setting consensus="true"/];
const DOCUMENT_AGE_WARNING = /^The document date \((\d{4}-\d{2}-\d{2})\) is more than 3 days away from today's date$/u;

/**
 * Keep validation errors and unknown warnings fatal. A posted snapshot may
 * retain its original date; only its exact, past-date freshness warning is
 * exempt, and callers omit historicalDocumentDate for a new filing.
 *
 * @param {string} stderr
 * @param {{ historicalDocumentDate?: string | null, today?: string }} [options]
 * @returns {string[]}
 */
export function unexpectedXml2rfcWarnings(stderr, {
  historicalDocumentDate = null,
  today = new Date().toISOString().slice(0, 10),
} = {}) {
  const historicalTime = historicalDocumentDate === null ? NaN : Date.parse(historicalDocumentDate);
  const todayTime = Date.parse(today);
  const isPastSnapshot = Number.isFinite(historicalTime) && Number.isFinite(todayTime)
    && todayTime - historicalTime > 3 * 24 * 60 * 60 * 1000;
  return stderr.split(/\r?\n/u).filter((line) => {
    const diagnostic = /\b(Warning|Error):\s*(.*)$/u.exec(line);
    if (!diagnostic) return false;
    const [, severity, message] = diagnostic;
    if (severity === 'Error') return true;
    if (INDIVIDUAL_DRAFT_WARNINGS.some((warning) => warning.test(message))) return false;
    const ageWarning = DOCUMENT_AGE_WARNING.exec(message.trim());
    return !(isPastSnapshot && ageWarning?.[1] === historicalDocumentDate);
  });
}
