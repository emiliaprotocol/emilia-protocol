/**
 * EP Signoff — Error class and typed error codes.
 *
 * Machine-readable error builders for accountable signoff operations.
 *
 * @license Apache-2.0
 */

export class SignoffError extends Error {
  /**
   * @param {string} message - Human-readable error message
   * @param {number} [status] - HTTP status code
   * @param {string} [code] - Machine-readable error code
   */
  constructor(message, status = 400, code = 'SIGNOFF_ERROR') {
    super(message);
    this.name = 'SignoffError';
    this.status = status;
    this.code = code;
  }
}
