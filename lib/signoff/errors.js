/**
 * EP Signoff — Error class and typed error codes.
 *
 * Machine-readable error builders for accountable signoff operations.
 *
 * @license Apache-2.0
 */

export class SignoffError extends Error {
  constructor(message, status = 400, code = 'SIGNOFF_ERROR') {
    super(message);
    this.name = 'SignoffError';
    this.status = status;
    this.code = code;
  }
}
