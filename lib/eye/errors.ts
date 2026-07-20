/**
 * EP Eye — Error class and typed error codes.
 *
 * Machine-readable error builders for Eye observation operations.
 *
 * @license Apache-2.0
 */

export class EyeError extends Error {
  constructor(message, status = 400, code = 'EYE_ERROR') {
    super(message);
    this.name = 'EyeError';
    this.status = status;
    this.code = code;
  }
}
