/**
 * EP Eye — Error class and typed error codes.
 *
 * Machine-readable error builders for Eye observation operations.
 *
 * @license Apache-2.0
 */

export class EyeError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number = 400, code: string = 'EYE_ERROR') {
    super(message);
    this.name = 'EyeError';
    this.status = status;
    this.code = code;
  }
}
