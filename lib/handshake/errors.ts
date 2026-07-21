/**
 * EP Handshake — Error class and typed error codes.
 *
 * Machine-readable error builders for handshake operations.
 *
 * @license Apache-2.0
 */

export class HandshakeError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number = 400, code: string = 'HANDSHAKE_ERROR') {
    super(message);
    this.name = 'HandshakeError';
    this.status = status;
    this.code = code;
  }
}
