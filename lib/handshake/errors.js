/**
 * EP Handshake — Error class and typed error codes.
 *
 * Machine-readable error builders for handshake operations.
 *
 * @license Apache-2.0
 */

export class HandshakeError extends Error {
  constructor(message, status = 400, code = 'HANDSHAKE_ERROR') {
    super(message);
    this.name = 'HandshakeError';
    this.status = status;
    this.code = code;
  }
}
