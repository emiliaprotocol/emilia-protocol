// SPDX-License-Identifier: Apache-2.0
//
// @emilia-protocol/gateway-authz — one external-authorization core, two thin
// proxy adapters.

export {
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_CARRIER_BYTES,
  DEFAULT_PROOF_HEADER,
  DEFAULT_REQUIRED_FIELDS,
  GATEWAY_BINDING_VERSION,
  GatewayBindingError,
  HTTP_TRANSPORT,
  httpActionBinding,
  normalizeRequestDescriptor,
  readSingleHeader,
  selectMaterialHeaders,
} from './descriptor.mjs';

export {
  RECEIPT_REQUIRED_STATUS,
  REFUSAL_REASON_HEADER,
  VERIFIED_ACTION_HEADER,
  VERIFIED_RECEIPT_ID_HEADER,
  authorizeAndForward,
  createExternalAuthorizer,
  statusForReason,
} from './authz.mjs';

export {
  ENVOY_INTERNAL_HEADERS,
  ENVOY_ORIGINAL_HOST_HEADER,
  ENVOY_ORIGINAL_METHOD_HEADER,
  ENVOY_ORIGINAL_URI_HEADER,
  ENVOY_PARTIAL_BODY_HEADER,
  createEnvoyHttpHandler,
  envoyDescriptor,
  toEnvoyHttpResponse,
} from './envoy.mjs';

export {
  createKongAccessHandler,
  kongAuthzDecision,
  kongDescriptor,
  toKongExit,
} from './kong.mjs';
