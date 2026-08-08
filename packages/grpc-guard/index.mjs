// SPDX-License-Identifier: Apache-2.0
//
// @emilia-protocol/grpc-guard — EMILIA rides gRPC instead of replacing it.

export {
  DEFAULT_MAX_CARRIER_BYTES,
  DEFAULT_MAX_REQUEST_BYTES,
  DEFAULT_REQUIRED_FIELDS,
  GRPC_BINDING_VERSION,
  GRPC_TRANSPORT,
  GrpcBindingError,
  METADATA_KEY_PATTERN,
  METHOD_PATH_PATTERN,
  REQUEST_BINDING_SOURCES,
  TARGET_PATTERN,
  grpcActionBinding,
  readMetadataValues,
  readSingleMetadataValue,
  resolveRequestBytes,
  selectMaterialMetadata,
} from './binding.mjs';

export {
  DEFAULT_RECEIPT_METADATA_KEY,
  INDETERMINATE_REASON,
  createGrpcReceiptGuard,
} from './guard.mjs';

export {
  GRPC_STATUS,
  GRPC_STATUS_NAME,
  refusalToServiceError,
  statusForReason,
} from './status.mjs';

export {
  createClientInterceptor,
  createClientReceiptAttacher,
  createServerInterceptor,
  guardUnaryHandler,
  passthroughRequestDefinition,
} from './interceptors.mjs';
