// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — MongoDB system-of-record adapter.
 *
 * The opaque connector binds the held Mongo client to a deployment-pinned
 * cluster identity. Callers can propose database, collection, filter, update,
 * and operation id; they cannot relabel the credential's cluster. Filters and
 * update documents are executed only as preimages of the digests authorized
 * by the receipt.
 */
import { canonicalActuatorObject, createAdapter, hashCanonical, manifestFromPack } from './_kit.js';

const MONGODB_FILTER_BINDING_VERSION = 'EP-MONGODB-FILTER-v1';
const MONGODB_UPDATE_BINDING_VERSION = 'EP-MONGODB-UPDATE-v1';
const SAFE_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

function boundedComponent(value: unknown, field: string): string {
  if (typeof value !== 'string' || !SAFE_COMPONENT.test(value)) {
    throw new TypeError(`MongoDB ${field} must be a bounded identifier`);
  }
  return value;
}

function boundedOperationId(value: unknown): string {
  if (typeof value !== 'string' || value.length < 8 || value.length > 256
      || !/^[A-Za-z0-9:_.@/-]+$/.test(value)) {
    throw new TypeError('MongoDB operation_id must be a bounded unique identifier');
  }
  return value;
}

function documentDigest(version: string, value: unknown): string {
  return `sha256:${hashCanonical({ version, value })}`;
}

export function mongoFilterDigest(filter: unknown): string {
  return documentDigest(MONGODB_FILTER_BINDING_VERSION, filter);
}

export function mongoUpdateDigest(update: unknown): string {
  return documentDigest(MONGODB_UPDATE_BINDING_VERSION, update);
}

export const MONGODB_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'mongodb.document.delete_many',
    label: 'MongoDB bulk document deletion',
    action_type: 'mongodb.document.delete_many',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { protocol: 'mongodb', tool: 'delete_many' },
    why: 'Deletes a selected population from the system of record. Bind the pinned cluster, namespace, filter, and operation id.',
    execution_binding: { required_fields: ['action_type', 'cluster', 'database', 'collection', 'filter_digest', 'operation_id'] },
  }),
  Object.freeze({
    id: 'mongodb.document.update_many',
    label: 'MongoDB bulk document update',
    action_type: 'mongodb.document.update_many',
    risk: 'high',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { protocol: 'mongodb', tool: 'update_many' },
    why: 'Rewrites a selected population. Bind both the selection and update documents.',
    execution_binding: { required_fields: ['action_type', 'cluster', 'database', 'collection', 'filter_digest', 'update_digest', 'operation_id'] },
  }),
  Object.freeze({
    id: 'mongodb.collection.drop',
    label: 'MongoDB collection drop',
    action_type: 'mongodb.collection.drop',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'quorum',
    match: { protocol: 'mongodb', tool: 'drop_collection' },
    why: 'Destroys an entire collection. Require a distinct-person quorum bound to the exact namespace.',
    execution_binding: { required_fields: ['action_type', 'cluster', 'database', 'collection', 'operation_id'] },
  }),
]);

const OPS = {
  'document.delete_many': {
    selector: { protocol: 'mongodb', tool: 'delete_many' },
    observed: (p) => ({
      action_type: 'mongodb.document.delete_many',
      cluster: boundedComponent(p.cluster, 'cluster'),
      database: boundedComponent(p.database, 'database'),
      collection: boundedComponent(p.collection, 'collection'),
      filter_digest: mongoFilterDigest(p.filter),
      operation_id: boundedOperationId(p.operation_id),
    }),
    actuator: (p, observed) => ({ ...observed, filter: p.filter }),
    perform: (client, p) => client.db(p.database).collection(p.collection)
      .deleteMany(p.filter, { comment: p.operation_id }),
  },
  'document.update_many': {
    selector: { protocol: 'mongodb', tool: 'update_many' },
    observed: (p) => ({
      action_type: 'mongodb.document.update_many',
      cluster: boundedComponent(p.cluster, 'cluster'),
      database: boundedComponent(p.database, 'database'),
      collection: boundedComponent(p.collection, 'collection'),
      filter_digest: mongoFilterDigest(p.filter),
      update_digest: mongoUpdateDigest(p.update),
      operation_id: boundedOperationId(p.operation_id),
    }),
    actuator: (p, observed) => ({ ...observed, filter: p.filter, update: p.update }),
    perform: (client, p) => client.db(p.database).collection(p.collection)
      .updateMany(p.filter, p.update, { comment: p.operation_id }),
  },
  'collection.drop': {
    selector: { protocol: 'mongodb', tool: 'drop_collection' },
    observed: (p) => ({
      action_type: 'mongodb.collection.drop',
      cluster: boundedComponent(p.cluster, 'cluster'),
      database: boundedComponent(p.database, 'database'),
      collection: boundedComponent(p.collection, 'collection'),
      operation_id: boundedOperationId(p.operation_id),
    }),
    perform: (client, p) => client.db(p.database).collection(p.collection)
      .drop({ comment: p.operation_id }),
  },
};

const adapter = createAdapter({ system: 'mongodb', ops: OPS });
export const MONGODB_OPS = adapter.OPS;
const mongoConnectors = new WeakMap<object, { client: any; cluster: string }>();

export function createMongoManifest(extraActions = []) {
  return manifestFromPack(MONGODB_ACTION_PACK, extraActions);
}

/** Bind the held client to a cluster identity configured outside agent input. */
export function createMongoConnector({ client, cluster }: { client?: any; cluster?: string } = {}) {
  if (!client || typeof client.db !== 'function') {
    throw new TypeError('createMongoConnector requires a MongoClient-compatible client');
  }
  const pinnedCluster = boundedComponent(cluster, 'cluster');
  const connector = Object.freeze({});
  mongoConnectors.set(connector, { client, cluster: pinnedCluster });
  return connector;
}

export async function guardMongoMutation(
  gate,
  connector,
  { op, params = {}, receipt = null }: { op?: string; params?: object; receipt?: any } = {},
) {
  const configured = mongoConnectors.get(connector);
  if (!configured) throw new TypeError('guardMongoMutation requires a configured MongoDB connector');
  const input = canonicalActuatorObject(params);
  if (Object.prototype.hasOwnProperty.call(input, 'cluster') && input.cluster !== configured.cluster) {
    throw new TypeError('MongoDB caller-supplied cluster conflicts with the connector identity');
  }
  return await adapter.guard(gate, configured.client, {
    op,
    params: { ...input, cluster: configured.cluster },
    receipt,
  });
}

export default {
  MONGODB_ACTION_PACK,
  MONGODB_OPS,
  createMongoManifest,
  createMongoConnector,
  guardMongoMutation,
  mongoFilterDigest,
  mongoUpdateDigest,
};
