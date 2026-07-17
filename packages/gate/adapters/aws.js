// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — AWS System-of-Record adapter (IAM + network).
 *
 * "Install this before your agent can change cloud permissions or open the
 * network." Wraps the high-blast-radius AWS operations — attach IAM policy,
 * create access key, delete user, and open a security-group ingress — so they
 * never reach AWS without a valid, sufficiently-assured, non-replayed receipt
 * bound to THIS principal/policy/group. Privilege and network changes default
 * to quorum (the two-person rule).
 *
 *   import { IAMClient, EC2Client } from '@aws-sdk/...';
 *   import { createGate } from '@emilia-protocol/gate';
 *   import { createAwsManifest, guardAwsMutation } from '@emilia-protocol/gate/adapters/aws';
 *
 *   const gate = createGate({ manifest: createAwsManifest(), trustedKeys: [ISSUER], store: sharedConsumptionStore });
 *   // client: { iam: { attachUserPolicy, createAccessKey, deleteUser }, ec2: { authorizeSecurityGroupIngress } }
 *   await guardAwsMutation(gate, client, {
 *     op: 'iam.attach_policy', params: { user: 'svc-bot', policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess' }, receipt,
 *   });
 */
import { createAdapter, manifestFromPack } from './_kit.js';

export const AWS_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'aws.iam.attach_policy', label: 'IAM attach policy', action_type: 'aws.iam.attach_policy',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'aws', tool: 'attach_user_policy' },
    why: 'Grants permissions. Privilege escalation deserves the two-person rule.',
    execution_binding: { required_fields: ['action_type', 'user', 'policy_arn'] },
  }),
  Object.freeze({
    id: 'aws.iam.create_access_key', label: 'IAM create access key', action_type: 'aws.iam.create_access_key',
    risk: 'critical', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'aws', tool: 'create_access_key' },
    why: 'Mints long-lived credentials. Bind the user to a named approval.',
    execution_binding: { required_fields: ['action_type', 'user'] },
  }),
  Object.freeze({
    id: 'aws.iam.delete_user', label: 'IAM delete user', action_type: 'aws.iam.delete_user',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'aws', tool: 'delete_user' },
    why: 'Destroys an identity. Bind the target user.',
    execution_binding: { required_fields: ['action_type', 'user'] },
  }),
  Object.freeze({
    id: 'aws.ec2.authorize_ingress', label: 'Open security-group ingress', action_type: 'aws.ec2.authorize_ingress',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'aws', tool: 'authorize_security_group_ingress' },
    why: 'Opens the network. Bind group/CIDR/port so 0.0.0.0/0:22 cannot slip through.',
    execution_binding: { required_fields: ['action_type', 'group_id', 'cidr', 'protocol', 'from_port', 'to_port'] },
  }),
]);

const OPS = {
  'iam.attach_policy': {
    selector: { protocol: 'aws', tool: 'attach_user_policy' },
    observed: (p) => ({ action_type: 'aws.iam.attach_policy', user: p.user, policy_arn: p.policy_arn }),
    perform: (client, p) => client.iam.attachUserPolicy({ UserName: p.user, PolicyArn: p.policy_arn }),
  },
  'iam.create_access_key': {
    selector: { protocol: 'aws', tool: 'create_access_key' },
    observed: (p) => ({ action_type: 'aws.iam.create_access_key', user: p.user }),
    perform: (client, p) => client.iam.createAccessKey({ UserName: p.user }),
  },
  'iam.delete_user': {
    selector: { protocol: 'aws', tool: 'delete_user' },
    observed: (p) => ({ action_type: 'aws.iam.delete_user', user: p.user }),
    perform: (client, p) => client.iam.deleteUser({ UserName: p.user }),
  },
  'ec2.authorize_ingress': {
    selector: { protocol: 'aws', tool: 'authorize_security_group_ingress' },
    observed: (p) => ({
      action_type: 'aws.ec2.authorize_ingress',
      group_id: p.group_id,
      cidr: p.cidr,
      protocol: p.protocol ?? 'tcp',
      from_port: p.from_port,
      to_port: p.to_port ?? p.from_port,
    }),
    perform: (client, p) => client.ec2.authorizeSecurityGroupIngress({
      GroupId: p.group_id,
      CidrIp: p.cidr,
      FromPort: p.from_port,
      ToPort: p.to_port,
      IpProtocol: p.protocol,
    }),
  },
};

const adapter = createAdapter({ system: 'aws', ops: OPS });
export const AWS_OPS = adapter.OPS;

export function createAwsManifest(extraActions = []) {
  return manifestFromPack(AWS_ACTION_PACK, extraActions);
}

/**
 * Guard a high-blast-radius AWS mutation behind the gate.
 * @param {object} gate    a gate built with createAwsManifest()
 * @param {object} client  { iam: {attachUserPolicy, createAccessKey, deleteUser}, ec2: {authorizeSecurityGroupIngress} }
 * @param {object} o       { op, params, receipt }
 * @throws Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the call never reaches AWS
 */
export function guardAwsMutation(gate, client, args) {
  return adapter.guard(gate, client, args);
}

export default { AWS_ACTION_PACK, AWS_OPS, createAwsManifest, guardAwsMutation };
