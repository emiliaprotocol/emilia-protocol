// SPDX-License-Identifier: Apache-2.0

export function mobileActionView(item, { includePassport = false } = {}) {
  const view = {
    action_reference: item.action_reference,
    title: item.presentation?.title || 'Approval required',
    summary: item.presentation?.summary || 'Review the exact action before deciding.',
    risk: item.presentation?.risk || 'consequential',
    material_fields: item.presentation?.material_fields || {},
    expires_at: item.expires_at,
    created_at: item.created_at,
    status: item.status,
    revision: item.revision,
    identity: item.identity || null,
    supersedes_action_caid: item.supersedes_action_caid || null,
    changes: item.changes || [],
    continuity: item.continuity || null,
    quorum: item.quorum || null,
    alignments: item.alignments || [],
    events: item.events || [],
    can_withdraw: item.can_withdraw === true,
  };
  if (includePassport) view.passport = item.passport || null;
  return view;
}
