// SPDX-License-Identifier: Apache-2.0
import { getWorksPublicWorkflowStates } from '@/lib/works/workflow-store';

/** Missing or unavailable state never makes a job look open. Examples skip it. */
export async function publicJobStates(ids: string[]): Promise<Map<string, string> | null> {
  if (!ids.length) return new Map();
  try {
    const result = await getWorksPublicWorkflowStates('opportunities', ids);
    if (!result.ok) return null;
    const allowed = new Set(['open', 'closed', 'assigned']);
    if (result.states.length !== ids.length || result.states.some(item => !ids.includes(item.record_id)
      || !allowed.has(item.workflow.state))) return null;
    const states = new Map(result.states.map(item => [item.record_id, item.workflow.state]));
    return states.size === ids.length ? states : null;
  } catch { return null; }
}
