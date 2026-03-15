/**
 * EP Host Adapter — GitHub
 * 
 * Extracts trust-relevant metadata from GitHub Apps, repos, and orgs.
 * Used by install preflight and identity binding verification.
 * 
 * @license Apache-2.0
 */

const GITHUB_API = 'https://api.github.com';

/**
 * Fetch GitHub App metadata for install preflight.
 */
export async function getGitHubAppMetadata(appSlug, token = null) {
  const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'EMILIA-Protocol' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const r = await fetch(`${GITHUB_API}/apps/${appSlug}`, { headers });
    if (!r.ok) return { error: `GitHub API returned ${r.status}`, available: false };

    const app = await r.json();
    return {
      available: true,
      app_id: app.id,
      slug: app.slug,
      name: app.name,
      owner: app.owner?.login,
      owner_type: app.owner?.type, // User or Organization
      description: app.description,
      external_url: app.external_url,
      html_url: app.html_url,
      created_at: app.created_at,
      updated_at: app.updated_at,
      permissions: app.permissions || {},
      events: app.events || [],
      installations_count: app.installations_count,
      // Trust-relevant extractions
      trust_signals: {
        publisher_is_org: app.owner?.type === 'Organization',
        has_description: !!app.description,
        has_external_url: !!app.external_url,
        permission_count: Object.keys(app.permissions || {}).length,
        event_count: (app.events || []).length,
        age_days: Math.floor((Date.now() - new Date(app.created_at).getTime()) / (86400000)),
        installations: app.installations_count || 0,
      },
    };
  } catch (err) {
    return { error: err.message, available: false };
  }
}

/**
 * Verify GitHub org ownership for identity binding.
 * Checks if a specific user/app has admin access to the org.
 */
export async function verifyGitHubOrgControl(orgName, token) {
  if (!token) return { verified: false, reason: 'Token required for org verification' };

  const headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': `Bearer ${token}`,
    'User-Agent': 'EMILIA-Protocol',
  };

  try {
    const r = await fetch(`${GITHUB_API}/orgs/${orgName}/memberships`, { headers });
    if (!r.ok) return { verified: false, reason: `Cannot verify org membership: ${r.status}` };

    const membership = await r.json();
    return {
      verified: membership.role === 'admin',
      role: membership.role,
      state: membership.state,
      org: orgName,
    };
  } catch (err) {
    return { verified: false, reason: err.message };
  }
}

/**
 * Extract permission risk class from GitHub App permissions.
 */
export function classifyGitHubPermissions(permissions) {
  const dangerousPerms = ['administration', 'organization_administration', 'members', 'organization_secrets', 'actions'];
  const sensitivePerms = ['contents', 'issues', 'pull_requests', 'workflows', 'packages'];
  const readOnlyPerms = ['metadata', 'statuses', 'checks'];

  const permKeys = Object.keys(permissions);
  const writePerms = Object.entries(permissions).filter(([, v]) => v === 'write').map(([k]) => k);

  if (writePerms.some(p => dangerousPerms.includes(p))) return 'dangerous';
  if (writePerms.some(p => sensitivePerms.includes(p))) return 'sensitive';
  if (writePerms.length > 0) return 'moderate';
  if (permKeys.length > 0) return 'read_only';
  return 'minimal';
}
