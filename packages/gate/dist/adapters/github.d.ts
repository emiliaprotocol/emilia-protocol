export declare const GITHUB_ACTION_PACK: readonly (Readonly<{
    id: "github.repo.delete";
    label: "GitHub repo delete";
    action_type: "github.repo.delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys a repository and its history. Bind owner/repo to a named human approval.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "github.permission.change";
    label: "GitHub permission change";
    action_type: "github.permission.change";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes who can act on the repo. Privilege change deserves the two-person rule.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "github.branch_protection.remove";
    label: "GitHub branch-protection removal";
    action_type: "github.branch_protection.remove";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Removes the guard rails on a protected branch.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const GITHUB_OPS: readonly string[];
/** Build an action-risk manifest for the GitHub destructive ops (plus any extras). */
export declare function createGithubManifest(extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
/**
 * Guard a destructive GitHub mutation behind the gate. The call never reaches
 * GitHub unless a valid, sufficiently-assured, non-replayed receipt bound to
 * THIS repo is present.
 * @param {object} gate     a gate built with createGithubManifest()
 * @param {object} octokit  an Octokit-like client (@octokit/rest or compatible)
 * @param {object} o
 * @param {string} o.op     'repo.delete' | 'permission.change' | 'branch_protection.remove'
 * @param {object} o.params { owner, repo, [username], [permission], [branch] }
 * @param {object} o.receipt the EMILIA receipt authorizing THIS exact op
 * @returns {Promise<{ result:any, reliance:object, execution:object }>}
 * @throws  Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the call never reaches GitHub
 */
export declare function guardGithubMutation(gate: any, octokit: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
declare const _default: {
    GITHUB_ACTION_PACK: readonly (Readonly<{
        id: "github.repo.delete";
        label: "GitHub repo delete";
        action_type: "github.repo.delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Destroys a repository and its history. Bind owner/repo to a named human approval.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "github.permission.change";
        label: "GitHub permission change";
        action_type: "github.permission.change";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Changes who can act on the repo. Privilege change deserves the two-person rule.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "github.branch_protection.remove";
        label: "GitHub branch-protection removal";
        action_type: "github.branch_protection.remove";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Removes the guard rails on a protected branch.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    GITHUB_OPS: readonly string[];
    createGithubManifest: typeof createGithubManifest;
    guardGithubMutation: typeof guardGithubMutation;
};
export default _default;
//# sourceMappingURL=github.d.ts.map