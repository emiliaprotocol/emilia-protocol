// SPDX-License-Identifier: Apache-2.0

export type ProductStoryKey =
  | 'authority-brain'
  | 'gate'
  | 'approver'
  | 'protocol'
  | 'assurance';

export type ProductStory = {
  key: ProductStoryKey;
  chapter: string;
  verb: string;
  name: string;
  href: string;
  headline: string;
  lead: string;
  storyMoment: string;
  customerReceives: string;
  withoutEmilia: string;
  withEmilia: string;
  job: string;
  boundary: string;
  primaryCta: { label: string; href: string };
  proofCta: { label: string; href: string };
};

export const PRODUCT_STORY_SCENARIO = {
  label: 'Illustrative workflow',
  title: 'A routine email asks to change a vendor bank account before the next payment.',
  setup:
    'The agent has a valid identity and working credentials. Neither fact establishes that this exact destination change is inside the customer\'s authority.',
  action: 'vendor.bank_account.update',
  materialChange: 'Old destination •••• 1842 → new destination •••• 7719',
} as const;

export const PRODUCT_STORIES: readonly ProductStory[] = [
  {
    key: 'authority-brain',
    chapter: '01',
    verb: 'Discover',
    name: 'Authority Brain',
    href: '/authority-brain',
    headline: 'First, find the action that could redirect money.',
    lead:
      'Authority Brain runs locally and maps supported actions the agent declares it can reach, the fields that would matter, and the paths it cannot see.',
    storyMoment:
      'The scan finds vendor.bank_account.update and proposes it for owner review before the next payment workflow is protected.',
    customerReceives: 'A reviewed Authority Map and a proposed protection scaffold.',
    withoutEmilia: 'The action is buried in a tool list. The owner has no usable map of the consequence or its blind spots.',
    withEmilia: 'The owner can see the declared action, name the exact fields that matter, and decide whether it needs a protected boundary.',
    job: 'Map declared action surfaces and blind spots so the customer can choose what needs authority.',
    boundary:
      'Authority Brain does not inspect every hidden path, decide policy, or block an action. Its scanner proposes. The customer decides.',
    primaryCta: { label: 'Run the local scan', href: '/authority-brain#run-local' },
    proofCta: { label: 'See the mapping limits', href: '/authority-brain#honesty-heading' },
  },
  {
    key: 'gate',
    chapter: '02',
    verb: 'Prevent',
    name: 'EMILIA Gate',
    href: '/gate',
    headline: 'Then stop the exact change before it reaches the system of record.',
    lead:
      'Gate sits in front of the system that can make the change. It checks this exact destination against the customer\'s rules before the account can be updated.',
    storyMoment:
      'The customer requires fresh controller approval for a new destination. Gate refuses the first attempt before the provider is entered and creates an exact-action challenge.',
    customerReceives: 'A named refusal, or a record that one protected attempt was allowed to enter the provider.',
    withoutEmilia: 'Valid credentials and a plausible request can be enough to change the destination.',
    withEmilia: 'The exact destination must fit the customer\'s mandate and evidence rule before the mediated provider path can be entered.',
    job: 'Enforce customer authority where a consequential action can still be stopped.',
    boundary:
      'The prevention claim applies only to completely mediated protected paths. Admission is at most one provider attempt, not exactly-once physical execution.',
    primaryCta: { label: 'Protect one workflow', href: '/pilot?v=gate' },
    proofCta: { label: 'Open the Gate reference', href: '/gate/live' },
  },
  {
    key: 'approver',
    chapter: '03',
    verb: 'Decide',
    name: 'EMILIA Approver',
    href: '/product/accountable-signoff',
    headline: 'When a person is required, show the whole change, not a vague “Approve?”',
    lead:
      'Approver shows the old and new destination, who is asking, and what will happen on a separate enrolled device.',
    storyMoment:
      'The controller reviews the exact change and makes a fresh decision. If accepted, that response can accompany a new Gate attempt. The first refusal remains in the record.',
    customerReceives: 'A fresh decision tied to the exact change, which Gate can check and use once.',
    withoutEmilia: 'A click or MFA event can be recorded without proving which exact bank-detail change the person saw.',
    withEmilia: 'The enrolled credential, challenge, profile, and exact action are bound into one fresh decision ceremony.',
    job: 'Capture fresh exact-action human authority when the customer\'s mandate or policy requires it.',
    boundary:
      'The ceremony proves that a pinned enrolled key completed a response over the exact action data. It does not prove perception, comprehension, legal sufficiency, or honest pixels.',
    primaryCta: { label: 'See the Approver flow', href: '/product/accountable-signoff#how-it-works' },
    proofCta: { label: 'Inspect the open specification', href: '/spec' },
  },
  {
    key: 'protocol',
    chapter: '04',
    verb: 'Verify',
    name: 'EMILIA Protocol',
    href: '/protocol',
    headline: 'Make the record verifiable without asking EMILIA to vouch for itself.',
    lead:
      'The open Protocol lets a customer, partner, or reviewer check one portable evidence packet without trusting an EMILIA dashboard.',
    storyMoment:
      'Weeks later, a reviewer checks the first refusal, the later human decision, and any admitted attempt as separate facts tied to the same bank-detail change.',
    customerReceives: 'A portable evidence packet and a repeatable result for one action.',
    withoutEmilia: 'The reviewer receives a screenshot or a dashboard verdict from the same system whose behavior is in question.',
    withEmilia: 'The reviewer can independently check that each artifact is valid, that the material fields match, and that the customer\'s evidence rule was satisfied.',
    job: 'Give anyone the free machinery to verify one evidence packet without trusting EMILIA.',
    boundary:
      'Verification does not create authority, prove execution, establish complete mediation, or make every native evidence source trustworthy.',
    primaryCta: { label: 'Follow the evidence path', href: '/protocol#canonical-path' },
    proofCta: { label: 'Run the open verifier', href: '/verify' },
  },
  {
    key: 'assurance',
    chapter: '05',
    verb: 'Re-perform',
    name: 'Assurance Plane',
    href: '/assurance',
    headline: 'Later, rerun the evidence and make drift visible.',
    lead:
      'The Assurance Plane implements procedures for checking many packets over time. It repeats chosen checks, exposes drift and unresolved cases, and prepares a scoped workpaper. Any deployment or service engagement must be separately scoped.',
    storyMoment:
      'An audit lead re-performs the supplied payee-change population and sees exactly which records passed, refused, diverged, or remained unresolved.',
    customerReceives: 'An implemented procedure that can produce a versioned review record and reproducible technical workpaper when run on supplied inputs.',
    withoutEmilia: 'The reviewer must trust a live dashboard and reconstruct the population by hand.',
    withEmilia: 'The same supplied inputs can be rerun under pinned rules, with drift and uncertainty preserved instead of rounded into a pass.',
    job: 'Provide implemented procedures for re-performance across a supplied deployment or population.',
    boundary:
      'EMILIA supports the procedure. It does not issue an audit opinion, accredited certification, legal conclusion, or insurance decision.',
    primaryCta: { label: 'Discuss a scoped assurance pilot', href: '/partners' },
    proofCta: { label: 'Run the open procedure', href: '/assurance#open-verification' },
  },
] as const;

export function getProductStory(key: ProductStoryKey): ProductStory {
  const story = PRODUCT_STORIES.find((item) => item.key === key);
  if (!story) throw new Error(`Missing product story: ${key}`);
  return story;
}
