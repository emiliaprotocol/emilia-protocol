# EP Target List + Cold Outreach

This file focuses on **publicly reachable channels** for pilot outreach. It is designed for government fraud / payment integrity teams and financial institutions with treasury, payment, or fraud-control surfaces.

## How to use this list
1. Start with the organizations most aligned to your first pilot workflow.
2. Lead with one workflow only.
3. Ask for a 20-minute discovery call or a pilot architecture review.
4. Use the cold emails below as your starting point.

---

## Priority government targets

### 1. U.S. Treasury — Payment Integrity and Resolution Services / Fiscal Service
**Why target them:** EP fits payment integrity, fraud prevention, federal payment issues, and agency / financial institution support workflows.  
**Public channel:** paymentintegrity@fiscal.treasury.gov, PFC.CustomerEngagementCenter@fiscal.treasury.gov, 1-855-868-0151  
**Best pitch:** high-risk payment destination changes, replay-resistant authorization, accountable signoff for operator exceptions

### 2. U.S. Treasury — Do Not Pay / Office of Payment Integrity
**Why target them:** Do Not Pay already frames the problem around fraud and improper payments across agencies. EP is a control layer for exact action-level enforcement inside those workflows.  
**Public channel:** use the Do Not Pay site and Treasury Fiscal Service channels above  
**Best pitch:** exact action binding and accountable execution on top of existing data verification

### 3. CMS — Medicaid Integrity Program
**Why target them:** Medicaid program integrity is a direct match for beneficiary fraud, provider/provider-supplier workflow controls, and state program integrity support.  
**Public channel:** Medicaid_Integrity_Program@cms.hhs.gov  
**Best pitch:** beneficiary change controls, provider change approvals, accountable signoff for high-risk exceptions

### 4. California Department of Social Services — Program Integrity Bureau
**Why target them:** Large benefit-administration environment with direct program integrity surface.  
**Public channel:** FraudHotline@dss.ca.gov, 1-800-344-TIPS  
**Best pitch:** benefit redirect prevention, case-action controls, delegated worker authority

### 5. Maryland Department of Labor — unemployment fraud reporting channel
**Why target them:** Unemployment fraud remains a practical entry point for action-level controls and payment integrity.  
**Public channel:** ui.fraud@maryland.gov, 1-800-492-6804  
**Best pitch:** claimant/payment change controls, high-risk exception approval architecture

---

## Priority financial-institution targets

### 1. U.S. Bank — Treasury Management
**Why target them:** Explicit public treasury team and fraud / payment solution messaging; strong fit for beneficiary and payout controls.  
**Public channel:** Treasury contact form on U.S. Bank treasury page; treasury team inquiry page  
**Best pitch:** beneficiary change and payout destination controls, treasury approval signoff

### 2. Wells Fargo — Treasury Management Services
**Why target them:** Public treasury contact path and strong commercial / treasury positioning.  
**Public channel:** 1-866-902-9181 and treasury / commercial banking contact paths  
**Best pitch:** treasury approvals, privileged payment actions, exact action binding

### 3. PNC — Treasury Management Direct / fraud mitigation
**Why target them:** Public fraud-mitigation treasury contact line; good fit for first pilot discussions.  
**Public channel:** 1-800-669-1518  
**Best pitch:** fraud-mitigation architecture for remittance changes and payment controls

### 4. BNY — Business Inquiries
**Why target them:** Strong payments / trade / treasury positioning and public business inquiry form.  
**Public channel:** BNY business inquiries form  
**Best pitch:** high-assurance controls for treasury, payments, and regulated operations

### 5. JPMorgan Payments — Trust & Safety / Payments
**Why target them:** Strong narrative around end-to-end payments, trust, and safety.  
**Public channel:** JPMorgan Payments solutions/contact paths and security/fraud channels  
**Best pitch:** exact authorization and accountable signoff for high-risk payment actions

---

## Recommended target order

### Government first
1. U.S. Treasury Fiscal Service / PIRS
2. CMS Medicaid Integrity Program
3. California CDSS Program Integrity Bureau
4. Maryland Department of Labor unemployment-fraud channel

### Financial first
1. U.S. Bank Treasury
2. Wells Fargo Treasury
3. PNC Treasury Management
4. BNY Business Inquiries
5. JPMorgan Payments

---

## Cold email — government

Subject: Trust controls before high-risk payment actions

Hi [Team/Name],

Most payment fraud in government workflows doesn’t happen because authentication failed. It happens because authentication was the only control. The action — a payment destination change, a benefit redirect, an operator override — never had to satisfy an action-level policy.

EMILIA Protocol (EP) sits between authentication and execution. It verifies actor identity, authority chain, and policy before a specific action proceeds — exactly once, with an immutable event record. When policy requires it, a named accountable human must assume ownership before execution.

EP has been independently audited at 100/100 across all 10 categories. Apache 2.0 open source.

A pilot could scope to one workflow: payment destination changes, benefit redirects, or delegated case actions. Happy to send the brief or schedule a 20-minute call.

Best,
[Your Name]

---

## Cold email — financial institutions

Subject: Authorization controls for beneficiary and payout changes

Hi [Team/Name],

Wire fraud and BEC both succeed because authorization systems validate identity, not action. A fraudulent beneficiary change looks identical to a legitimate one at the session level — because neither the specific action, the authority chain, nor the policy was ever bound at authorization time.

EMILIA Protocol (EP) enforces trust at the action layer. EP binds actor identity, authority chain, policy, transaction context, and one-time consumption before a financial action proceeds. A named accountable human can be required to explicitly own the action before execution.

EP has been independently audited at 100/100 across all 10 categories, load-tested to 500 concurrent users with zero correctness violations, and is Apache 2.0 open source.

A pilot could focus on beneficiary changes, payout destination approvals, or treasury release controls. Happy to send the architecture brief.

Best,
[Your Name]

---

## Cold email — JPM / large-bank / payments platform version

Subject: Exact action controls for high-risk payment workflows

Hi [Team/Name],

For large payment environments, the authorization problem isn’t identity — identity is solved. The gap is the action layer: a fraudulent beneficiary change can look identical to a legitimate one because neither the specific action, the authority chain, nor the policy was ever bound.

EMILIA Protocol (EP) closes that gap. EP creates a cryptographic authorization envelope — actor identity, authority chain, exact transaction context, policy hash, replay resistance, one-time consumption — before execution. Accountable Signoff adds named human accountability for actions that require it.

EP is Apache 2.0 open source, independently audited at 100/100 (2026-04-02), and MCP-native with TypeScript and Python SDKs.

If this fits your trust, safety, or payment integrity work, I can send the technical brief or propose a pilot scope.

Best,
[Your Name]
