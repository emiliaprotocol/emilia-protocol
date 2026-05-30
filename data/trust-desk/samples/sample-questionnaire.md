# Vendor AI Security Review — Acme Financial (sample)

## AI Data Handling
- Does your AI use customer data for model training?
- What is your data retention period for customer-submitted content, and how is deletion handled?
- Do you fine-tune foundation models on our data?

## Prompt Injection & Model Security
- Describe your prompt injection defense and how you handle indirect injection from retrieved content.
- How do you prevent the model from leaking the system prompt or other tenants' data?

## Subprocessors & Data Flow
- List your AI subprocessors and where customer data flows during inference.
- Do you have an executed DPA with each model provider?

## Agent Access Control
- How do you enforce least-privilege tool access for autonomous agents?
- Are destructive agent actions gated behind human approval?

## Incident Response
- Describe your AI incident response process and your breach notification SLA.

## General Security
- Do you encrypt customer data at rest and in transit?
- Do you enforce MFA and least-privilege access reviews for employees?

## Deployment Specifics
- Which cloud provider and region hosts the production AI workload?
