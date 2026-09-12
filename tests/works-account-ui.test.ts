// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import AccountForm, { AccountForm as NamedAccountForm } from '../app/works/account/AccountForm.tsx';

describe('Works account form', () => {
  it('is embeddable and fail-closed before hydration', () => {
    expect(NamedAccountForm).toBe(AccountForm);
    const html = renderToStaticMarkup(createElement(AccountForm, { onAuthenticated: () => {} }));
    expect(html).toMatch(/<form[^>]*method="post"/);
    expect(html).toMatch(/<fieldset[^>]*disabled=""/);
    expect(html).toContain('JavaScript is required');
    expect(html).toContain('Create a Works account');
    expect(html).toContain('Sign in');
  });

  it('uses only same-origin credentialed account routes and never browser API-key storage', () => {
    const source = readFileSync(new URL('../app/works/account/AccountForm.tsx', import.meta.url), 'utf8');
    expect(source).toContain('/api/works/account/start');
    expect(source).toContain('/api/works/account/verify');
    expect(source).toContain("credentials: 'same-origin'");
    expect(source).not.toMatch(/localStorage|sessionStorage|apiKey|authorization/i);
  });

  it('does not overstate identity verification or grant operating authority', () => {
    const html = renderToStaticMarkup(createElement(AccountForm));
    expect(html).toContain('Your email is verified');
    expect(html).toContain('does not verify your organization or any agent claim');
    expect(html).toContain('does not give an agent permission to act');
  });
});

