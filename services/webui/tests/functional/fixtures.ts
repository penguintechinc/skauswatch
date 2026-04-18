import { test as base, expect, Page } from '@playwright/test';

type AuthFixtures = {
  authenticatedPage: Page;
  adminPage: Page;
  viewerPage: Page;
};

/**
 * Attempt login using the LoginPageBuilder component from @penguintechinc/react-libs.
 * The LoginPageBuilder renders standard email/password inputs and a submit button.
 * We use flexible selectors to handle the component library's rendered output.
 */
async function loginAs(page: Page, email: string, password: string) {
  await page.goto('/login');

  // Wait for the login form to be visible - LoginPageBuilder renders a form
  await page.waitForSelector('form, [data-testid="login-form"]', { timeout: 10000 }).catch(() => {});

  // Fill email field - try multiple selector strategies
  const emailInput = page.locator(
    'input[type="email"], input[name="email"], input[placeholder*="email" i], input[placeholder*="Email" i]'
  ).first();
  await emailInput.fill(email);

  // Fill password field
  const passwordInput = page.locator(
    'input[type="password"], input[name="password"], input[placeholder*="password" i]'
  ).first();
  await passwordInput.fill(password);

  // Submit the form
  const submitButton = page.locator(
    'button[type="submit"], button:has-text("Sign In"), button:has-text("Login"), button:has-text("Log In")'
  ).first();
  await submitButton.click();

  // Wait for redirect - after login we expect to land at / (dashboard)
  await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 8000 }).catch(() => {});
}

export const test = base.extend<AuthFixtures>({
  authenticatedPage: async ({ page }, use) => {
    await loginAs(page, 'admin@skauswatch.local', 'admin');
    await use(page);
  },
  adminPage: async ({ page }, use) => {
    await loginAs(page, 'admin@skauswatch.local', 'admin');
    await use(page);
  },
  viewerPage: async ({ page }, use) => {
    await loginAs(page, 'viewer@skauswatch.local', 'viewer');
    await use(page);
  },
});

export { expect };
