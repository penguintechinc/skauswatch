import { test, expect } from '@playwright/test';

test.describe('Smoke Tests', () => {
  test('login page loads', async ({ page }) => {
    await page.goto('/login');
    const heading = await page.getByText(/login/i);
    await expect(heading).toBeVisible();
  });

  test('dashboard redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/');
    await page.waitForURL('**/login');
    expect(page.url()).toContain('/login');
  });

  test('page title is set', async ({ page }) => {
    await page.goto('/login');
    const title = await page.title();
    expect(title).toBeTruthy();
  });

  test('no JS console errors on login page', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto('/login');
    await page.waitForLoadState('networkidle');

    expect(errors).toEqual([]);
  });

  test('form elements are visible on login', async ({ page }) => {
    await page.goto('/login');
    const emailInput = page.getByLabel(/email/i);
    const passwordInput = page.getByLabel(/password/i);

    await expect(emailInput).toBeVisible({ timeout: 5000 });
    await expect(passwordInput).toBeVisible({ timeout: 5000 });
  });

  test('login form is accessible via keyboard', async ({ page }) => {
    await page.goto('/login');

    // Tab to email field and check focus
    await page.keyboard.press('Tab');
    const focused = await page.evaluate(() => document.activeElement?.getAttribute('data-testid'));
    expect(focused || document.activeElement?.tagName).toBeTruthy();
  });
});
