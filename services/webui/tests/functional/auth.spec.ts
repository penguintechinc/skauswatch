/**
 * Auth Tests - Login page and authentication flows.
 *
 * The Login page uses @penguintechinc/react-libs LoginPageBuilder which renders
 * a standard login form with email/password fields and a submit button.
 *
 * NOTE: Tests that require a running backend are annotated accordingly.
 * The login page UI tests (rendering, fields) work without a backend.
 * Authentication flow tests require the backend API at /api/v1.
 */
import { test, expect } from './fixtures';
import { Page } from '@playwright/test';

test.describe('Login Page', () => {
  test('login page renders with expected elements', async ({ page }) => {
    await page.goto('/login');

    // Page should render without crashing - title or heading should be visible
    await expect(page).toHaveTitle(/SkausWatch|Skaus|Loading/i);

    // The LoginPageBuilder renders the app name
    await expect(page.getByText('SkausWatch')).toBeVisible({ timeout: 10000 });
  });

  test('login page renders email and password fields', async ({ page }) => {
    await page.goto('/login');

    // Wait for form to appear
    await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10000 });

    // Email field should be present
    const emailField = page.locator(
      'input[type="email"], input[name="email"], input[placeholder*="email" i]'
    ).first();
    await expect(emailField).toBeVisible();

    // Password field should be present
    const passwordField = page.locator('input[type="password"]').first();
    await expect(passwordField).toBeVisible();
  });

  test('login page has a submit button', async ({ page }) => {
    await page.goto('/login');

    await page.waitForSelector('button[type="submit"], form', { timeout: 10000 });

    const submitButton = page.locator(
      'button[type="submit"], button:has-text("Sign In"), button:has-text("Login"), button:has-text("Log In")'
    ).first();
    await expect(submitButton).toBeVisible();
  });

  test('submitting empty form shows validation feedback', async ({ page }) => {
    await page.goto('/login');
    await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10000 });

    // Click submit without filling any fields
    const submitButton = page.locator(
      'button[type="submit"], button:has-text("Sign In"), button:has-text("Login"), button:has-text("Log In")'
    ).first();
    await submitButton.click();

    // HTML5 validation or error messages should prevent submission and keep us on /login
    // Either we stay on login, or validation messages appear
    const currentUrl = page.url();
    const isStillOnLogin = currentUrl.includes('/login') || currentUrl.endsWith('/');

    // Check for HTML5 validation (browser may block submit) or error messages
    const hasValidationMessage = await page.evaluate(() => {
      const inputs = document.querySelectorAll('input[required]');
      for (const input of inputs) {
        if ((input as HTMLInputElement).validity && !(input as HTMLInputElement).validity.valid) {
          return true;
        }
      }
      return false;
    });

    // Either stayed on login page or showed validation
    expect(isStillOnLogin || hasValidationMessage).toBe(true);
  });

  test('wrong credentials show error message', async ({ page }) => {
    // Note: This test requires a running backend
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');

    await page.goto('/login');
    await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10000 });

    const emailField = page.locator(
      'input[type="email"], input[name="email"], input[placeholder*="email" i]'
    ).first();
    await emailField.fill('wrong@example.com');

    const passwordField = page.locator('input[type="password"]').first();
    await passwordField.fill('wrongpassword');

    const submitButton = page.locator(
      'button[type="submit"], button:has-text("Sign In"), button:has-text("Login"), button:has-text("Log In")'
    ).first();
    await submitButton.click();

    // Should show an error message and stay on login
    await page.waitForTimeout(2000);
    const errorMessage = page.locator(
      '[role="alert"], .error, [class*="error"], [class*="danger"], [class*="red"]'
    ).first();
    await expect(errorMessage).toBeVisible({ timeout: 5000 });
    expect(page.url()).toContain('/login');
  });

  test('successful login redirects to dashboard', async ({ page }) => {
    // Note: This test requires a running backend
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');

    await page.goto('/login');
    await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10000 });

    const emailField = page.locator(
      'input[type="email"], input[name="email"], input[placeholder*="email" i]'
    ).first();
    await emailField.fill('admin@skauswatch.local');

    const passwordField = page.locator('input[type="password"]').first();
    await passwordField.fill('admin');

    const submitButton = page.locator(
      'button[type="submit"], button:has-text("Sign In"), button:has-text("Login"), button:has-text("Log In")'
    ).first();
    await submitButton.click();

    // Should redirect away from login to dashboard
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 8000 });
    expect(page.url()).not.toContain('/login');
  });

  test('authenticated user navigating to /login is redirected to dashboard', async ({ page }) => {
    // Note: This test requires a running backend for auth state
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');

    // First login
    await page.goto('/login');
    await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10000 });

    const emailField = page.locator(
      'input[type="email"], input[name="email"], input[placeholder*="email" i]'
    ).first();
    await emailField.fill('admin@skauswatch.local');
    await page.locator('input[type="password"]').first().fill('admin');
    await page.locator('button[type="submit"]').first().click();

    // Wait for redirect to complete
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 8000 });

    // Now try to navigate back to login
    await page.goto('/login');

    // Should be redirected away from /login since we're authenticated
    // The App.tsx does: isAuthenticated ? <Navigate to="/" replace /> : <Login />
    await page.waitForTimeout(1000);
    expect(page.url()).not.toContain('/login');
  });

  test('logout clears session and redirects to login', async ({ page }) => {
    // Note: This test requires a running backend
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');

    // Login first
    await page.goto('/login');
    await page.waitForSelector('input[type="email"], input[name="email"]', { timeout: 10000 });

    await page.locator('input[type="email"], input[name="email"]').first().fill('admin@skauswatch.local');
    await page.locator('input[type="password"]').first().fill('admin');
    await page.locator('button[type="submit"]').first().click();
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 8000 });

    // Find and click logout - the Sidebar renders a Logout footer item
    const logoutButton = page.getByText('Logout').first();
    await expect(logoutButton).toBeVisible({ timeout: 5000 });
    await logoutButton.click();

    // Should redirect to login
    await page.waitForURL('**/login', { timeout: 5000 });
    expect(page.url()).toContain('/login');
  });
});
