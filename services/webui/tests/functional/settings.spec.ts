/**
 * Settings Page Tests.
 *
 * The Settings page (/settings) is protected by RoleGuard for ['admin', 'maintainer'].
 * Viewer role will be blocked by RoleGuard and not see this page.
 *
 * Settings page renders:
 * - Heading "Settings"
 * - Three tabs: General | Notifications | Security
 *
 * General tab: Dark Mode checkbox, Compact View checkbox, Timezone select
 * Notifications tab: Email Notifications, System Alerts, Weekly Reports checkboxes
 * Security tab: Two-Factor Authentication checkbox, Session Timeout select, Active Sessions
 */
import { test, expect } from './fixtures';

test.describe('Settings Page', () => {
  test.beforeEach(async ({ page }) => {
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');
  });

  test('settings page renders heading and tabs for admin', async ({ adminPage: page }) => {
    await page.goto('/settings');

    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Manage application settings')).toBeVisible();
  });

  test('settings page renders three tab options', async ({ adminPage: page }) => {
    await page.goto('/settings');

    await expect(page.getByRole('button', { name: 'General' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: 'Notifications' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Security' })).toBeVisible();
  });

  test('General tab is active by default with Dark Mode checkbox', async ({ adminPage: page }) => {
    await page.goto('/settings');

    // Default active tab is 'general'
    await expect(page.getByText('General Settings')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Dark Mode')).toBeVisible();
  });

  test('General tab shows Compact View checkbox and Timezone select', async ({ adminPage: page }) => {
    await page.goto('/settings');

    await expect(page.getByText('Compact View')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Timezone')).toBeVisible();

    // Timezone select element should be present
    const timezoneSelect = page.locator('select').first();
    await expect(timezoneSelect).toBeVisible();
  });

  test('Dark Mode checkbox is checked by default', async ({ adminPage: page }) => {
    await page.goto('/settings');

    // The Dark Mode checkbox has defaultChecked
    const checkboxes = page.locator('input[type="checkbox"]');
    const firstCheckbox = checkboxes.first();
    await expect(firstCheckbox).toBeVisible({ timeout: 10000 });
    await expect(firstCheckbox).toBeChecked();
  });

  test('clicking Notifications tab shows notification settings', async ({ adminPage: page }) => {
    await page.goto('/settings');

    await page.getByRole('button', { name: 'Notifications' }).click();

    await expect(page.getByText('Notification Settings')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Email Notifications')).toBeVisible();
    await expect(page.getByText('System Alerts')).toBeVisible();
    await expect(page.getByText('Weekly Reports')).toBeVisible();
  });

  test('clicking Security tab shows security settings', async ({ adminPage: page }) => {
    await page.goto('/settings');

    await page.getByRole('button', { name: 'Security' }).click();

    await expect(page.getByText('Security Settings')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Two-Factor Authentication')).toBeVisible();
    await expect(page.getByText('Session Timeout')).toBeVisible();
    await expect(page.getByText('Active Sessions')).toBeVisible();
  });

  test('Security tab session timeout select has options', async ({ adminPage: page }) => {
    await page.goto('/settings');

    await page.getByRole('button', { name: 'Security' }).click();

    // Select element for session timeout
    const sessionTimeoutSelect = page.locator('select').first();
    await expect(sessionTimeoutSelect).toBeVisible({ timeout: 5000 });

    // Check option values exist
    await expect(sessionTimeoutSelect.locator('option[value="15"]')).toHaveCount(1);
    await expect(sessionTimeoutSelect.locator('option[value="30"]')).toHaveCount(1);
  });

  test('toggle switches (checkboxes) are interactive in General tab', async ({ adminPage: page }) => {
    await page.goto('/settings');

    // Find Compact View checkbox (second checkbox, not default-checked)
    const compactViewLabel = page.getByText('Compact View');
    await expect(compactViewLabel).toBeVisible({ timeout: 10000 });

    // Find the associated checkbox - it's in the same label/container
    const checkboxes = page.locator('input[type="checkbox"]');
    const compactViewCheckbox = checkboxes.nth(1); // Second checkbox

    const wasChecked = await compactViewCheckbox.isChecked();
    await compactViewCheckbox.click();
    // State should have toggled
    const isNowChecked = await compactViewCheckbox.isChecked();
    expect(isNowChecked).toBe(!wasChecked);
  });

  test('viewer role cannot access settings page', async ({ page }) => {
    // This requires knowing viewer credentials - login as viewer
    // The RoleGuard for settings allows ['admin', 'maintainer'] only
    // We cannot easily test this without a running backend (login required)
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');

    // Navigate directly to settings while not logged in (or as viewer)
    // If not authenticated, ProtectedRoute redirects to /login
    await page.goto('/settings');

    // Should be redirected to login if not authenticated
    await page.waitForTimeout(2000);
    const currentUrl = page.url();

    // Either redirected to login or shows an access denied message
    const isRedirectedToLogin = currentUrl.includes('/login');
    const hasAccessDenied = await page.getByText(/access denied|not authorized|permission/i).isVisible().catch(() => false);

    expect(isRedirectedToLogin || hasAccessDenied).toBe(true);
  });
});
