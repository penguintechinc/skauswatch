/**
 * Navigation / Sidebar Tests.
 *
 * The Sidebar uses @penguintechinc/react-libs SidebarMenu with these categories:
 *
 * Main:
 *   - Dashboard → /
 *   - Profile → /profile
 *
 * Security (visible to all):
 *   - Threat Intel → /threat-intel
 *   - S3 Scanning → /s3-scan
 *
 * Management (roles: admin, maintainer):
 *   - Settings → /settings
 *
 * Administration (roles: admin):
 *   - Users → /users
 *
 * Footer items:
 *   - User info (full_name, email, role badge)
 *   - Logout button
 *
 * The SidebarMenu from the react-libs package filters nav items by role.
 */
import { test, expect } from './fixtures';

test.describe('Navigation / Sidebar', () => {
  test.beforeEach(async ({ page }) => {
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');
  });

  test('sidebar renders with SkausWatch app name', async ({ authenticatedPage: page }) => {
    // After auth, the Layout renders Sidebar with appName="SkausWatch"
    await expect(page.getByText('SkausWatch')).toBeVisible({ timeout: 10000 });
  });

  test('sidebar contains Dashboard navigation link', async ({ authenticatedPage: page }) => {
    await expect(page.getByText('Dashboard')).toBeVisible({ timeout: 10000 });
  });

  test('sidebar contains Profile navigation link', async ({ authenticatedPage: page }) => {
    await expect(page.getByText('Profile')).toBeVisible({ timeout: 10000 });
  });

  test('sidebar contains Threat Intel navigation link', async ({ authenticatedPage: page }) => {
    await expect(page.getByText('Threat Intel')).toBeVisible({ timeout: 10000 });
  });

  test('sidebar contains S3 Scanning navigation link', async ({ authenticatedPage: page }) => {
    await expect(page.getByText('S3 Scanning')).toBeVisible({ timeout: 10000 });
  });

  test('clicking Dashboard link navigates to dashboard', async ({ authenticatedPage: page }) => {
    // Navigate away first
    await page.goto('/profile');
    await page.waitForLoadState('networkidle');

    // Click Dashboard in sidebar
    await page.getByText('Dashboard').click();

    // Should navigate to /
    await page.waitForURL((url) => url.pathname === '/', { timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 5000 });
  });

  test('clicking Profile link navigates to profile page', async ({ authenticatedPage: page }) => {
    // Start from dashboard
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await page.getByText('Profile').click();

    await page.waitForURL('**/profile', { timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'Your Profile' })).toBeVisible({ timeout: 5000 });
  });

  test('clicking Threat Intel link navigates to threat intel page', async ({ authenticatedPage: page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await page.getByText('Threat Intel').click();

    await page.waitForURL('**/threat-intel', { timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'Threat Intelligence' })).toBeVisible({ timeout: 5000 });
  });

  test('clicking S3 Scanning link navigates to s3 scan page', async ({ authenticatedPage: page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await page.getByText('S3 Scanning').click();

    await page.waitForURL('**/s3-scan', { timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'S3 Malware Scanning' })).toBeVisible({ timeout: 5000 });
  });

  test('admin sidebar shows Settings link', async ({ adminPage: page }) => {
    // Settings is in 'Management' category, roles: ['admin', 'maintainer']
    await expect(page.getByText('Settings')).toBeVisible({ timeout: 10000 });
  });

  test('clicking Settings link navigates to settings page for admin', async ({ adminPage: page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await page.getByText('Settings').click();

    await page.waitForURL('**/settings', { timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible({ timeout: 5000 });
  });

  test('admin sidebar shows Users link', async ({ adminPage: page }) => {
    // Users is in 'Administration' category, roles: ['admin']
    await expect(page.getByText('Users')).toBeVisible({ timeout: 10000 });
  });

  test('clicking Users link navigates to users management page', async ({ adminPage: page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await page.getByText('Users').click();

    await page.waitForURL('**/users', { timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'User Management' })).toBeVisible({ timeout: 5000 });
  });

  test('sidebar shows Logout button', async ({ authenticatedPage: page }) => {
    // Logout is in the footer items of SidebarMenu
    await expect(page.getByText('Logout')).toBeVisible({ timeout: 10000 });
  });

  test('clicking Logout redirects to login page', async ({ authenticatedPage: page }) => {
    const logoutButton = page.getByText('Logout').first();
    await expect(logoutButton).toBeVisible({ timeout: 10000 });

    await logoutButton.click();

    // Should navigate to /login
    await page.waitForURL('**/login', { timeout: 8000 });
    expect(page.url()).toContain('/login');
  });

  test('sidebar is present after navigating between pages', async ({ authenticatedPage: page }) => {
    // Navigate through multiple pages and verify sidebar persists
    await page.goto('/profile');
    await expect(page.getByText('SkausWatch')).toBeVisible({ timeout: 10000 });

    await page.goto('/threat-intel');
    await expect(page.getByText('SkausWatch')).toBeVisible({ timeout: 10000 });

    await page.goto('/s3-scan');
    await expect(page.getByText('SkausWatch')).toBeVisible({ timeout: 10000 });
  });

  test('sidebar shows user info in footer', async ({ authenticatedPage: page }) => {
    // The SidebarMenu footerItems include user full_name and role badge
    // The role badge should be visible (admin, maintainer, or viewer)
    const roleText = page.locator('text=/admin|maintainer|viewer/i').first();
    await expect(roleText).toBeVisible({ timeout: 10000 });
  });

  test('navigation from /dashboard redirects to /', async ({ authenticatedPage: page }) => {
    // App.tsx: Route path="/dashboard" redirects to "/" via Navigate
    await page.goto('/dashboard');

    await page.waitForURL((url) => url.pathname === '/', { timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 5000 });
  });
});
