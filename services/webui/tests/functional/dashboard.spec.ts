/**
 * Dashboard Tests - Main dashboard page after login.
 *
 * The Dashboard page renders:
 * - A page heading "Dashboard"
 * - A welcome message with the user's name
 * - Tab navigation: Overview | System Status | Metrics
 * - Cards: Welcome, Your Account, Quick Stats (on Overview tab)
 * - Flask Backend / Go Backend status cards (on System Status tab)
 * - Metrics card (on Metrics tab)
 *
 * Tests requiring a backend are gated with process.env.BACKEND_URL check.
 */
import { test, expect } from './fixtures';

test.describe('Dashboard Page', () => {
  test.beforeEach(async ({ page }) => {
    // Skip all dashboard tests when backend is not available
    // by navigating and checking if we end up authenticated
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');
  });

  test('dashboard renders with heading', async ({ authenticatedPage: page }) => {
    // After login, we should be at / which renders Dashboard
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 10000 });
  });

  test('dashboard shows welcome message for authenticated user', async ({ authenticatedPage: page }) => {
    // The Dashboard shows "Welcome back, {user.full_name || 'User'}"
    const welcomeText = page.getByText(/Welcome back/i);
    await expect(welcomeText).toBeVisible({ timeout: 10000 });
  });

  test('tab navigation renders three tabs', async ({ authenticatedPage: page }) => {
    // Dashboard has: Overview, System Status, Metrics tabs
    // TabNavigation renders <button> elements with .tab-item class
    await expect(page.getByRole('button', { name: 'Overview' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: 'System Status' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Metrics' })).toBeVisible();
  });

  test('overview tab is active by default and shows cards', async ({ authenticatedPage: page }) => {
    // Default active tab is 'overview'
    // Should show Welcome, Your Account, and Quick Stats cards
    await expect(page.getByText('Welcome')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Your Account')).toBeVisible();
    await expect(page.getByText('Quick Stats')).toBeVisible();
  });

  test('clicking System Status tab shows backend status cards', async ({ authenticatedPage: page }) => {
    await page.getByRole('button', { name: 'System Status' }).click();

    // Should show Flask Backend and Go Backend cards
    await expect(page.getByText('Flask Backend')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Go Backend')).toBeVisible();
  });

  test('clicking Metrics tab shows metrics content', async ({ authenticatedPage: page }) => {
    await page.getByRole('button', { name: 'Metrics' }).click();

    // Metrics tab shows "System Metrics" card
    await expect(page.getByText('System Metrics')).toBeVisible({ timeout: 5000 });
  });

  test('Your Account card shows user email', async ({ authenticatedPage: page }) => {
    // The "Your Account" card shows user email and role
    await expect(page.getByText('Email:')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Role:')).toBeVisible();
  });

  test('navigation sidebar is visible on dashboard', async ({ authenticatedPage: page }) => {
    // The Layout renders the Sidebar which uses SidebarMenu from @penguintechinc/react-libs
    // The sidebar should contain "SkausWatch" app name and nav items
    await expect(page.getByText('SkausWatch')).toBeVisible({ timeout: 10000 });
  });

  test('Overview tab switching back from other tabs works', async ({ authenticatedPage: page }) => {
    // Switch to System Status then back to Overview
    await page.getByRole('button', { name: 'System Status' }).click();
    await expect(page.getByText('Flask Backend')).toBeVisible({ timeout: 5000 });

    await page.getByRole('button', { name: 'Overview' }).click();
    await expect(page.getByText('Welcome')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Quick Stats')).toBeVisible();
  });
});
