/**
 * Profile Page Tests.
 *
 * The Profile page (/profile) renders:
 * - A heading "Your Profile"
 * - Profile Information card with: Full Name, Email, Password (masked), Edit Profile button
 * - Account Summary card with: Role badge, Status, Member Since
 *
 * In edit mode it shows:
 * - Full Name input
 * - Email input (disabled)
 * - Change Password section: Current Password, New Password, Confirm New Password
 * - Cancel and Save Changes buttons
 *
 * Password mismatch validation: "New passwords do not match"
 */
import { test, expect } from './fixtures';

test.describe('Profile Page', () => {
  test.beforeEach(async ({ page }) => {
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');
  });

  test('profile page renders heading and user info', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    await expect(page.getByRole('heading', { name: 'Your Profile' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Manage your account settings')).toBeVisible();
  });

  test('profile page shows user information in view mode', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    // Profile Information card
    await expect(page.getByText('Profile Information')).toBeVisible({ timeout: 10000 });

    // Should show Full Name and Email labels
    await expect(page.getByText('Full Name')).toBeVisible();
    await expect(page.getByText('Email')).toBeVisible();

    // Password field shows masked value
    await expect(page.getByText('••••••••')).toBeVisible();
  });

  test('account summary card renders with role and status', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    // Account Summary card
    await expect(page.getByText('Account Summary')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Role')).toBeVisible();
    await expect(page.getByText('Status')).toBeVisible();
    await expect(page.getByText('Member Since')).toBeVisible();
  });

  test('Edit Profile button toggles edit mode and shows form', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    // Click Edit Profile button
    const editButton = page.getByRole('button', { name: 'Edit Profile' });
    await expect(editButton).toBeVisible({ timeout: 10000 });
    await editButton.click();

    // Form should appear with Full Name input
    const fullNameInput = page.locator('input[type="text"]').first();
    await expect(fullNameInput).toBeVisible({ timeout: 5000 });

    // Email field should be visible but disabled
    const emailInput = page.locator('input[type="email"]').first();
    await expect(emailInput).toBeVisible();
    await expect(emailInput).toBeDisabled();
  });

  test('edit mode shows Change Password section', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    await page.getByRole('button', { name: 'Edit Profile' }).click();

    // Change Password heading
    await expect(page.getByText('Change Password')).toBeVisible({ timeout: 5000 });

    // Three password fields: Current, New, Confirm
    const passwordInputs = page.locator('input[type="password"]');
    await expect(passwordInputs).toHaveCount(3);
  });

  test('edit mode shows Cancel and Save Changes buttons', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    await page.getByRole('button', { name: 'Edit Profile' }).click();

    await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: 'Save Changes' })).toBeVisible();
  });

  test('Cancel button in edit mode returns to view mode', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    await page.getByRole('button', { name: 'Edit Profile' }).click();
    await expect(page.locator('input[type="text"]').first()).toBeVisible({ timeout: 5000 });

    await page.getByRole('button', { name: 'Cancel' }).click();

    // Should return to view mode - Edit Profile button appears again
    await expect(page.getByRole('button', { name: 'Edit Profile' })).toBeVisible({ timeout: 5000 });

    // Edit form should be gone
    await expect(page.locator('button[type="submit"]').filter({ hasText: 'Save Changes' })).not.toBeVisible();
  });

  test('password mismatch shows validation error', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    await page.getByRole('button', { name: 'Edit Profile' }).click();
    await page.waitForSelector('input[type="password"]', { timeout: 5000 });

    const passwordInputs = page.locator('input[type="password"]');

    // Fill current password
    await passwordInputs.nth(0).fill('currentpassword');

    // Fill new password
    await passwordInputs.nth(1).fill('newpassword123');

    // Fill confirm with a DIFFERENT password to trigger mismatch
    await passwordInputs.nth(2).fill('differentpassword123');

    // Click Save
    await page.getByRole('button', { name: 'Save Changes' }).click();

    // Error message should appear
    await expect(page.getByText('New passwords do not match')).toBeVisible({ timeout: 5000 });
  });

  test('can update full name field value in edit mode', async ({ authenticatedPage: page }) => {
    await page.goto('/profile');

    await page.getByRole('button', { name: 'Edit Profile' }).click();
    await page.waitForSelector('input[type="text"]', { timeout: 5000 });

    const fullNameInput = page.locator('input[type="text"]').first();

    // Clear and type a new name
    await fullNameInput.clear();
    await fullNameInput.fill('Test User Name');
    await expect(fullNameInput).toHaveValue('Test User Name');
  });
});
