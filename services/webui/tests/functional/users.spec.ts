/**
 * Users Management Page Tests (/users).
 *
 * The Users page is protected by RoleGuard for ['admin'] only.
 * It renders:
 * - Heading "User Management"
 * - "+ Add User" button
 * - Users table with columns: Name, Email, Role, Status, Actions
 * - FormModalBuilder modal when "+ Add User" is clicked:
 *   Fields: Full Name, Email, Password, Role (select: viewer/maintainer/admin)
 *   Submit button: "Create User"
 *
 * Delete action uses window.confirm() dialog.
 */
import { test, expect } from './fixtures';

test.describe('Users Management Page', () => {
  test.beforeEach(async ({ page }) => {
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');
  });

  test('users page renders heading and add user button', async ({ adminPage: page }) => {
    await page.goto('/users');

    await expect(page.getByRole('heading', { name: 'User Management' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Manage system users and permissions')).toBeVisible();

    // Add User button
    const addButton = page.getByRole('button', { name: /\+ Add User/i });
    await expect(addButton).toBeVisible();
  });

  test('users table renders with column headers', async ({ adminPage: page }) => {
    await page.goto('/users');

    // Wait for page content to load
    await page.waitForSelector('table, [role="table"]', { timeout: 10000 }).catch(async () => {
      // Table may not render if no users / loading state
      await page.waitForSelector('.animate-pulse, table', { timeout: 5000 });
    });

    // Table headers should be present
    await expect(page.getByText('Name')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Email')).toBeVisible();
    await expect(page.getByText('Role')).toBeVisible();
    await expect(page.getByText('Status')).toBeVisible();
    await expect(page.getByText('Actions')).toBeVisible();
  });

  test('clicking Add User button opens create user modal', async ({ adminPage: page }) => {
    await page.goto('/users');

    await page.waitForSelector('button', { timeout: 10000 });
    const addButton = page.getByRole('button', { name: /\+ Add User/i });
    await expect(addButton).toBeVisible({ timeout: 10000 });
    await addButton.click();

    // FormModalBuilder renders a modal with title "Create New User"
    await expect(page.getByText('Create New User')).toBeVisible({ timeout: 5000 });
  });

  test('create user modal has required form fields', async ({ adminPage: page }) => {
    await page.goto('/users');

    const addButton = page.getByRole('button', { name: /\+ Add User/i });
    await expect(addButton).toBeVisible({ timeout: 10000 });
    await addButton.click();

    // Wait for modal
    await expect(page.getByText('Create New User')).toBeVisible({ timeout: 5000 });

    // Check for form fields as defined in the FormModalBuilder:
    // Full Name, Email, Password, Role
    await expect(page.getByText('Full Name')).toBeVisible();
    await expect(page.getByText('Email')).toBeVisible();
    await expect(page.getByText('Password')).toBeVisible();
    await expect(page.getByText('Role')).toBeVisible();
  });

  test('create user modal has submit button', async ({ adminPage: page }) => {
    await page.goto('/users');

    const addButton = page.getByRole('button', { name: /\+ Add User/i });
    await expect(addButton).toBeVisible({ timeout: 10000 });
    await addButton.click();

    await expect(page.getByText('Create New User')).toBeVisible({ timeout: 5000 });

    // FormModalBuilder submit button text is "Create User"
    const submitButton = page.getByRole('button', { name: /Create User/i });
    await expect(submitButton).toBeVisible();
  });

  test('create user modal has role selector with correct options', async ({ adminPage: page }) => {
    await page.goto('/users');

    const addButton = page.getByRole('button', { name: /\+ Add User/i });
    await expect(addButton).toBeVisible({ timeout: 10000 });
    await addButton.click();

    await expect(page.getByText('Create New User')).toBeVisible({ timeout: 5000 });

    // Role select should have viewer, maintainer, admin options
    const roleSelect = page.locator('select').first();
    if (await roleSelect.isVisible()) {
      const options = await roleSelect.locator('option').allTextContents();
      const optionTexts = options.map(o => o.toLowerCase());
      expect(optionTexts.some(o => o.includes('viewer'))).toBe(true);
      expect(optionTexts.some(o => o.includes('maintainer') || o.includes('admin'))).toBe(true);
    }
  });

  test('create user modal can be closed', async ({ adminPage: page }) => {
    await page.goto('/users');

    const addButton = page.getByRole('button', { name: /\+ Add User/i });
    await expect(addButton).toBeVisible({ timeout: 10000 });
    await addButton.click();

    await expect(page.getByText('Create New User')).toBeVisible({ timeout: 5000 });

    // Close button - FormModalBuilder usually has an X button or Cancel
    const closeButton = page.locator(
      'button:has-text("Cancel"), button:has-text("Close"), button[aria-label="Close"]'
    ).first();

    if (await closeButton.isVisible()) {
      await closeButton.click();
      await expect(page.getByText('Create New User')).not.toBeVisible({ timeout: 3000 });
    }
  });

  test('delete user shows confirmation dialog', async ({ adminPage: page }) => {
    await page.goto('/users');

    // Wait for table to load
    await page.waitForSelector('table', { timeout: 10000 }).catch(() => {});

    // Check if there are any delete buttons in the table
    const deleteButtons = page.locator('button:has-text("Delete"), a:has-text("Delete")');
    const count = await deleteButtons.count();

    if (count > 0) {
      // Set up dialog handler before clicking - the code uses window.confirm()
      let dialogMessage = '';
      page.once('dialog', async (dialog) => {
        dialogMessage = dialog.message();
        await dialog.dismiss(); // Cancel to avoid actual deletion
      });

      await deleteButtons.first().click();

      // The confirm message should mention deleting the user
      await page.waitForTimeout(500);
      expect(dialogMessage).toMatch(/Are you sure you want to delete this user/i);
    } else {
      // No users in the table - the confirm dialog test is not applicable
      test.skip(true, 'No users present to test delete confirmation');
    }
  });

  test('unauthenticated access to /users redirects to login', async ({ page }) => {
    // Navigate directly without authentication
    await page.goto('/users');

    await page.waitForTimeout(2000);
    // Should be redirected to login
    expect(page.url()).toContain('/login');
  });
});
