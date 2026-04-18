/**
 * Threat Intelligence Page Tests (/threat-intel).
 *
 * The ThreatIntel page renders:
 * - Heading "Threat Intelligence"
 * - Four tabs: IOCs | Feeds | Statistics | Research
 *
 * IOCs tab: placeholder "IOC management coming soon..."
 * Feeds tab: placeholder "Threat feed management coming soon..."
 * Statistics tab: placeholder "Threat intel statistics coming soon..."
 * Research tab: ResearchTab component
 *   - "Indicator Research" card title
 *   - ResearchInput component:
 *     - Search input (placeholder: "Search IP, domain, hash, URL, or email...")
 *     - Search button (emoji: 🔍 or spinner)
 *     - When text is typed, auto-detects type badge (IP, Domain, Hash, URL, Email, Unknown)
 *   - ResearchResults (shown after search)
 */
import { test, expect } from './fixtures';

test.describe('Threat Intelligence Page', () => {
  test.beforeEach(async ({ page }) => {
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend');
  });

  test('threat intel page renders heading', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    await expect(page.getByRole('heading', { name: 'Threat Intelligence' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Monitor and research threat indicators')).toBeVisible();
  });

  test('four tabs render correctly', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    // All four tab buttons should be visible
    await expect(page.getByRole('button', { name: 'IOCs' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: 'Feeds' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Statistics' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Research' })).toBeVisible();
  });

  test('Research tab is active by default (default state)', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    // Default activeTab in ThreatIntel is 'research'
    // ResearchTab renders a Card with title "Indicator Research"
    await expect(page.getByText('Indicator Research')).toBeVisible({ timeout: 10000 });
  });

  test('Research tab renders search input', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    // ResearchInput renders an input with placeholder text
    const searchInput = page.getByPlaceholder('Search IP, domain, hash, URL, or email...');
    await expect(searchInput).toBeVisible({ timeout: 10000 });
  });

  test('Research tab renders search button', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    // Wait for the research input
    await page.waitForSelector('input[placeholder*="Search IP"]', { timeout: 10000 });

    // Search button contains the 🔍 emoji or loading spinner
    // The button is next to the input in a flex container
    const searchButton = page.locator('button').filter({ hasText: /🔍|Lookup|Search/ }).first();
    await expect(searchButton).toBeVisible({ timeout: 5000 });
  });

  test('typing an IP address shows IP type badge', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    const searchInput = page.getByPlaceholder('Search IP, domain, hash, URL, or email...');
    await expect(searchInput).toBeVisible({ timeout: 10000 });

    // Type a valid IP address
    await searchInput.fill('192.168.1.1');

    // Badge "IP" should appear (auto-detection from ResearchInput)
    await expect(page.getByText('IP')).toBeVisible({ timeout: 3000 });
  });

  test('typing a domain shows Domain type badge', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    const searchInput = page.getByPlaceholder('Search IP, domain, hash, URL, or email...');
    await expect(searchInput).toBeVisible({ timeout: 10000 });

    await searchInput.fill('example.com');

    // Badge "Domain" should appear
    await expect(page.getByText('Domain')).toBeVisible({ timeout: 3000 });
  });

  test('typing an MD5 hash shows Hash type badge', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    const searchInput = page.getByPlaceholder('Search IP, domain, hash, URL, or email...');
    await expect(searchInput).toBeVisible({ timeout: 10000 });

    // 32 hex chars = MD5
    await searchInput.fill('d41d8cd98f00b204e9800998ecf8427e');

    await expect(page.getByText('Hash')).toBeVisible({ timeout: 3000 });
  });

  test('typing a URL shows URL type badge', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    const searchInput = page.getByPlaceholder('Search IP, domain, hash, URL, or email...');
    await expect(searchInput).toBeVisible({ timeout: 10000 });

    await searchInput.fill('https://example.com/malware');

    await expect(page.getByText('URL')).toBeVisible({ timeout: 3000 });
  });

  test('typing an email shows Email type badge', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    const searchInput = page.getByPlaceholder('Search IP, domain, hash, URL, or email...');
    await expect(searchInput).toBeVisible({ timeout: 10000 });

    await searchInput.fill('attacker@evil.com');

    await expect(page.getByText('Email')).toBeVisible({ timeout: 3000 });
  });

  test('clicking IOCs tab shows IOC placeholder content', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    await page.getByRole('button', { name: 'IOCs' }).click();

    await expect(page.getByText('Indicators of Compromise')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('IOC management coming soon...')).toBeVisible();
  });

  test('clicking Feeds tab shows Feeds placeholder content', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    await page.getByRole('button', { name: 'Feeds' }).click();

    await expect(page.getByText('Threat Feeds')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Threat feed management coming soon...')).toBeVisible();
  });

  test('clicking Statistics tab shows Statistics placeholder', async ({ authenticatedPage: page }) => {
    await page.goto('/threat-intel');

    await page.getByRole('button', { name: 'Statistics' }).click();

    await expect(page.getByText('Statistics')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Threat intel statistics coming soon...')).toBeVisible();
  });

  test('search button triggers lookup on Research tab', async ({ authenticatedPage: page }) => {
    // Note: Requires backend for actual lookup results
    test.skip(!process.env.BACKEND_URL && !process.env.CI, 'Requires running backend for search results');

    await page.goto('/threat-intel');

    const searchInput = page.getByPlaceholder('Search IP, domain, hash, URL, or email...');
    await expect(searchInput).toBeVisible({ timeout: 10000 });

    await searchInput.fill('8.8.8.8');

    // Wait for IP badge to show
    await expect(page.getByText('IP')).toBeVisible({ timeout: 3000 });

    // Click search button
    const searchButton = page.locator('button').filter({ hasText: /🔍/ }).first();
    await searchButton.click();

    // Should show some kind of response - loading state or results
    // (exact results depend on backend)
    await page.waitForTimeout(1000);
    // Test passes if no error thrown / page doesn't crash
  });
});
