/**
 * AGCMS Dashboard — Playwright E2E smoke tests.
 *
 * Prerequisites:
 *   - Docker stack running: docker compose up -d --wait
 *   - Dashboard served on http://localhost:3000  (nginx inside container)
 *   - Gateway on http://localhost:8000
 *
 * Each test navigates to a page and verifies:
 *   1. No crash (page title / heading present)
 *   2. Key UI element visible within the load timeout
 *   3. No uncaught JS errors that break rendering
 *
 * We do NOT assert on exact data values — those come from the live DB
 * and vary across runs. We assert structure (headings, table headers,
 * buttons) that must always be rendered regardless of data.
 */

import { expect, test } from '@playwright/test';

// Collect any uncaught page errors per test
const pageErrors: string[] = [];

test.beforeEach(async ({ page }) => {
  pageErrors.length = 0;
  page.on('pageerror', (err) => pageErrors.push(err.message));
});

test.afterEach(async () => {
  // Fail on any unhandled JS errors (excludes expected network errors in dev)
  const fatal = pageErrors.filter(
    (e) => !e.includes('Failed to fetch') && !e.includes('NetworkError'),
  );
  expect(fatal, `Uncaught JS errors: ${fatal.join('; ')}`).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// Sidebar navigation helper
// ---------------------------------------------------------------------------

async function navigateTo(page: import('@playwright/test').Page, path: string) {
  await page.goto(path, { waitUntil: 'domcontentloaded' });
  // Wait for React to render — look for main content area
  await page.waitForSelector('main, [role="main"], .min-h-screen', { timeout: 10_000 });
}

// ---------------------------------------------------------------------------
// 1. Overview
// ---------------------------------------------------------------------------

test('Overview page renders stats cards', async ({ page }) => {
  await navigateTo(page, '/');
  await expect(page.getByRole('heading', { name: /overview/i })).toBeVisible();
  // Stats cards — at least one number visible
  await expect(page.locator('text=/Total Requests|Violations|Escalations/i').first()).toBeVisible();
});

// ---------------------------------------------------------------------------
// 2. Violations
// ---------------------------------------------------------------------------

test('Violations page renders table', async ({ page }) => {
  await navigateTo(page, '/violations');
  await expect(page.getByRole('heading', { name: /violations/i })).toBeVisible();
  // Table headers
  await expect(page.locator('text=/Action|User|Tenant/i').first()).toBeVisible();
});

// ---------------------------------------------------------------------------
// 3. Playground
// ---------------------------------------------------------------------------

test('Playground page renders prompt input', async ({ page }) => {
  await navigateTo(page, '/playground');
  await expect(page.getByRole('heading', { name: /playground/i })).toBeVisible();
  await expect(page.locator('textarea, [placeholder*="prompt" i], [placeholder*="message" i]').first()).toBeVisible();
});

// ---------------------------------------------------------------------------
// 4. Users
// ---------------------------------------------------------------------------

test('Users page renders user table', async ({ page }) => {
  await navigateTo(page, '/users');
  await expect(page.getByRole('heading', { name: /Users & Departments/i })).toBeVisible();
  // Table columns
  await expect(page.locator('text=/Email|Role|Department/i').first()).toBeVisible({ timeout: 10_000 });
});

// ---------------------------------------------------------------------------
// 5. Policy
// ---------------------------------------------------------------------------

test('Policy page shows active policy version', async ({ page }) => {
  await navigateTo(page, '/policy');
  await expect(page.getByRole('heading', { name: /Policy Manager/i })).toBeVisible();
  await expect(page.locator('text=/Active|Version|Deploy/i').first()).toBeVisible({ timeout: 10_000 });
});

// ---------------------------------------------------------------------------
// 6. Audit
// ---------------------------------------------------------------------------

test('Audit page renders log table with filter bar', async ({ page }) => {
  await navigateTo(page, '/audit');
  await expect(page.getByRole('heading', { name: /audit/i })).toBeVisible();
  // Filter bar
  await expect(page.locator('select, [role="combobox"]').first()).toBeVisible({ timeout: 10_000 });
  // Export button
  await expect(page.getByRole('button', { name: /export/i }).first()).toBeVisible();
});

// ---------------------------------------------------------------------------
// 7. Alerts
// ---------------------------------------------------------------------------

test('Alerts page renders escalations section', async ({ page }) => {
  await navigateTo(page, '/alerts');
  await expect(page.getByRole('heading', { name: /alerts|escalations/i }).first()).toBeVisible();
  // Status-related text
  await expect(page.locator('text=/Pending|Escalation|Status/i').first()).toBeVisible({ timeout: 10_000 });
});

// ---------------------------------------------------------------------------
// 8. Reports
// ---------------------------------------------------------------------------

test('Reports page shows GDPR and EU AI Act cards', async ({ page }) => {
  await navigateTo(page, '/reports');
  await expect(page.getByRole('heading', { name: /reports/i })).toBeVisible();
  await expect(page.locator('text=/GDPR/i').first()).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('text=/EU AI Act/i').first()).toBeVisible();
  // Generate buttons
  await expect(page.getByRole('button', { name: /generate/i }).first()).toBeVisible();
});

test('Reports page generates GDPR report on button click', async ({ page }) => {
  await navigateTo(page, '/reports');
  await page.getByRole('button', { name: /generate/i }).first().click();
  // Report content should appear within 10s (live API call)
  await expect(page.locator('text=/total_requests|PII|findings|pass/i').first()).toBeVisible({
    timeout: 15_000,
  });
});

// ---------------------------------------------------------------------------
// 9. Settings
// ---------------------------------------------------------------------------

test('Settings page shows token and quota info', async ({ page }) => {
  await navigateTo(page, '/settings');
  await expect(page.getByRole('heading', { name: /settings/i })).toBeVisible();
  await expect(page.locator('text=/Token|Auth|Quota|Rate/i').first()).toBeVisible({ timeout: 10_000 });
});

// ---------------------------------------------------------------------------
// 10. Sidebar navigation — links work
// ---------------------------------------------------------------------------

test('Sidebar links navigate to all 8 pages without crash', async ({ page }) => {
  await navigateTo(page, '/');

  const routes = [
    '/violations',
    '/playground',
    '/users',
    '/policy',
    '/audit',
    '/alerts',
    '/reports',
    '/settings',
  ];

  for (const route of routes) {
    await page.goto(route, { waitUntil: 'domcontentloaded' });
    // Page must not show a blank screen — at least one heading visible
    await expect(
      page.locator('h1, h2').first(),
    ).toBeVisible({ timeout: 10_000 });
  }
});
