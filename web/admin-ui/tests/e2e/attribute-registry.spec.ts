import { test, expect } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test('filters the generated typed attribute registry', async ({ page }) => {
  await seedAuthenticatedSession(page);
  await installMockApi(page);
  await page.goto('/vendor-compatibility');

  await expect(page.getByRole('heading', { name: 'Typed Attribute Registry' })).toBeVisible();
  await expect(page.getByText('Schema 1 / FreeRADIUS 3.2.8')).toBeVisible();
  const registry = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Typed Attribute Registry' }) });
  await registry.getByLabel('Vendor').fill('Aruba');
  await registry.getByLabel('Status').selectOption('partial');
  await registry.getByRole('button', { name: 'Filter' }).click();

  await expect(page.getByText('Aruba-User-Role')).toBeVisible();
  await expect(page.getByText('Aruba-User-Vlan')).toBeVisible();
  await expect(page.getByText('PEN 14823 / 1')).toBeVisible();
});
