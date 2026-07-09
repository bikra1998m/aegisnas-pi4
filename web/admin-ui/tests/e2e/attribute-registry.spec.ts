import { test, expect } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test('filters the generated typed attribute registry', async ({ page }) => {
  await seedAuthenticatedSession(page);
  await installMockApi(page);
  await page.goto('/vendor-compatibility');

  const releaseProfile = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Dictionary Release Profile' }) });
  await expect(releaseProfile).toBeVisible();
  await expect(releaseProfile.getByText('freeradius-3.2.8').first()).toBeVisible();
  await expect(releaseProfile.getByText('UniFi Network')).toBeVisible();

  const codec = page.locator('section').filter({ has: page.getByRole('heading', { name: 'VSA Codec' }) });
  await expect(codec).toBeVisible();
  await expect(codec.getByText('Codec schema 1')).toBeVisible();
  await expect(codec.getByText('Grouped OIDs', { exact: true })).toBeVisible();
  await expect(codec.getByText('type 4 / length 2')).toBeVisible();

  const evidence = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Compatibility Evidence' }) });
  await expect(evidence).toBeVisible();
  await expect(evidence.getByText('UBNT-Data-Rate-DL')).toBeVisible();
  await evidence.getByLabel('Claim').selectOption('software_ready_external_required');
  await evidence.getByRole('button', { name: 'Filter' }).click();
  await expect(evidence.getByText('software ready external required')).toBeVisible();
  await expect(evidence.getByText('external required', { exact: true })).toBeVisible();

  await expect(page.getByRole('heading', { name: 'Typed Attribute Registry' })).toBeVisible();
  await expect(page.getByText('freeradius-3.2.8 / schema 1')).toBeVisible();
  const registry = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Typed Attribute Registry' }) });
  await registry.getByLabel('Vendor').fill('Aruba');
  await registry.getByLabel('Status').selectOption('partial');
  await registry.getByRole('button', { name: 'Filter' }).click();

  await expect(page.getByText('Aruba-User-Role')).toBeVisible();
  await expect(page.getByText('Aruba-User-Vlan')).toBeVisible();
  await expect(page.getByText('PEN 14823 / 1')).toBeVisible();
});
