import { expect, test } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test('verifies, previews, and applies a production PEN migration', async ({ page }) => {
  await seedAuthenticatedSession(page);
  await installMockApi(page);
  await page.goto('/vendor-compatibility');

  await expect(page.getByRole('heading', { name: 'Product Vendor Identity' })).toBeVisible();
  await expect(page.getByText('Lab identity')).toBeVisible();

  await page.getByLabel('Assigned PEN').fill('424242');
  await page.getByLabel('Exact IANA organization').fill('AegisNAS Systems Ltd.');
  await page.getByRole('button', { name: 'Verify with IANA and Preview' }).click();

  await expect(page.getByRole('heading', { name: 'Verified Migration Preview' })).toBeVisible();
  await expect(page.getByText('IANA matched')).toBeVisible();
  await page.getByRole('button', { name: 'Apply Verified Migration' }).click();

  await expect(page.getByText('Production vendor identity applied and FreeRADIUS restarted.')).toBeVisible();
  await expect(page.getByText('Verified assignment')).toBeVisible();
  await expect(page.getByText('production verified')).toBeVisible();
});
