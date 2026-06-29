import { expect, test } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test.describe('ACL policy library', () => {
  test('lists policies and stages validated vendor-neutral rules', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/acl-policies');
    await expect(page.getByRole('heading', { name: 'ACL Policies' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'guest-internet' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'guest-in', exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: '1', exact: true })).toBeVisible();

    await page.getByRole('button', { name: 'Add ACL Policy' }).click();
    await page.getByLabel('Name', { exact: true }).fill('employee-web');
    await page.getByRole('button', { name: 'Stage Create' }).click();
    await expect(page.getByText('Change staged. Review and apply it from the pending changes bar.')).toBeVisible();
  });
});
