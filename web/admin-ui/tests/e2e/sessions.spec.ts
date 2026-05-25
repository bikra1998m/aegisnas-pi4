import { expect, test } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test.describe('Sessions page', () => {
  test('shows analytics and allows terminating an active session', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    page.on('dialog', async (dialog) => {
      await dialog.accept();
    });

    await page.goto('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions', exact: true })).toBeVisible();
    await expect(page.getByText('Session Activity Summary')).toBeVisible();
    await expect(page.getByText('Authentication Mix')).toBeVisible();
    await expect(page.getByText('Peak Concurrent')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Export Analytics JSON' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Export Analytics CSV' })).toBeVisible();

    await expect(page.getByRole('row', { name: /alice/i })).toBeVisible();
    await page.getByRole('button', { name: 'Terminate' }).first().click();
    await expect(page.getByText('Session terminated.')).toBeVisible();
  });
});
