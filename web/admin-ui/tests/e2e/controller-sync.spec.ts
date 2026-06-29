import { expect, test } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test.describe('controller policy synchronization', () => {
  test('previews pull state, reports drift, and confirms policy push', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/');
    await expect(page.getByText('Controller Automation', { exact: true })).toBeVisible();

    await page.getByRole('button', { name: 'Preview Pull' }).click();
    await expect(page.getByText('Read-only pull preview is ready.')).toBeVisible();
    await expect(page.getByText(/GET https:\/\/controller\.example\.test\/api\/state/)).toBeVisible();

    await page.getByRole('button', { name: 'Pull And Check Drift' }).click();
    await expect(page.getByText('Controller pull completed with detected policy drift.')).toBeVisible();
    await expect(page.getByText('Detected 2 controller drift item(s).')).toBeVisible();

    await page.getByRole('button', { name: 'Preview Push' }).click();
    await expect(page.getByText('Policy push preview is ready.')).toBeVisible();
    const pushButton = page.getByRole('button', { name: 'Push Controller Policy' });
    await expect(pushButton).toBeDisabled();
    await page.getByLabel('Push confirmation phrase').fill('PUSH CONTROLLER POLICY');
    await expect(pushButton).toBeEnabled();
    await pushButton.click();
    await expect(page.getByText('Controller push completed successfully.')).toBeVisible();
  });
});
