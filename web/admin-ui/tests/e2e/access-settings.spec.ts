import { expect, test } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test.describe('Access Settings edge-network flow', () => {
  test('previews, confirms, applies, and rolls back risky edge-network changes', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    await expect(page.getByRole('heading', { name: 'Access Settings' })).toBeVisible();

    await page.getByLabel('Local DNS Domain').fill('lab.aegis.test');
    await page.getByRole('button', { name: 'Save Settings' }).click();
    await expect(page.getByText(/Settings saved\./)).toBeVisible();

    await page.getByRole('button', { name: 'Preview Edge Network' }).click();
    await expect(page.getByText('Management Impact Confirmation Required')).toBeVisible();
    await expect(page.getByText('The apply button stays locked until this phrase matches exactly.')).toBeVisible();

    const applyButton = page.getByRole('button', { name: 'Confirm And Apply Edge Network' });
    await expect(applyButton).toBeDisabled();

    await page.getByLabel('Type the confirmation phrase to unlock apply').fill('APPLY EDGE NETWORK');
    await expect(applyButton).toBeEnabled();
    await applyButton.click();

    await expect(page.getByText('Last Apply Validation Passed')).toBeVisible();
    await expect(page.getByText(/Interfaces, routes, dnsmasq, and firewall rules were applied on the appliance\./)).toBeVisible();
    await expect(page.getByText(/Backup snapshot snap-002 was saved first\./)).toBeVisible();

    await page.getByRole('button', { name: 'Rollback Edge Network' }).click();
    await expect(page.getByText(/Edge network state rolled back to snapshot snap-002\./)).toBeVisible();
    await expect(page.getByText('Management Impact Confirmation Required')).toBeVisible();
  });
});
