import { expect, test } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test.describe('Access Settings edge-network flow', () => {
  test('configures inbound and outbound RadSec without exposing a UDP fallback', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);
    await page.goto('/access-settings');

    await expect(page.getByRole('heading', { name: 'RadSec', exact: true })).toBeVisible();
    await page.getByLabel('Inbound RadSec').check();
    await page.getByLabel('Server Certificate').fill('/etc/aegisnas/radsec/server.crt');
    await page.getByLabel('Server Private Key').fill('/etc/aegisnas/radsec/server.key');
    await page.getByLabel('Trusted CA File').first().fill('/etc/aegisnas/radsec/ca.crt');

    await page.getByRole('button', { name: 'Add Server' }).click();
    const serverPanel = page.getByRole('heading', { name: 'Server 1' }).locator('../..');
    await serverPanel.getByLabel('Transport').selectOption('radsec');
    await expect(serverPanel.getByLabel('RadSec Port')).toBeVisible();
    await expect(serverPanel.getByLabel('Secret')).toHaveCount(0);
    await serverPanel.getByLabel('Verified Server Name').fill('aaa.example.test');
    await serverPanel.getByLabel('Client Certificate').fill('/etc/aegisnas/radsec/client.crt');
    await serverPanel.getByLabel('Client Private Key').fill('/etc/aegisnas/radsec/client.key');

    await page.getByRole('button', { name: 'Save Settings' }).click();
    await expect(page.getByText(/Settings saved\./)).toBeVisible();
  });

  test('previews, confirms, applies, and rolls back risky edge-network changes', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    await expect(page.getByRole('heading', { name: 'Access Settings' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'EAP-TLS Certificate Revocation' })).toBeVisible();
    const checkClientCRL = page.getByLabel('Check Client CRL');
    await expect(checkClientCRL).not.toBeChecked();
    await checkClientCRL.check();
    await expect(checkClientCRL).toBeChecked();

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
    await expect(page.getByText('Management Reachability Confirmation Pending')).toBeVisible();
    await expect(page.getByRole('button', { name: 'I Still Have Admin Access' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Awaiting Reachability Confirmation' })).toBeDisabled();

    await page.getByRole('button', { name: 'I Still Have Admin Access' }).click();
    await expect(page.getByText(/Management access confirmed\. Automatic rollback has been cancelled/)).toBeVisible();
    await expect(page.getByText('Latest Reachability Recovery Status')).toBeVisible();

    await page.getByRole('button', { name: 'Rollback Edge Network' }).click();
    await expect(page.getByText(/Edge network state rolled back to snapshot snap-002\./)).toBeVisible();
    await expect(page.getByText('Management Impact Confirmation Required')).toBeVisible();
  });
});
