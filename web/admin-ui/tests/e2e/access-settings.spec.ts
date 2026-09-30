import { expect, test } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test.describe('Access Settings edge-network flow', () => {
  test('configures inbound and outbound RadSec without exposing a UDP fallback', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);
    await page.goto('/access-settings');

    await expect(page.getByRole('heading', { name: 'Access Settings' })).toBeVisible();
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

  test('previews and applies 802.11r/k/v roaming lifecycle', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    const roamingSection = page.locator('section').filter({
      has: page.getByRole('heading', { name: '802.11r/k/v Roaming Lifecycle' }),
    });
    await expect(roamingSection).toBeVisible();
    await expect(
      roamingSection.getByRole('heading', { name: 'Roaming SSIDs' }),
    ).toBeVisible();
    await expect(
      roamingSection.locator('div').filter({ hasText: /^FT SSIDs$/ }).first(),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Preview 802.11r/k/v' }).click();
    await expect(
      page.getByText(/802\.11r\/k\/v roaming preview recorded/),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Apply 802.11r/k/v' }).click();
    await expect(
      page.getByText(/802\.11r\/k\/v roaming lifecycle applied/),
    ).toBeVisible();
  });

  test('previews and applies Passpoint and Hotspot 2.0 lifecycle', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    const passpointSection = page.locator('section').filter({
      has: page.getByRole('heading', { name: 'Passpoint And Hotspot 2.0 Lifecycle' }),
    });
    await expect(passpointSection).toBeVisible();
    await expect(
      passpointSection.getByRole('heading', { name: 'Passpoint SSIDs' }),
    ).toBeVisible();
    await expect(
      passpointSection.locator('div').filter({ hasText: /^HS2\.0 SSIDs$/ }).first(),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Preview Passpoint' }).click();
    await expect(
      page.getByText(/Passpoint and Hotspot 2\.0 preview recorded/),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Apply Passpoint' }).click();
    await expect(
      page.getByText(/Passpoint and Hotspot 2\.0 lifecycle applied/),
    ).toBeVisible();
  });

  test('previews and applies DPSK and PPSK lifecycle', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    const ppskSection = page.locator('section').filter({
      has: page.getByRole('heading', { name: 'DPSK And PPSK Lifecycle' }),
    });
    await expect(ppskSection).toBeVisible();
    await expect(
      ppskSection.getByRole('heading', { name: 'PPSK SSIDs' }),
    ).toBeVisible();
    await expect(
      ppskSection.locator('div').filter({ hasText: /^Active Keys$/ }).first(),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Preview PPSK' }).click();
    await expect(page.getByText(/DPSK\/PPSK preview recorded/)).toBeVisible();

    await page.getByRole('button', { name: 'Apply PPSK' }).click();
    await expect(
      page.getByText(/DPSK\/PPSK lifecycle applied/),
    ).toBeVisible();
  });

  test('previews and applies controller estate lifecycle', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    const controllerEstateSection = page.locator('section').filter({
      has: page.getByRole('heading', { name: 'Controller Estate Lifecycle' }),
    });
    await expect(controllerEstateSection).toBeVisible();
    await expect(
      controllerEstateSection.getByRole('heading', { name: 'WLAN Templates' }),
    ).toBeVisible();
    await expect(
      controllerEstateSection.getByRole('heading', { name: 'Compliance Checks' }),
    ).toBeVisible();
    await expect(
      controllerEstateSection.locator('div').filter({ hasText: /^Delete Guards$/ }).first(),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Preview Controller Estate' }).click();
    await expect(
      page.getByText(/Controller estate preview recorded/),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Apply Controller Estate' }).click();
    await expect(
      page.getByText(/Controller estate lifecycle applied/),
    ).toBeVisible();
  });

  test('previews and applies RF, RRM, mesh, and radio planning lifecycle', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    const rfSection = page.locator('section').filter({
      has: page.getByRole('heading', { name: 'RF, RRM, Mesh, And Radio Planning' }),
    });
    await expect(rfSection).toBeVisible();
    await expect(
      rfSection.getByRole('heading', { name: 'Radio Plan', exact: true }),
    ).toBeVisible();
    await expect(
      rfSection.getByRole('heading', { name: 'Channel Plan', exact: true }),
    ).toBeVisible();
    await expect(
      rfSection.getByRole('heading', { name: 'Compliance Checks', exact: true }),
    ).toBeVisible();
    await expect(
      rfSection.locator('div').filter({ hasText: /^Mesh Links$/ }).first(),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Preview RF Plan' }).click();
    await expect(
      page.getByText(/RF planning preview recorded/),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Apply RF Plan' }).click();
    await expect(
      page.getByText(/RF planning lifecycle applied/),
    ).toBeVisible();
  });

  test('previews and applies rogue, WIPS, spectrum, location, and multicast lifecycle', async ({ page }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    const securitySection = page.locator('section').filter({
      has: page.getByRole('heading', {
        name: 'Rogue, WIPS, Spectrum, Location, And Multicast',
      }),
    });
    await expect(securitySection).toBeVisible();
    await expect(
      securitySection.getByRole('heading', { name: 'Rogue Governance' }),
    ).toBeVisible();
    await expect(
      securitySection.getByRole('heading', { name: 'WIPS Detections' }),
    ).toBeVisible();
    await expect(
      securitySection.getByRole('heading', { name: 'Multicast Policy' }),
    ).toBeVisible();
    await expect(
      securitySection.locator('div').filter({ hasText: /^WIPS Checks$/ }).first(),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Preview WIPS Plan' }).click();
    await expect(
      page.getByText(/Wireless security preview recorded/),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Apply WIPS Plan' }).click();
    await expect(
      page.getByText(/Wireless security lifecycle applied/),
    ).toBeVisible();
  });

  test('previews and applies controller CWA and safe portal lifecycle', async ({
    page,
  }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto('/access-settings');
    const cwaSection = page.locator('section').filter({
      has: page.getByRole('heading', {
        name: 'Controller CWA And Safe Portal',
      }),
    });
    await expect(cwaSection).toBeVisible();
    await expect(cwaSection.getByText('RFC 8910 API', { exact: true })).toBeVisible();
    await expect(
      cwaSection.getByRole('heading', { name: 'Walled Garden' }),
    ).toBeVisible();
    await expect(
      cwaSection.getByRole('heading', { name: 'Redirect And CoA' }),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Preview CWA Portal' }).click();
    await expect(page.getByText(/CWA portal preview recorded/)).toBeVisible();

    await page.getByRole('button', { name: 'Apply CWA Portal' }).click();
    await expect(page.getByText(/CWA portal lifecycle applied/)).toBeVisible();
  });
});
