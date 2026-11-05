import { test, expect } from '@playwright/test';
import { installMockApi, seedAuthenticatedSession } from './support/mockApi';

test('shows missing evidence and never keeps a stale success after refresh failure', async ({ page }) => {
  await seedAuthenticatedSession(page);
  await installMockApi(page);
  let failed = false;
  await page.route('**/api/v1/system/release-security', (route) => route.fulfill(failed ? {
    status: 503, body: '{}', contentType: 'application/json',
  } : {
    json: { status: 'not_admitted', go_version: 'go1.26.9', signature_reverified: false,
      signature_verified_at_admission: false, current_binary_matches_receipt: false,
      blockers: ['No readable release admission receipt is installed.'], scope: 'Admission record only.' },
  }));
  await page.goto('/release-security');
  await expect(page.getByRole('heading', { name: 'No verified admission recorded' })).toBeVisible();
  await expect(page.getByText('Not performed by this page')).toBeVisible();
  failed = true;
  await page.getByRole('button', { name: 'Refresh evidence' }).click();
  await expect(page.getByRole('alert')).toContainText('Verification state is unknown');
  await expect(page.getByText('Admission record only.')).toHaveCount(0);
});

test('distinguishes recorded admission from fresh signature verification', async ({ page }) => {
  await seedAuthenticatedSession(page);
  await installMockApi(page);
  await page.route('**/api/v1/system/release-security', (route) => route.fulfill({ json: {
    status: 'admission_recorded', go_version: 'go1.26.9', signature_reverified: false,
    signature_verified_at_admission: true, current_binary_matches_receipt: true,
    verified_at: '2026-10-15T10:00:00Z', artifact_sha256: 'a'.repeat(64),
    release: { repository: 'owner/repo', source_commit: 'b'.repeat(40), platform: 'linux-arm64', release_sequence: 12 },
    blockers: [], scope: 'Admission record only.',
  } }));
  await page.goto('/release-security');
  await expect(page.getByRole('heading', { name: 'Admission recorded; API binary matches' })).toBeVisible();
  await expect(page.getByText('Not performed by this page')).toBeVisible();
  await expect(page.getByText('linux-arm64')).toBeVisible();
  await expect(page.getByText('b'.repeat(40))).toBeVisible();
});
