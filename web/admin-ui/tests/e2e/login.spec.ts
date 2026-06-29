import { expect, test } from '@playwright/test';
import { installMockApi } from './support/mockApi';

test.describe('admin authentication', () => {
  test('signs in with a token and lands on the dashboard', async ({ page }) => {
    await installMockApi(page);

    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'AegisNAS Admin' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Continue With Single Sign-On' })).toBeVisible();

    await page.getByPlaceholder('Enter admin token').fill('token-super');
    await page.getByRole('button', { name: 'Sign In With Token' }).click();

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('Live appliance health, access posture, and service readiness.')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Production Readiness' })).toBeVisible();
    await expect(page.getByText('Production readiness is blocked by 1 required check(s).')).toBeVisible();
    await expect(page.getByText('AegisNAS Vendor Identity')).toBeVisible();
  });

  test('completes the admin SSO redirect flow', async ({ page }) => {
    await installMockApi(page);

    await page.goto('/login');
    await page.getByRole('button', { name: 'Continue With Single Sign-On' }).click();

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('OIDC admin SSO ready.')).toBeVisible();
  });
});
