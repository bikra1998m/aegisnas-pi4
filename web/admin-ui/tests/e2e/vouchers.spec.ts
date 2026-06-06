import { expect, test } from "@playwright/test";
import { installMockApi, seedAuthenticatedSession } from "./support/mockApi";

test.describe("voucher analytics page", () => {
  test("shows voucher inventory analytics and export actions", async ({
    page,
  }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);

    await page.goto("/vouchers");

    await expect(page.getByRole("heading", { name: "Vouchers" })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Voucher Inventory Summary" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Voucher Creation And State Trend" }),
    ).toBeVisible();
    await expect(page.getByText("Total Vouchers")).toBeVisible();
    await expect(page.getByText("Utilization")).toBeVisible();
    await expect(page.getByText("58%")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Export Analytics JSON" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Export Analytics CSV" }),
    ).toBeVisible();
    await expect(
      page
        .locator("section")
        .filter({ has: page.getByRole("heading", { name: "Role Mix" }) })
        .getByText("guest-basic"),
    ).toBeVisible();
    await expect(page.getByRole("cell", { name: "V-001" })).toBeVisible();
  });
});
