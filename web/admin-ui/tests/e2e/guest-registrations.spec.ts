import { expect, test } from "@playwright/test";
import { installMockApi, seedAuthenticatedSession } from "./support/mockApi";

test.describe("guest workflow admin path", () => {
  test("approves and rejects guest registrations from the admin UI", async ({
    page,
  }) => {
    await seedAuthenticatedSession(page);
    await installMockApi(page);
    await page.addInitScript(() => {
      window.confirm = () => true;
      window.prompt = () => "Missing sponsor clearance";
    });

    await page.goto("/guest-registrations");
    await expect(
      page.getByRole("heading", { name: "Guest Registrations" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Lifecycle JSON" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Delivery JSON" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Recent lifecycle trend" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Sponsor delivery analytics" }),
    ).toBeVisible();

    const aliceRow = page.locator("tr", { hasText: "Alice Guest" });
    await aliceRow.getByRole("button", { name: "Approve" }).click();
    await expect(aliceRow).toContainText("approved");
    await expect(aliceRow).toContainText("Invite: sent");

    const bobRow = page.locator("tr", { hasText: "Bob Visitor" });
    await bobRow.getByRole("button", { name: "Reject" }).click();
    await expect(bobRow).toContainText("rejected");
    await expect(bobRow).toContainText("Missing sponsor clearance");
  });
});
