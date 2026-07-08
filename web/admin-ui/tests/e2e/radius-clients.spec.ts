import { expect, test } from "@playwright/test";
import { installMockApi, seedAuthenticatedSession } from "./support/mockApi";

test("manages a certificate-authenticated RadSec NAS identity", async ({
  page,
}) => {
  await seedAuthenticatedSession(page);
  await installMockApi(page);
  await page.goto("/radius-clients");

  await expect(
    page.getByRole("heading", { name: "RADIUS Clients" }),
  ).toBeVisible();
  await expect(page.getByRole("cell", { name: "radsec" })).toBeVisible();
  await expect(page.getByText("secure-nas.example.test")).toHaveCount(0);

  await page.getByRole("button", { name: "Add RADIUS client" }).click();
  await page.getByLabel("Short Name").fill("branch-nas");
  await page.getByLabel("IP Address").fill("198.51.100.10");
  await page.getByLabel("Transport").selectOption("radsec");
  await page
    .getByLabel("RadSec Client Certificate CN")
    .fill("branch-nas.example.test");
  await page.getByLabel("RADIUS/1.1 Policy").selectOption("forbid");
  await page.getByRole("button", { name: "Stage Create" }).click();

  await expect(page.getByText(/Change staged/)).toBeVisible();
});
